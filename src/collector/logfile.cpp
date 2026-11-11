#include "slaptop/collector/logfile.hpp"

#include <sys/stat.h>

#include <cctype>
#include <cstddef>
#include <cstring>
#include <utility>

namespace slaptop::collector {
namespace {

/// Reads an unsigned decimal number starting at `pos`, advancing it.
bool readNumber(std::string_view text, std::size_t& pos, std::uint64_t& value) {
    while (pos < text.size() && !std::isdigit(static_cast<unsigned char>(text[pos]))) {
        ++pos;
    }
    if (pos >= text.size()) {
        return false;
    }
    std::uint64_t result = 0;
    while (pos < text.size() && std::isdigit(static_cast<unsigned char>(text[pos]))) {
        result = result * 10 + static_cast<std::uint64_t>(text[pos] - '0');
        ++pos;
    }
    value = result;
    return true;
}

/// Finds `key` followed by '=' and parses the decimal value after it.
bool valueAfter(std::string_view line, std::string_view key, std::uint64_t& value) {
    const std::size_t at = line.find(key);
    if (at == std::string_view::npos) {
        return false;
    }
    std::size_t pos = at + key.size();
    return readNumber(line, pos, value);
}

std::uintmax_t inodeOf(const std::string& path) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        return 0;
    }
    return static_cast<std::uintmax_t>(info.st_ino);
}

bool isLevelSeparator(char c) {
    return c == ' ' || c == '\t' || c == ',' || c == '|';
}

/// Case-insensitive comparison against one slapd loglevel name.
bool tokenIs(std::string_view token, std::string_view name) {
    if (token.size() != name.size()) {
        return false;
    }
    for (std::size_t i = 0; i < token.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(token[i])) != name[i]) {
            return false;
        }
    }
    return true;
}

/// Parses a signed decimal token.  Returns false when it is not a number.
bool parseLevelNumber(std::string_view token, long& out) {
    if (token.empty()) {
        return false;
    }
    bool negative = false;
    std::size_t i = 0;
    if (token[0] == '-' || token[0] == '+') {
        negative = token[0] == '-';
        i = 1;
    }
    if (i >= token.size()) {
        return false;
    }
    long value = 0;
    for (; i < token.size(); ++i) {
        if (token[i] < '0' || token[i] > '9') {
            return false;
        }
        value = value * 10 + static_cast<long>(token[i] - '0');
    }
    out = negative ? -value : value;
    return true;
}

}  // namespace

LogLineInfo parseLogLine(std::string_view line) {    LogLineInfo info;

    if (std::uint64_t conn = 0; valueAfter(line, "conn=", conn)) {
        info.conn = conn;
    }
    if (std::uint64_t op = 0; valueAfter(line, "op=", op)) {
        info.op = op;
    }
    if (std::uint64_t err = 0; valueAfter(line, "err=", err)) {
        info.err = static_cast<int>(err);
        // err=32 (noSuchObject) is routine: probing a naming context without
        // a root entry, or asking for an attribute a backend does not expose.
        // Counting it as a failure would drown real errors.
        info.isError = err != 0 && err != 32;
    }

    // Result codes also appear as "RESULT tag=101 err=0"; a bare "error" or
    // "warning" marker covers the non-result diagnostics (config, backend).
    if (line.find("error") != std::string_view::npos ||
        line.find("Error") != std::string_view::npos) {
        info.isError = true;
    }
    if (line.find("warning") != std::string_view::npos) {
        info.isWarning = true;
    }

    // Operation keyword: first token that looks like a slapd verb after the
    // structured fields.
    static constexpr std::string_view verbs[] = {
        "ACCEPT", "BIND", "UNBIND", "SEARCH", "RESULT", "COMPARE", "MODIFY",
        "MODRDN", "ADD",    "DEL",    "ABANDON", "EXTENDED", "SRCH", "CLOSE",
    };
    for (const std::string_view verb : verbs) {
        if (line.find(verb) != std::string_view::npos) {
            info.operation = std::string(verb);
            break;
        }
    }
    return info;
}

bool logLevelHasStats(std::string_view level) {
    std::size_t i = 0;
    bool seen = false;
    while (i < level.size()) {
        while (i < level.size() && isLevelSeparator(level[i])) {
            ++i;
        }
        const std::size_t start = i;
        while (i < level.size() && !isLevelSeparator(level[i])) {
            ++i;
        }
        if (start == i) {
            break;
        }
        seen = true;
        const std::string_view token = level.substr(start, i - start);
        long number = 0;
        if (parseLevelNumber(token, number)) {
            // 256 = stats, 512 = stats2, negative = every bit set.
            if (number < 0 || (number & 256L) != 0 || (number & 512L) != 0) {
                return true;
            }
            continue;
        }
        if (tokenIs(token, "stats") || tokenIs(token, "stats2") || tokenIs(token, "any")) {
            return true;
        }
    }
    // No value at all: unknown, so do not blame the configuration.
    return !seen;
}

std::optional<LogFileSettings> readLogSettingsFromConfigDir(const std::string& configDir) {
    if (configDir.empty()) {
        return std::nullopt;
    }
    // The -F directory holds either a plain slapd.conf or the cn=config LDIF
    // tree; both name the log file.
    std::vector<std::string> candidates = {configDir + "/cn=config.ldif",
                                           configDir + "/slapd.conf"};
    for (const std::string& path : candidates) {
        std::ifstream in(path);
        if (!in) {
            continue;
        }
        LogFileSettings settings;
        std::vector<std::string> lines;
        std::string line;
        while (std::getline(in, line)) {
            if (!line.empty() && line.back() == '\r') {
                line.pop_back();
            }
            lines.push_back(line);
        }
        for (std::size_t i = 0; i < lines.size(); ++i) {
            const std::string& current = lines[i];
            const std::size_t colon = current.find(':');
            if (colon == std::string::npos) {
                continue;
            }
            std::string key = current.substr(0, colon);
            std::string value = current.substr(colon + 1);
            // LDIF continuation lines start with a single space; fold them in
            // without swallowing the next attribute line.
            while (i + 1 < lines.size() && !lines[i + 1].empty() &&
                   lines[i + 1].front() == ' ') {
                value += lines[++i].substr(1);
            }
            const std::size_t start = value.find_first_not_of(" \t");
            value = start == std::string::npos ? std::string() : value.substr(start);
            if (key == "olcLogFile" || key == "logfile") {
                settings.path = value;
            } else if (key == "olcLogFileFormat" || key == "logfile-format") {
                settings.format = value;
            } else if (key == "olcLogLevel" || key == "loglevel") {
                // cn=config stores one value per level: `olcLogLevel: stats`
                // then `olcLogLevel: sync`.  Keeping the last one only would
                // hide `stats` and make the log look silent.
                if (!settings.level.empty()) {
                    settings.level.push_back(' ');
                }
                settings.level += value;
            }
        }
        if (!settings.path.empty()) {
            return settings;
        }
    }
    return std::nullopt;
}

LogTailer::LogTailer(std::string path) : path_(std::move(path)) {
    openAtEnd();
}

bool LogTailer::openAtEnd() {
    stream_.close();
    stream_.open(path_, std::ios::binary);
    if (!stream_) {
        offset_ = 0;
        return false;
    }
    stream_.seekg(0, std::ios::end);
    offset_ = static_cast<std::uintmax_t>(stream_.tellg());
    inode_ = inodeOf(path_);
    pending_.clear();
    return true;
}

void LogTailer::seekToEnd() {
    if (stream_.is_open()) {
        stream_.seekg(0, std::ios::end);
        offset_ = static_cast<std::uintmax_t>(stream_.tellg());
    } else {
        openAtEnd();
    }
}

std::vector<std::string> LogTailer::poll(std::size_t maxLines) {
    std::vector<std::string> lines;

    // Rotation: a different inode, or a file shorter than what we already
    // consumed, means the server opened a fresh file.
    const std::uintmax_t currentInode = inodeOf(path_);
    if (currentInode != 0 && inode_ != 0 && currentInode != inode_) {
        openAtEnd();
        return lines;
    }
    struct stat info {};
    if (::stat(path_.c_str(), &info) == 0 && static_cast<std::uintmax_t>(info.st_size) < offset_) {
        openAtEnd();
        return lines;
    }

    if (!stream_.is_open() && !openAtEnd()) {
        return lines;
    }

    stream_.clear();
    stream_.seekg(static_cast<std::streamoff>(offset_));

    std::string chunk;
    while (lines.size() < maxLines && std::getline(stream_, chunk)) {
        offset_ += chunk.size() + 1;  // getline consumed the newline
        if (!chunk.empty() && chunk.back() == '\r') {
            chunk.pop_back();
        }
        lines.push_back(std::move(chunk));
        chunk.clear();
    }
    if (!stream_ && !stream_.eof()) {
        // Read error: drop the stream so the next poll reopens it.
        stream_.close();
    }
    return lines;
}

}  // namespace slaptop::collector
