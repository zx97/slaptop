#pragma once

#include <cstdint>
#include <fstream>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace slaptop::collector {

/// Parsed highlights of one slapd log line.
struct LogLineInfo {
    bool isError{false};
    bool isWarning{false};
    /// LDAP result code from `err=N`, -1 when the line carries none.
    int err{-1};
    std::uint64_t conn{0};
    std::uint64_t op{0};
    std::string operation;  ///< ACCEPT, BIND, SEARCH, RESULT, ...
};

/// Extracts the fields the dashboard counts, without allocating a regex.
LogLineInfo parseLogLine(std::string_view line);

/// Settings read either from cn=config over LDAP or from the on-disk
/// `<configDir>/cn=config.ldif` when anonymous LDAP cannot see cn=config.
struct LogFileSettings {
    std::string path;
    std::string format;
    /// Every olcLogLevel value, space separated.  The attribute is
    /// multi-valued in cn=config (`olcLogLevel: stats` + `olcLogLevel: sync`);
    /// keeping only the last one made a server that does log statistics look
    /// like one that does not.
    std::string level;
};

/// True when the configured level enables statistics, i.e. writes the
/// `SRCH`/`RESULT` lines the behaviour tab needs.
///
/// `level` may be a list ("stats sync", "256 512", "Stats,Stats2"): cn=config
/// stores one value per level and slapd ORs them.  Numeric values are taken
/// as a bit mask (256 = stats, 512 = stats2, negative = every bit), names are
/// matched case-insensitively against slapd's table; `any` enables
/// everything, `none` nothing.  An empty value means "unknown" and is not
/// reported as missing statistics.
bool logLevelHasStats(std::string_view level);

/// Reads olcLogFile / olcLogFileFormat / olcLogLevel from the slapd config
/// directory (`slapd -F`).  Works without any LDAP privileges.
std::optional<LogFileSettings> readLogSettingsFromConfigDir(const std::string& configDir);

/// Incremental reader for the slapd log file declared by olcLogFile.
///
/// Starts at end-of-file so a running server is not replayed from the
/// beginning, follows appends, and detects rotation by comparing inode and
/// truncation (size smaller than the last offset).
class LogTailer {public:
    explicit LogTailer(std::string path);

    const std::string& path() const { return path_; }
    bool available() const { return stream_.is_open(); }

    /// Points the reader at the current end of file.
    void seekToEnd();

    /// Returns up to `maxLines` complete new lines, empty when nothing new.
    std::vector<std::string> poll(std::size_t maxLines = 8192);

private:
    bool openAtEnd();

    std::string path_;
    std::ifstream stream_;
    std::uintmax_t offset_{0};
    std::uintmax_t inode_{0};
    std::string pending_;
};

}  // namespace slaptop::collector
