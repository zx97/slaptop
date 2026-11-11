#include "slaptop/ldaprc.hpp"

#include <sys/stat.h>

#include <cstdlib>
#include <fstream>
#include <sstream>

namespace slaptop {
namespace {

std::string home() {
    const char* value = std::getenv("HOME");
    return value == nullptr ? std::string() : std::string(value);
}

/// Reads one file; missing or unreadable files are simply skipped.
bool readFile(const std::string& path, std::vector<LdapRcEntry>& entries) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0 || !S_ISREG(info.st_mode)) {
        return false;
    }
    std::ifstream in(path);
    if (!in) {
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        const std::size_t start = line.find_first_not_of(" \t");
        if (start == std::string::npos || line[start] == '#') {
            continue;
        }
        const std::size_t space = line.find_first_of(" \t", start);
        LdapRcEntry entry;
        entry.key = line.substr(start, space == std::string::npos ? std::string::npos
                                                                 : space - start);
        if (space != std::string::npos) {
            const std::size_t valueStart = line.find_first_not_of(" \t", space);
            if (valueStart != std::string::npos) {
                entry.value = line.substr(valueStart);
            }
        }
        entries.push_back(std::move(entry));
    }
    return true;
}

}  // namespace

std::vector<LdapRcFile> readLdapRcFiles() {
    std::vector<LdapRcFile> files;
    if (std::getenv("LDAPNOINIT") != nullptr) {
        return files;  // libldap ignores every ldaprc, so we do too
    }

    std::vector<std::string> candidates;
    if (const char* rc = std::getenv("LDAPRC"); rc != nullptr && *rc != '\0') {
        candidates.emplace_back(rc);
    }
    candidates.emplace_back("./ldaprc");
    candidates.emplace_back("./.ldaprc");
    const std::string base = home();
    if (!base.empty()) {
        candidates.push_back(base + "/ldaprc");
        candidates.push_back(base + "/.ldaprc");
    }

    for (const std::string& candidate : candidates) {
        LdapRcFile file;
        file.path = candidate;
        if (readFile(candidate, file.entries)) {
            files.push_back(std::move(file));
        }
    }
    return files;
}

std::string ldapRcKeys(const LdapRcFile& file) {
    std::string keys;
    for (const LdapRcEntry& entry : file.entries) {
        if (keys.find(entry.key) != std::string::npos) {
            continue;  // same key repeated
        }
        keys += (keys.empty() ? "" : ", ") + entry.key;
    }
    return keys;
}

}  // namespace slaptop
