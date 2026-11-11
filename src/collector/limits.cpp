#include "slaptop/collector/limits.hpp"

#include <dirent.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <string>

namespace slaptop::collector {
namespace {

/// Whole content of a small file, empty when unreadable.
std::string readFile(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return {};
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    return buffer.str();
}

std::string trim(const std::string& text) {
    const std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

/// "Max open files            1024                 1048576              files"
/// -> 1024.  The soft limit is what the process actually gets.
std::uint64_t softNoFile(const std::string& limits) {
    std::istringstream lines(limits);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("Max open files", 0) != 0) {
            continue;
        }
        std::istringstream fields(line.substr(std::string("Max open files").size()));
        std::string soft;
        std::string hard;
        fields >> soft >> hard;
        if (soft == "unlimited") {
            return 0;  // no cap: the caller shows "-"
        }
        try {
            return std::stoull(soft);
        } catch (...) {
            return 0;
        }
    }
    return 0;
}

/// /proc/sys/fs/file-nr is "allocated  unused  maximum".
void parseFileNr(const std::string& text, SocketLimits& limits) {
    std::istringstream fields(text);
    std::uint64_t allocated = 0;
    std::uint64_t unused = 0;
    std::uint64_t maximum = 0;
    if (!(fields >> allocated >> unused >> maximum)) {
        return;
    }
    limits.systemFilesAllocated = allocated;
    limits.systemFilesMax = maximum;
}

/// "32768\t60999" -> 32768, 60999.
void parsePortRange(const std::string& text, SocketLimits& limits) {
    std::istringstream fields(text);
    std::uint64_t first = 0;
    std::uint64_t last = 0;
    if (!(fields >> first >> last) || first > last || last > 65535) {
        return;
    }
    limits.portFirst = static_cast<std::uint32_t>(first);
    limits.portLast = static_cast<std::uint32_t>(last);
}

/// Counts the local ports of /proc/net/tcp{,6} that fall in the ephemeral
/// range, and the TIME_WAIT sockets of the whole system.  When the process'
/// socket inodes are known, the ones it owns are counted separately.
///
/// Line shape (the local address is the second field):
///   sl  local_address rem_address   st tx_queue rx_queue ...
///    0: 0100007F:1F90 00000000:0000 0A ...
/// The address is little-endian hex with the port after the colon, in hex.
void parseSockets(const std::string& text, SocketLimits& limits,
                  const std::vector<std::uint64_t>& inodes) {
    std::istringstream lines(text);
    std::string line;
    std::getline(lines, line);  // column headers
    while (std::getline(lines, line)) {
        std::istringstream fields(trim(line));
        std::string slot;
        std::string local;
        std::string remote;
        std::string state;
        if (!(fields >> slot >> local >> remote >> state)) {
            continue;
        }
        // TIME_WAIT is worth counting even when the range is unknown: it is
        // the state that keeps a port unusable for a minute.
        if (state == "06") {
            ++limits.hostTimeWait;
        }
        if (limits.portRange() == 0) {
            continue;
        }
        const std::size_t colon = local.rfind(':');
        if (colon == std::string::npos) {
            continue;
        }
        unsigned long port = 0;
        try {
            port = std::stoul(local.substr(colon + 1), nullptr, 16);
        } catch (...) {
            continue;
        }
        if (port < limits.portFirst || port > limits.portLast) {
            continue;
        }
        ++limits.hostPortsInUse;
        if (!inodes.empty()) {
            // Field 10 of the row is the socket inode; the columns after it
            // (refcount, sock pointer) vary with the kernel, so it must be read
            // by position, never as "the last field".
            std::istringstream row(trim(line));
            std::string field;
            std::uint64_t inode = 0;
            for (int index = 1; index <= 10 && (row >> field); ++index) {
                if (index == 10) {
                    try {
                        inode = std::stoull(field);
                    } catch (...) {
                        inode = 0;
                    }
                }
            }
            if (inode != 0 && std::binary_search(inodes.begin(), inodes.end(), inode)) {
                ++limits.portsInUse;
                if (state == "06") {
                    ++limits.timeWait;
                }
            }
        }
    }
}

/// Inodes of the socket descriptors of `pid`, from the "socket:[N]" target of
/// each /proc/<pid>/fd link.  Empty when the directory is unreadable.
std::vector<std::uint64_t> socketInodes(int pid) {
    std::vector<std::uint64_t> inodes;
    const std::string base = "/proc/" + std::to_string(pid) + "/fd";
    DIR* dir = ::opendir(base.c_str());
    if (dir == nullptr) {
        return inodes;
    }
    while (const dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name == "." || name == "..") {
            continue;
        }
        char target[64];
        const ssize_t length = ::readlink((base + "/" + name).c_str(), target, sizeof(target) - 1);
        if (length <= 0) {
            continue;
        }
        target[length] = '\0';
        const std::string link(target);
        const std::size_t open = link.find("socket:[");
        if (open == std::string::npos) {
            continue;
        }
        try {
            inodes.push_back(std::stoull(link.substr(open + 8)));
        } catch (...) {
        }
    }
    ::closedir(dir);
    return inodes;
}

/// Number of entries in /proc/<pid>/fd, 0 when unreadable.
std::uint64_t countFds(int pid) {
    DIR* dir = ::opendir(("/proc/" + std::to_string(pid) + "/fd").c_str());
    if (dir == nullptr) {
        return 0;
    }
    std::uint64_t count = 0;
    while (const dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name != "." && name != "..") {
            ++count;
        }
    }
    ::closedir(dir);
    return count;
}

}  // namespace

SocketLimits parseSocketLimits(std::string_view limits, std::uint64_t fdCount,
                               std::string_view netTcp, std::string_view netTcp6,
                               std::string_view fileNr, std::string_view portRange,
                               const std::vector<std::uint64_t>& socketInodes) {
    SocketLimits result;
    result.fdsOpen = fdCount;
    result.fdsLimit = softNoFile(std::string(limits));
    parseFileNr(std::string(fileNr), result);
    parsePortRange(std::string(portRange), result);
    std::vector<std::uint64_t> sorted = socketInodes;
    std::sort(sorted.begin(), sorted.end());
    parseSockets(std::string(netTcp), result, sorted);
    parseSockets(std::string(netTcp6), result, sorted);

    // Available means "these files were read", not "the limit is non-zero":
    // a soft limit of `unlimited` is a real answer, and so is a kernel without
    // ip_local_port_range.  Only an empty /proc/<pid> leaves it false.
    result.available = !limits.empty() || fdCount != 0 || result.portRange() != 0;
    return result;
}

SocketLimits readSocketLimits(int pid) {
    if (pid <= 0) {
        return {};
    }
    const std::string base = "/proc/" + std::to_string(pid);
    return parseSocketLimits(readFile(base + "/limits"), countFds(pid),
                             readFile("/proc/net/tcp"), readFile("/proc/net/tcp6"),
                             readFile("/proc/sys/fs/file-nr"),
                             readFile("/proc/sys/net/ipv4/ip_local_port_range"),
                             socketInodes(pid));
}

}  // namespace slaptop::collector
