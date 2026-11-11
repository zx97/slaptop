#include "slaptop/collector/io.hpp"

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netinet/in.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <sstream>
#include <utility>

namespace slaptop::collector {
namespace {

bool readFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    out = buffer.str();
    return true;
}

std::uint64_t toU64(const std::string& text) {
    try {
        return std::stoull(text);
    } catch (...) {
        return 0;
    }
}

/// "sda1" -> "sda", "nvme0n1p2" -> "nvme0n1", "dm-0" stays "dm-0".  Only
/// applied when the parent actually exists in /proc/diskstats.
std::string parentDevice(const std::string& name,
                         const std::map<std::string, DiskCounters>& stats) {
    if (stats.count(name) != 0 || name.empty()) {
        return name;
    }
    std::string candidate = name;
    while (!candidate.empty() && std::isdigit(static_cast<unsigned char>(candidate.back()))) {
        candidate.pop_back();
    }
    if (!candidate.empty() && candidate.back() == 'p' && candidate != name &&
        std::isdigit(static_cast<unsigned char>(candidate[candidate.size() - 2]))) {
        candidate.pop_back();
    }
    return stats.count(candidate) != 0 ? candidate : name;
}

}  // namespace

std::map<std::string, NetCounters> readNetDev() {
    std::string text;
    if (!readFile("/proc/net/dev", text)) {
        return {};
    }
    return parseNetDev(text);
}

std::map<std::string, NetCounters> parseNetDev(std::string_view text) {
    std::map<std::string, NetCounters> counters;
    std::istringstream stream{std::string(text)};
    std::string line;
    std::getline(stream, line);  // header 1
    std::getline(stream, line);  // header 2
    while (std::getline(stream, line)) {
        const std::size_t colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        std::string name = line.substr(0, colon);
        const std::size_t first = name.find_first_not_of(" \t");
        const std::size_t last = name.find_last_not_of(" \t");
        if (first == std::string::npos) {
            continue;
        }
        name = name.substr(first, last - first + 1);
        std::istringstream fields(line.substr(colon + 1));
        std::vector<std::string> values;
        std::string value;
        while (fields >> value) {
            values.push_back(value);
        }
        if (values.size() < 16) {
            continue;
        }
        NetCounters counter;
        counter.rxBytes = toU64(values[0]);
        counter.rxPackets = toU64(values[1]);
        counter.rxErrors = toU64(values[2]);
        counter.rxDropped = toU64(values[3]);
        counter.txBytes = toU64(values[8]);
        counter.txPackets = toU64(values[9]);
        counter.txErrors = toU64(values[10]);
        counter.txDropped = toU64(values[11]);
        counters.emplace(std::move(name), counter);
    }
    return counters;
}

std::map<std::string, DiskCounters> readDiskStats() {
    std::string text;
    if (!readFile("/proc/diskstats", text)) {
        return {};
    }
    return parseDiskStats(text);
}

std::map<std::string, DiskCounters> parseDiskStats(std::string_view text) {
    std::map<std::string, DiskCounters> counters;
    std::istringstream stream{std::string(text)};
    std::string line;
    while (std::getline(stream, line)) {
        std::istringstream fields(line);
        std::vector<std::string> values;
        std::string value;
        while (fields >> value) {
            values.push_back(value);
        }
        // major minor name reads reads_merged sectors_read ms_reading
        // writes writes_merged sectors_written ... io_ms weighted_io_ms ...
        if (values.size() < 14) {
            continue;
        }
        DiskCounters counter;
        counter.reads = toU64(values[3]);
        counter.readBytes = toU64(values[5]) * 512ULL;
        counter.writes = toU64(values[7]);
        counter.writeBytes = toU64(values[9]) * 512ULL;
        counter.ioMillis = toU64(values[12]);
        counters.emplace(values[2], counter);
    }
    return counters;
}

std::string deviceForPath(const std::string& path) {
    struct stat info {};
    if (path.empty() || ::stat(path.c_str(), &info) != 0) {
        return std::string();
    }
    const unsigned major = static_cast<unsigned>((info.st_dev >> 8) & 0xfffU);
    const unsigned minor = static_cast<unsigned>((info.st_dev & 0xffU) | ((info.st_dev >> 12) & 0xfff00U));

    // /sys/dev/block/M:m is a symlink whose uevent names the device.
    char sysPath[64];
    std::snprintf(sysPath, sizeof(sysPath), "/sys/dev/block/%u:%u/uevent", major, minor);
    std::string uevent;
    if (!readFile(sysPath, uevent)) {
        return std::string();
    }
    const std::size_t key = uevent.find("DEVNAME=");
    if (key == std::string::npos) {
        return std::string();
    }
    std::string name = uevent.substr(key + 8);
    if (const std::size_t newline = name.find('\n'); newline != std::string::npos) {
        name.resize(newline);
    }
    return parentDevice(name, readDiskStats());
}

PathUsage usageOfPath(const std::string& path) {
    PathUsage usage;
    usage.path = path;
    if (path.empty()) {
        return usage;
    }
    struct statvfs filesystem {};
    if (::statvfs(path.c_str(), &filesystem) == 0) {
        usage.totalBytes = static_cast<std::uint64_t>(filesystem.f_blocks) * filesystem.f_frsize;
        usage.freeBytes = static_cast<std::uint64_t>(filesystem.f_bavail) * filesystem.f_frsize;
    }
    usage.device = deviceForPath(path);

    // Mount point: the longest prefix in /proc/self/mountinfo that matches.
    std::string mountinfo;
    if (readFile("/proc/self/mountinfo", mountinfo) && !usage.device.empty()) {
        std::istringstream stream(mountinfo);
        std::string line;
        std::string best;
        while (std::getline(stream, line)) {
            std::istringstream fields(line);
            std::vector<std::string> values;
            std::string value;
            while (fields >> value) {
                values.push_back(value);
            }
            if (values.size() < 5) {
                continue;
            }
            const std::string& mountPoint = values[4];
            const bool deviceMatches = line.find("/dev/" + usage.device) != std::string::npos;
            if (!deviceMatches && mountPoint != "/") {
                continue;
            }
            if (mountPoint.size() > best.size() && path.rfind(mountPoint, 0) == 0) {
                best = mountPoint;
            }
        }
        usage.mountPoint = best;
    }
    return usage;
}

std::vector<std::string> interfacesForAddresses(const std::vector<std::string>& addresses) {
    std::vector<std::string> names;
    const auto add = [&names](const std::string& name) {
        if (std::find(names.begin(), names.end(), name) == names.end()) {
            names.push_back(name);
        }
    };

    struct ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) {
        return names;
    }
    for (struct ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next) {
        if (entry->ifa_addr == nullptr || entry->ifa_addr->sa_family != AF_INET) {
            continue;
        }
        char text[INET_ADDRSTRLEN] = "";
        const auto* address = reinterpret_cast<const struct sockaddr_in*>(entry->ifa_addr);
        if (::inet_ntop(AF_INET, &address->sin_addr, text, sizeof(text)) == nullptr) {
            continue;
        }
        for (const std::string& wanted : addresses) {
            // "0.0.0.0" is a wildcard bind: every interface accepts, so show
            // the real ones (loopback excluded, it is noise for traffic).
            const bool wildcard = wanted.empty() || wanted == "0.0.0.0" || wanted == "*";
            if (wildcard) {
                if (std::strcmp(entry->ifa_name, "lo") != 0) {
                    add(entry->ifa_name);
                }
            } else if (wanted == text) {
                add(entry->ifa_name);
            }
        }
    }
    ::freeifaddrs(list);
    if (names.empty()) {
        add("lo");
    }
    return names;
}

}  // namespace slaptop::collector
