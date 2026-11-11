#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace slaptop::collector {

/// Cumulative counters of one network interface, from /proc/net/dev.
struct NetCounters {
    std::uint64_t rxBytes{0};
    std::uint64_t txBytes{0};
    std::uint64_t rxPackets{0};
    std::uint64_t txPackets{0};
    std::uint64_t rxErrors{0};
    std::uint64_t txErrors{0};
    std::uint64_t rxDropped{0};
    std::uint64_t txDropped{0};
};

/// Cumulative counters of one block device, from /proc/diskstats.  The kernel
/// reports sectors (always 512 bytes), converted here to bytes.
struct DiskCounters {
    std::uint64_t readBytes{0};
    std::uint64_t writeBytes{0};
    std::uint64_t ioMillis{0};
    std::uint64_t reads{0};
    std::uint64_t writes{0};
};

/// Where a path lives: its mount point, the block device behind it, and how
/// full that filesystem is.
struct PathUsage {
    std::string path;
    std::string mountPoint;
    std::string device;
    std::uint64_t totalBytes{0};
    std::uint64_t freeBytes{0};
};

/// /proc/net/dev, keyed by interface name.
std::map<std::string, NetCounters> readNetDev();

/// Same, from the content of /proc/net/dev: a remote node ships the file over
/// SSH and the parser stays identical.
std::map<std::string, NetCounters> parseNetDev(std::string_view text);

/// /proc/diskstats, keyed by kernel device name (sda, nvme0n1, dm-0, ...).
std::map<std::string, DiskCounters> readDiskStats();

/// Same, from the content of /proc/diskstats.
std::map<std::string, DiskCounters> parseDiskStats(std::string_view text);

/// Block device name holding `path`, through stat(2), /proc/self/mountinfo and
/// /sys/dev/block.  A partition is folded onto its whole disk, because
/// /proc/diskstats reports the useful counters at the disk level.  Empty when
/// the device cannot be determined.
std::string deviceForPath(const std::string& path);

/// Mount point, device and capacity of `path`.
PathUsage usageOfPath(const std::string& path);

/// Interfaces that carry one of the given addresses (empty address or
/// "0.0.0.0" means "every interface").  Used to show the NICs slapd listens on
/// rather than the whole machine.
std::vector<std::string> interfacesForAddresses(const std::vector<std::string>& addresses);

}  // namespace slaptop::collector
