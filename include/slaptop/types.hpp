#pragma once

#include <sys/types.h>

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

namespace slaptop {

/// Monitored slapd instance, as discovered from /proc/<pid>/cmdline.
struct Instance {
    /// Short label derived from the config directory name (e.g. "proxy" from
    /// ".../slapd_proxy.d").  Falls back to the raw basename when the naming
    /// convention differs.
    std::string name;
    /// Directory passed through `-F`, e.g. ".../slapd_proxy.d".
    std::string configDir;
    /// File passed through `-f` (the slapd.conf style, without -F).
    std::string configFile;
    /// File passed through `-l`: slapd's own log destination.
    std::string logArg;
    /// Process id owning this configuration.
    pid_t pid{0};
    /// Listeners extracted from `-h` (e.g. "ldap://:1389/").
    std::vector<std::string> listeners;
    /// Empty for a locally discovered instance; the node label when the
    /// instance lives on a host reached over SSH.
    std::string nodeLabel;

    // --- Remote targets only ---------------------------------------------
    // A remote server can need its own credentials: one global bind DN cannot
    // cover several directories.  Empty/false means "use the global option".
    std::string bindDn;
    std::string password;
    /// Upgrade an ldap:// connection with StartTLS before binding.
    bool startTls{false};
    /// Accept a self-signed certificate on this instance only.
    bool insecureTls{false};
};

/// One /proc/<pid> sample.  Raw counters are kept so callers can derive rates
/// themselves; `cpuPercent` is already scaled against the previous sample.
struct ProcSample {
    pid_t pid{0};
    std::uint64_t utimeTicks{0};
    std::uint64_t stimeTicks{0};
    std::uint64_t numThreads{0};
    std::uint64_t rssBytes{0};
    std::uint64_t vszBytes{0};
    /// Share of one core (0..N*100), meaningful from the second sample on.
    /// A process busy on three cores reads 300, which is why `cpuCount` is
    /// carried along: 300 of 800 % is a third of the machine, and without the
    /// denominator the number looks like a measurement error.
    double cpuPercent{0.0};
    /// Online CPUs of the host running the process (0 when unknown): the
    /// denominator, 100 % per core.
    int cpuCount{0};
    /// Total RAM of that host, in bytes (0 when unknown).  Taken from the
    /// instance's own /proc/meminfo, so a graph showing "602.9M / 16G" talks
    /// about the node, never about the machine running slaptop.
    std::uint64_t memTotalBytes{0};
    /// MemAvailable of that host, in bytes (0 when unknown): what the kernel
    /// says can still be handed out without swapping.  `memTotalBytes -
    /// memAvailableBytes` is the system's real usage, page cache excluded.
    std::uint64_t memAvailableBytes{0};
    std::chrono::steady_clock::time_point at{};
};

}  // namespace slaptop
