#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace slaptop::collector {

/// The two resources that cap how many connections a server can hold, and how
/// many it can open: file descriptors and ephemeral ports.
///
/// They are read from /proc, never estimated:
///   * fds:    the process' own count (/proc/<pid>/fd) against its RLIMIT_NOFILE
///             (/proc/<pid>/limits), plus the system-wide /proc/sys/fs/file-nr;
///   * ports:  the ephemeral range (net.ipv4.ip_local_port_range) and how many
///             local ports inside it are currently taken across /proc/net/tcp
///             and /proc/net/tcp6.
///
/// A port is taken by an outbound connection; an accepted connection costs an
/// fd.  When either is exhausted, slapd refuses new work with "Too many open
/// files" or a bind failure, which is why both are shown together.
struct SocketLimits {
    bool available{false};

    // --- file descriptors -------------------------------------------------
    std::uint64_t fdsOpen{0};
    /// RLIMIT_NOFILE soft limit of the slapd process.
    std::uint64_t fdsLimit{0};
    /// /proc/sys/fs/file-nr: allocated file handles and the system maximum.
    std::uint64_t systemFilesAllocated{0};
    std::uint64_t systemFilesMax{0};

    // --- ephemeral ports (outbound) ---------------------------------------
    std::uint32_t portFirst{0};
    std::uint32_t portLast{0};
    /// Ephemeral ports held by *this process*: its own sockets whose local
    /// port falls in the range.  That is what it opens upstream, so it is the
    /// outbound headroom of the instance — the exact counterpart of its fds.
    std::uint64_t portsInUse{0};
    /// Same count over the whole host: the pool is shared, so the remaining
    /// headroom is the range minus this figure, not minus the process one.
    std::uint64_t hostPortsInUse{0};
    /// TIME_WAIT sockets of *this process*: they keep their port unusable for
    /// 60 s, which is what makes a busy client run out before the range is
    /// actually full.
    std::uint64_t timeWait{0};
    /// Same state over the whole host.  The pool is shared, so the figure that
    /// matters for exhaustion is the host one, but both are kept distinct.
    std::uint64_t hostTimeWait{0};

    std::uint64_t portRange() const {
        return portLast >= portFirst && portLast != 0 ? portLast - portFirst + 1 : 0;
    }
    /// Ports an outbound connection can still obtain.  Computed from the host
    /// total: another process holding a port makes it unavailable too.
    std::uint64_t portsFree() const {
        const std::uint64_t range = portRange();
        const std::uint64_t taken = std::max(portsInUse, hostPortsInUse);
        return range > taken ? range - taken : 0;
    }
    /// File descriptors the process can still open.
    std::uint64_t fdsFree() const { return fdsLimit > fdsOpen ? fdsLimit - fdsOpen : 0; }
};

/// Reads everything from the local /proc for `pid`.  `available` stays false
/// when /proc/<pid> cannot be read (another user's process).
SocketLimits readSocketLimits(int pid);

/// Same, from the files shipped by a remote node, so one SSH call carries the
/// whole measurement and the parser is shared with the local path.
///
/// `limits` is /proc/<pid>/limits, `netTcp`/`netTcp6` are /proc/net/tcp{,6},
/// `fileNr` is /proc/sys/fs/file-nr and `portRange` is
/// /proc/sys/net/ipv4/ip_local_port_range; `fdCount` is the number of entries
/// in /proc/<pid>/fd.  `socketInodes` are the inodes of that process' socket
/// descriptors (the "socket:[N]" targets of its fd links): they are what ties a
/// /proc/net/tcp row to this process rather than to the machine.
SocketLimits parseSocketLimits(std::string_view limits, std::uint64_t fdCount,
                               std::string_view netTcp, std::string_view netTcp6,
                               std::string_view fileNr, std::string_view portRange,
                               const std::vector<std::uint64_t>& socketInodes = {});

}  // namespace slaptop::collector
