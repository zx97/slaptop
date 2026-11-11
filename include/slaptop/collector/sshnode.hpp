#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "slaptop/collector/limits.hpp"
#include "slaptop/types.hpp"

namespace slaptop::collector {

/// One remote host reached over SSH, with the key that opens it.
///
///   user@ldap1.example.com key=/home/user/.ssh/id_ed25519 port=22 name=lab instances=proxy,provider,replica compress=on
///
/// `key` and `port` are optional (ssh's defaults), `name` labels the cards,
/// and `instances` restricts the replay to some `slapd_<name>.d` directories.
struct SshNodeSpec {
    std::string user;
    std::string host;
    std::string keyPath;
    int port{0};
    std::string name;
    std::string instances;  ///< "proxy,provider,replica", empty means every instance
    /// Where this line came from ("--node", "config /home/me/.config/... [group acc]",
    /// "node-file ..."): quoted when a duplicate is discarded, so the reason
    /// points at the line to fix rather than at the tool.
    std::string origin;
    /// Compress the SSH stream (`-o Compression=yes`).  The payloads compress
    /// 6 to 9 times (slapd.d mirror, log tail, /proc/net/tcp), so this is a
    /// clear win on a bandwidth-limited link (DMZ, WAN) and a small loss of
    /// CPU on a LAN: off by default, turned on per node.
    bool compress{false};
};

/// Parses one node specification.  Unknown keys are refused, like the remote
/// targets: a typo must not silently fall back to another host's key.
bool parseNodeSpec(std::string_view text, SshNodeSpec& out, std::string& error);

/// Host name ssh would actually use for `target`, with ~/.ssh/config applied
/// (HostName, Match, ProxyJump are resolved by ssh itself): `ssh -G` prints the
/// effective configuration without opening a connection.  Returns `target`
/// unchanged when ssh cannot tell.
std::string sshEffectiveHost(const std::string& target);

/// One specification per line, `#` comments, blank lines ignored.
bool loadNodeFile(const std::string& path, std::vector<SshNodeSpec>& out, std::string& error);

/// True when `name` is selected by the spec's `instances=` list (empty: yes).
bool nodeSelectsInstance(const SshNodeSpec& spec, const std::string& name);

/// A command to read all the local-only sources of one host over SSH.
///
/// One authenticated connection per node (ControlMaster) carries every call:
/// the first one pays the handshake, the rest cost a few milliseconds.  The
/// same connection also forwards the instances' `ldapi` sockets, which is what
/// gives EXTERNAL bind (peer credentials of the SSH user) without any password
/// or TLS: cn=monitor *and* cn=config work exactly as they do locally.
class SshNode {
public:
    explicit SshNode(SshNodeSpec spec);
    ~SshNode();

    SshNode(const SshNode&) = delete;
    SshNode& operator=(const SshNode&) = delete;

    const SshNodeSpec& spec() const { return spec_; }
    std::string label() const { return spec_.name.empty() ? spec_.host : spec_.name; }

    /// Runs one command; returns false and fills `error` when ssh fails.
    bool run(std::string_view command, std::string& out, std::string& error) const;

    /// Runs one command and returns its output, empty on failure (the error is
    /// recorded for the diagnostics).
    std::string runOrEmpty(std::string_view command, std::string& error) const;

    /// Starts a forwarding process for one unix socket and returns the local
    /// `ldapi://` URI to hand to libldap.  Returns an empty string on failure.
    std::string forwardSharedSocket(const std::string& instance, const std::string& remotePath,
                                    std::string& error);

    /// Caches the node's `slapd.d` tree locally and returns that directory, so
    /// the on-disk parsers (architecture, databases, log settings) work
    /// unchanged on a remote instance.  `maxAgeSeconds` keeps the ssh traffic
    /// reasonable: the tree changes only on configuration edits.
    std::string mirrorConfigDir(const std::string& instance, const std::string& remoteDir,
                                int maxAgeSeconds, std::string& error);

    /// Remote `/proc` sampling for a set of pids, in one call.
    struct ProcSnapshot {
        pid_t pid{0};
        std::uint64_t utimeTicks{0};
        std::uint64_t stimeTicks{0};
        std::uint64_t threads{0};
        std::uint64_t rssBytes{0};
        std::uint64_t vszBytes{0};
        /// Online CPUs of the node, the denominator of cpuPercent.
        int cpuCount{0};
        /// Total RAM of the node, in bytes: the denominator of a memory graph.
        std::uint64_t memTotalBytes{0};
        /// MemAvailable of the node, in bytes.
        std::uint64_t memAvailableBytes{0};
        bool valid{false};
    };
    std::vector<ProcSnapshot> sampleProcesses(const std::vector<pid_t>& pids, std::string& error) const;

    /// One sample for `pid`, taken from a batch that covers every pid the node
    /// knows, refreshed at most every `maxAgeMs`.  Three instances on one host
    /// then cost one `cat` per round instead of three.
    std::optional<ProcSnapshot> cachedSample(pid_t pid, int maxAgeMs, std::string& error);

    /// File descriptors and ephemeral ports of one instance, cached `maxAgeMs`.
    ///
    /// One call serves every pid the node knows: /proc/net/tcp is 130 KB on a
    /// busy proxy and belongs to the node, not to an instance, so asking per
    /// instance would ship it three times for the same answer.
    SocketLimits socketLimits(pid_t pid, int maxAgeMs, std::string& error);

    /// `/proc/net/dev` and `/proc/diskstats` of the node.
    bool readIoFiles(std::string& netDev, std::string& diskStats, std::string& error) const;

    /// The same, cached for `maxAgeMs`: the counters belong to the node, not to
    /// an instance, so three instances on one host must not cost three calls
    /// per round.
    bool cachedIoFiles(std::string& netDev, std::string& diskStats, int maxAgeMs,
                       std::string& error) const;

    /// `df -B1 --output=source,size,avail,target <path>`; empty when unknown.
    struct PathUsage {
        std::string path;
        std::string source;      ///< kernel device name (dm-0, sda1, ...)
        std::string mountPoint;
        std::uint64_t total{0};
        std::uint64_t free{0};
        bool valid{false};
    };
    /// One `df` for every path of one instance: a round must not cost one SSH
    /// call per database directory.
    std::vector<PathUsage> pathUsages(const std::vector<std::string>& paths,
                                      std::string& error) const;

    /// Sizes of files, one line "path size blocks" per file.
    struct FileSize {
        std::string path;
        std::uint64_t apparent{0};
        std::uint64_t allocated{0};
        bool valid{false};
    };
    std::vector<FileSize> fileSizes(const std::vector<std::string>& paths,
                                    std::string& error) const;

    /// The instance list of the node, discovered from `ps`.
    std::vector<Instance> discoverInstances(std::string& error);

private:
    std::string sshCommand(const std::string& remoteCommand) const;
    std::string controlPath() const;
    std::string localSocketDir() const;

    SshNodeSpec spec_;
    std::string controlPath_;
    std::string socketDir_;
    mutable std::string lastError_;
    mutable std::mutex cacheMutex_;
    mutable std::string cachedNet_;
    mutable std::string cachedDisk_;
    mutable std::chrono::steady_clock::time_point cachedAt_{};
    mutable std::mutex procMutex_;
    mutable std::chrono::steady_clock::time_point procAt_{};
    mutable std::map<pid_t, ProcSnapshot> procCache_;
    mutable std::vector<pid_t> knownPids_;
    mutable std::mutex limitsMutex_;
    mutable std::chrono::steady_clock::time_point limitsAt_{};
    mutable std::map<pid_t, SocketLimits> limitsCache_;
};

/// Polling tail of a remote file: one short ssh call per round, bounded in
/// size, rotation-aware.  Same contract as LogTailer, so the log panel and the
/// behaviour window consume both without knowing where the lines came from.
class RemoteTailer {
public:
    RemoteTailer(std::shared_ptr<SshNode> node, std::string path, std::uintmax_t backlog = 262144);

    const std::string& path() const { return path_; }
    bool available() const { return node_ != nullptr; }

    std::vector<std::string> poll(std::size_t maxLines = 8192);

private:
    std::shared_ptr<SshNode> node_;
    std::string path_;
    std::uintmax_t offset_{0};
    std::uintmax_t inode_{0};
    std::uintmax_t backlog_{0};
    bool started_{false};
    std::string pending_;
};

}  // namespace slaptop::collector
