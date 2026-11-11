#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "slaptop/collector/sshnode.hpp"
#include "slaptop/model/metrics.hpp"

namespace slaptop {

namespace collector {
class LogTailer;
}

#ifdef SLAPTOP_WITH_LDAP
class LdapClient;
#endif

/// A remote server to watch over LDAP, with its own connection settings.
/// Several directories rarely share one bind DN, so each target carries the
/// credentials it needs; empty fields fall back to the global options.
struct RemoteTarget {
    std::string uri;
    std::string name;  ///< display name; derived from the URI when empty
    std::string bindDn;
    std::string password;
    bool startTls{false};
    bool insecureTls{false};
};

struct EngineOptions {
    /// Seconds between two collection rounds of one instance.
    double intervalSeconds{1.0};
    /// Seconds between two cn=monitor reads.  Listing ~87 monitor entries
    /// costs a few percent of one core on the tested host, and LDAP counters
    /// move slowly: 2s halves the server cost with no visible loss.
    double ldapIntervalSeconds{2.0};
    /// Read cn=monitor over the instance's ldapi:// listener.
    bool enableLdap{true};
    /// Read and tail the file declared by olcLogFile.
    bool enableLog{true};
    /// Optional explicit credentials; empty means anonymous.
    std::string bindDn;
    std::string password;
    /// Watch these servers in addition to the locally discovered instances
    /// (remote monitoring: no /proc data, LDAP only).
    std::vector<RemoteTarget> remoteTargets;
    /// Accept self-signed certificates on ldaps://.
    bool insecureTls{false};
    /// Hosts reached over SSH: their instances are monitored exactly like the
    /// local ones (/proc, cn=config, log, ldapi) through one connection each.
    std::vector<collector::SshNodeSpec> nodes;
};

/// Immutable view handed to the UI: `instances` and `history` share indices.
struct FleetSnapshot {
    std::vector<InstanceMetrics> instances;
    std::vector<InstanceHistory> history;
    std::chrono::system_clock::time_point at{};
    /// Newest contextCSN over the whole fleet, empty when none.
    std::string fleetNewestCsn;
    /// True when a worker was publishing while the snapshot was taken: the
    /// copy is incomplete, so the UI keeps the previous one instead of
    /// blanking the screen.
    bool busy{false};
};

/// Collects every running slapd instance in the background.
///
/// One worker thread per instance keeps a slow or stuck server (a proxy
/// backend can block cn=monitor for seconds) from delaying the others.  The
/// UI only ever reads a mutex-protected snapshot, so a hung server degrades
/// one row instead of freezing the dashboard.
class MonitorEngine {
public:
    explicit MonitorEngine(EngineOptions options);
    ~MonitorEngine();

    MonitorEngine(const MonitorEngine&) = delete;
    MonitorEngine& operator=(const MonitorEngine&) = delete;

    void start();
    void stop();

    /// Copies the current state.  Cheap enough for a frequent UI redraw.
    FleetSnapshot snapshot() const;

    /// Number of instances currently tracked (running workers included).
    std::size_t instanceCount() const;

    /// Workers currently inside a collection round: what the spinner shows.
    int busyCount() const { return collecting_.load(); }

    /// What the operator should know once the dashboard is gone: instances
    /// discarded as duplicates (with the line that declared them) and nodes
    /// that could not be read.  Printed by main() after stop().
    std::vector<std::string> report() const;

    /// Targets the run was configured with: SSH nodes plus remote URIs.  The
    /// startup screen says "0 of 6" instead of guessing.
    std::size_t configuredTargets() const {
        return options_.nodes.size() + options_.remoteTargets.size();
    }

    /// One configured target, as the startup screen needs it.
    struct ConfiguredTarget {
        std::string label;
        /// True when the host is this machine: its instances are merged with
        /// the local discovery, so no instance will ever carry that label.
        bool sameMachine{false};
    };

    /// Targets in declaration order: the startup screen lists them before
    /// discovery has found anything, so a node that never answers is visible
    /// as a missing line rather than as silence.
    std::vector<ConfiguredTarget> configuredTargetsInfo() const;

    /// Live collection period, adjustable from the dashboard (+ / -).
    double collectInterval() const { return interval_.load(); }
    void setCollectInterval(double seconds);

private:
    struct Worker;

    void supervise();
    void runWorker(Worker& worker);
    void collect(Worker& worker, InstanceMetrics& metrics);
    void publish(Worker& worker, const InstanceMetrics& metrics, const InstanceHistory& history);

    EngineOptions options_;
    mutable std::mutex mutex_;
    std::map<std::string, std::unique_ptr<Worker>> workers_;
    /// One SSH connection per node, shared by its instances.
    std::map<std::string, std::shared_ptr<collector::SshNode>> nodes_;
    /// Notes for report(), keyed by their own text so a node that fails on
    /// every cycle is mentioned once.
    /// Naming contexts some instance actually replicates, taken from the
    /// `olcSyncRepl` agreements, never from a contextCSN: a contextCSN can be
    /// inherited from an import and means nothing on its own.
    std::set<std::string> replicatedContexts_;
    std::set<std::string> agreedContexts() const;
    std::set<std::string> noted_;
    std::vector<std::string> notes_;
    void note(const std::string& message);

    /// `spec.host` -> "is this machine", resolved once in start(): an alias in
    /// ~/.ssh/config pointing at this host is a duplicate like any other.
    std::map<std::string, bool> hostIsLocal_;
    bool hostIsThisMachine(const std::string& host);
    std::thread supervisor_;
    std::atomic<bool> running_{false};
    std::atomic<double> interval_{1.0};
    /// Incremented around every collect(), so the UI can say "refreshing".
    std::atomic<int> collecting_{0};
};

}  // namespace slaptop
