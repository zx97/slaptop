#include "slaptop/engine.hpp"

#include <ifaddrs.h>
#include <netdb.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <ctime>
#include <deque>
#include <set>
#include <thread>
#include <utility>

#include "slaptop/collector/behavior.hpp"
#include "slaptop/collector/configdir.hpp"
#include "slaptop/collector/discovery.hpp"
#include "slaptop/collector/io.hpp"
#include "slaptop/collector/lmdb.hpp"
#include "slaptop/collector/logfile.hpp"
#include "slaptop/collector/sshnode.hpp"
#include "slaptop/collector/proc.hpp"

#ifdef SLAPTOP_WITH_LDAP
#include "slaptop/collector/ldap.hpp"
#endif

namespace slaptop {
namespace {

using Clock = std::chrono::steady_clock;

/// Short, lowercased hostname of this machine.
std::string localHostName() {
    char buffer[256];
    if (::gethostname(buffer, sizeof(buffer)) != 0) {
        return {};
    }
    std::string name(buffer);
    if (const std::size_t dot = name.find('.'); dot != std::string::npos) {
        name.resize(dot);
    }
    for (char& c : name) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return name;
}

/// Every address of this machine (all interfaces and loopback), as text.
std::set<std::string> localAddresses() {
    std::set<std::string> addresses;
    ifaddrs* list = nullptr;
    if (::getifaddrs(&list) != 0) {
        return addresses;
    }
    for (const ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next) {
        if (entry->ifa_addr == nullptr) {
            continue;
        }
        char text[NI_MAXHOST];
        const socklen_t length = static_cast<socklen_t>(
            entry->ifa_addr->sa_family == AF_INET ? sizeof(sockaddr_in) : sizeof(sockaddr_in6));
        if (::getnameinfo(entry->ifa_addr, length, text, sizeof(text), nullptr, 0,
                          NI_NUMERICHOST) == 0) {
            addresses.insert(text);
        }
    }
    ::freeifaddrs(list);
    return addresses;
}

/// Addresses `host` resolves to, as text.
std::set<std::string> resolveAddresses(const std::string& host) {
    std::set<std::string> addresses;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* result = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &result) != 0) {
        return addresses;
    }
    for (const addrinfo* entry = result; entry != nullptr; entry = entry->ai_next) {
        char text[NI_MAXHOST];
        if (::getnameinfo(entry->ai_addr, entry->ai_addrlen, text, sizeof(text), nullptr, 0,
                          NI_NUMERICHOST) == 0) {
            addresses.insert(text);
        }
    }
    ::freeaddrinfo(result);
    return addresses;
}

/// True when `host` designates the machine running slaptop.
///
/// Three answers, cheapest first: the literal name, then the name ssh would
/// really use (an alias in ~/.ssh/config), then the address it resolves to
/// compared with this machine's own addresses.  Monitoring a host both locally
/// and as a node is a duplicate, not a second server.
bool isThisHost(const std::string& host) {
    const auto shortName = [](std::string name) {
        if (const std::size_t dot = name.find('.'); dot != std::string::npos) {
            name.resize(dot);
        }
        for (char& c : name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return name;
    };
    const std::string name = shortName(host);
    if (name == localHostName() || name == "localhost" || name == "127" || name == "::1" ||
        name == "[::1]") {
        return true;
    }

    // The alias may only exist in ssh's configuration.
    static const std::set<std::string> kLocal = localAddresses();
    const std::string effective = collector::sshEffectiveHost(host);
    for (const std::string& address : resolveAddresses(effective)) {
        if (kLocal.count(address) != 0) {
            return true;
        }
    }
    return false;
}

/// "ldapi://%2Frun%2Fldapi-proxy" -> "/run/ldapi-proxy".
std::string decodeLdapiPath(const std::string& listener) {
    const std::string scheme = "ldapi://";
    if (listener.rfind(scheme, 0) != 0) {
        return {};
    }
    std::string out;
    const std::string encoded = listener.substr(scheme.size());
    for (std::size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '%' && i + 2 < encoded.size()) {
            const auto hex = [](char c) -> int {
                if (c >= '0' && c <= '9') return c - '0';
                if (c >= 'a' && c <= 'f') return c - 'a' + 10;
                if (c >= 'A' && c <= 'F') return c - 'A' + 10;
                return -1;
            };
            const int high = hex(encoded[i + 1]);
            const int low = hex(encoded[i + 2]);
            if (high >= 0 && low >= 0) {
                out.push_back(static_cast<char>((high << 4) | low));
                i += 2;
                continue;
            }
        }
        out.push_back(encoded[i]);
    }
    return out;
}

/// Extracts the epoch seconds of a CSN timestamp ("20261104020651.123456Z").
/// Returns -1 when the shape is unexpected.
long long csnSeconds(const std::string& csn) {
    if (csn.size() < 14) {
        return -1;
    }
    for (std::size_t i = 0; i < 14; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(csn[i]))) {
            return -1;
        }
    }
    std::tm tm{};
    tm.tm_year = std::stoi(csn.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(csn.substr(4, 2)) - 1;
    tm.tm_mday = std::stoi(csn.substr(6, 2));
    tm.tm_hour = std::stoi(csn.substr(8, 2));
    tm.tm_min = std::stoi(csn.substr(10, 2));
    tm.tm_sec = std::stoi(csn.substr(12, 2));
    return static_cast<long long>(::timegm(&tm));
}

/// SID of a CSN: "20261104143557.123456Z#000000#001#000000" -> 1 (hex).
int csnSid(const std::string& csn) {
    const std::size_t first = csn.find('#');
    if (first == std::string::npos) {
        return -1;
    }
    const std::size_t second = csn.find('#', first + 1);
    if (second == std::string::npos) {
        return -1;
    }
    const std::size_t third = csn.find('#', second + 1);
    if (third == std::string::npos) {
        return -1;
    }
    const std::string sid = csn.substr(second + 1, third - second - 1);
    try {
        return static_cast<int>(std::stoul(sid, nullptr, 16));
    } catch (const std::exception&) {
        return -1;
    }
}

/// Stable identity for a worker.  The configuration directory identifies a
/// local instance across a restart (a new pid, same tree), which is what lets
/// a stopped instance keep its card and be revived instead of duplicated.
std::string workerKey(const Instance& instance) {
    if (!instance.nodeLabel.empty()) {
        return "node:" + instance.nodeLabel + "/" + instance.name;
    }
    if (!instance.configDir.empty()) {
        return "cfg:" + instance.configDir;
    }
    if (!instance.listeners.empty()) {
        return "uri:" + instance.listeners.front();
    }
    if (instance.pid > 0) {
        return "pid:" + std::to_string(instance.pid);
    }
    return "name:" + instance.name;
}

/// contextCSN exists only on replicated naming contexts; skip the private
/// ones (cn=config, cn=Monitor, cn=accesslog) that every instance carries.
bool isReplicatedContext(const std::string& namingContext) {    if (namingContext.empty()) {
        return false;
    }
    std::string lower = namingContext;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return lower.rfind("cn=", 0) != 0;
}

}  // namespace

const char* healthLabel(Health health) {
    switch (health) {
        case Health::Running:
            return "running";
        case Health::Degraded:
            return "degraded";
        case Health::Stopped:
            return "stopped";
        case Health::Unknown:
        default:
            return "unknown";
    }
}

// ---------------------------------------------------------------------------
// Worker
// ---------------------------------------------------------------------------

struct MonitorEngine::Worker {
    Instance instance;
    std::thread thread;
    std::atomic<bool> stop{false};

    // --- Owned by the worker thread, never touched by readers ------------
    collector::ProcSampler sampler;
    std::unique_ptr<collector::LogTailer> tailer;
    /// Set when the instance lives on an SSH node: every local source (/proc,
    /// /proc/net, slapd.d, the log file) is then read through the connection.
    std::shared_ptr<collector::SshNode> node;
    std::unique_ptr<collector::RemoteTailer> remoteTailer;
    /// Previous ticks per pid, for the CPU delta of a remote process.
    std::map<pid_t, std::pair<std::uint64_t, Clock::time_point>> remoteTicks;
    /// Local mirror of the node's slapd.d tree, refreshed every five minutes.
    std::string mirrorDir;
    /// Non-empty when the ldapi EXTERNAL bind was refused: the naming context
    /// (and cn=config) are then unreadable, and the replication page says so
    /// rather than staying empty.
    std::string externalRefused;
    std::string externalRefusedFor;
    /// Format of the tailed log, kept because the path and format must be
    /// republished on every round (the file is resolved once).
    std::string logFormat;
    /// `df` and `data.mdb` sizes change slowly and cost one SSH call each:
    /// they are refreshed every ten seconds, not every round.
    std::map<std::string, collector::SshNode::PathUsage> usageCache;
    std::map<std::string, collector::SshNode::FileSize> sizeCache;
    Clock::time_point slowAt{};
#ifdef SLAPTOP_WITH_LDAP
    std::unique_ptr<LdapClient> ldap;
#endif
    std::string connectError;
    bool logConfigSeen{false};
    InstanceHistory live;
    std::uint64_t lastOps{0};
    double lastOpsPerSecond{0.0};
    Clock::time_point lastLdapAt{};
    /// cn=config / slapd.d is re-read every five minutes: a topology change
    /// (new overlay, new database) must show up without a restart, and reading
    /// the files is cheap.
    bool directorySeen{false};
    Clock::time_point directoryAt{};
    collector::DirectoryConfig directory;

    /// Rolling window of log lines, shared with the UI through the snapshot.
    std::deque<LogEntry> recentLog;
    /// Behaviour window: who spends the etime, on which filter family.  Fed
    /// from the same lines as the log panel, so the two always agree.
    collector::BehaviorWindow behavior;
    /// conn -> bind DN, recovered from BIND lines.
    std::map<unsigned long, std::string> connectionBinds;
    /// Connection numbers used by slaptop itself: every line they produce is
    /// dropped, so the log shows the traffic being monitored, not the monitor.
    std::set<unsigned long> selfConns;
    /// When the previous monitoring round completed, for the per-type rates.
    Clock::time_point lastMonitorAt{};
    /// Previous I/O counters, for the per-second rates of the interfaces and
    /// the disks this instance uses.
    std::map<std::string, collector::NetCounters> lastNet;
    std::map<std::string, collector::DiskCounters> lastDisk;
    Clock::time_point lastIoAt{};
    /// When MDB_MAP_FULL was last seen in the log: at that point writes are
    /// already failing, which is a fact, not a forecast.
    Clock::time_point mapFullAt{};
    std::uint64_t logSequence{0};
    std::uint64_t lastLogLines{0};
    std::uint64_t lastLogErrors{0};
    Clock::time_point lastAt{};

    /// contextCSN is expensive and noisy (`err=32` on empty contexts), so it
    /// is polled on its own slower cadence and cached between rounds.
    std::map<std::string, Clock::time_point> csnNextCheck;
    std::map<std::string, std::vector<std::string>> csnCache;

    /// Connection list: refreshed at most every 30 s (a busy server exposes
    /// thousands of entries, and each costs memory and render time).
    Clock::time_point lastConnectionRefresh{};
    std::vector<ConnectionInfo> cachedConnections;

    /// Last cn=monitor answer, reused between slower LDAP rounds.
    Clock::time_point nextLdapAt{};
    bool hasLastMonitor{false};
    MonitorSnapshot lastMonitor;

    // --- Published under the engine mutex --------------------------------
    InstanceMetrics metrics;
    InstanceHistory history;
};

// ---------------------------------------------------------------------------
// MonitorEngine
// ---------------------------------------------------------------------------

MonitorEngine::MonitorEngine(EngineOptions options) : options_(std::move(options)) {
    interval_.store(options_.intervalSeconds);
}

void MonitorEngine::setCollectInterval(double seconds) {
    if (seconds >= 0.1 && seconds <= 60.0) {
        interval_.store(seconds);
    }
}

MonitorEngine::~MonitorEngine() {
    stop();
}

void MonitorEngine::start() {
    if (running_.exchange(true)) {
        return;
    }
    // Resolve every node once, before the first round: the lookups (and the
    // `ssh -G` that expands an alias) cost one round-trip each, and doing them
    // here keeps the collection loop free of DNS and of process spawns.
    for (const collector::SshNodeSpec& spec : options_.nodes) {
        hostIsThisMachine(spec.host);
    }
    supervisor_ = std::thread([this] {
        try {
            supervise();
        } catch (const std::exception& error) {
            // An exception here would terminate the whole process; keep the
            // dashboard alive and put the reason in the report.
            note(std::string("supervisor stopped: ") + error.what());
            running_.store(false);
        } catch (...) {
            note("supervisor stopped: unknown error");
            running_.store(false);
        }
    });
}

void MonitorEngine::stop() {
    if (!running_.exchange(false)) {
        return;
    }
    if (supervisor_.joinable()) {
        supervisor_.join();
    }

    std::vector<std::unique_ptr<Worker>> leftovers;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        // The last error of every instance goes into the report: once the
        // dashboard is gone, a red card leaves nothing to read.
        for (auto& [pid, worker] : workers_) {
            if (!worker->metrics.error.empty()) {
                note("instance '" + worker->instance.name + "'" +
                     (worker->instance.nodeLabel.empty()
                          ? std::string()
                          : " (node " + worker->instance.nodeLabel + ")") +
                     ": " + worker->metrics.error);
            }
        }
        for (auto& [pid, worker] : workers_) {
            worker->stop = true;
            leftovers.push_back(std::move(worker));
        }
        workers_.clear();
    }
    // Join outside the lock: a worker may still be publishing its last round,
    // and destroying a joinable std::thread would std::terminate.
    for (auto& worker : leftovers) {
        if (worker->thread.joinable()) {
            worker->thread.join();
        }
    }
    leftovers.clear();
}

std::size_t MonitorEngine::instanceCount() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return workers_.size();
}

/// Normalised DN, the form used to compare a search base with a naming context.
static std::string normalizedDn(const std::string& dn) {
    std::string out;
    for (const char c : dn) {
        if (c != ' ') {
            out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }
    }
    return out;
}

std::set<std::string> MonitorEngine::agreedContexts() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return replicatedContexts_;
}

void MonitorEngine::note(const std::string& message) {
    if (noted_.insert(message).second) {
        notes_.push_back(message);
    }
}

std::vector<MonitorEngine::ConfiguredTarget> MonitorEngine::configuredTargetsInfo() const {
    std::vector<ConfiguredTarget> targets;
    for (const collector::SshNodeSpec& spec : options_.nodes) {
        ConfiguredTarget target;
        target.label = spec.name.empty() ? spec.host : spec.name;
        const auto cached = hostIsLocal_.find(spec.host);
        target.sameMachine = cached != hostIsLocal_.end() && cached->second;
        targets.push_back(std::move(target));
    }
    for (const RemoteTarget& remote : options_.remoteTargets) {
        targets.push_back(ConfiguredTarget{remote.name.empty() ? remote.uri : remote.name,
                                           false});
    }
    return targets;
}

std::vector<std::string> MonitorEngine::report() const { return notes_; }

bool MonitorEngine::hostIsThisMachine(const std::string& host) {
    const auto cached = hostIsLocal_.find(host);
    if (cached != hostIsLocal_.end()) {
        return cached->second;
    }
    const bool local = isThisHost(host);
    hostIsLocal_[host] = local;
    return local;
}

void MonitorEngine::supervise() {
    while (running_.load()) {
        std::vector<Instance> discovered = collector::discoverInstances();
        // Remote URIs are *added* to the local ones: watching a distant server
        // from a host that also runs slapd is the common case.
        if (!options_.remoteTargets.empty()) {
            for (const RemoteTarget& target : options_.remoteTargets) {
                Instance remote;
                remote.pid = 0;
                remote.configDir.clear();
                remote.listeners = {target.uri};
                // Name the card after host:port so two remote URIs on the same
                // host stay distinguishable, unless the target names itself.
                if (!target.name.empty()) {
                    remote.name = target.name;
                } else {
                    const std::size_t scheme = target.uri.find("://");
                    remote.name = scheme == std::string::npos
                                      ? target.uri
                                      : target.uri.substr(scheme + 3);
                }
                if (remote.name.empty()) {
                    remote.name = "remote";
                }
                remote.bindDn = target.bindDn;
                remote.password = target.password;
                remote.startTls = target.startTls;
                remote.insecureTls = target.insecureTls;
                discovered.push_back(std::move(remote));
            }
        }

        // Instances living on remote nodes: one SSH connection per node, then
        // the same discovery as local, keyed by the -F directory.
        {
            std::lock_guard<std::mutex> lock(mutex_);
            for (const collector::SshNodeSpec& spec : options_.nodes) {
                const std::string label = spec.name.empty() ? spec.host : spec.name;
                if (nodes_.find(label) == nodes_.end()) {
                    nodes_[label] = std::make_shared<collector::SshNode>(spec);
                }
            }
        }
        // Instances already claimed by a node of each host, so a host listed
        // twice does not publish the same process twice.
        std::set<std::string> seenOnHost;
        // Pids the local discovery already published: a node that is in fact
        // this machine would report them a second time.
        std::set<pid_t> localPids;
        for (const Instance& instance : discovered) {
            if (instance.pid > 0 && instance.nodeLabel.empty()) {
                localPids.insert(instance.pid);
            }
        }
        for (const collector::SshNodeSpec& spec : options_.nodes) {
            const std::string label = spec.name.empty() ? spec.host : spec.name;
            std::shared_ptr<collector::SshNode> node;
            {
                std::lock_guard<std::mutex> lock(mutex_);
                node = nodes_[label];
            }
            std::string error;
            std::vector<Instance> found = node->discoverInstances(error);
            if (!error.empty()) {
                note("node '" + label + "' (" + (spec.origin.empty() ? "node" : spec.origin) +
                     "): " + error);
            }
            const bool sameMachine = hostIsThisMachine(spec.host);
            const std::string origin = spec.origin.empty() ? "node" : spec.origin;
            // Gathered per node so the report says "repeats proxy, replica, provider" once
            // instead of one line per instance.
            std::vector<std::string> localDuplicates;
            std::vector<std::string> nodeDuplicates;
            for (Instance& instance : found) {
                instance.nodeLabel = label;
                if (sameMachine && localPids.count(instance.pid) != 0) {
                    // Nothing is wrong with the config: the host can be watched
                    // either way, but not both at once.
                    localDuplicates.push_back(instance.name);
                    continue;
                }
                // The same host can be reached by two node lines.  Disjoint
                // `instances=` lists are legitimate (`instances=proxy` and
                // `instances=provider`), but listing a whole host twice is not: every
                // instance would appear twice on every screen.
                const std::string key =
                    spec.host + "|" + std::to_string(static_cast<long long>(instance.pid));
                if (!seenOnHost.insert(key).second) {
                    nodeDuplicates.push_back(instance.name);
                    continue;
                }
                discovered.push_back(std::move(instance));
            }
            const auto join = [](const std::vector<std::string>& names) {
                std::string joined;
                for (const std::string& name : names) {
                    joined += (joined.empty() ? "" : ", ") + name;
                }
                return joined;
            };
            if (!localDuplicates.empty()) {
                note("duplicate discarded: node '" + label + "' (" + origin + ") repeats " +
                     join(localDuplicates) +
                     " — this host is the machine running slaptop, so declare it locally or as "
                     "a node, not both");
            }
            if (!nodeDuplicates.empty()) {
                note("duplicate discarded: node '" + label + "' (" + origin + ") repeats " +
                     join(nodeDuplicates) + " of " + spec.host +
                     " — use one node line per host, or disjoint instances= lists");
            }
        }

        // What is replicated, according to the agreements only: the searchbase
        // of each olcSyncRepl (the database suffix when the line omits it).
        {
            std::set<std::string> agreed;
            std::lock_guard<std::mutex> lock(mutex_);
            for (const auto& [key, worker] : workers_) {
                for (const auto& database : worker->directory.databases) {
                    for (const auto& consumer : database.syncrepl) {
                        const std::string base =
                            consumer.searchBase.empty() ? database.suffix
                                                        : consumer.searchBase;
                        if (!base.empty()) {
                            agreed.insert(normalizedDn(base));
                        }
                    }
                }
            }
            replicatedContexts_ = std::move(agreed);
            if (std::getenv("SLAPTOP_CSN_DEBUG") != nullptr) {
                std::fprintf(stderr, "agreements: %zu\n", replicatedContexts_.size());
                for (const auto& [key, worker] : workers_) {
                    std::size_t consumers = 0;
                    for (const auto& database : worker->directory.databases) {
                        consumers += database.syncrepl.size();
                    }
                    std::fprintf(stderr, "  worker %s: %zu databases, %zu syncrepl\n",
                                 key.c_str(), worker->directory.databases.size(), consumers);
                }
            }
        }

        std::vector<Worker*> starting;
        std::vector<std::unique_ptr<Worker>> finishing;
        {
            std::lock_guard<std::mutex> lock(mutex_);

            for (const Instance& instance : discovered) {
                const std::string key = workerKey(instance);
                auto existing = workers_.find(key);
                if (existing != workers_.end()) {
                    if (existing->second->instance.pid == instance.pid) {
                        continue;  // same process, nothing to do
                    }
                    // Same configuration, different pid: the instance was
                    // restarted.  Drop the old worker and start a fresh one so
                    // its counters restart from zero.
                    existing->second->stop = true;
                    finishing.push_back(std::move(existing->second));
                    workers_.erase(existing);
                }
                auto worker = std::make_unique<Worker>();
                worker->instance = instance;
                if (!instance.nodeLabel.empty()) {
                    // The enclosing scope already holds mutex_: locking again
                    // here would deadlock a non-recursive mutex.
                    worker->node = nodes_[instance.nodeLabel];
                }
                worker->metrics.instance = instance;
                worker->metrics.health = Health::Unknown;
                starting.push_back(worker.get());
                workers_[key] = std::move(worker);
            }

            // Workers whose process disappeared are *kept*: their thread keeps
            // polling, publishes Health::Stopped and keeps the log readable, so
            // an instance that crashed does not silently leave the fleet.  A
            // later restart is matched on the same key and revives the card.
        }

        for (Worker* worker : starting) {
            worker->thread = std::thread([this, worker] { runWorker(*worker); });
        }

        // Stop and join the workers whose process exited.  The join must
        // happen before destruction, or std::thread would std::terminate.
        for (auto& worker : finishing) {
            if (worker->thread.joinable()) {
                worker->thread.join();
            }
        }
        finishing.clear();

        for (int tick = 0; tick < 20 && running_.load(); ++tick) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

void MonitorEngine::runWorker(Worker& worker) {
    while (!worker.stop.load()) {
        struct BusyGuard {
            std::atomic<int>& counter;
            explicit BusyGuard(std::atomic<int>& c) : counter(c) { counter.fetch_add(1); }
            ~BusyGuard() { counter.fetch_sub(1); }
        };
        const Clock::time_point begin = Clock::now();

        InstanceMetrics metrics;
        metrics.instance = worker.instance;
        {
            const BusyGuard guard(collecting_);
            collect(worker, metrics);
        }

        {
            std::lock_guard<std::mutex> lock(mutex_);
            worker.metrics = metrics;
            worker.history = worker.live;
        }

        const auto elapsed = Clock::now() - begin;
        const auto target = std::chrono::duration<double>(interval_.load());
        if (elapsed < target) {
            std::this_thread::sleep_for(target - elapsed);
        }
    }
}

namespace {

/// Samples one remote pid over SSH and derives the CPU percentage from the
/// previous call, exactly like ProcSampler does locally.
std::optional<ProcSample> sampleRemote(
    const std::shared_ptr<collector::SshNode>& node,
    std::map<pid_t, std::pair<std::uint64_t, Clock::time_point>>& ticks, pid_t pid) {
    std::string error;
    const std::optional<collector::SshNode::ProcSnapshot> snapshot =
        node->cachedSample(pid, 900, error);
    if (!snapshot || !snapshot->valid) {
        return std::nullopt;
    }
    const auto& raw = *snapshot;
    ProcSample sample;
    sample.pid = raw.pid;
    sample.utimeTicks = raw.utimeTicks;
    sample.stimeTicks = raw.stimeTicks;
    sample.numThreads = raw.threads;
    sample.rssBytes = raw.rssBytes;
    sample.vszBytes = raw.vszBytes;
    sample.cpuCount = raw.cpuCount;
    sample.memTotalBytes = raw.memTotalBytes;
    sample.memAvailableBytes = raw.memAvailableBytes;
    const Clock::time_point now = Clock::now();
    const std::uint64_t total = raw.utimeTicks + raw.stimeTicks;
    const auto previous = ticks.find(raw.pid);
    if (previous != ticks.end()) {
        const double seconds =
            std::chrono::duration<double>(now - previous->second.second).count();
        const double elapsedTicks =
            total >= previous->second.first ? static_cast<double>(total - previous->second.first)
                                            : 0.0;
        const double hertz = static_cast<double>(std::max(1L, ::sysconf(_SC_CLK_TCK)));
        if (seconds > 0.0) {
            sample.cpuPercent = 100.0 * elapsedTicks / (seconds * hertz);
        }
    }
    ticks[raw.pid] = {total, now};
    sample.at = now;
    return sample;
}

}  // namespace

void MonitorEngine::collect(Worker& worker, InstanceMetrics& metrics) {
    // Mirror the node's slapd.d locally once every five minutes: the on-disk
    // parsers (architecture, databases, log settings) then work unchanged.
    if (worker.node && !worker.instance.configDir.empty()) {
        std::string mirrorError;
        const std::string mirrored = worker.node->mirrorConfigDir(
            worker.instance.name, worker.instance.configDir, 300, mirrorError);
        if (!mirrored.empty()) {
            worker.mirrorDir = mirrored;
        }
    }
    // Where the configuration can be read.  `-F` first, then the environment
    // convention ($LDAPCONFPROXY for the instance named proxy), then a slapd.conf
    // given with `-f`: cn=config may be out of reach (an olcAuthzRegexp can
    // rewrite the EXTERNAL identity to a DN its ACL does not name), and the
    // files always are.
    const std::string configDir =
        worker.node ? worker.mirrorDir
                    : (!worker.instance.configDir.empty()
                           ? worker.instance.configDir
                           : collector::configDirFromEnvironment(worker.instance.name));

    metrics.collectedAt = std::chrono::system_clock::now();

    const Clock::time_point configNow = Clock::now();
    const bool directoryStale =
        !worker.directorySeen ||
        std::chrono::duration_cast<std::chrono::seconds>(configNow - worker.directoryAt)
                .count() >= 300;
    if (directoryStale) {
        if (!configDir.empty()) {
            worker.directory = collector::readDirectoryConfig(configDir);
            worker.directorySeen = true;
        } else if (!worker.instance.configFile.empty()) {
            worker.directory = collector::readSlapdConf(worker.instance.configFile);
            worker.directorySeen = true;
        }
        if (worker.directorySeen) {
            worker.directoryAt = configNow;
        }
    }
    metrics.directory = worker.directory;

    // A remote instance (--uri) has no /proc entry: skip process sampling.
    bool processGone = false;
    if (worker.instance.pid > 0) {
        const std::optional<ProcSample> sample =
            worker.node ? sampleRemote(worker.node, worker.remoteTicks, worker.instance.pid)
                        : worker.sampler.sample(worker.instance.pid);
        if (!sample) {
            // The card stays, marked stopped: the log of the instance is still
            // on disk and is often the thing to read after a crash.
            metrics.health = Health::Stopped;
            metrics.error = "process exited";
            processGone = true;
        } else {
            metrics.proc = *sample;
            metrics.hasProc = true;
        }
    }

    const Clock::time_point now = Clock::now();
    const double seconds = worker.lastAt.time_since_epoch().count() == 0
                               ? 0.0
                               : std::chrono::duration<double>(now - worker.lastAt).count();

    if (!processGone) {
        metrics.health = Health::Running;
    } else if (worker.hasLastMonitor) {
        // Keep the last cn=monitor answer: a crashed instance is often
        // diagnosed from what it looked like a moment before.
        metrics.monitor = worker.lastMonitor;
        metrics.hasMonitor = true;
    }
    double opsPerSecond = 0.0;

#ifdef SLAPTOP_WITH_LDAP
    if (options_.enableLdap && !processGone) {
        if (!worker.ldap) {
            std::string uri;
            if (worker.instance.pid == 0) {
                uri = worker.instance.listeners.empty() ? std::string()
                                                        : worker.instance.listeners.front();
            } else if (worker.node) {
                // Forward the remote ldapi socket: slapd then sees the SSH
                // user's peer credentials, so EXTERNAL works as it does locally.
                std::string remote;
                for (const std::string& listener : worker.instance.listeners) {
                    if (listener.rfind("ldapi://", 0) == 0) {
                        remote = decodeLdapiPath(listener);
                        break;
                    }
                }
                if (!remote.empty()) {
                    uri = worker.node->forwardSharedSocket(worker.instance.name, remote,
                                                           worker.connectError);
                }
            } else {
                uri = collector::ldapiUri(worker.instance);
            }
            if (!uri.empty()) {
                // A remote target can carry its own credentials: several
                // directories rarely share one bind DN.
                std::string bindDn =
                    worker.instance.bindDn.empty() ? options_.bindDn : worker.instance.bindDn;
                // Over ldapi the peer credentials are the whole point: an
                // anonymous bind reads cn=monitor but NOT the naming context,
                // so contextCSN answered "No such object" while the dashboard
                // looked healthy.  EXTERNAL is the local identity, no password
                // and no TLS.
                if (bindDn.empty() && uri.rfind("ldapi://", 0) == 0) {
                    bindDn = "EXTERNAL";
                }
                const std::string& password = worker.instance.password.empty()
                                                  ? options_.password
                                                  : worker.instance.password;
                const bool insecure = worker.instance.insecureTls || options_.insecureTls;
                auto client = LdapClient::open(uri, bindDn, password, &worker.connectError,
                                               insecure, worker.instance.startTls);
                if (!client && bindDn == "EXTERNAL") {
                    // The peer identity was refused — an olcAuthzRegexp can map
                    // it to a DN that needs a password.  Anonymous still reads
                    // cn=monitor, so keep the dashboard alive and remember the
                    // reason for the replication page.
                    worker.externalRefused = worker.connectError;
                    worker.externalRefusedFor = uri;
                    client = LdapClient::open(uri, "", "", &worker.connectError, insecure,
                                              worker.instance.startTls);
                }
                if (client) {
                    worker.ldap = std::make_unique<LdapClient>(std::move(*client));
                }
            } else {
                worker.connectError = "no ldapi listener";
            }
        }

        if (worker.ldap) {
            // cn=monitor is read on its own (slower) cadence; between two
            // reads the previous answer is reused.
            const bool ldapDue = !worker.hasLastMonitor || now >= worker.nextLdapAt;
            std::optional<MonitorSnapshot> monitor;
            if (ldapDue) {
                monitor = worker.ldap->fetchMonitor();
            }

            if (ldapDue && !monitor) {
                metrics.health = Health::Degraded;
                metrics.error = worker.ldap->lastError();
                // A stuck search leaves the socket unusable: reconnect next round.
                worker.ldap.reset();
                worker.hasLastMonitor = false;
            } else if (ldapDue && monitor) {
                // Refresh the connection list at most every 30 s.
                constexpr auto kConnectionPeriod = std::chrono::seconds(30);
                const bool refreshConnections =
                    worker.lastConnectionRefresh.time_since_epoch().count() == 0 ||
                    now - worker.lastConnectionRefresh >= kConnectionPeriod;
                if (refreshConnections) {
                    // Dedicated query, bounded by a size limit: the periodic
                    // round never carries the connection list.
                    constexpr unsigned kMaxConnections = 40;
                    // Backend connections are the proxy's own; a handful is
                    // enough to see where they point, and a large proxy can
                    // hold hundreds of them.
                    constexpr unsigned kMaxBackendConnections = 20;
                    std::vector<ConnectionInfo> merged;
                    if (auto clients = worker.ldap->fetchConnections(kMaxConnections);
                        clients) {
                        merged = std::move(*clients);
                    }
                    // The proxy's own connections to its upstreams are half the
                    // picture: which application saturates the backend.
                    if (auto backends = worker.ldap->fetchBackendConnections(kMaxBackendConnections);
                        backends) {
                        merged.insert(merged.end(), backends->begin(), backends->end());
                    }
                    if (!merged.empty()) {
                        worker.cachedConnections = std::move(merged);
                        worker.lastConnectionRefresh = now;
                    }
                }
                // Per-operation rates, the "Num/s" line of slapd-watcher:
                // computed here from two monitoring rounds, so the UI needs no
                // history of its own for ten counters.
                const double monitorSeconds =
                    std::chrono::duration<double>(now - worker.lastMonitorAt).count();
                if (worker.hasLastMonitor && monitorSeconds > 0.0) {
                    for (const auto& [type, count] : monitor->opsByType) {
                        const auto previous = worker.lastMonitor.opsByType.find(type);
                        const std::uint64_t before =
                            previous == worker.lastMonitor.opsByType.end() ? count
                                                                          : previous->second;
                        const double delta =
                            count >= before ? static_cast<double>(count - before) : 0.0;
                        monitor->opsRateByType[type] = delta / monitorSeconds;
                    }
                }
                worker.lastMonitorAt = now;
                monitor->connections = worker.cachedConnections;
                worker.lastMonitor = *monitor;
                worker.hasLastMonitor = true;
                worker.nextLdapAt =
                    now + std::chrono::duration_cast<Clock::duration>(
                              std::chrono::duration<double>(options_.ldapIntervalSeconds));

                // olcLogFile comes from cn=config; anonymous binds usually
                // cannot read it, so fall back to the on-disk -F directory.
                if (options_.enableLog && !worker.logConfigSeen) {
                    std::string logPath;
                    std::string logFormat;
    /// `df` and `data.mdb` sizes change slowly and cost one SSH call each:
    /// they are refreshed every ten seconds, not every round.
    std::map<std::string, collector::SshNode::PathUsage> usageCache;
    std::map<std::string, collector::SshNode::FileSize> sizeCache;
    Clock::time_point slowAt{};
                    std::string logLevel;
                    // Files first: they cost nothing, need no ACL, and slapd
                    // rewrites them when the setting changes.  cn=config is the
                    // fallback, for an instance whose files are out of reach.
                    if (!configDir.empty()) {
                        const auto disk = collector::readLogSettingsFromConfigDir(configDir);
                        if (disk && !disk->path.empty()) {
                            logPath = disk->path;
                            logFormat = disk->format;
                            logLevel = disk->level;
                        }
                    }
                    if (logPath.empty()) {
                        if (const auto logConfig = worker.ldap->fetchLogConfig();
                            logConfig && !logConfig->path.empty()) {
                            logPath = logConfig->path;
                            logFormat = logConfig->format;
                            logLevel = logConfig->level;
                        }
                    }
                    if (logPath.empty() && !worker.instance.logArg.empty()) {
                        // `-l` is slapd's own answer, and it costs nothing.
                        logPath = worker.instance.logArg;
                    }
                    if (logPath.empty() && !worker.instance.configFile.empty()) {
                        logPath = collector::logFileFromSlapdConf(worker.instance.configFile);
                    }
                    if (!logPath.empty()) {
                        if (worker.node) {
                            worker.remoteTailer =
                                std::make_unique<collector::RemoteTailer>(worker.node, logPath);
                        } else {
                            worker.tailer = std::make_unique<collector::LogTailer>(logPath);
                        }
                        worker.behavior.setLogLevel(logLevel);
                        worker.logFormat = logFormat;
                        worker.logConfigSeen = true;
                    }
                }

                // Rate must be computed over the LDAP sampling period, not the
                // /proc one: the counters only move when we read them.
                const double ldapSeconds =
                    worker.lastLdapAt.time_since_epoch().count() == 0
                        ? 0.0
                        : std::chrono::duration<double>(now - worker.lastLdapAt).count();
                if (ldapSeconds > 0.0 && worker.lastOps != 0 &&
                    monitor->opsInitiated >= worker.lastOps) {
                    worker.lastOpsPerSecond =
                        static_cast<double>(monitor->opsInitiated - worker.lastOps) / ldapSeconds;
                }
                worker.lastOps = monitor->opsInitiated;
                worker.lastLdapAt = now;
            }

            // Keep the last computed rate visible between two LDAP rounds.
            opsPerSecond = worker.lastOpsPerSecond;

            if (worker.hasLastMonitor) {
                metrics.monitor = worker.lastMonitor;
                metrics.hasMonitor = true;

                // The same naming context appears on several databases
                // (frontend, the real backend, a proxy): read its contextCSN
                // once, otherwise the replication view shows the same SID
                // several times.  The agreement set is copied under the lock:
                // supervise() rebuilds it from the other workers, and reading
                // it unlocked raced.
                const std::set<std::string> agreed = agreedContexts();
                std::set<std::string> contextsSeen;
                for (const DatabaseInfo& database : worker.lastMonitor.databases) {
                    // `monitorIsShadow` is TRUE on a replica — which is exactly
                    // the instance whose contextCSN matters.  Skipping shadow
                    // databases meant a provider read fine while its replicas
                    // showed nothing at all.  Duplicates are already handled by
                    // contextsSeen below.
                    for (const std::string& naming : database.namingContexts) {
                        if (!isReplicatedContext(naming)) {
                            continue;
                        }
                        // No olcSyncRepl covers this context: whatever
                        // contextCSN says here is history (an import), not a
                        // replication state.  Skip it instead of reporting a
                        // lag that means nothing.
                        if (agreed.count(normalizedDn(naming)) == 0) {
                            continue;
                        }
                        if (!contextsSeen.insert(naming).second) {
                            continue;
                        }
                        const auto due = worker.csnNextCheck.find(naming);
                        if (due == worker.csnNextCheck.end() || now >= due->second) {
                            const auto csn = worker.ldap->fetchContextCsn(naming);
                            if (std::getenv("SLAPTOP_CSN_DEBUG") != nullptr) {
                                std::fprintf(stderr, "csn %s -> %s (%s)\n", naming.c_str(),
                                             csn ? std::to_string(csn->size()).c_str() : "nullopt",
                                             worker.ldap->lastError().c_str());
                            }
                            if (csn && !csn->empty()) {
                                worker.csnCache[naming] = *csn;
                                // Providers update often: 5s is plenty for a
                                // replication lag indicator.
                                worker.csnNextCheck[naming] = now + std::chrono::seconds(5);
                            } else {
                                worker.csnCache.erase(naming);
                                // Empty context or access denied: back off so
                                // the server log is not flooded with err=32,
                                // but say it once.
                                if (!worker.externalRefused.empty()) {
                                    metrics.replication.error =
                                        "EXTERNAL refused on " + naming + ": " +
                                        worker.externalRefused +
                                        " — this instance maps the peer credential to a DN that "
                                        "cannot be used without a password";
                                } else if (csn) {
                                    metrics.replication.error =
                                        "no contextCSN on " + naming +
                                        " (this directory is not replicated)";
                                } else {
                                    metrics.replication.error =
                                        naming + ": " + worker.ldap->lastError() +
                                        " — the LDAP identity cannot read this naming context "
                                        "(run slaptop as the slapd user, or grant read access)";
                                }
                                worker.csnNextCheck[naming] = now + std::chrono::seconds(60);
                            }
                        }
                        for (const std::string& value : worker.csnCache[naming]) {
                            metrics.replication.contextCsn.push_back(value);
                        }
                    }
                }
                if (!metrics.replication.contextCsn.empty()) {
                    metrics.replication.available = true;
                    metrics.replication.csns.clear();
                    for (const std::string& value : metrics.replication.contextCsn) {
                        CsnsEntry entry;
                        entry.csn = value;
                        entry.sid = csnSid(value);
                        entry.epoch = csnSeconds(value);
                        metrics.replication.csns.push_back(std::move(entry));
                    }
                    metrics.replication.newestCsn =
                        *std::max_element(metrics.replication.contextCsn.begin(),
                                          metrics.replication.contextCsn.end());
                }
            }
        } else {
            metrics.health = Health::Degraded;
            metrics.error = worker.connectError;
        }
    }
#endif

    // Log statistics.
    if (options_.enableLog && (worker.tailer || worker.remoteTailer)) {
        metrics.log.available = true;
        metrics.log.path =
            worker.tailer ? worker.tailer->path() : worker.remoteTailer->path();
        metrics.log.format = worker.logFormat;
        std::uint64_t newLines = 0;
        std::uint64_t newErrors = 0;
        const std::vector<std::string> fresh = worker.tailer
                                                   ? worker.tailer->poll()
                                                   : worker.remoteTailer->poll();
        for (const std::string& line : fresh) {
            ++newLines;
            const collector::LogLineInfo info = collector::parseLogLine(line);
            LogLevel level = LogLevel::Info;
            if (info.isError) {
                ++newErrors;
                level = LogLevel::Error;
            } else if (info.isWarning) {
                ++metrics.log.warnings;
                level = LogLevel::Warning;
            }
            // The dashboard reads cn=monitor, the databases and contextCSN
            // every few seconds; those requests land in the very log being
            // displayed and would scroll everything else away.  slapd logs one
            // line per base and another per attribute list, and the RESULT
            // lines carry neither, so the only reliable unit is the connection:
            // the first monitor search identifies it, then every line of that
            // connection is dropped until it closes.
            const bool monitorSearch =
                line.find("cn=Monitor\"") != std::string::npos ||
                line.find("cn=monitor\"") != std::string::npos ||
                line.find("attr=contextCSN") != std::string::npos;
            if (info.conn != 0) {
                if (monitorSearch) {
                    worker.selfConns.insert(info.conn);
                    if (worker.selfConns.size() > 32) {
                        worker.selfConns.erase(worker.selfConns.begin());
                    }
                }
                if (worker.selfConns.count(info.conn) != 0) {
                    // The connection is gone: forget it, so a later connection
                    // reusing the number is no longer filtered.
                    if (line.find("closed") != std::string::npos ||
                        line.find("UNBIND") != std::string::npos) {
                        worker.selfConns.erase(info.conn);
                    }
                    continue;
                }
            }

            // Behavioural analysis: same lines as the log panel, but paired
            // (SRCH + RESULT) and folded into a 60 s window.  It runs on the
            // lines that survive the self-traffic filter, so slaptop's own
            // cn=monitor reads never show up as a resource hog.
            worker.behavior.feed(line, now);
            if (line.find("MDB_MAP_FULL") != std::string::npos) {
                worker.mapFullAt = now;
            }

            // "conn=1234 op=0 BIND dn=\"uid=foo,dc=example\" method=128"
            if (line.find("BIND dn=\"") != std::string::npos) {
                const std::size_t connAt = line.find("conn=");
                const std::size_t dnAt = line.find("BIND dn=\"");
                if (connAt != std::string::npos && dnAt != std::string::npos) {
                    std::size_t numberEnd = connAt + 5;
                    while (numberEnd < line.size() &&
                           std::isdigit(static_cast<unsigned char>(line[numberEnd]))) {
                        ++numberEnd;
                    }
                    const std::string number = line.substr(connAt + 5, numberEnd - connAt - 5);
                    const std::size_t valueStart = dnAt + 9;
                    const std::size_t valueEnd = line.find('"', valueStart);
                    if (!number.empty() && valueEnd != std::string::npos) {
                        try {
                            worker.connectionBinds[std::stoul(number)] =
                                line.substr(valueStart, valueEnd - valueStart);
                        } catch (...) {
                        }
                        if (worker.connectionBinds.size() > 128) {
                            worker.connectionBinds.erase(worker.connectionBinds.begin());
                        }
                    }
                }
            }
            worker.recentLog.push_back(LogEntry{line, level, ++worker.logSequence});
            if (worker.recentLog.size() > 120) {
                worker.recentLog.pop_front();
            }
        }
        metrics.log.recent = worker.recentLog;
        metrics.log.binds = worker.connectionBinds;
        worker.behavior.roll(now);
        // The reports are capped far above what any screen can show: the UI
        // draws as many rows as it has room for, and the JSON keeps the rest.
        // A cap equal to the visible height would leave a tall terminal half
        // empty and hide the rows just below the fold.
        metrics.behavior = worker.behavior.snapshot(100);
        metrics.behavior.available = metrics.log.available;
        metrics.behavior.logPath = metrics.log.path;
        worker.lastLogLines += newLines;
        worker.lastLogErrors += newErrors;
        metrics.log.linesRead = worker.lastLogLines;
        metrics.log.errors = worker.lastLogErrors;
        if (seconds > 0.0) {
            metrics.log.linesPerSecond = static_cast<double>(newLines) / seconds;
            metrics.log.errorsPerSecond = static_cast<double>(newErrors) / seconds;
        }
    }

    // --- I/O: the interfaces slapd listens on and the disks it writes to ---
    // A local instance reads /proc and /sys here; a node ships the same files
    // over its SSH connection, so both go through the same code below.
    if (worker.instance.pid > 0 && !processGone) {
        // Which interfaces: the addresses cn=monitor publishes for the
        // listeners ("IP=0.0.0.0:636"); a wildcard bind means the real NICs.
        std::vector<std::string> addresses;
        for (const ListenerInfo& listener : metrics.monitor.listeners) {
            std::string address = listener.address;
            if (address.rfind("IP=", 0) == 0) {
                address = address.substr(3);
            }
            if (const std::size_t colon = address.rfind(':'); colon != std::string::npos) {
                address.resize(colon);
            }
            addresses.push_back(address);
        }
        if (addresses.empty() && !metrics.instance.listeners.empty()) {
            addresses.emplace_back();  // unknown: fall back to every interface
        }

        const double ioSeconds = worker.lastIoAt.time_since_epoch().count() == 0
                                     ? 0.0
                                     : std::chrono::duration<double>(now - worker.lastIoAt).count();
        std::map<std::string, collector::NetCounters> net;
        std::map<std::string, collector::DiskCounters> disk;
        if (worker.node) {
            std::string netText;
            std::string diskText;
            std::string ioError;
            if (worker.node->cachedIoFiles(netText, diskText, 2000, ioError)) {
                net = collector::parseNetDev(netText);
                disk = collector::parseDiskStats(diskText);
            }
        } else {
            net = collector::readNetDev();
            disk = collector::readDiskStats();
        }

        // Which interfaces to show: locally the ones carrying the listener
        // addresses; on a node there is no local getifaddrs() to match against,
        // so every interface the node publishes is listed (loopback aside).
        std::vector<std::string> interfaceNames;
        if (worker.node) {
            for (const auto& entry : net) {
                if (entry.first != "lo") {
                    interfaceNames.push_back(entry.first);
                }
            }
        } else {
            interfaceNames = collector::interfacesForAddresses(addresses);
        }

        metrics.io.available = true;
        for (const std::string& name : interfaceNames) {
            const auto current = net.find(name);
            if (current == net.end()) {
                continue;
            }
            IoInterface interface;
            interface.name = name;
            interface.rxBytes = current->second.rxBytes;
            interface.txBytes = current->second.txBytes;
            interface.rxErrors = current->second.rxErrors;
            interface.txErrors = current->second.txErrors;
            interface.rxDropped = current->second.rxDropped;
            interface.txDropped = current->second.txDropped;
            if (const auto previous = worker.lastNet.find(name);
                previous != worker.lastNet.end() && ioSeconds > 0.0) {
                interface.rxPerSecond =
                    current->second.rxBytes >= previous->second.rxBytes
                        ? static_cast<double>(current->second.rxBytes - previous->second.rxBytes) /
                              ioSeconds
                        : 0.0;
                interface.txPerSecond =
                    current->second.txBytes >= previous->second.txBytes
                        ? static_cast<double>(current->second.txBytes - previous->second.txBytes) /
                              ioSeconds
                        : 0.0;
            }
            metrics.io.interfaces.push_back(std::move(interface));
        }
        worker.lastNet = net;

        // Which disks: every LMDB directory, one per naming context, and the
        // directory holding the log file slapd writes.  cn=monitor publishes
        // olmDbDirectory per database, which is what a remote instance has;
        // the on-disk cn=config only fills the gaps.
        struct WantedPath {
            std::string path;
            std::string label;
        };
        std::vector<WantedPath> paths;
        const auto addPath = [&paths](const std::string& rawPath, const std::string& label) {
            if (rawPath.empty()) {
                return;
            }
            // cn=config writes "…/dir_wf/" while cn=monitor writes
            // "…/dir_wf": same directory, and without this they would be
            // listed twice.
            std::string path = rawPath;
            while (path.size() > 1 && path.back() == '/') {
                path.pop_back();
            }
            for (WantedPath& existing : paths) {
                if (existing.path == path) {
                    if (existing.label.find(label) == std::string::npos) {
                        existing.label += (existing.label.empty() ? "" : " + ") + label;
                    }
                    return;
                }
            }
            paths.push_back(WantedPath{path, label});
        };
        for (const DatabaseInfo& database : metrics.monitor.databases) {
            if (database.directory.empty()) {
                continue;
            }
            std::string label;
            for (const std::string& naming : database.namingContexts) {
                label += (label.empty() ? "" : ", ") + naming;
            }
            addPath(database.directory, label.empty() ? database.label : label);
        }
        for (const auto& database : metrics.directory.databases) {
            if (database.directory.empty() || database.backend == "config" ||
                database.backend == "monitor") {
                continue;
            }
            addPath(database.directory,
                    database.suffix.empty() ? database.label : database.suffix);
        }
        // Databases owned by an overlay: the pcache cache file lives here and
        // never appears in cn=monitor's database list.
        for (const auto& database : metrics.directory.overlayDatabases) {
            if (database.directory.empty()) {
                continue;
            }
            addPath(database.directory, database.overlay + " cache");
        }
        if (!metrics.log.path.empty()) {
            std::string logDir = metrics.log.path;
            if (const std::size_t slash = logDir.rfind('/'); slash != std::string::npos) {
                logDir.resize(slash == 0 ? 1 : slash);
            }
            addPath(logDir, "log");
        }
        // A node answers for every path in one `df`: asking once per database
        // directory made a round cost ten SSH calls per instance.
        const bool slowDue = worker.slowAt.time_since_epoch().count() == 0 ||
                             now - worker.slowAt > std::chrono::seconds(10);
        std::map<std::string, collector::SshNode::PathUsage> remoteUsage;
        if (worker.node) {
            if (!slowDue) {
                remoteUsage = worker.usageCache;
            } else {
                std::vector<std::string> wantedPaths;
                wantedPaths.reserve(paths.size());
                for (const WantedPath& wanted : paths) {
                    wantedPaths.push_back(wanted.path);
                }
                std::string usageError;
                for (auto& usage : worker.node->pathUsages(wantedPaths, usageError)) {
                    remoteUsage[usage.path] = std::move(usage);
                }
                worker.usageCache = remoteUsage;
            }
        }
        for (const WantedPath& wanted : paths) {
            collector::PathUsage usage;
            if (worker.node) {
                const auto found = remoteUsage.find(wanted.path);
                if (found == remoteUsage.end() || !found->second.valid) {
                    continue;
                }
                usage.path = wanted.path;
                usage.mountPoint = found->second.mountPoint;
                usage.device = found->second.source;
                usage.totalBytes = found->second.total;
                usage.freeBytes = found->second.free;
            } else {
                usage = collector::usageOfPath(wanted.path);
            }
            IoDisk entry;
            entry.label = wanted.label;
            entry.path = wanted.path;
            entry.mountPoint = usage.mountPoint;
            entry.device = usage.device;
            entry.totalBytes = usage.totalBytes;
            entry.freeBytes = usage.freeBytes;
            const auto current = disk.find(usage.device);
            if (current != disk.end()) {
                if (const auto previous = worker.lastDisk.find(usage.device);
                    previous != worker.lastDisk.end() && ioSeconds > 0.0) {
                    entry.readPerSecond =
                        current->second.readBytes >= previous->second.readBytes
                            ? static_cast<double>(current->second.readBytes -
                                                  previous->second.readBytes) /
                                  seconds
                            : 0.0;
                    entry.writePerSecond =
                        current->second.writeBytes >= previous->second.writeBytes
                            ? static_cast<double>(current->second.writeBytes -
                                                  previous->second.writeBytes) /
                                  ioSeconds
                            : 0.0;
                    entry.busyPercent =
                        current->second.ioMillis >= previous->second.ioMillis
                            ? 100.0 * static_cast<double>(current->second.ioMillis -
                                                          previous->second.ioMillis) /
                                  (ioSeconds * 1000.0)
                            : 0.0;
                }
            }
            metrics.io.disks.push_back(std::move(entry));
        }
        // Keep a short history per interface and per disk: the I/O tab draws
        // a sparkline under each row, which is what shows a burst.
        for (const IoInterface& interface : metrics.io.interfaces) {
            worker.live.ioRx[interface.name].push(interface.rxPerSecond);
            worker.live.ioTx[interface.name].push(interface.txPerSecond);
        }
        for (const IoDisk& entry : metrics.io.disks) {
            worker.live.diskRead[entry.path].push(entry.readPerSecond);
            worker.live.diskWrite[entry.path].push(entry.writePerSecond);
        }
        worker.lastDisk = disk;
        worker.lastIoAt = now;

        // Descriptors and ephemeral ports: what still allows this instance to
        // accept a connection (an fd) or open one upstream (a port).  Slower
        // movers than the counters above, so a node answer is kept 5 s.
        if (worker.node) {
            std::string limitsError;
            metrics.limits =
                worker.node->socketLimits(worker.instance.pid, 5000, limitsError);
        } else {
            metrics.limits = collector::readSocketLimits(worker.instance.pid);
        }

        // data.mdb sizes: LMDB grows its file in large sparse steps, so the
        // apparent size can be ten times what the filesystem really holds.
        // A node answers for all its databases in one `stat` call.
        std::map<std::string, collector::SshNode::FileSize> remoteSizes;
        if (worker.node && !slowDue) {
            remoteSizes = worker.sizeCache;
        } else if (worker.node) {
            std::vector<std::string> wanted;
            for (const DatabaseInfo& database : metrics.monitor.databases) {
                if (database.directory.empty()) {
                    continue;
                }
                std::string file = database.directory;
                if (file.back() != '/') {
                    file += '/';
                }
                file += "data.mdb";
                wanted.push_back(file);
            }
            std::string sizeError;
            for (const auto& size : worker.node->fileSizes(wanted, sizeError)) {
                remoteSizes[size.path] = size;
            }
            worker.sizeCache = remoteSizes;
            worker.slowAt = now;
        }
        for (const DatabaseInfo& database : metrics.monitor.databases) {
            if (database.directory.empty()) {
                continue;
            }
            std::string file = database.directory;
            if (file.back() != '/') {
                file += '/';
            }
            file += "data.mdb";
            DbFileUsage usage;
            usage.label = database.label;
            usage.path = file;
            if (worker.node) {
                const auto found = remoteSizes.find(file);
                if (found == remoteSizes.end() || !found->second.valid) {
                    continue;
                }
                usage.apparentBytes = found->second.apparent;
                usage.allocatedBytes = found->second.allocated;
                metrics.dbFiles.push_back(std::move(usage));
                continue;
            }
            struct stat info {};
            if (::stat(file.c_str(), &info) != 0) {
                continue;
            }
            usage.apparentBytes = static_cast<std::uint64_t>(info.st_size);
            usage.allocatedBytes = static_cast<std::uint64_t>(info.st_blocks) * 512ULL;
            metrics.dbFiles.push_back(std::move(usage));
        }
    }

    // --- LMDB map headroom -------------------------------------------------
    // MDB_MAP_FULL in the log means writes are already failing; the useful
    // signal is the room left in the map and the rate at which it shrinks.
    // Nothing here is acted upon: the suggestion is text an administrator may
    // choose to apply.
    {
        const double sampleSeconds = std::max(0.1, interval_.load());
        for (const DatabaseInfo& database : metrics.monitor.databases) {
            if (database.pagesMax == 0 || database.pageSize == 0) {
                continue;
            }
            auto& series = worker.live.lmdbPagesUsed[database.label];
            series.push(static_cast<double>(database.pagesUsed));

            collector::LmdbRiskInput input;
            input.label = database.label;
            input.suffix = database.namingContexts.empty() ? std::string()
                                                           : database.namingContexts.front();
            input.directory = database.directory;
            input.pagesUsed = database.pagesUsed;
            input.pagesMax = database.pagesMax;
            input.pagesFree = database.pagesFree;
            input.pageSize = database.pageSize;
            const std::size_t samples = series.size();
            if (samples >= 2) {
                const double oldest = series.at(0);
                const double newest = series.at(samples - 1);
                input.observedSeconds =
                    static_cast<double>(samples - 1) * sampleSeconds;
                if (newest > oldest && input.observedSeconds > 0.0) {
                    input.growthPagesPerSecond = (newest - oldest) / input.observedSeconds;
                }
            }
            // A suggestion must fit on the filesystem that holds the database:
            // the map itself writes nothing, but the data eventually will.
            for (const IoDisk& disk : metrics.io.disks) {
                if (disk.mountPoint.empty() || database.directory.empty()) {
                    continue;
                }
                if (database.directory.rfind(disk.mountPoint, 0) == 0) {
                    input.diskFreeBytes = disk.freeBytes;
                    break;
                }
            }
            if (worker.mapFullAt.time_since_epoch().count() != 0 &&
                now - worker.mapFullAt < std::chrono::seconds(300)) {
                input.mapFullSeen = true;
            }
            collector::LmdbRisk risk = collector::assessLmdb(input);
            if (risk.severity != collector::AlertSeverity::Info) {
                risk.instance = metrics.instance.name;
                metrics.alerts.push_back(std::move(risk));
            }
        }
    }

    worker.lastAt = now;
    // Raw percentages on purpose: the series carries what was measured, and the
    // graph draws it against the capacity of the host that runs the instance.
    // Dividing here would need the same core count in several places, and a
    // node does not have this machine's cores.
    worker.live.sampleSeconds = std::max(0.0, interval_.load());
    worker.live.cpuPercent.push(metrics.proc.cpuPercent);
    worker.live.rssMiB.push(static_cast<double>(metrics.proc.rssBytes) / (1024.0 * 1024.0));
    worker.live.connectionsCurrent.push(
        metrics.hasMonitor ? static_cast<double>(metrics.monitor.connectionsCurrent) : 0.0);
    worker.live.opsPerSecond.push(opsPerSecond);
    worker.live.errorsPerSecond.push(metrics.log.errorsPerSecond);
}

FleetSnapshot MonitorEngine::snapshot() const {
    FleetSnapshot snapshot;

    // Never make the UI wait for a publisher: a slow SSH node must not freeze
    // the keyboard.  When the lock is held, the caller keeps its previous copy
    // and shows the "refreshing" spinner instead.
    std::unique_lock<std::mutex> lock(mutex_, std::try_to_lock);
    if (!lock.owns_lock()) {
        snapshot.busy = true;
        return snapshot;
    }
    snapshot.at = std::chrono::system_clock::now();
    snapshot.instances.reserve(workers_.size());
    snapshot.history.reserve(workers_.size());

    for (const auto& [pid, worker] : workers_) {
        snapshot.instances.push_back(worker->metrics);
        snapshot.history.push_back(worker->history);
    }

    // One order for every screen: the workers live in a std::map keyed by
    // "node:<label>/<name>", "cfg:<dir>", "uri:<uri>"… so the copy above comes
    // out in key order, which mixes local, SSH and URI instances and is not the
    // order the operator expects.  Sort by name (then node) once, here, and
    // every page agrees — the selected index stays meaningful across screens.
    if (snapshot.instances.size() > 1) {
        std::vector<std::size_t> order(snapshot.instances.size());
        for (std::size_t i = 0; i < order.size(); ++i) {
            order[i] = i;
        }
        std::sort(order.begin(), order.end(), [&snapshot](std::size_t a, std::size_t b) {
            const Instance& left = snapshot.instances[a].instance;
            const Instance& right = snapshot.instances[b].instance;
            if (left.name != right.name) {
                return left.name < right.name;
            }
            return left.nodeLabel < right.nodeLabel;
        });
        std::vector<InstanceMetrics> instances;
        std::vector<InstanceHistory> history;
        instances.reserve(order.size());
        history.reserve(order.size());
        for (const std::size_t index : order) {
            instances.push_back(std::move(snapshot.instances[index]));
            history.push_back(std::move(snapshot.history[index]));
        }
        snapshot.instances = std::move(instances);
        snapshot.history = std::move(history);
    }

    // Fleet-wide CSN lag: compare each instance timestamp with the newest.
    // A proxy is excluded: the contextCSN it returns is the upstream's answer
    // relayed to it, so a "lag" computed from it measures the relay, not a
    // replication state of its own.
    // A proxy is an instance whose every *real* backend forwards: pseudo
    // backends (frontend, config, monitor, null) have suffixes of their own and
    // made a proxy look like a normal server.
    const auto proxiedOnly = [](const InstanceMetrics& metrics) {
        bool any = false;
        for (const auto& database : metrics.directory.databases) {
            if (database.suffix.empty() || database.backend == "frontend" ||
                database.backend == "config" || database.backend == "monitor" ||
                database.backend == "null") {
                continue;
            }
            any = true;
            if (database.backend != "ldap" && database.backend != "meta") {
                return false;
            }
        }
        return any;
    };
    long long fleetSeconds = -1;
    for (const InstanceMetrics& metrics : snapshot.instances) {
        if (!metrics.replication.available || proxiedOnly(metrics)) {
            continue;
        }
        const long long seconds = csnSeconds(metrics.replication.newestCsn);
        if (seconds > fleetSeconds) {
            fleetSeconds = seconds;
            snapshot.fleetNewestCsn = metrics.replication.newestCsn;
        }
    }
    for (InstanceMetrics& metrics : snapshot.instances) {
        if (!metrics.replication.available || fleetSeconds < 0 || proxiedOnly(metrics)) {
            continue;  // a proxy has no replication state of its own: lag stays -1
        }
        const long long seconds = csnSeconds(metrics.replication.newestCsn);
        if (seconds >= 0) {
            metrics.replication.lagSeconds = static_cast<double>(fleetSeconds - seconds);
        }
    }

    return snapshot;
}

}  // namespace slaptop
