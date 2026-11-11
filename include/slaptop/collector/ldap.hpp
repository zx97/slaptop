#pragma once

#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace slaptop {

/// One raw LDAP entry: DN plus every attribute value, in server order.
struct LdapEntry {
    std::string dn;
    std::vector<std::pair<std::string, std::vector<std::string>>> attributes;

    /// First value of `name` (case-insensitive), empty when absent.
    const std::string& first(const std::string& name) const;
    /// All values of `name` (case-insensitive).
    std::vector<std::string> all(const std::string& name) const;
    /// Numeric value of `name`, 0 when absent or unparsable.
    std::uint64_t number(const std::string& name) const;
    bool flag(const std::string& name) const;
};

/// One entry of cn=<N>,cn=Connections,cn=Monitor.
struct ConnectionInfo {
    unsigned long number{0};
    std::string protocol;
    std::string listener;
    std::string peerAddress;
    std::string peerDomain;
    std::string localAddress;
    std::uint64_t opsReceived{0};
    std::uint64_t opsExecuting{0};
    std::uint64_t opsPending{0};
    std::uint64_t opsCompleted{0};
    /// Socket activity (number of calls, not bytes): monitorConnectionGet,
    /// Read, Write.
    std::uint64_t ioGet{0};
    std::uint64_t ioRead{0};
    std::uint64_t ioWrite{0};
    std::string startTime;
    std::string activityTime;
    /// DN actually authenticated on this connection (monitorConnectionAuthzDN):
    /// no need to dig it out of the logs.
    std::string authzDn;
    /// Access mask granted to the connection ("r", "w", "rx", ...).
    std::string mask;
    /// Backend connections (cn=Connections,cn=database N): the DN the proxy
    /// bound with, the backend URI, the peer and the connection flags.
    std::string backendBoundDn;
    std::string backendUri;
    std::string backendPeerAddress;
    std::string backendFlags;
    /// True for the proxy's own connections to its upstreams.
    bool isBackend{false};
};

/// One cn=<N>,cn=Listeners,cn=Monitor entry.
struct ListenerInfo {
    std::string address;
    bool tls{false};
};

/// One cached query, as pcache publishes it in pcacheQueryURL:
/// `ldap:///<base>??<scope>?<filter>?x-uuid=...,x-expiry=...,x-answerable=N`.
/// `answerable` is the number of times that query was served from the cache:
/// the hit counter, per query object.
struct PcacheQuery {
    std::string uuid;
    std::string base;
    std::string scope;
    std::string filter;
    std::uint64_t answerable{0};
    long long expiry{0};
};

/// One cn=Database <N>,cn=Databases,cn=Monitor entry.
struct DatabaseInfo {
    std::string label;
    std::string backend;
    std::vector<std::string> namingContexts;
    /// olmMDBEntries: how many entries the database holds.
    std::uint64_t entries{0};
    /// LMDB page accounting, exactly as back-mdb publishes it:
    ///   pagesMax  = me_mapsize / psize      (how far the file may grow)
    ///   pagesUsed = me_last_pgno + 1        (pages the file contains)
    ///   pagesFree = pages in the freelist   (allocated, reusable)
    /// Data pages are pagesUsed - pagesFree; the map still has pagesMax -
    /// pagesUsed to grow into.
    std::uint64_t pagesMax{0};
    std::uint64_t pagesUsed{0};
    std::uint64_t pagesFree{0};
    std::uint64_t pageSize{0};
    /// LMDB reader slots (olmMDBReadersUsed/Max).  A slot is taken by each
    /// read transaction: the used count should follow the current connections,
    /// and a growing gap means read transactions that were never released.
    std::uint64_t readersUsed{0};
    std::uint64_t readersMax{0};
    bool shadow{false};
    bool readOnly{false};
    std::vector<std::string> overlays;
    std::string directory;
    /// Operations handled by this database, keyed by operation name.
    std::map<std::string, std::uint64_t> ops;
    /// pcache gauges: cached queries and cached entries right now.
    std::uint64_t pcacheQueries{0};
    std::uint64_t pcacheEntries{0};
    /// The cached queries themselves, with their hit counter.
    std::vector<PcacheQuery> pcache;
};

/// One lloadd backend server, as published under cn=Backend Tiers.
struct LloadServer {
    std::string name;
    std::string uri;
    std::uint64_t activeConnections{0};
    std::uint64_t pendingConnections{0};
    std::uint64_t pendingOps{0};
    std::uint64_t receivedOps{0};
    std::uint64_t completedOps{0};
    std::uint64_t failedOps{0};
};

/// One lloadd tier with its backend servers.
struct LloadTier {
    std::string name;
    std::vector<LloadServer> servers;
};

/// Snapshot of everything useful from one cn=monitor subtree.
struct MonitorSnapshot {
    std::uint64_t connectionsTotal{0};
    std::uint64_t connectionsCurrent{0};
    std::uint64_t maxFileDescriptors{0};
    std::uint64_t opsInitiated{0};
    std::uint64_t opsCompleted{0};
    /// Counters per operation type (Bind, Search, Modify, ...).
    std::map<std::string, std::uint64_t> opsByType;
    /// Same counters, per second, computed between two monitoring rounds
    /// (what slapd-watcher prints on its "Num/s" line).
    std::map<std::string, double> opsRateByType;
    std::vector<DatabaseInfo> databases;
    std::vector<ListenerInfo> listeners;
    std::vector<ConnectionInfo> connections;
    /// cn=Log counters, when the server exposes them.
    std::uint64_t logConnections{0};
    std::uint64_t logOps{0};
    std::uint64_t logEntries{0};
    std::uint64_t logRead{0};
    std::uint64_t logWrite{0};
    std::string logLevel;
    /// Server start, when the server exposes it (cn=Start,cn=Time,cn=Monitor).
    std::string startTime;
    /// Server uptime in seconds (cn=Uptime,cn=Time,cn=Monitor), 0 when absent.
    std::uint64_t uptimeSeconds{0};
    /// Searches that failed during the round (base + LDAP message).
    std::vector<std::string> errors;
    /// lloadd tiers and their backend servers (empty on a plain slapd).
    std::vector<LloadTier> lloadTiers;
    /// Every entry of the subtree verbatim: the dashboard renders whatever the
    /// server exposes (pcache counters, MDB pages, overlays) without having to
    /// know each attribute in advance.
    std::vector<LdapEntry> raw;
    std::chrono::system_clock::time_point collectedAt{};
};

/// Values read from cn=config that drive the log collectors.
struct LogFileConfig {
    std::string path;
    std::string format;
    std::string level;
};

/// Thin RAII wrapper around libldap, connected to one instance.
///
/// The class is move-only because it owns a live LDAP* handle.  Every fetch
/// returns std::nullopt on failure and stores the diagnostic in lastError():
/// a monitoring loop must survive a transient server outage.
class LdapClient {
public:
    /// Opens a connection.  With an empty bindDn an anonymous simple bind is
    /// used (cn=monitor is usually world-readable); pass "EXTERNAL" as bindDn
    /// for SASL peer credentials on ldapi://.  When `error` is provided it
    /// receives a human-readable diagnostic on failure.
    static std::optional<LdapClient> open(const std::string& uri,
                                          const std::string& bindDn = {},
                                          const std::string& password = {},
                                          std::string* error = nullptr,
                                          bool insecureTls = false,
                                          bool startTls = false);

    ~LdapClient();
    LdapClient(LdapClient&& other) noexcept;
    LdapClient& operator=(LdapClient&& other) noexcept;
    LdapClient(const LdapClient&) = delete;
    LdapClient& operator=(const LdapClient&) = delete;

    /// Reads the counters that matter, with targeted searches only.
    ///
    /// A production server can hold 7000+ connections: listing them on every
    /// round would cost 7000 entries per poll and saturate slapd.  The
    /// individual connections are therefore fetched separately, on demand and
    /// with a server-side size limit.
    std::optional<MonitorSnapshot> fetchMonitor();

    /// Reads at most `limit` connections (scope one under cn=Connections).
    std::optional<std::vector<ConnectionInfo>> fetchConnections(unsigned limit);

    /// Reads at most `limit` backend connections (the proxy's own connections
    /// to its upstreams, under cn=Connections,cn=database N,...).
    std::optional<std::vector<ConnectionInfo>> fetchBackendConnections(unsigned limit);

    /// Reads olcLogFile / olcLogFileFormat / olcLogLevel from cn=config.
    std::optional<LogFileConfig> fetchLogConfig();

    /// Reads the contextCSN values of a naming context (empty on a provider
    /// that has not written any yet, or on a non-replicated database).
    std::optional<std::vector<std::string>> fetchContextCsn(const std::string& baseDn);

    const std::string& lastError() const { return error_; }

private:
    explicit LdapClient(void* handle);

    /// Runs a search and returns every entry, preserving attribute order.
    /// `sizeLimit` bounds the entries the server sends back (0 = no limit).
    std::optional<std::vector<LdapEntry>> search(const std::string& base,
                                                 int scope,
                                                 const std::vector<std::string>& attributes,
                                                 int sizeLimit = 0,
                                                 const std::string& filter = "(objectClass=*)",
                                                 void** serverControls = nullptr);

    void* handle_{nullptr};
    std::string error_;
};

}  // namespace slaptop
