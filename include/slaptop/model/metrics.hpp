#pragma once

#include <chrono>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <vector>

#include "slaptop/collector/configdir.hpp"
#include "slaptop/types.hpp"

#include "slaptop/collector/behavior.hpp"
#include "slaptop/collector/limits.hpp"
#include "slaptop/collector/lmdb.hpp"

#ifdef SLAPTOP_WITH_LDAP
#include "slaptop/collector/ldap.hpp"
#endif

namespace slaptop {

#ifdef SLAPTOP_WITH_LDAP
struct MonitorSnapshot;
struct LogFileConfig;
#endif

/// Health of one instance as seen by the last collection round.
enum class Health {
    Unknown,      ///< Not collected yet.
    Running,      ///< Process alive, monitor answers.
    Degraded,     ///< Process alive, but cn=monitor timed out or failed.
    Stopped,      ///< Process disappeared since the previous round.
};

const char* healthLabel(Health health);

/// Severity of one log line, used for colouring.
enum class LogLevel { Info, Warning, Error };

struct LogEntry {
    std::string text;
    LogLevel level{LogLevel::Info};
    /// Monotonic id, so the UI can tell "already displayed" from "new".
    std::uint64_t sequence{0};
};

/// Aggregated counters derived from the slapd log file.
struct LogStats {
    bool available{false};
    std::string path;
    std::string format;
    std::uint64_t linesRead{0};
    std::uint64_t errors{0};
    std::uint64_t warnings{0};
    double linesPerSecond{0.0};
    double errorsPerSecond{0.0};
    /// Most recent lines (all severities), newest last, for the log panel.
    std::deque<LogEntry> recent;
    /// Bind DN per connection, recovered from the log ("conn=N op=0 BIND
    /// dn=\"...\""): cn=monitor does not expose it.
    std::map<unsigned long, std::string> binds;
};

/// One contextCSN value, split into what the replication view compares.
struct CsnsEntry {
    int sid{-1};        ///< SID parsed from the third component ("#001#")
    std::string csn;    ///< full CSN, for display
    long long epoch{0}; ///< CSN timestamp in seconds, -1 when unreadable
};

/// Replication view built from contextCSN values.
struct ReplicationInfo {
    /// Raw contextCSN values of the naming context (one per SID).
    std::vector<std::string> contextCsn;
    /// The same values, parsed per SID: what the replication screen compares
    /// across instances without re-parsing strings every frame.
    std::vector<CsnsEntry> csns;
    /// Highest CSN seen, formatted as `20261104020651.000000Z#000000#000#000000`.
    std::string newestCsn;
    /// Seconds between the newest CSN and the newest CSN of the whole fleet.
    /// Negative when unknown.
    double lagSeconds{-1.0};
    /// True when at least one provider/consumer CSN was readable.
    bool available{false};
    /// Why nothing was readable, when that is an error rather than a directory
    /// without replication.  Shown by the screen: a missing tab or an empty
    /// page leaves the operator guessing.
    std::string error;
};

/// One network interface slapd listens on, with the throughput measured
/// between two rounds.
struct IoInterface {
    std::string name;
    std::uint64_t rxBytes{0};  ///< cumulative, for the "since boot" column
    std::uint64_t txBytes{0};
    std::uint64_t rxErrors{0};
    std::uint64_t txErrors{0};
    std::uint64_t rxDropped{0};
    std::uint64_t txDropped{0};
    double rxPerSecond{0.0};
    double txPerSecond{0.0};
};

/// One filesystem slapd writes to (database directory, log directory), with
/// the block device behind it.
struct IoDisk {
    /// What this filesystem is used for: the naming context it holds, "log",
    /// or both when one path serves several purposes.
    std::string label;
    std::string path;
    std::string mountPoint;
    std::string device;
    std::uint64_t totalBytes{0};
    std::uint64_t freeBytes{0};
    double readPerSecond{0.0};
    double writePerSecond{0.0};
    double busyPercent{0.0};
};

/// Size of one LMDB database file.  data.mdb is sparse: st_size is the size it
/// claims, st_blocks the space it actually occupies — the two can differ by a
/// factor of ten, which is exactly what the pie chart in the Databases tab
/// shows.
struct DbFileUsage {
    std::string label;  ///< database label ("database 4"), to match the box
    std::string path;
    std::uint64_t apparentBytes{0};   ///< st_size
    std::uint64_t allocatedBytes{0};  ///< st_blocks * 512
};

/// I/O view: the network interfaces and the disks this instance uses.
struct IoStats {
    bool available{false};
    std::vector<IoInterface> interfaces;
    std::vector<IoDisk> disks;
};

/// Everything known about one instance at a given round.
struct InstanceMetrics {
    Instance instance;
    Health health{Health::Unknown};
    ProcSample proc;
    bool hasProc{false};
#ifdef SLAPTOP_WITH_LDAP
    MonitorSnapshot monitor;
#endif
    bool hasMonitor{false};
    /// Databases and overlays declared in the instance's cn=config tree.
    collector::DirectoryConfig directory;
    LogStats log;
    /// Behavioural analysis of the access log: accounts, filter families and
    /// the resource-hog verdict, over a sliding window.
    collector::BehaviorSnapshot behavior;
    /// Measured risks worth showing (LMDB map headroom).  Displayed, never
    /// acted upon.
    std::vector<collector::LmdbRisk> alerts;
    ReplicationInfo replication;
    IoStats io;
    /// File descriptors and ephemeral ports: the two caps on how many
    /// connections this instance can still accept or open.
    collector::SocketLimits limits;
    /// data.mdb sizes, one entry per database directory that could be read.
    std::vector<DbFileUsage> dbFiles;
    std::chrono::system_clock::time_point collectedAt{};
    std::string error;
};

/// Fixed-size history of one series (numbers only, cheap to copy).
template <std::size_t Capacity>
class Series {
public:
    void push(double value) {
        values_.push_back(value);
        if (values_.size() > Capacity) {
            values_.pop_front();
        }
    }

    std::size_t size() const { return values_.size(); }
    bool empty() const { return values_.empty(); }
    double last(double fallback = 0.0) const { return values_.empty() ? fallback : values_.back(); }

    /// Value at `index` from the oldest sample, 0 when out of range.
    double at(std::size_t index) const {
        return index < values_.size() ? values_[index] : 0.0;
    }

    const std::deque<double>& values() const { return values_; }

    double maximum() const {
        double result = 0.0;
        for (const double value : values_) {
            if (value > result) {
                result = value;
            }
        }
        return result;
    }

    /// Smallest sample, or 0 when the series is empty.
    double minimum() const {
        if (values_.empty()) {
            return 0.0;
        }
        double result = values_.front();
        for (const double value : values_) {
            if (value < result) {
                result = value;
            }
        }
        return result;
    }

private:
    std::deque<double> values_;
};

/// History of the series the dashboard draws.
struct InstanceHistory {
    /// Seconds between two samples, as collected.  The graphs label their time
    /// axis with it: a grid line every four cells is only meaningful if the
    /// reader can convert it to seconds.
    double sampleSeconds{0.0};
    Series<180> cpuPercent;
    Series<180> rssMiB;
    Series<180> connectionsCurrent;
    Series<180> opsPerSecond;
    Series<180> errorsPerSecond;
    /// Throughput per interface and per disk, keyed by name / path.  The keys
    /// follow what the instance publishes, so a replaced NIC starts a new
    /// series instead of inheriting the old one's shape.
    std::map<std::string, Series<120>> ioRx;
    std::map<std::string, Series<120>> ioTx;
    std::map<std::string, Series<120>> diskRead;
    std::map<std::string, Series<120>> diskWrite;
    /// pagesUsed per database: the slope is what forecasts MDB_MAP_FULL.
    std::map<std::string, Series<180>> lmdbPagesUsed;
};

}  // namespace slaptop
