#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace slaptop::collector {

/// Clock of the behaviour window.  Monotonic: the analysis must survive a
/// wall-clock jump (NTP step, manual date) without opening a hole.
using BehaviorClock = std::chrono::steady_clock;

/// A family is the "resource hog" when it spends at least this share of the
/// window's etime (same threshold as slaplog, so both tools agree).
constexpr double kHogSharePercent = 20.0;

/// ...and averages at least this much server time per search.
///
/// A share alone is not a verdict: 30 % of a 6 s window spread over hundreds of
/// 2 ms searches is a healthy account doing normal work, and calling it a hog
/// is a false positive that makes the screen untrustworthy.  Below this
/// average, no share is worth a warning — 25 ms per search is where a
/// directory starts to feel slow under load.
constexpr double kHogMinimumAverageSeconds = 0.025;

/// One family needs this many completed searches before repetition alone can
/// blame it: with three searches in the window, everything is 100 % of the
/// etime.
constexpr std::uint64_t kMinFamilyOps = 10;

/// ...unless a single search already cost this much server time: a 1 s scan
/// among a hundred fast ones is a hog even when it happened once.
constexpr std::uint64_t kMinFamilyEtimeNs = 100'000'000;  // 100 ms

/// The window needs either enough searches for a share to mean something, or
/// enough accumulated server time for the absolute figures to speak.
constexpr std::uint64_t kMinSearchesForVerdict = 100;
constexpr std::uint64_t kMinEtimeForVerdictNs = 500'000'000;  // 500 ms

/// `(uid=user123)` -> `(uid=$#)`, `(cn=*foo*)` -> `(cn=*$*)`,
/// `(|(uid=a)(uid=b)(uid=c))` -> `(|(uid=$)+)`: the literals are masked and
/// the structure is kept, so clients searching the same shape with different
/// data land in one family.  Same algorithm as slaplog's `generalize_filter`,
/// so a family has the same name in both tools.
std::string generalizeFilter(std::string_view filter);

/// True when the family cannot use an index: a negation, or a wildcard other
/// than a plain presence test.  `(uid=*)` is indexed, `(uid=$#)` is not.
bool isSlowFilter(std::string_view family);

/// Counters of one window key.  Times are integer nanoseconds: the window is
/// added to and subtracted from as it slides, and floating-point subtraction
/// would drift over a long run.
struct AccessCounters {
    std::uint64_t ops{0};
    std::uint64_t etimeNs{0};
    std::uint64_t qtimeNs{0};  ///< time spent waiting for a thread
    std::uint64_t wtimeNs{0};  ///< time spent waiting for a backend
    std::uint64_t nentries{0};
};

/// One account of the ranking.
struct BehaviorAccount {
    std::string account;  ///< bind DN; empty for anonymous
    AccessCounters counters;
    double etimeSeconds{0.0};
    double averageSeconds{0.0};
    double sharePercent{0.0};
};

/// One (account, family) pair: the raw material of the verdict.
struct BehaviorFamily {
    std::string account;
    std::string family;
    AccessCounters counters;
    double etimeSeconds{0.0};
    double averageSeconds{0.0};
    double sharePercent{0.0};
    bool slow{false};
};

/// The verdict itself: an account whose family takes the largest share of the
/// window's etime.  Selected by measurement; `slowShape` only says the filter
/// looks expensive (substring or negation), which is a hint, not the reason.
struct BehaviorHog {
    std::string account;
    std::string family;
    AccessCounters counters;
    double etimeSeconds{0.0};
    double averageSeconds{0.0};
    double sharePercent{0.0};
    bool slowShape{false};
};

/// One attribute the window saw a filter use, on one search base.  The index
/// screen needs both halves: an index belongs to a database, and a database is
/// identified by its suffix — comparing every filter to one database's index
/// list is what produced "uid has no index" on a directory that indexes uid in
/// the database actually queried.
struct BaseAttributeUse {
    std::string base;
    std::string attribute;
    std::string kind;  ///< "eq", "sub" or "pres": what the filter asked for
    std::uint64_t searches{0};
};

/// Search count per base, so the screen can say which suffix carries the load.
struct BaseTraffic {
    std::string base;
    std::uint64_t searches{0};
};

/// Immutable view of the window, small enough to be copied into the snapshot
/// on every collection round.
struct BehaviorSnapshot {
    /// False when there is no log at all (remote instance, no olcLogFile).
    bool available{false};
    /// False until the window holds enough evidence: kMinSearchesForVerdict
    /// searches, or kMinEtimeForVerdictNs of accumulated server time (a quiet
    /// minute with one 1 s scan is worth a verdict).
    bool enoughTraffic{false};
    /// olcLogLevel, as configured: the tab says so when `stats` is missing.
    std::string logLevel;
    std::string logPath;
    double windowSeconds{0.0};
    /// How much of the window actually carries data, in seconds.
    double elapsedSeconds{0.0};
    std::uint64_t searches{0};
    std::uint64_t slowSearches{0};
    AccessCounters totals;
    std::vector<BehaviorHog> hogs;
    std::vector<BehaviorAccount> accounts;
    std::vector<BehaviorFamily> families;
    /// Attributes used by filters, with the search base that carried them.
    std::vector<BaseAttributeUse> attributesByBase;
    /// Searches per base, largest first.
    std::vector<BaseTraffic> baseTraffic;
    std::size_t accountsSeen{0};
    std::size_t familiesSeen{0};
    /// Searches and etime per second over the window, oldest first: the two
    /// sparklines of the tab.
    std::deque<double> searchTimeline;
    std::deque<double> etimeTimeline;
};

/// Sliding-window analysis of the access log: who spends the server's time,
/// and on which filter shape.
///
/// Fed line by line from the same tail as the log panel, so it costs one
/// substring scan per line and never re-reads a file.  Operations are paired
/// on `(conn, op)`: the `SRCH` line carries the filter, the `RESULT` line the
/// etime.  A search whose result never arrives (abandon, crash) is dropped
/// after kPendingTtlSeconds.
class BehaviorWindow {
public:
    static constexpr std::size_t kBuckets = 60;       ///< 60 s of 1 s slices
    static constexpr std::size_t kMaxAccounts = 512;  ///< distinct bind DNs
    static constexpr std::size_t kMaxPending = 4096;  ///< in-flight searches
    static constexpr std::size_t kMaxFamilyLength = 512;
    static constexpr std::size_t kMaxAccountLength = 512;
    static constexpr int kPendingTtlSeconds = 120;

    /// Feeds one access-log line.  Anything that is not a BIND, a search
    /// request or a result is ignored without allocating.
    void feed(std::string_view line, BehaviorClock::time_point now);

    /// Advances the ring and drops what left the window.  Call once per
    /// collection round, before snapshot().
    void roll(BehaviorClock::time_point now);

    /// Ranks accounts and families, and decides the verdict.  `maxRows` caps
    /// each list; the ranking itself is always computed over every key.  Call
    /// it with a cap well above any screen height (100), not with the visible
    /// row count: the UI truncates what does not fit, and the JSON keeps what
    /// the screen never shows.
    BehaviorSnapshot snapshot(std::size_t maxRows = 100) const;

    /// Records the configured log level, shown by the tab when `stats` is
    /// missing and no search line ever appears.
    void setLogLevel(std::string level);

    void reset();

private:
    using PendingKey = std::pair<std::uint64_t, std::uint64_t>;
    using FamilyKey = std::pair<std::string, std::string>;  // (account, family)

    struct PendingSearch {
        std::string family;
        std::string base;
        bool slow{false};
        BehaviorClock::time_point at{};
    };

    struct Bucket {
        BehaviorClock::time_point start{};
        AccessCounters total;
        std::uint64_t searches{0};
        std::uint64_t slowSearches{0};
        std::map<std::string, AccessCounters> accounts;
        std::map<FamilyKey, AccessCounters> families;
        /// Per base and attribute: the searches that used it and the kind of
        /// comparison, which is what the index screen compares with the lines
        /// of the database owning that suffix.
        struct AttributeUse {
            std::uint64_t searches{0};
            std::string kind;
        };
        std::map<std::string, std::map<std::string, AttributeUse>> baseAttributes;
        std::map<std::string, std::uint64_t> baseSearches;
    };

    void advance(BehaviorClock::time_point now);
    void add(const std::string& account, const PendingSearch& search,
             const AccessCounters& counters);
    void subtractBucket(const Bucket& bucket);
    void sweepPending(BehaviorClock::time_point now);
    const std::string& accountOf(std::uint64_t conn);
    void rememberBind(std::uint64_t conn, std::string dn);

    std::deque<Bucket> buckets_;
    AccessCounters totals_;
    std::uint64_t searches_{0};
    std::uint64_t slowSearches_{0};

    std::map<std::string, AccessCounters> accountTotals_;
    std::map<FamilyKey, AccessCounters> familyTotals_;

    std::map<std::uint64_t, std::string> binds_;  ///< conn -> bind DN
    std::deque<std::uint64_t> bindOrder_;         ///< insertion order, for LRU
    std::map<PendingKey, PendingSearch> pending_;
    std::deque<PendingKey> pendingOrder_;

    std::string logLevel_;
    std::size_t accountsDropped_{0};  ///< folded into "(other)"
    /// Time of the last advance: snapshot() derives the covered span from it.
    BehaviorClock::time_point last_{};
};

}  // namespace slaptop::collector
