#pragma once

#include <cstdint>
#include <deque>
#include <string>

namespace slaptop::collector {

/// Severity of one alert.  There is deliberately no notion of environment
/// (dev/test/prod): the tool reports what it measures and lets the
/// administrator decide what matters.
enum class AlertSeverity { Info, Warning, Critical };

/// Everything needed to judge one LMDB map, measured or derived.
struct LmdbRiskInput {
    std::string label;             ///< "{3}mdb", as written in olcDatabase
    std::string suffix;            ///< naming context, for the message
    std::string directory;         ///< olcDbDirectory
    std::uint64_t pagesUsed{0};    ///< me_last_pgno + 1
    std::uint64_t pagesMax{0};     ///< me_mapsize / psize
    std::uint64_t pagesFree{0};    ///< freelist
    std::uint64_t pageSize{0};
    /// Growth of pagesUsed, in pages per second, over the observation window.
    /// 0 means "not growing or not measurable yet" (a fresh start has no
    /// slope, and that is reported as such rather than invented).
    double growthPagesPerSecond{0.0};
    /// Free space of the filesystem holding olcDbDirectory, 0 when unknown.
    std::uint64_t diskFreeBytes{0};
    /// True when the access log showed MDB_MAP_FULL for this instance in the
    /// recent window: writes are already failing, this is not a forecast.
    bool mapFullSeen{false};
    /// Seconds the growth was measured over (0 when unknown): the estimate is
    /// only shown once it rests on enough observation.
    double observedSeconds{0.0};
};

/// The judgement on one map, ready to display.  Nothing here is acted upon.
struct LmdbRisk {
    AlertSeverity severity{AlertSeverity::Info};
    /// Filled by the engine: the instance this map belongs to.
    std::string instance;
    /// The database label ("{3}mdb"), as written in olcDatabase.
    std::string label;
    /// Share of the map already used, 0..100.
    double usagePercent{0.0};
    /// Estimated hours before the map is full; negative when unknown.
    double hoursToFull{-1.0};
    /// One line for the banner.
    std::string message;
    /// The measured values, so the message can be checked.
    std::string detail;
    /// The change an administrator may choose to apply, as LDIF text.  Never
    /// executed: slaptop is a diagnostic aid, not an agent.
    std::string suggestion;
};

/// Below this share of the map, nothing is reported.
constexpr double kMapWarningPercent = 75.0;
/// Above this share, the next large write fails: MDB_MAP_FULL is imminent.
constexpr double kMapCriticalPercent = 90.0;
/// A map that fills within this delay is critical whatever the percentage.
constexpr double kMapCriticalHours = 24.0;
/// A map that fills within this delay is a warning.
constexpr double kMapWarningHours = 168.0;  // one week
/// The forecast needs this much observation before it is shown at all.
constexpr double kMinObservedSeconds = 180.0;  // three minutes

/// Judges one map: percentage, forecast, severity and the LDIF an
/// administrator could apply.  `hoursToFull` is derived from the slope, not
/// from the percentage, so a map at 40 % growing fast outranks one at 80 %
/// that is stable.
LmdbRisk assessLmdb(const LmdbRiskInput& input);

/// Human-readable size ("40.0 GB"), shared with the UI.
std::string humanSize(std::uint64_t bytes);

}  // namespace slaptop::collector
