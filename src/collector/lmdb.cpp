#include "slaptop/collector/lmdb.hpp"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

namespace slaptop::collector {
namespace {

constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;

std::uint64_t roundUpGiB(std::uint64_t bytes) {
    return ((bytes + kGiB - 1) / kGiB) * kGiB;
}

std::uint64_t roundDownGiB(std::uint64_t bytes) {
    return (bytes / kGiB) * kGiB;
}

std::string formatHours(double hours) {
    char text[48];
    if (hours < 1.0) {
        std::snprintf(text, sizeof(text), "~%.0f min", hours * 60.0);
    } else if (hours < 48.0) {
        std::snprintf(text, sizeof(text), "~%.0f h", hours);
    } else {
        std::snprintf(text, sizeof(text), "~%.0f days", hours / 24.0);
    }
    return text;
}

}  // namespace

std::string humanSize(std::uint64_t bytes) {
    char text[48];
    if (bytes >= kGiB) {
        std::snprintf(text, sizeof(text), "%.1f GB",
                      static_cast<double>(bytes) / static_cast<double>(kGiB));
    } else if (bytes >= 1024ULL * 1024ULL) {
        std::snprintf(text, sizeof(text), "%.1f MB",
                      static_cast<double>(bytes) / (1024.0 * 1024.0));
    } else {
        std::snprintf(text, sizeof(text), "%.0f KB", static_cast<double>(bytes) / 1024.0);
    }
    return text;
}

LmdbRisk assessLmdb(const LmdbRiskInput& input) {
    LmdbRisk risk;
    risk.label = input.label;
    const std::uint64_t mapBytes = input.pagesMax * input.pageSize;
    const std::uint64_t usedBytes = input.pagesUsed * input.pageSize;

    if (input.pagesMax > 0 && input.pagesUsed <= input.pagesMax) {
        risk.usagePercent =
            100.0 * static_cast<double>(input.pagesUsed) / static_cast<double>(input.pagesMax);
    } else if (input.pagesMax > 0) {
        risk.usagePercent = 100.0;
    }

    // The slope, not the percentage, is what makes this a forecast: a stable
    // database at 85 % is not in trouble, a database at 40 % that doubles every
    // hour is.
    if (input.growthPagesPerSecond > 0.0 && input.observedSeconds >= kMinObservedSeconds &&
        input.pagesUsed <= input.pagesMax) {
        const double remainingPages =
            static_cast<double>(input.pagesMax - input.pagesUsed);
        const double seconds = remainingPages / input.growthPagesPerSecond;
        risk.hoursToFull = seconds / 3600.0;
    }

    const bool forecastSoon = risk.hoursToFull >= 0.0 && risk.hoursToFull <= kMapWarningHours;
    if (input.mapFullSeen) {
        risk.severity = AlertSeverity::Critical;
    } else if (risk.usagePercent >= kMapCriticalPercent ||
               (risk.hoursToFull >= 0.0 && risk.hoursToFull <= kMapCriticalHours)) {
        risk.severity = AlertSeverity::Critical;
    } else if (risk.usagePercent >= kMapWarningPercent || forecastSoon) {
        risk.severity = AlertSeverity::Warning;
    }

    // --- Message: what is measured, then what is forecast ------------------
    std::string what = input.label;
    if (!input.suffix.empty()) {
        what += " " + input.suffix;
    }
    char line[320];
    if (input.mapFullSeen) {
        std::snprintf(line, sizeof(line),
                      "%s: MDB_MAP_FULL in the log - writes are failing (map %s of %s)",
                      what.c_str(), humanSize(usedBytes).c_str(),
                      humanSize(mapBytes).c_str());
        risk.message = line;
    } else {
        std::snprintf(line, sizeof(line), "%s: LMDB map %.0f%% used (%s of %s)", what.c_str(),
                      risk.usagePercent, humanSize(usedBytes).c_str(),
                      humanSize(mapBytes).c_str());
        risk.message = line;
        if (risk.hoursToFull >= 0.0) {
            risk.message += ", full in " + formatHours(risk.hoursToFull);
        } else if (input.growthPagesPerSecond > 0.0) {
            risk.message += ", growing (forecast needs 3 min of data)";
        } else {
            risk.message += ", not growing";
        }
    }

    // --- Detail: the numbers the message is built from ---------------------
    std::snprintf(line, sizeof(line), "pages %llu/%llu, free %llu, page %llu B",
                  static_cast<unsigned long long>(input.pagesUsed),
                  static_cast<unsigned long long>(input.pagesMax),
                  static_cast<unsigned long long>(input.pagesFree),
                  static_cast<unsigned long long>(input.pageSize));
    risk.detail = line;
    if (!input.directory.empty()) {
        risk.detail += ", " + input.directory;
    }

    // --- Suggestion: LDIF text, never applied ------------------------------
    if (risk.severity != AlertSeverity::Info && input.pagesMax > 0 && input.pageSize > 0) {
        const std::uint64_t currentMax = mapBytes;
        std::uint64_t proposed = std::max(currentMax + currentMax / 2, currentMax + kGiB);
        proposed = roundUpGiB(proposed);
        std::string note;
        if (input.diskFreeBytes > 0) {
            // Growing the map does not write anything, but the data eventually
            // does: do not suggest a size the filesystem cannot hold.
            if (proposed > input.diskFreeBytes) {
                const std::uint64_t fitting = roundDownGiB(input.diskFreeBytes);
                if (fitting > currentMax) {
                    proposed = fitting;
                    note = " (the file will not fit more: " + humanSize(input.diskFreeBytes) +
                           " free)";
                } else {
                    proposed = currentMax;
                    note = " (no room to grow: " + humanSize(input.diskFreeBytes) +
                           " free on the filesystem)";
                }
            } else {
                note = " (" + humanSize(input.diskFreeBytes) + " free)";
            }
        }
        char ldif[320];
        std::snprintf(ldif, sizeof(ldif),
                      "dn: olcDatabase=%s,cn=config\n"
                      "changetype: modify\n"
                      "replace: olcDbMaxSize\n"
                      "olcDbMaxSize: %llu%s",
                      input.label.c_str(), static_cast<unsigned long long>(proposed),
                      note.c_str());
        risk.suggestion = ldif;
        if (risk.message.size() < 220) {
            risk.message += " -> olcDbMaxSize " + humanSize(proposed);
        }
    }
    return risk;
}

}  // namespace slaptop::collector
