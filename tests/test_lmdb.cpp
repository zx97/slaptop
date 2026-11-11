#include <cstdint>
#include <iostream>
#include <string>

#include "slaptop/collector/lmdb.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

using slaptop::collector::AlertSeverity;
using slaptop::collector::LmdbRiskInput;
using slaptop::collector::assessLmdb;

constexpr std::uint64_t kPage = 4096;
constexpr std::uint64_t kGiB = 1024ULL * 1024ULL * 1024ULL;

/// A database with a 40 GB map (10 M pages), `usedPercent` percent of it.
LmdbRiskInput makeInput(double usedPercent, std::uint64_t pagesMax = 10'000'000) {
    LmdbRiskInput input;
    input.label = "{3}mdb";
    input.suffix = "dc=example,dc=org";
    input.directory = "/var/lib/ldap/example";
    input.pagesMax = pagesMax;
    input.pagesUsed = static_cast<std::uint64_t>(
        static_cast<double>(pagesMax) * usedPercent / 100.0);
    input.pagesFree = 0;
    input.pageSize = kPage;
    return input;
}

void testComfortableMapIsSilent() {
    const auto risk = assessLmdb(makeInput(50.0));
    CHECK(risk.severity == AlertSeverity::Info);
    CHECK(risk.usagePercent > 49.9 && risk.usagePercent < 50.1);
    CHECK(risk.hoursToFull < 0.0);
    CHECK(risk.suggestion.empty());
}

void testHighUsageWarnsWithLdif() {
    auto input = makeInput(80.0);
    input.diskFreeBytes = 100 * kGiB;
    const auto risk = assessLmdb(input);
    CHECK(risk.severity == AlertSeverity::Warning);
    // The suggestion is LDIF text for the administrator, never an action.
    CHECK(risk.suggestion.find("dn: olcDatabase={3}mdb,cn=config") != std::string::npos);
    CHECK(risk.suggestion.find("replace: olcDbMaxSize") != std::string::npos);
    CHECK(risk.message.find("olcDbMaxSize") != std::string::npos);
}

void testNearlyFullIsCritical() {
    CHECK(assessLmdb(makeInput(95.0)).severity == AlertSeverity::Critical);
    CHECK(assessLmdb(makeInput(90.0)).severity == AlertSeverity::Critical);
    // Just under the line, still a warning.
    CHECK(assessLmdb(makeInput(89.9)).severity == AlertSeverity::Warning);
}

void testForecastOutranksPercentage() {
    // 40 % used, but the map fills in under two hours: critical.
    auto input = makeInput(40.0);
    input.growthPagesPerSecond = 500.0;  // 6M pages left -> 12000 s
    input.observedSeconds = 600.0;
    const auto risk = assessLmdb(input);
    CHECK(risk.severity == AlertSeverity::Critical);
    CHECK(risk.hoursToFull > 3.0 && risk.hoursToFull < 3.5);
    CHECK(risk.message.find("full in") != std::string::npos);
}

void testSlowGrowthWarnsWithoutHighUsage() {
    // 40 % used, filling in about a week: warning, not critical.
    auto input = makeInput(40.0);
    input.growthPagesPerSecond = 10.0;  // 6M pages -> ~167 h
    input.observedSeconds = 600.0;
    const auto risk = assessLmdb(input);
    CHECK(risk.hoursToFull > 160.0 && risk.hoursToFull < 175.0);
    CHECK(risk.severity == AlertSeverity::Warning);
}

void testNoForecastBeforeEnoughObservation() {
    // Same slope, but only one minute of data: no forecast is invented.
    auto input = makeInput(40.0);
    input.growthPagesPerSecond = 500.0;
    input.observedSeconds = 60.0;
    const auto risk = assessLmdb(input);
    CHECK(risk.hoursToFull < 0.0);
    CHECK(risk.severity == AlertSeverity::Info);
    CHECK(risk.message.find("forecast needs") != std::string::npos);
}

void testMapFullSeenIsCriticalWhateverTheUsage() {
    auto input = makeInput(10.0);
    input.mapFullSeen = true;
    const auto risk = assessLmdb(input);
    CHECK(risk.severity == AlertSeverity::Critical);
    CHECK(risk.message.find("MDB_MAP_FULL") != std::string::npos);
}

void testDiskFreeCapsTheSuggestion() {
    // A 40 GB map, only 45 GB free: do not suggest 60 GB.
    auto input = makeInput(80.0);
    input.diskFreeBytes = 45 * kGiB;
    const auto risk = assessLmdb(input);
    CHECK(risk.severity == AlertSeverity::Warning);
    CHECK(risk.suggestion.find("will not fit more") != std::string::npos);
    // Parse the proposed value and check it fits.
    const std::size_t at = risk.suggestion.find("olcDbMaxSize: ");
    CHECK(at != std::string::npos);
    const std::uint64_t proposed =
        std::stoull(risk.suggestion.substr(at + std::string("olcDbMaxSize: ").size()));
    CHECK(proposed <= 45 * kGiB);
    CHECK(proposed >= 40'000'000ULL);  // still larger than the current map
}

void testMissingCountersProduceNothing() {
    LmdbRiskInput input;
    input.label = "{2}mdb";
    const auto risk = assessLmdb(input);  // no pages, no page size
    CHECK(risk.severity == AlertSeverity::Info);
    CHECK(risk.suggestion.empty());
    CHECK(risk.usagePercent == 0.0);
}

void testShrinkingMapDoesNotForecast() {
    // pagesUsed fell (freelist released the tail): a negative slope is not a
    // growth, and the tool must not invent one.
    auto input = makeInput(60.0);
    input.growthPagesPerSecond = 0.0;
    input.observedSeconds = 600.0;
    const auto risk = assessLmdb(input);
    CHECK(risk.hoursToFull < 0.0);
    CHECK(risk.severity == AlertSeverity::Info);
    CHECK(risk.message.find("not growing") != std::string::npos);
}

}  // namespace

int main() {
    testComfortableMapIsSilent();
    testHighUsageWarnsWithLdif();
    testNearlyFullIsCritical();
    testForecastOutranksPercentage();
    testSlowGrowthWarnsWithoutHighUsage();
    testNoForecastBeforeEnoughObservation();
    testMapFullSeenIsCriticalWhateverTheUsage();
    testDiskFreeCapsTheSuggestion();
    testMissingCountersProduceNothing();
    testShrinkingMapDoesNotForecast();
    if (g_failures == 0) {
        std::cout << "test_lmdb: all checks passed\n";
        return 0;
    }
    std::cerr << "test_lmdb: " << g_failures << " failure(s)\n";
    return 1;
}
