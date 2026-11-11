#include <chrono>
#include <cstdio>
#include <iostream>
#include <string>

#include "slaptop/collector/behavior.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

using Clock = slaptop::collector::BehaviorClock;

Clock::time_point at(double seconds) {
    return Clock::time_point{} + std::chrono::duration_cast<Clock::duration>(
                                      std::chrono::duration<double>(seconds));
}

// Every fixture below is synthetic: RFC 2606 domain, RFC 5737 address, made-up
// DNs.  Real captures never enter the repository.
std::string bindLine(std::uint64_t conn, const std::string& dn) {
    return "2026-11-09T01:31:48.394585735Z ldap1.example.com slapd[11247]: conn=" +
           std::to_string(conn) + " op=0 BIND dn=\"" + dn + "\" method=128";
}

std::string searchLine(std::uint64_t conn, std::uint64_t op, const std::string& filter) {
    return "2026-11-09T01:32:10.402963601Z ldap1.example.com slapd[11247]: conn=" +
           std::to_string(conn) + " op=" + std::to_string(op) +
           " SRCH base=\"dc=example,dc=org\" scope=2 deref=0 filter=\"" + filter + "\"";
}

std::string attrLine(std::uint64_t conn, std::uint64_t op) {
    return "2026-11-09T01:32:10.402968431Z ldap1.example.com slapd[11247]: conn=" +
           std::to_string(conn) + " op=" + std::to_string(op) + " SRCH attr=cn sn";
}

std::string resultLine(std::uint64_t conn, std::uint64_t op, const std::string& etime) {
    return "2026-11-09T01:32:10.402990111Z ldap1.example.com slapd[11247]: conn=" +
           std::to_string(conn) + " op=" + std::to_string(op) +
           " SEARCH RESULT tag=101 err=0 qtime=0.000010 etime=" + etime +
           " nentries=8 text=";
}

void testGeneralize() {
    using slaptop::collector::generalizeFilter;
    // The documented examples of slaplog's generalize_filter: both tools must
    // produce the same family name for the same filter.
    CHECK(generalizeFilter("(employeeNumber=100*)") == "(employeenumber=#*)");
    CHECK(generalizeFilter("(employeeType=i)") == "(employeetype=$)");
    CHECK(generalizeFilter("(&(objectClass=person)(uid=abc))") ==
          "(&(objectclass=$)(uid=$))");
    CHECK(generalizeFilter("(uid=*)") == "(uid=*)");
    CHECK(generalizeFilter("(cn=*foo*)") == "(cn=*$*)");
    CHECK(generalizeFilter("(!(mail=*))") == "(!(mail=*))");
    CHECK(generalizeFilter("(uid=user123)") == "(uid=$#)");
    CHECK(generalizeFilter("(cn=12ab)") == "(cn=#$)");  // run order is kept
    CHECK(generalizeFilter("( uid = a b )") == "(uid=$)");
    // Consecutive identical siblings collapse: an enumeration of a hundred
    // uids is one family, not one family per arity.
    CHECK(generalizeFilter("(|(uid=a)(uid=b)(uid=c))") == "(|(uid=$)+)");
    CHECK(generalizeFilter("(|(uid=a)(cn=b)(uid=c))") == "(|(uid=$)(cn=$)(uid=$))");
    // A quote ends the filter: attributes logged after it must not leak in.
    CHECK(generalizeFilter("(uid=abc)\" attrs=\"cn") == "(uid=$)");
}

void testSlowFilter() {
    using slaptop::collector::isSlowFilter;
    CHECK(!isSlowFilter("(uid=$)"));
    CHECK(!isSlowFilter("(objectclass=$)"));
    CHECK(!isSlowFilter("(uid=*)"));          // presence test: indexed
    CHECK(isSlowFilter("(uid=$*)"));          // prefix wildcard
    CHECK(isSlowFilter("(uid=*$)"));          // suffix wildcard
    CHECK(isSlowFilter("(cn=*$*)"));          // substring
    CHECK(isSlowFilter("(!(mail=*))"));       // negation
}

void testPairing() {
    slaptop::collector::BehaviorWindow window;
    window.setLogLevel("stats");
    window.feed(bindLine(7, "uid=alice,ou=people,dc=example,dc=org"), at(0));
    window.feed(searchLine(7, 1, "(uid=alice)"), at(0));
    window.feed(attrLine(7, 1), at(0));  // the second SRCH line adds nothing
    window.feed(resultLine(7, 1, "0.012000"), at(0));
    window.roll(at(0));

    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 1);
    CHECK(snapshot.totals.ops == 1);
    CHECK(snapshot.accounts.size() == 1);
    CHECK(snapshot.accounts[0].account == "uid=alice,ou=people,dc=example,dc=org");
    CHECK(snapshot.accounts[0].counters.ops == 1);
    CHECK(snapshot.accounts[0].etimeSeconds > 0.0119);
    CHECK(snapshot.accounts[0].etimeSeconds < 0.0121);
    CHECK(snapshot.accounts[0].sharePercent > 99.0);
    CHECK(snapshot.families.size() == 1);
    CHECK(snapshot.families[0].family == "(uid=$)");
    CHECK(!snapshot.families[0].slow);
    CHECK(snapshot.families[0].counters.qtimeNs > 0);
    CHECK(snapshot.families[0].counters.nentries == 8);
}

void testResultWithoutRequestIsIgnored() {
    slaptop::collector::BehaviorWindow window;
    window.feed(resultLine(3, 0, "0.5"), at(0));
    window.roll(at(0));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 0);
    CHECK(snapshot.totals.ops == 0);
}

void testAnonymousAndUnknown() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, ""), at(0));                       // anonymous
    window.feed(searchLine(1, 1, "(cn=*)"), at(0));
    window.feed(resultLine(1, 1, "0.001"), at(0));
    window.feed(searchLine(2, 1, "(cn=*)"), at(0));            // no BIND seen
    window.feed(resultLine(2, 1, "0.001"), at(0));
    window.roll(at(0));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 2);
    CHECK(snapshot.accounts.size() == 2);
    CHECK(snapshot.accounts[0].account == "(anonymous)" ||
          snapshot.accounts[1].account == "(anonymous)");
    CHECK(snapshot.accounts[0].account == "(unknown)" ||
          snapshot.accounts[1].account == "(unknown)");
}

void testWindowExpiry() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, "uid=bob,dc=example,dc=org"), at(0));
    window.feed(searchLine(1, 1, "(uid=bob)"), at(0));
    window.feed(resultLine(1, 1, "0.020"), at(0));
    window.roll(at(0));
    CHECK(window.snapshot().searches == 1);

    // One second before the slice leaves the window, it is still counted.
    window.roll(at(59));
    CHECK(window.snapshot().searches == 1);

    // Past the window, it is gone.
    window.roll(at(62));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 0);
    CHECK(snapshot.totals.ops == 0);
    CHECK(snapshot.accounts.empty());
    CHECK(snapshot.families.empty());
}

void testLongGapResets() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, "uid=bob,dc=example,dc=org"), at(0));
    window.feed(searchLine(1, 1, "(uid=bob)"), at(0));
    window.feed(resultLine(1, 1, "0.020"), at(0));
    // The process was paused for ten minutes: nothing can still be in the
    // window, and the ring must not iterate over 600 empty slices.
    window.roll(at(600));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 0);
    CHECK(snapshot.searchTimeline.size() == slaptop::collector::BehaviorWindow::kBuckets);
}

void testRankingAndVerdict() {
    using slaptop::collector::BehaviorWindow;
    BehaviorWindow window;

    // 200 fast searches: the noise a server always carries.
    window.feed(bindLine(10, "uid=user002,dc=example,dc=org"), at(0));
    for (int i = 0; i < 200; ++i) {
        window.feed(searchLine(10, static_cast<std::uint64_t>(i), "(uid=a)"), at(0));
        window.feed(resultLine(10, static_cast<std::uint64_t>(i), "0.001"), at(0));
    }
    // 20 scanning searches from another account: 20 x 0.5 s = 10 s, 96 % of
    // the window's etime, far above the 20 % threshold.
    window.feed(bindLine(11, "uid=user003,dc=example,dc=org"), at(0));
    for (int i = 0; i < 20; ++i) {
        window.feed(searchLine(11, static_cast<std::uint64_t>(i), "(cn=*foo*)"), at(0));
        window.feed(resultLine(11, static_cast<std::uint64_t>(i), "0.500000"), at(0));
    }
    window.roll(at(0));

    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 220);
    CHECK(snapshot.slowSearches == 20);
    CHECK(snapshot.enoughTraffic);
    CHECK(snapshot.accounts.size() == 2);
    // Ranking is by etime, not by operation count.
    CHECK(snapshot.accounts[0].account == "uid=user003,dc=example,dc=org");
    CHECK(snapshot.accounts[0].counters.ops == 20);
    CHECK(snapshot.accounts[1].counters.ops == 200);
    CHECK(snapshot.accounts[0].sharePercent > 90.0);
    CHECK(snapshot.accounts[0].averageSeconds > 0.49);

    CHECK(snapshot.hogs.size() == 1);
    CHECK(snapshot.hogs[0].account == "uid=user003,dc=example,dc=org");
    CHECK(snapshot.hogs[0].family == "(cn=*$*)");
    CHECK(snapshot.hogs[0].sharePercent > 90.0);
    CHECK(snapshot.hogs[0].counters.ops == 20);
}

/// The verdict is a measurement: an equality filter that dominates the window
/// is a hog too.  Gating on the "expensive shape" (substring, negation) used to
/// hide exactly this case.
void testEqualityHogIsDetected() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(20, "uid=user002,dc=example,dc=org"), at(0));
    for (int i = 0; i < 200; ++i) {
        window.feed(searchLine(20, static_cast<std::uint64_t>(i), "(uid=a)"), at(0));
        window.feed(resultLine(20, static_cast<std::uint64_t>(i), "0.001"), at(0));
    }
    // Plain equality on an attribute, 20 x 0.4 s: no wildcard, no negation.
    window.feed(bindLine(21, "uid=user004,dc=example,dc=org"), at(0));
    for (int i = 0; i < 20; ++i) {
        window.feed(searchLine(21, static_cast<std::uint64_t>(i), "(mail=a@example.org)"), at(0));
        window.feed(resultLine(21, static_cast<std::uint64_t>(i), "0.400000"), at(0));
    }
    window.roll(at(0));

    const auto snapshot = window.snapshot();
    CHECK(snapshot.slowSearches == 0);  // no substring, no negation
    CHECK(snapshot.hogs.size() == 1);
    CHECK(snapshot.hogs[0].account == "uid=user004,dc=example,dc=org");
    CHECK(snapshot.hogs[0].sharePercent > 20.0);
    CHECK(!snapshot.hogs[0].slowShape);  // the shape is reported, not used
}

/// The false positive the user reported: a family that takes most of the
/// window's etime while averaging 2 ms per search is normal work, not a hog.
/// The share is a pointer; the absolute figure decides.
void testFastFamilyIsNotAHog() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(30, "uid=user002,dc=example,dc=org"), at(0));
    for (int i = 0; i < 200; ++i) {
        window.feed(searchLine(30, static_cast<std::uint64_t>(i), "(uid=a)"), at(0));
        window.feed(resultLine(30, static_cast<std::uint64_t>(i), "0.001"), at(0));
    }
    // 300 searches at 2 ms: 0.6 s, i.e. 75 % of the window's etime, but 2 ms
    // per search is a healthy directory.
    window.feed(bindLine(31, "uid=user005,dc=example,dc=org"), at(0));
    for (int i = 0; i < 300; ++i) {
        window.feed(searchLine(31, static_cast<std::uint64_t>(i), "(mail=a@example.org)"), at(0));
        window.feed(resultLine(31, static_cast<std::uint64_t>(i), "0.002000"), at(0));
    }
    window.roll(at(0));

    const auto snapshot = window.snapshot();
    CHECK(snapshot.enoughTraffic);
    CHECK(snapshot.hogs.empty());
    // The ranking still shows who spends the time: the verdict alone is silent.
    CHECK(!snapshot.accounts.empty());
    CHECK(snapshot.accounts[0].sharePercent > 50.0);
}

void testNoVerdictWithoutTraffic() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, "uid=alice,dc=example,dc=org"), at(0));
    // Three sub-millisecond searches: one family is 100 % of the etime, but
    // the window carries neither enough searches nor enough server time to
    // blame anyone.
    for (int i = 0; i < 3; ++i) {
        window.feed(searchLine(1, static_cast<std::uint64_t>(i), "(cn=*x*)"), at(0));
        window.feed(resultLine(1, static_cast<std::uint64_t>(i), "0.001"), at(0));
    }
    window.roll(at(0));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 3);
    CHECK(!snapshot.enoughTraffic);
    CHECK(snapshot.hogs.empty());
}

void testSingleExpensiveQueryIsAVerdict() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, "uid=alice,dc=example,dc=org"), at(0));
    // A quiet minute: three searches, one of which scans for a second.  One
    // operation is not "repetition", but a second of server time is a hog on
    // its own, and the window holds enough evidence (500 ms).
    window.feed(searchLine(1, 1, "(uid=a)"), at(0));
    window.feed(resultLine(1, 1, "0.001"), at(0));
    window.feed(searchLine(1, 2, "(cn=*x*)"), at(0));
    window.feed(resultLine(1, 2, "1.000"), at(0));
    window.feed(searchLine(1, 3, "(uid=b)"), at(0));
    window.feed(resultLine(1, 3, "0.001"), at(0));
    window.roll(at(0));
    const auto snapshot = window.snapshot();
    CHECK(snapshot.searches == 3);
    CHECK(snapshot.enoughTraffic);  // by accumulated time, not by count
    CHECK(snapshot.hogs.size() == 1);
    CHECK(snapshot.hogs[0].family == "(cn=*$*)");
    CHECK(snapshot.hogs[0].counters.ops == 1);
}

void testTopRowsAreCapped() {
    slaptop::collector::BehaviorWindow window;
    for (std::uint64_t conn = 1; conn <= 30; ++conn) {
        window.feed(bindLine(conn, "uid=user" + std::to_string(conn) + ",dc=example,dc=org"),
                    at(0));
        window.feed(searchLine(conn, 1, "(uid=user" + std::to_string(conn) + ")"), at(0));
        window.feed(resultLine(conn, 1, "0.010"), at(0));
    }
    window.roll(at(0));
    // The cap is a report limit, never the visible height: ask for 10 here and
    // the ranking must still know about all 30.
    const auto capped = window.snapshot(10);
    CHECK(capped.accountsSeen == 30);
    CHECK(capped.accounts.size() == 10);
    CHECK(capped.familiesSeen == 30);
    CHECK(capped.families.size() == 10);
    // The default keeps well above any screen height, so a tall terminal shows
    // the rows that the old 10-row cap used to hide.
    const auto full = window.snapshot();
    CHECK(full.accounts.size() == 30);
    CHECK(full.families.size() == 30);
}

void testTimelineShape() {
    slaptop::collector::BehaviorWindow window;
    window.feed(bindLine(1, "uid=alice,dc=example,dc=org"), at(0));
    window.feed(searchLine(1, 1, "(uid=alice)"), at(0));
    window.feed(resultLine(1, 1, "0.010"), at(0));
    window.roll(at(3));
    const auto snapshot = window.snapshot();
    // The axis always has kBuckets columns so the sparkline does not jump when
    // the window is not full yet; the newest slice is the last one.
    CHECK(snapshot.searchTimeline.size() == slaptop::collector::BehaviorWindow::kBuckets);
    CHECK(snapshot.etimeTimeline.size() == slaptop::collector::BehaviorWindow::kBuckets);
    // The newest slice is the last column and is still empty (the search
    // happened at t=0, the roll is at t=3): the window shows the gap honestly.
    double total = 0.0;
    for (const double value : snapshot.searchTimeline) {
        total += value;
    }
    CHECK(total >= 1.0);
    CHECK(snapshot.elapsedSeconds > 2.9);
    CHECK(snapshot.elapsedSeconds < 3.1);
}

void testNonSearchLinesAreIgnored() {
    slaptop::collector::BehaviorWindow window;
    window.feed("2026-11-09T01:31:48.541334122Z ldap1.example.com slapd[11247]: "
                "conn=2 fd=67 closed (connection lost)",
                at(0));
    window.feed("2026-11-09T01:31:48.541254043Z ldap1.example.com slapd[11247]: "
                "conn=2 op=0 RESULT tag=97 err=0 qtime=0.000022 etime=0.000106 text=",
                at(0));
    window.roll(at(0));
    CHECK(window.snapshot().searches == 0);
}

}  // namespace

int main() {
    testGeneralize();
    testSlowFilter();
    testPairing();
    testResultWithoutRequestIsIgnored();
    testAnonymousAndUnknown();
    testWindowExpiry();
    testLongGapResets();
    testRankingAndVerdict();
    testEqualityHogIsDetected();
    testFastFamilyIsNotAHog();
    testNoVerdictWithoutTraffic();
    testSingleExpensiveQueryIsAVerdict();
    testTopRowsAreCapped();
    testTimelineShape();
    testNonSearchLinesAreIgnored();
    if (g_failures == 0) {
        std::cout << "test_behavior: all checks passed\n";
        return 0;
    }
    std::cerr << "test_behavior: " << g_failures << " failure(s)\n";
    return 1;
}
