#include <unistd.h>

#include <cstdio>
#include <fstream>
#include <iostream>
#include <string>

#include "slaptop/collector/logfile.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

void testParseResultLine() {
    const auto info = slaptop::collector::parseLogLine(
        "2026-11-04T02:21:36.226196581Z host slapd[2164]: conn=1013 op=17 "
        "SEARCH RESULT tag=101 err=32 qtime=0.000014 etime=0.000698 nentries=0 text=");
    // err=32 is "no such object": routine, must not count as a failure.
    CHECK(!info.isError);
    CHECK(info.err == 32);
    CHECK(info.conn == 1013);
    CHECK(info.op == 17);
    CHECK(info.operation == "SEARCH");
}

void testParseFailureLine() {
    const auto info = slaptop::collector::parseLogLine(
        "2026-11-04T02:10:23.897903960Z host slapd[2164]: conn=1000 fd=12 "
        "closed (operations error)");
    CHECK(info.isError);
    CHECK(info.err == -1);
}

void testParseInsufficientAccess() {
    const auto info = slaptop::collector::parseLogLine(
        "2026-11-04T02:11:51.428646120Z host slapd[2164]: conn=1001 op=2 "
        "SEARCH RESULT tag=101 err=50 qtime=0.000006 etime=0.000037 nentries=0 text=");
    CHECK(info.isError);
    CHECK(info.err == 50);
}

void testParseSuccessLine() {
    const auto info = slaptop::collector::parseLogLine(
        "2026-11-04T02:21:35.724531106Z host slapd[2164]: conn=1013 op=14 "
        "SEARCH RESULT tag=101 err=0 qtime=0.000013 etime=0.016033 nentries=70 text=");
    CHECK(!info.isError);
    CHECK(info.err == 0);
    CHECK(info.op == 14);
}

void testParseAcceptLine() {
    const auto info = slaptop::collector::parseLogLine(
        "2026-10-19T13:59:05.991141106Z host slapd[2209]: conn=1000 fd=12 "
        "ACCEPT from IP=127.0.0.1:52344 (IP=127.0.0.1:389)");
    CHECK(!info.isError);
    CHECK(info.err == -1);
    CHECK(info.conn == 1000);
    CHECK(info.operation == "ACCEPT");
}

void testTailerFollowsAppends() {
    std::string path = "/dev/shm/slaptop-test-log-XXXXXX";
    const int fd = ::mkstemp(path.data());
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    ::close(fd);

    {
        std::ofstream out(path, std::ios::app);
        out << "line one\nline two\n";
    }

    slaptop::collector::LogTailer tailer(path);
    CHECK(tailer.available());
    // Created at end-of-file, so existing content is not replayed.
    CHECK(tailer.poll().empty());

    {
        std::ofstream out(path, std::ios::app);
        out << "line three\nline four\n";
    }
    const auto lines = tailer.poll();
    CHECK(lines.size() == 2);
    if (lines.size() == 2) {
        CHECK(lines[0] == "line three");
        CHECK(lines[1] == "line four");
    }
    CHECK(tailer.poll().empty());

    ::unlink(path.c_str());
}

void testTailerHandlesTruncation() {
    std::string path = "/dev/shm/slaptop-test-rot-XXXXXX";
    const int fd = ::mkstemp(path.data());
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    ::close(fd);

    {
        std::ofstream out(path, std::ios::app);
        out << "aaaaaaaaaa\nbbbbbbbbbb\n";
    }
    slaptop::collector::LogTailer tailer(path);

    // Simulate rotation through truncation.
    {
        std::ofstream out(path, std::ios::trunc);
        out << "fresh\n";
    }
    const auto lines = tailer.poll();
    CHECK(lines.empty() || lines.front() == "fresh");

    {
        std::ofstream out(path, std::ios::app);
        out << "after\n";
    }
    const auto after = tailer.poll();
    CHECK(!after.empty());
    if (!after.empty()) {
        CHECK(after.back() == "after");
    }

    ::unlink(path.c_str());
}

void testLogSettingsFromConfigDir() {
    std::string dir = "/dev/shm/slaptop-cfg-XXXXXX";
    CHECK(::mkdtemp(dir.data()) != nullptr);

    {
        std::ofstream out(dir + "/cn=config.ldif");
        out << "dn: cn=config\n"
            << "objectClass: olcGlobal\n"
            << "olcLogFile: /var/log/slapd_test.log\n"
            << "olcLogFileFormat: rfc3339-utc\n"
            << "olcLogLevel: stats\n";
    }

    const auto settings = slaptop::collector::readLogSettingsFromConfigDir(dir);
    CHECK(settings.has_value());
    if (settings) {
        CHECK(settings->path == "/var/log/slapd_test.log");
        CHECK(settings->format == "rfc3339-utc");
        CHECK(settings->level == "stats");
    }

    ::unlink((dir + "/cn=config.ldif").c_str());
    ::rmdir(dir.c_str());

    // Missing directory must return nullopt, never throw.
    CHECK(!slaptop::collector::readLogSettingsFromConfigDir("/nonexistent/dir").has_value());
}

void testLogLevelIsMultiValued() {
    std::string dir = "/dev/shm/slaptop-cfg-XXXXXX";
    CHECK(::mkdtemp(dir.data()) != nullptr);

    // cn=config writes one olcLogLevel line per level.  `sync` comes last, so
    // keeping only the last value used to hide `stats` completely.
    {
        std::ofstream out(dir + "/cn=config.ldif");
        out << "dn: cn=config\n"
            << "olcLogFile: /var/log/slapd_test.log\n"
            << "olcLogLevel: stats\n"
            << "olcLogLevel: sync\n"
            << "olcLogLevel: 512\n";
    }

    const auto settings = slaptop::collector::readLogSettingsFromConfigDir(dir);
    CHECK(settings.has_value());
    if (settings) {
        // All values are kept, in file order, space separated.
        CHECK(settings->level == "stats sync 512");
        CHECK(slaptop::collector::logLevelHasStats(settings->level));
    }

    ::unlink((dir + "/cn=config.ldif").c_str());
    ::rmdir(dir.c_str());
}

void testLogLevelHasStats() {
    using slaptop::collector::logLevelHasStats;
    CHECK(logLevelHasStats("stats"));
    CHECK(logLevelHasStats("Stats"));
    CHECK(logLevelHasStats("stats2"));
    CHECK(logLevelHasStats("any"));
    CHECK(logLevelHasStats("256"));
    CHECK(logLevelHasStats("512"));
    CHECK(logLevelHasStats("-1"));
    // A list: cn=config stores one value per level, and the last one is what
    // a last-wins parser would have kept.
    CHECK(logLevelHasStats("stats sync"));
    CHECK(logLevelHasStats("sync stats"));
    CHECK(logLevelHasStats("256 512"));
    CHECK(logLevelHasStats("sync,stats"));
    CHECK(logLevelHasStats("config|stats"));
    // The attribute is there, statistics are not.
    CHECK(!logLevelHasStats("sync"));
    CHECK(!logLevelHasStats("none"));
    CHECK(!logLevelHasStats("0"));
    CHECK(!logLevelHasStats("128"));
    // No value at all: unknown, so the caller must not blame the config.
    CHECK(logLevelHasStats(""));
    CHECK(logLevelHasStats("   "));
}

}  // namespace

int main() {
    testParseResultLine();
    testParseFailureLine();
    testParseInsufficientAccess();
    testParseSuccessLine();
    testParseAcceptLine();
    testTailerFollowsAppends();
    testTailerHandlesTruncation();
    testLogSettingsFromConfigDir();
    testLogLevelIsMultiValued();
    testLogLevelHasStats();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "log checks passed\n";
    return 0;
}
