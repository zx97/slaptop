// Configuration file parsing: sections, groups, and the mistakes that used to
// be silent.  The rule under test is that a key written in a section that
// cannot hold it is an *error*, not a warning: dropping `group = lab` means
// monitoring another environment than the file says.

#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "slaptop/config.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

/// Writes `text` to a temporary file and returns its path.
std::string writeConfig(const std::string& text) {
    char path[] = "/tmp/slaptop-config-XXXXXX";
    const int fd = ::mkstemp(path);
    if (fd < 0) {
        std::perror("mkstemp");
        std::abort();
    }
    ::close(fd);
    std::ofstream out(path, std::ios::trunc);
    out << text;
    out.close();
    return path;
}

std::string describe(const std::vector<std::string>& messages) {
    std::string joined;
    for (const std::string& message : messages) {
        joined += message;
        joined += '\n';
    }
    return joined;
}

void testMissingFileIsNotAnError() {
    const slaptop::Config config = slaptop::Config::load("/nonexistent/slaptop/config");
    CHECK(config.errors.empty());
    CHECK(config.groups.empty());
    CHECK(config.defaultGroup.empty());
    CHECK(config.interval == 1.0);
}

void testGroupsAndDefault() {
    const std::string path = writeConfig(
        "group = dev\n"
        "interval = 2.5\n"
        "\n"
        "[theme]\n"
        "animate = false\n"
        "\n"
        "[group dev]\n"
        "node = ldap3.example.com name=ldap3\n"
        "node = ldap3.example.com name=ldap3\n"
        "\n"
        "[group acc]\n"
        "node = ldap1 name=ldap1\n"
        "uri  = ldaps://lb-acc:636 insecure=yes\n");
    std::vector<std::string> warnings;
    const slaptop::Config config = slaptop::Config::load(path, &warnings);
    std::remove(path.c_str());

    CHECK(config.errors.empty());
    CHECK(warnings.empty());
    CHECK(config.defaultGroup == "dev");
    CHECK(config.interval == 2.5);
    CHECK(config.groups.size() == 2);
    if (config.groups.size() == 2) {
        CHECK(config.groups[0].name == "dev");
        CHECK(config.groups[0].nodes.size() == 2);
        CHECK(config.groups[1].name == "acc");
        CHECK(config.groups[1].uris.size() == 1);
        CHECK(config.groups[1].nodes.size() == 1);
    }
}

/// The bug that hid a real configuration: `group = lab` pasted after the theme
/// keys, read as a theme key, silently ignored.
void testTopLevelKeyInsideThemeIsAnError() {
    const std::string path = writeConfig(
        "[theme]\n"
        "animate = true\n"
        "group = lab\n"
        "\n"
        "[group lab]\n"
        "node = ldap1.example.com name=proxy\n");
    std::vector<std::string> warnings;
    const slaptop::Config config = slaptop::Config::load(path, &warnings);
    std::remove(path.c_str());

    CHECK(!config.errors.empty());
    CHECK(config.defaultGroup.empty());
    const std::string message = describe(config.errors);
    CHECK(message.find("'group' is a top-level key") != std::string::npos);
    CHECK(message.find("line 3") != std::string::npos);
}

void testThemeKeyInsideGroupIsAnError() {
    const std::string path = writeConfig(
        "[group dev]\n"
        "animate = false\n"
        "node = ldap3.example.com\n");
    std::vector<std::string> warnings;
    const slaptop::Config config = slaptop::Config::load(path, &warnings);
    std::remove(path.c_str());

    CHECK(!config.errors.empty());
    const std::string message = describe(config.errors);
    CHECK(message.find("cannot be set in [group dev]") != std::string::npos);
}

void testUnknownKeysOnlyWarn() {
    const std::string path = writeConfig(
        "[theme]\n"
        "colur = #ff0000\n"
        "animet = false\n");
    std::vector<std::string> warnings;
    const slaptop::Config config = slaptop::Config::load(path, &warnings);
    std::remove(path.c_str());

    // A typo must not keep the dashboard from starting.
    CHECK(config.errors.empty());
    CHECK(warnings.size() == 2);
    CHECK(describe(warnings).find("line 2") != std::string::npos);
}

}  // namespace

int main() {
    testMissingFileIsNotAnError();
    testGroupsAndDefault();
    testTopLevelKeyInsideThemeIsAnError();
    testThemeKeyInsideGroupIsAnError();
    testUnknownKeysOnlyWarn();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "config: all checks passed\n";
    return 0;
}
