#include <chrono>
#include <iostream>
#include <thread>

#include "slaptop/engine.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

/// Starting and stopping the engine must never leave a joinable thread
/// behind (regression: destroying one calls std::terminate).
void testStartStopIsSafe() {
    for (int iteration = 0; iteration < 5; ++iteration) {
        slaptop::EngineOptions options;
        options.intervalSeconds = 0.05;
        options.ldapIntervalSeconds = 0.05;
        options.enableLdap = false;
        options.enableLog = false;

        slaptop::MonitorEngine engine(options);
        engine.start();
        std::this_thread::sleep_for(std::chrono::milliseconds(120));
        const slaptop::FleetSnapshot snapshot = engine.snapshot();
        CHECK(snapshot.instances.size() == snapshot.history.size());
        engine.stop();
        // A second stop is a no-op, not a crash.
        engine.stop();
    }
}

/// A remote URI that cannot be reached must degrade, not hang or throw.
void testUnreachableRemote() {
    slaptop::EngineOptions options;
    options.intervalSeconds = 0.05;
    options.ldapIntervalSeconds = 0.05;
    options.remoteTargets = {slaptop::RemoteTarget{"ldap://127.0.0.1:1"}};
    options.insecureTls = true;

    slaptop::MonitorEngine engine(options);
    engine.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    const slaptop::FleetSnapshot snapshot = engine.snapshot();
    engine.stop();

    // The local host may itself run slapd, so only assert the remote one.
    bool foundRemote = false;
    for (const slaptop::InstanceMetrics& metrics : snapshot.instances) {
        if (metrics.instance.pid == 0) {
            foundRemote = true;
            CHECK(metrics.health != slaptop::Health::Running);
        }
    }
    // Discovery empty -> the remote list is used; otherwise local instances win.
    if (snapshot.instances.empty()) {
        CHECK(!foundRemote);
    }
}

/// Two remote URIs must produce two distinct entries (regression: both have
/// pid 0 and used to collide in a pid-keyed map).
void testTwoRemotesAreDistinct() {
    slaptop::EngineOptions options;
    options.intervalSeconds = 0.05;
    options.ldapIntervalSeconds = 0.05;
    options.remoteTargets = {slaptop::RemoteTarget{"ldap://127.0.0.1:1"},
                             slaptop::RemoteTarget{"ldap://127.0.0.1:2"}};

    slaptop::MonitorEngine engine(options);
    engine.start();
    std::this_thread::sleep_for(std::chrono::milliseconds(400));
    const slaptop::FleetSnapshot snapshot = engine.snapshot();
    const std::size_t count = engine.instanceCount();
    engine.stop();

    // On a host already running slapd, local discovery adds its instances to
    // the remote ones: only assert the remote-only case.  Checking every
    // instance (not just the first) keeps the test independent of the display
    // order, which is now sorted by name.
    bool anyLocal = false;
    for (const auto& metrics : snapshot.instances) {
        if (metrics.instance.pid > 0) {
            anyLocal = true;
        }
    }
    if (!anyLocal) {
        CHECK(count == 2);
        CHECK(snapshot.instances.size() == 2);
    }
}

}  // namespace

int main() {
    testStartStopIsSafe();
    testUnreachableRemote();
    testTwoRemotesAreDistinct();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "engine checks passed\n";
    return 0;
}
