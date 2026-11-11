#include <unistd.h>

#include <cstdint>
#include <iostream>
#include <string>

#include "slaptop/collector/discovery.hpp"
#include "slaptop/collector/proc.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

void testInstanceName() {
    using slaptop::collector::instanceNameFromConfigDir;

    CHECK(instanceNameFromConfigDir("/opt/openldap/etc/slapd_proxy.d") == "proxy");
    CHECK(instanceNameFromConfigDir("slapd_provider.d") == "provider");
    CHECK(instanceNameFromConfigDir("/var/lib/slapd_replica.d") == "replica");
    // Unmatched naming conventions fall back to the raw basename.
    CHECK(instanceNameFromConfigDir("/etc/ldap/slapd-custom") == "slapd-custom");
    CHECK(instanceNameFromConfigDir("") == "");
    // Degenerate inputs must not slice out of bounds.
    CHECK(instanceNameFromConfigDir("slapd_.d") == "slapd_.d");
}

void testSampleSelf() {
    const auto sample = slaptop::collector::sampleProcess(::getpid());
    CHECK(sample.has_value());
    if (sample) {
        CHECK(sample->pid == ::getpid());
        CHECK(sample->numThreads >= 1);
        CHECK(sample->rssBytes > 0);
        CHECK(sample->vszBytes >= sample->rssBytes);
    }
    // A pid that cannot exist yields no sample rather than throwing.
    CHECK(!slaptop::collector::sampleProcess(static_cast<pid_t>(1 << 30)).has_value());
}

void testSamplerDelta() {
    slaptop::collector::ProcSampler sampler;
    const auto first = sampler.sample(::getpid());
    CHECK(first.has_value());
    if (first) {
        CHECK(first->cpuPercent == 0.0);
    }

    // Burn a little CPU so the second sample has a measurable delta.
    std::uint64_t accumulator = 0;
    for (std::uint64_t i = 0; i < 20'000'000ULL; ++i) {
        accumulator += i;
    }
    // Keep the loop from being optimised away without volatile arithmetic.
    asm volatile("" : "+r"(accumulator) : : "memory");

    const auto second = sampler.sample(::getpid());
    CHECK(second.has_value());
    if (second) {
        CHECK(second->cpuPercent >= 0.0);
        CHECK(second->cpuPercent < 100.0 * 64.0);
    }

    sampler.forget(::getpid());
    CHECK(sampler.sample(static_cast<pid_t>(1 << 30)).has_value() == false);
}

void testDiscovery() {
    // Discovery must never throw, whatever the host runs.
    const auto instances = slaptop::collector::discoverInstances();
    for (const auto& instance : instances) {
        CHECK(instance.pid > 0);
        CHECK(!instance.name.empty());
    }
}

}  // namespace

int main() {
    testInstanceName();
    testSampleSelf();
    testSamplerDelta();
    testDiscovery();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "all checks passed\n";
    return 0;
}
