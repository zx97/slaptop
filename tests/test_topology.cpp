// Topology resolution: matching a declared URI to the instance it names, the
// SID owner, and the replica sets built from the agreements.
//
// These helpers look simple and are not: every instance of a fleet listens on
// the same ports, so a port-only match attributes everything to whichever
// instance is examined first, and an FQDN ends with its domain, not with the
// host name it starts with.  Both mistakes shipped once; this file is here to
// keep them from coming back.

#include <iostream>
#include <string>
#include <vector>

#include "slaptop/collector/configdir.hpp"
#include "slaptop/engine.hpp"
#include "slaptop/topology.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

using slaptop::collector::DirectoryDatabase;
using slaptop::collector::ServerId;

/// One instance named after its host, listening on the port every node of the
/// fleet shares: exactly the shape that made the port useless as a key.
slaptop::InstanceMetrics node(const std::string& name, const std::vector<std::string>& providers) {
    slaptop::InstanceMetrics metrics;
    metrics.instance.name = name;
    metrics.instance.nodeLabel = name;
    slaptop::ListenerInfo listener;
    listener.address = "IP=0.0.0.0:1389";
    metrics.monitor.listeners.push_back(listener);
    if (!providers.empty()) {
        metrics.directory.databases.resize(1);
        DirectoryDatabase& database = metrics.directory.databases.front();
        database.backend = "mdb";
        database.suffix = "dc=example,dc=com";
        database.syncreplProviders = providers;
    }
    return metrics;
}

void testEndpoints() {
    std::string host;
    int port = 0;
    slaptop::endpointOf("ldaps://ldap1.example.com:636/", host, port);
    CHECK(host == "ldap1.example.com");
    CHECK(port == 636);

    slaptop::endpointOf("IP=0.0.0.0:1389", host, port);
    CHECK(host == "0.0.0.0");
    CHECK(port == 1389);

    slaptop::endpointOf("ldap://[::1]:389", host, port);
    CHECK(host == "::1");
    CHECK(port == 389);

    CHECK(slaptop::wildcardHost("0.0.0.0"));
    CHECK(slaptop::wildcardHost("127.0.0.1"));
    CHECK(!slaptop::wildcardHost("ldap1.example.com"));

    CHECK(slaptop::shortHost("LDAP1.example.com") == "ldap1");
    CHECK(slaptop::shortHost("ldap1") == "ldap1");
}

void testHostMatchesName() {
    // The name is the first label, not the end of the whole name.
    CHECK(slaptop::hostMatchesName("ldap2.example.com", "ldap2"));
    CHECK(!slaptop::hostMatchesName("ldap2.example.com", "ldap1"));
    CHECK(slaptop::hostMatchesName("ldap2.cc.example.net", "ldap2"));
    CHECK(!slaptop::hostMatchesName("ldap2.example.com", "example.com"));
    // Two letters would match half the fleet by accident.
    CHECK(!slaptop::hostMatchesName("ldap2.example.com", "l2"));
}

void testResolveInstance() {
    slaptop::FleetSnapshot fleet;
    fleet.instances.push_back(node("ldap1", {}));
    fleet.instances.push_back(node("ldap2", {}));
    fleet.instances.push_back(node("ldap3", {}));
    fleet.instances.push_back(node("ldap4", {}));

    // The regression: a provider naming the fourth node resolved to the first
    // one, because they all listen on the same port.
    CHECK(slaptop::resolveInstance(fleet, 0, "ldap://ldap4.example.com:1389") == 3);
    CHECK(slaptop::resolveInstance(fleet, 3, "ldap://ldap1.example.com:1389/") == 0);
    CHECK(slaptop::resolveInstance(fleet, 0, "ldaps://ldap2.example.com:636") == 1);

    // No host, no link: the port alone is ambiguous on purpose.
    CHECK(slaptop::resolveInstance(fleet, 0, "ldap://:1389") == -1);
    // An unknown machine is not a guess either.
    CHECK(slaptop::resolveInstance(fleet, 0, "ldap://elsewhere.example.com:1389") == -1);
    // An instance is never its own provider.
    CHECK(slaptop::resolveInstance(fleet, 0, "ldap://ldap1.example.com:1389") == -1);
}

void testSidOwner() {
    slaptop::FleetSnapshot fleet;
    fleet.instances.push_back(node("ldap1", {}));
    fleet.instances.push_back(node("ldap2", {}));
    fleet.instances.push_back(node("ldap3", {""}));
    fleet.instances.front().directory.serverIds = {
        ServerId{1, "ldap://ldap1.example.com:1389/"},
        ServerId{2, "ldap://ldap2.example.com:1389/"},
        ServerId{3, "ldap://ldap3.example.com:1389/"},
    };

    // Every instance declares the same SID list; the URL decides the owner.
    CHECK(slaptop::sidOwner(fleet, 1) == 0);
    CHECK(slaptop::sidOwner(fleet, 2) == 1);
    CHECK(slaptop::sidOwner(fleet, 3) == 2);
    CHECK(slaptop::sidOwner(fleet, 4) == -1);

    // A SID without a URL belongs to the instance that declares it.
    slaptop::FleetSnapshot local;
    local.instances.push_back(node("solo", {}));
    local.instances.front().directory.serverIds = {ServerId{7, ""}};
    CHECK(slaptop::sidOwner(local, 7) == 0);
}

void testReplicaSets() {
    slaptop::FleetSnapshot fleet;
    // Two pairs with no agreement between them, plus a proxy that forwards but
    // does not replicate.
    fleet.instances.push_back(node("ldap1", {"ldap://ldap2.example.com:1389"}));
    fleet.instances.push_back(node("ldap2", {"ldap://ldap1.example.com:1389"}));
    fleet.instances.push_back(node("ldap3", {"ldap://ldap4.example.com:1389"}));
    fleet.instances.push_back(node("ldap4", {"ldap://ldap3.example.com:1389"}));
    fleet.instances.push_back(node("proxy1", {}));

    const std::vector<int> sets = slaptop::replicaSets(fleet);
    CHECK(sets.size() == fleet.instances.size());
    CHECK(sets[0] == sets[1]);
    CHECK(sets[2] == sets[3]);
    CHECK(sets[0] != sets[2]);  // the whole point: never compared
    CHECK(sets[4] != sets[0]);
    CHECK(sets[4] != sets[2]);

    // A provider that resolves to nothing links nothing: no invented sets.
    slaptop::FleetSnapshot orphan;
    orphan.instances.push_back(node("ldap1", {"ldap://unknown.example.com:9999"}));
    orphan.instances.push_back(node("ldap2", {}));
    const std::vector<int> orphanSets = slaptop::replicaSets(orphan);
    CHECK(orphanSets[0] != orphanSets[1]);
}

}  // namespace

int main() {
    testEndpoints();
    testHostMatchesName();
    testResolveInstance();
    testSidOwner();
    testReplicaSets();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "topology checks passed\n";
    return 0;
}
