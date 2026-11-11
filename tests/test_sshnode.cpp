#include <unistd.h>

#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "slaptop/collector/sshnode.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

using slaptop::collector::SshNodeSpec;
using slaptop::collector::loadNodeFile;
using slaptop::collector::nodeSelectsInstance;
using slaptop::collector::parseNodeSpec;

void testCompression() {
    SshNodeSpec spec;
    std::string error;
    CHECK(parseNodeSpec("lab compress=on", spec, error));
    CHECK(spec.compress);
    CHECK(parseNodeSpec("lab", spec, error));
    CHECK(!spec.compress);
    CHECK(!parseNodeSpec("lab compress=maybe", spec, error));
    CHECK(error.find("on/off") != std::string::npos);
}

void testPlainHost() {
    SshNodeSpec spec;
    std::string error;
    CHECK(parseNodeSpec("ldap1.example.com", spec, error));
    CHECK(spec.host == "ldap1.example.com");
    CHECK(spec.user.empty());
    CHECK(spec.keyPath.empty());
    CHECK(spec.port == 0);
    CHECK(spec.name.empty());
}

void testEveryOption() {
    SshNodeSpec spec;
    std::string error;
    CHECK(parseNodeSpec("deploy@example.com key=/etc/slaptop/id_ed25519 port=2222 name=dev instances=proxy,provider",
                        spec, error));
    CHECK(spec.user == "deploy");
    CHECK(spec.host == "example.com");
    CHECK(spec.keyPath == "/etc/slaptop/id_ed25519");
    CHECK(spec.port == 2222);
    CHECK(spec.name == "dev");
    CHECK(nodeSelectsInstance(spec, "proxy"));
    CHECK(nodeSelectsInstance(spec, "provider"));
    CHECK(!nodeSelectsInstance(spec, "replica"));
}

void testRefusedInput() {
    SshNodeSpec spec;
    std::string error;
    CHECK(!parseNodeSpec("", spec, error));
    CHECK(!error.empty());

    error.clear();
    CHECK(!parseNodeSpec("ldap1.example.com nonsense", spec, error));
    CHECK(error.find("key=value") != std::string::npos);

    error.clear();
    CHECK(!parseNodeSpec("ldap1.example.com port=abc", spec, error));
    CHECK(error.find("not a number") != std::string::npos);

    // A typo must be refused, not silently ignored: it would fall back to
    // another host's key or to the default port.
    error.clear();
    CHECK(!parseNodeSpec("ldap1.example.com keey=/tmp/k", spec, error));
    CHECK(error.find("unknown node option") != std::string::npos);
}

void testSelection() {
    SshNodeSpec spec;
    spec.host = "lab";
    CHECK(nodeSelectsInstance(spec, "anything"));  // no list: every instance
    spec.instances = "proxy";
    CHECK(nodeSelectsInstance(spec, "proxy"));
    CHECK(!nodeSelectsInstance(spec, "pc2"));
    spec.instances = " proxy , provider ";
    CHECK(nodeSelectsInstance(spec, "proxy"));
    CHECK(nodeSelectsInstance(spec, "provider"));
    CHECK(!nodeSelectsInstance(spec, "replica"));
}

void testNodeFile() {
    const std::string path = "/dev/shm/slaptop-nodes-XXXXXX";
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%s", path.c_str());
    const int fd = ::mkstemp(buffer);
    CHECK(fd >= 0);
    if (fd < 0) {
        return;
    }
    ::close(fd);
    {
        std::ofstream out(buffer);
        out << "# nodes of the lab\n"
            << "\n"
            << "deploy@example.com name=lab\n"
            << "deploy@example.com key=/etc/slaptop/id_ed25519 port=2222\n";
    }
    std::vector<SshNodeSpec> specs;
    std::string error;
    CHECK(loadNodeFile(buffer, specs, error));
    CHECK(specs.size() == 2);
    if (specs.size() == 2) {
        CHECK(specs[0].name == "lab");
        CHECK(specs[1].port == 2222);
    }
    ::unlink(buffer);

    specs.clear();
    CHECK(!loadNodeFile("/nonexistent/nodes", specs, error));
}

}  // namespace

int main() {
    testCompression();
    testPlainHost();
    testEveryOption();
    testRefusedInput();
    testSelection();
    testNodeFile();
    if (g_failures == 0) {
        std::cout << "test_sshnode: all checks passed\n";
        return 0;
    }
    std::cerr << "test_sshnode: " << g_failures << " failure(s)\n";
    return 1;
}
