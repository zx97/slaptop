#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iostream>
#include <string>

#include "slaptop/collector/configdir.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

void writeFile(const std::string& path, const std::string& content) {
    std::ofstream out(path);
    out << content;
}

/// Builds a small cn=config tree shaped like the ones slapd writes.
void buildFixture(const std::string& root) {
    ::mkdir(root.c_str(), 0700);
    ::mkdir((root + "/cn=config").c_str(), 0700);
    ::mkdir((root + "/cn=config/olcDatabase={3}mdb").c_str(), 0700);

    writeFile(root + "/cn=config.ldif",
              "dn: cn=config\n"
              "objectClass: olcGlobal\n"
              "olcServerID: 1\n"
              "olcLogFile: /tmp/slapd.log\n");

    writeFile(root + "/cn=config/olcDatabase={1}ldap.ldif",
              "dn: olcDatabase={1}ldap\n"
              "objectClass: olcDatabaseConfig\n"
              "olcDatabase: {1}ldap\n"
              "olcSuffix: dc=example,dc=com\n"
              "olcDbURI: \"ldaps://ldap1.example.com:2636\n");

    writeFile(root + "/cn=config/olcDatabase={3}mdb.ldif",
              "dn: olcDatabase={3}mdb\n"
              "objectClass: olcDatabaseConfig\n"
              "olcDatabase: {3}mdb\n"
              "olcSuffix: dc=example,dc=com\n"
              "olcDbDirectory: /var/lib/ldap/example\n"
              "olcMultiProvider: TRUE\n"
              // LDIF folds after a trailing space (RFC 2849), exactly as slapd writes it.
              "olcSyncrepl: {0}rid=001 provider=ldaps://ldap1.example:636 \n"
              " bindmethod=simple binddn=\"cn=admin,dc=example,dc=com\" \n"
              // The index prefixes the first pair and the search base is quoted:
              // both fooled the reader once, and the agreement was then ignored.
              " searchbase=\"dc=example,dc=com\" type=refreshAndPersist\n");

    // slapd writes the overlay DN without its parent: the directory says it.
    writeFile(root + "/cn=config/olcDatabase={3}mdb/olcOverlay={0}syncprov.ldif",
              "dn: olcOverlay={0}syncprov\n"
              "objectClass: olcOverlayConfig\n"
              "olcOverlay: {0}syncprov\n");

    writeFile(root + "/cn=config/olcDatabase={3}mdb/olcOverlay={1}ppolicy.ldif",
              "dn: olcOverlay={1}ppolicy\n"
              "objectClass: olcOverlayConfig\n"
              "olcOverlay: {1}ppolicy\n");

    // Rotated copy, as slapd leaves them: must be ignored.
    ::mkdir((root + "/cn=config/olcOverlay={0}chain.bak_121833").c_str(), 0700);
    writeFile(root + "/cn=config/olcOverlay={0}chain.bak_121833/olcDatabase={0}ldap.ldif",
              "dn: olcDatabase={0}ldap\n"
              "olcDatabase: {0}ldap\n"
              "olcDbURI: ldaps://ghost.example:636\n");
}

void testParsing(const std::string& root) {
    const auto config = slaptop::collector::readDirectoryConfig(root);

    // frontend + two live databases; the .bak copy must not add a third.
    CHECK(config.databases.size() == 2);
    CHECK(config.serverId == "1");

    const auto find = [&config](const std::string& label) {
        for (const auto& database : config.databases) {
            if (database.label == label) {
                return database;
            }
        }
        return slaptop::collector::DirectoryDatabase{};
    };

    const auto proxy = find("{1}ldap");
    CHECK(proxy.backend == "ldap");
    // The trailing slash and the quoting of olcDbURI must be normalised.
    CHECK(proxy.uri == "ldaps://ldap1.example.com:2636");
    CHECK(proxy.suffix == "dc=example,dc=com");

    const auto mdb = find("{3}mdb");
    CHECK(mdb.backend == "mdb");
    CHECK(mdb.multiProvider);
    CHECK(mdb.directory == "/var/lib/ldap/example");
    CHECK(mdb.syncreplProviders.size() == 1);
    CHECK(mdb.syncreplProviders.at(0) == "ldaps://ldap1.example:636");
    CHECK(mdb.syncrepl.size() == 1);
    CHECK(mdb.syncrepl.at(0).rid == 1);
    CHECK(mdb.syncrepl.at(0).provider == "ldaps://ldap1.example:636");
    CHECK(mdb.syncrepl.at(0).searchBase == "dc=example,dc=com");
    CHECK(mdb.syncrepl.at(0).type == "refreshAndPersist");
    // Overlays are attached through their DN, in a subdirectory.
    CHECK(mdb.overlays.size() == 2);
    CHECK(mdb.overlays.at(0) == "syncprov");
    CHECK(mdb.overlays.at(1) == "ppolicy");
}

void testMissingTree() {
    const auto config = slaptop::collector::readDirectoryConfig("/nonexistent/config");
    CHECK(config.databases.empty());
    CHECK(slaptop::collector::readDirectoryConfig("").databases.empty());
}

/// The `slapd.conf` layout, used when slapd runs with `-f` instead of `-F`.
void testSlapdConf(const std::string& root) {
    const std::string path = root + "/slapd.conf";
    {
        std::ofstream out(path);
        out << "# a comment\n"
            << "include\t/etc/openldap/schema/core.schema\n"
            << "logfile /var/log/slapd/slapd.log\n"
            << "database mdb\n"
            << "suffix \"dc=example,dc=org\"\n"
            << "directory /var/lib/ldap\n"
            << "overlay ppolicy\n"
            << "database ldap\n"
            << "suffix \"dc=example,dc=com\"\n"
            << "uri ldaps://upstream.example.org:636\n"
            << "overlay chain\n";
    }
    const auto config = slaptop::collector::readSlapdConf(path);
    CHECK(config.databases.size() == 2);
    if (config.databases.size() == 2) {
        CHECK(config.databases[0].backend == "mdb");
        CHECK(config.databases[0].suffix == "dc=example,dc=org");
        CHECK(config.databases[0].directory == "/var/lib/ldap");
        CHECK(config.databases[0].overlays.size() == 1);
        CHECK(config.databases[1].backend == "ldap");
        CHECK(config.databases[1].uri == "ldaps://upstream.example.org:636");
        CHECK(config.databases[1].chainUri == "ldaps://upstream.example.org:636");
    }
    CHECK(slaptop::collector::logFileFromSlapdConf(path) == "/var/log/slapd/slapd.log");
    CHECK(slaptop::collector::logFileFromSlapdConf("/nonexistent/slapd.conf").empty());
    std::remove(path.c_str());
}

/// $LDAPCONF<NAME> is the convention this deployment already uses.
void testConfigDirFromEnvironment(const std::string& root) {
    ::setenv("LDAPCONFOPSTEST", root.c_str(), 1);
    CHECK(slaptop::collector::configDirFromEnvironment("ops-test") == root);
    CHECK(slaptop::collector::configDirFromEnvironment("absent").empty());
    ::unsetenv("LDAPCONFOPSTEST");
}

}  // namespace

int main() {
    std::string root = "/dev/shm/slaptop-cfgdir-XXXXXX";
    CHECK(::mkdtemp(root.data()) != nullptr);
    buildFixture(root);
    testParsing(root);
    testMissingTree();
    testSlapdConf(root);
    testConfigDirFromEnvironment(root);

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "configdir checks passed\n";
    return 0;
}
