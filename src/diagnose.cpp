#include "slaptop/diagnose.hpp"

#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <functional>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>
#include <string>
#include <vector>

#include "slaptop/collector/discovery.hpp"
#include "slaptop/collector/logfile.hpp"
#include "slaptop/collector/sshnode.hpp"
#ifdef SLAPTOP_WITH_LDAP
#include "slaptop/collector/ldap.hpp"
#endif

namespace slaptop {
namespace {

/// One check: a label, a verdict, and what to do when it failed.
struct Check {
    std::string label;
    bool ok{false};
    bool fatal{false};   ///< false = warning: degraded, not broken
    std::string detail;  ///< what was found
    std::string fix;     ///< what to change
};

int g_failures = 0;
int g_warnings = 0;

void report(const std::string& section) {
    std::printf("\n%s\n%s\n", section.c_str(), std::string(section.size(), '-').c_str());
}

void printCheck(const Check& check) {
    const char* mark = check.ok ? "ok   " : (check.fatal ? "FAIL " : "warn ");
    std::printf("  %s %-34s %s\n", mark, check.label.c_str(), check.detail.c_str());
    if (!check.ok) {
        if (check.fatal) {
            ++g_failures;
        } else {
            ++g_warnings;
        }
        if (!check.fix.empty()) {
            std::printf("       -> %s\n", check.fix.c_str());
        }
    }
}

std::string userName() {
    if (const passwd* entry = ::getpwuid(::geteuid()); entry != nullptr && entry->pw_name != nullptr) {
        return entry->pw_name;
    }
    if (const char* login = std::getenv("USER"); login != nullptr && *login != '\0') {
        return login;
    }
    return "?";
}

/// The Unix user running us, as slapd's EXTERNAL will see it.
std::string peerIdentity() {
    return "gidNumber=" + std::to_string(::getegid()) + "+uidNumber=" +
           std::to_string(::geteuid()) + ",cn=peercred,cn=external,cn=auth";
}

/// Target DN of an `olcAuthzRegexp` that rewrites the peer-credential identity.
///
/// This is the trap that makes an identical ACL behave differently on two
/// instances: slapd rewrites the authenticated identity *before* applying the
/// ACL, so a regexp matching the peercred DN turns it into a real DN that the
/// `by dn.base="gidNumber=…+uidNumber=…,cn=peercred,…"` rule no longer covers.
/// The result is not "insufficient access" but "No such object", which reads
/// like a missing base.
std::string peercredRewrite(const std::string& ldif) {
    // LDIF folds long lines at 76 columns with a leading space: unfold first.
    std::string unfolded;
    std::istringstream lines(ldif);
    std::string line;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.front() == ' ' && !unfolded.empty()) {
            // Continuation: drop the newline of the line being folded, then
            // append without the leading space.
            if (unfolded.back() == '\n') {
                unfolded.pop_back();
            }
            unfolded += line.substr(1) + '\n';
        } else {
            unfolded += line + '\n';
        }
    }
    std::istringstream entries(unfolded);
    while (std::getline(entries, line)) {
        if (line.rfind("olcAuthzRegexp:", 0) != 0) {
            continue;
        }
        std::vector<std::string> quoted;
        for (std::size_t i = 0; i < line.size(); ++i) {
            if (line[i] != '"') {
                continue;
            }
            const std::size_t close = line.find('"', i + 1);
            if (close == std::string::npos) {
                break;
            }
            quoted.push_back(line.substr(i + 1, close - i - 1));
            i = close;
        }
        if (quoted.size() < 2 || quoted[0].find("peercred") == std::string::npos) {
            continue;
        }
        if (quoted[1].find("peercred") != std::string::npos) {
            continue;  // the identity is kept as it is
        }
        return quoted[1];
    }
    return {};
}

/// Reads `-h` listeners and the config directory of a local instance (already
/// done by discovery, kept here for clarity of the checks).
bool hasLdapi(const Instance& instance) {
    return !collector::ldapiUri(instance).empty();
}

#ifdef SLAPTOP_WITH_LDAP
/// Opens the instance over ldapi and reports what each subtree answers.
std::vector<Check> checkDirectory(const std::string& uri,
                                  const std::function<std::string()>& readGlobal) {
    std::vector<Check> checks;
    Check check;
    check.label = "ldap over ldapi (EXTERNAL)";
    std::string error;
    auto client = LdapClient::open(uri, "EXTERNAL", "", &error);
    if (!client) {
        check.ok = false;
        check.fatal = false;
        check.detail = error.empty() ? "bind refused" : error;
        check.fix = "the Unix user must be the one running slapd, or be mapped by "
                    "olcAuthzRegexp with read access on cn=config";
        checks.push_back(check);
        return checks;
    }
    check.ok = true;
    check.detail = "bind ok (" + peerIdentity() + ")";
    checks.push_back(check);

    // cn=monitor: what the counters and databases come from.
    if (auto monitor = client->fetchMonitor(); monitor) {
        Check sub;
        sub.label = "cn=monitor";
        sub.ok = true;
        sub.detail = std::to_string(monitor->raw.size()) + " entries, " +
                     std::to_string(monitor->databases.size()) + " databases";
        checks.push_back(sub);
    } else {
        Check sub;
        sub.label = "cn=monitor";
        sub.detail = client->lastError();
        sub.fix = "cn=monitor is world-readable with any authenticated bind; if this "
                  "fails, an ACL on cn=monitor blocks it";
        checks.push_back(sub);
    }

    // cn=config: architecture, overlays, log path.
    if (auto config = client->fetchLogConfig(); config) {
        Check sub;
        sub.label = "cn=config (log path)";
        sub.detail = config->path + "   format " + config->format;
        if (config->path.empty()) {
            // Readable, but nothing says where the log goes: the Behaviour
            // tab and the per-connection binds stay empty for that reason.
            sub.ok = false;
            sub.fatal = false;
            sub.detail = "readable, but olcLogFile is not set (logging to syslog?)";
            sub.fix = "set olcLogFile (and olcLogLevel stats/acl) so the Behaviour tab and "
                      "the binds per connection can be read";
        } else {
            sub.ok = true;
        }
        checks.push_back(sub);
    } else {
        Check sub;
        sub.label = "cn=config";
        sub.detail = "not readable (" + client->lastError() + ")";
        sub.fix = "cn=config is granted to the slapd user and to uid 0; run slaptop as "
                  "that user, or add an olcAuthzRegexp mapping with read access";
        if (readGlobal) {
            const std::string rewrite = peercredRewrite(readGlobal());
            if (!rewrite.empty()) {
                sub.detail = "hidden: EXTERNAL rewritten to " + rewrite;
                sub.fix = "an olcAuthzRegexp replaces your peer-credential identity with that "
                          "DN before the ACL is applied, so the rule naming "
                          "gidNumber=...+uidNumber=...,cn=peercred does not match; add that "
                          "DN to olcAccess on olcDatabase={0}config,cn=config, or restrict "
                          "the regexp";
            }
        }
        checks.push_back(sub);
    }
    return checks;
}
#endif

void checkLocalInstance(const Instance& instance) {
    std::printf("\n  instance %s (pid %ld)\n", instance.name.c_str(),
                static_cast<long>(instance.pid));

    Check proc;
    proc.label = "/proc/<pid> readable";
    proc.ok = ::access(("/proc/" + std::to_string(instance.pid) + "/stat").c_str(), R_OK) == 0;
    proc.detail = proc.ok ? "cpu, memory, threads, fds, ports" : "permission denied";
    proc.fix = "run slaptop as the user running slapd (" + userName() +
               " cannot read /proc/" + std::to_string(instance.pid) + ")";
    printCheck(proc);

    // Configuration files: the fallback that works when cn=config refuses.
    // Order matters and is the same as the engine's.
    Check configDir;
    configDir.label = "configuration files";
    configDir.fatal = false;
    const std::string fromEnv =
        instance.configDir.empty() ? collector::configDirFromEnvironment(instance.name)
                                   : std::string();
    if (!instance.configDir.empty()) {
        configDir.ok = ::access((instance.configDir + "/cn=config.ldif").c_str(), R_OK) == 0;
        configDir.detail = "-F " + instance.configDir;
    } else if (!fromEnv.empty()) {
        configDir.ok = ::access((fromEnv + "/cn=config.ldif").c_str(), R_OK) == 0;
        configDir.detail = "$LDAPCONF" + instance.name + " " + fromEnv;
    } else if (!instance.configFile.empty()) {
        configDir.ok = ::access(instance.configFile.c_str(), R_OK) == 0;
        configDir.detail = "-f " + instance.configFile;
    } else {
        configDir.detail = "no -F, no -f and no $LDAPCONF<NAME>";
    }
    configDir.fix = "the files give the architecture, the overlays and the log path even "
                    "when cn=config is out of reach; point $LDAPCONF" +
                    instance.name + " at the slapd.d directory";
    printCheck(configDir);

    Check ldapi;
    ldapi.label = "ldapi:// listener";
    ldapi.ok = hasLdapi(instance);
    ldapi.detail = ldapi.ok ? collector::ldapiUri(instance) : "none in -h";
    ldapi.fatal = false;
    ldapi.fix = "start slapd with -h \"ldapi://%2Fvar%2Frun%2Fopenldap%2Fldapi ldap:///\"";
    printCheck(ldapi);

#ifdef SLAPTOP_WITH_LDAP
    if (ldapi.ok) {
        const auto reader = [&instance] {
            std::string text;
            std::ifstream in(instance.configDir + "/cn=config.ldif");
            std::ostringstream buffer;
            buffer << in.rdbuf();
            return buffer.str();
        };
        for (const Check& check : checkDirectory(collector::ldapiUri(instance), reader)) {
            printCheck(check);
        }
    }
#endif
}

std::string shellLine(const collector::SshNode& node, const std::string& command,
                      bool& ok) {
    std::string out;
    std::string error;
    ok = node.run(command, out, error);
    if (!ok) {
        return error;
    }
    while (!out.empty() && (out.back() == '\n' || out.back() == '\r')) {
        out.pop_back();
    }
    // One line per check: a multi-line answer would break the alignment.
    for (char& c : out) {
        if (c == '\n' || c == '\r' || c == '\t') {
            c = ' ';
        }
    }
    while (out.find("  ") != std::string::npos) {
        out.replace(out.find("  "), 2, " ");
    }
    return out;
}

void checkNode(const collector::SshNodeSpec& spec) {
    const std::string label = spec.name.empty() ? spec.host : spec.name;
    std::printf("\n  node %s (%s)\n", label.c_str(),
                spec.origin.empty() ? "node" : spec.origin.c_str());

    collector::SshNode node(spec);

    Check transport;
    transport.label = "ssh transport";
    bool ok = false;
    const std::string who = shellLine(node, "id -un 2>/dev/null; id -u 2>/dev/null", ok);
    transport.ok = ok && !who.empty();
    // A node that cannot be reached is not a degraded view: nothing at all
    // comes from it, so it counts as a failure.
    transport.fatal = true;
    transport.detail = transport.ok ? "reaches " + spec.host : who;
    transport.fix = "register the key of " + userName() +
                    " in the remote ~/.ssh/authorized_keys; BatchMode means no password "
                    "prompt is possible";
    printCheck(transport);
    if (!transport.ok) {
        return;
    }

    Check identity;
    identity.label = "remote Unix identity";
    identity.ok = true;
    identity.detail = who;
    identity.fatal = false;
    printCheck(identity);

    Check cpus;
    cpus.label = "cpu count and meminfo";
    bool cpusOk = false;
    const std::string cpusText =
        shellLine(node, "getconf _NPROCESSORS_ONLN 2>/dev/null; "
                        "awk '/^MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null", cpusOk);
    cpus.ok = cpusOk && !cpusText.empty();
    cpus.detail = cpusText;
    cpus.fatal = false;
    cpus.fix = "the CPU and memory denominators come from /proc/meminfo";
    printCheck(cpus);

    std::string error;
    std::vector<Instance> found = node.discoverInstances(error);
    Check discovery;
    discovery.label = "slapd instances discovered";
    discovery.ok = !found.empty();
    discovery.detail = found.empty() ? (error.empty() ? "none found" : error)
                                     : std::to_string(found.size()) + " instance(s)";
    discovery.fix = "requires `ps -eo pid=,args=` and a process named slapd";
    printCheck(discovery);

    for (const Instance& instance : found) {
        std::printf("\n  instance %s (pid %ld, node %s)\n", instance.name.c_str(),
                    static_cast<long>(instance.pid), label.c_str());

        Check proc;
        proc.label = "remote /proc/<pid> readable";
        bool procOk = false;
        const std::string procText =
            shellLine(node, "head -1 /proc/" + std::to_string(instance.pid) +
                                "/stat 2>/dev/null | cut -c1-20", procOk);
        proc.ok = procOk && !procText.empty();
        proc.detail = proc.ok ? "readable" : "permission denied";
        proc.fix = "the SSH account must be slapd's user (or root) to read /proc and the "
                   "ldapi socket";
        printCheck(proc);

        Check files;
        files.label = "remote configuration files";
        files.fatal = false;
        bool filesOk = false;
        if (!instance.configDir.empty()) {
            const std::string seen = shellLine(
                node, "test -r " + instance.configDir + "/cn=config.ldif && echo yes", filesOk);
            files.ok = filesOk && seen == "yes";
            files.detail = "-F " + instance.configDir;
        } else if (!instance.configFile.empty()) {
            const std::string seen =
                shellLine(node, "test -r " + instance.configFile + " && echo yes", filesOk);
            files.ok = filesOk && seen == "yes";
            files.detail = "-f " + instance.configFile;
        } else {
            files.detail = "no -F and no -f on the command line";
        }
        files.fix = "the files are read when cn=config refuses; they must be readable by the "
                    "SSH account (they are tarred, not parsed remotely)";
        printCheck(files);

        Check ldapi;
        ldapi.label = "ldapi:// listener";
        ldapi.ok = hasLdapi(instance);
        ldapi.detail = ldapi.ok ? collector::ldapiUri(instance) : "none in -h";
        ldapi.fatal = false;
        ldapi.fix = "start the remote slapd with an ldapi listener";
        printCheck(ldapi);

        if (ldapi.ok) {
            const std::string remote = [&instance] {
                const std::string uri = collector::ldapiUri(instance);
                // ldapi://%2Frun%2Fldapi -> /run/ldapi
                std::string path;
                const std::string encoded = uri.substr(std::strlen("ldapi://"));
                for (std::size_t i = 0; i < encoded.size(); ++i) {
                    if (encoded[i] == '%' && i + 2 < encoded.size()) {
                        path.push_back(static_cast<char>(std::strtol(
                            encoded.substr(i + 1, 2).c_str(), nullptr, 16)));
                        i += 2;
                    } else {
                        path.push_back(encoded[i]);
                    }
                }
                return path;
            }();
            std::string forwardError;
            const std::string local = node.forwardSharedSocket(instance.name, remote,
                                                               forwardError);
            Check forward;
            forward.label = "ldapi socket forwarded";
            forward.ok = !local.empty();
            forward.detail = forward.ok ? "ok" : forwardError;
            forward.fix = "AllowStreamLocalForwarding in sshd_config, and the SSH account "
                          "must be able to connect to " + remote;
            printCheck(forward);

#ifdef SLAPTOP_WITH_LDAP
            if (forward.ok) {
                const auto reader = [&node, &instance] {
                    // Raw text: shellLine() flattens newlines, and the parser
                    // needs one logical line per directive.
                    std::string text;
                    std::string readError;
                    node.run("cat " + instance.configDir + "/cn=config.ldif 2>/dev/null",
                             text, readError);
                    return text;
                };
                for (const Check& check : checkDirectory(local, reader)) {
                    printCheck(check);
                }
            }
#endif
        }
    }
}

}  // namespace

int diagnose(const EngineOptions& options, const std::string& configPath) {
    std::printf("slaptop %s -- diagnose\n", SLAPTOP_VERSION);

    report("environment");
    Check user;
    user.label = "user / peer identity";
    user.ok = true;
    user.detail = userName() + "  " + peerIdentity();
    printCheck(user);

    Check config;
    config.label = "configuration file";
    config.ok = !configPath.empty() && ::access(configPath.c_str(), R_OK) == 0;
    config.fatal = false;
    config.detail = configPath.empty() ? "none"
                     : (config.ok ? configPath : configPath + "  (absent, defaults used)");
    config.fix = "the file is optional: defaults are used when it is absent";
    printCheck(config);

    const std::vector<Instance> local = collector::discoverInstances();
    Check discovery;
    discovery.label = "local slapd instances";
    discovery.ok = true;
    discovery.fatal = false;
    discovery.detail = local.empty() ? "none on this host" : std::to_string(local.size());
    printCheck(discovery);

    if (!local.empty()) {
        for (const Instance& instance : local) {
            checkLocalInstance(instance);
        }
    }

    for (const collector::SshNodeSpec& spec : options.nodes) {
        checkNode(spec);
    }

    for (const RemoteTarget& target : options.remoteTargets) {
        std::printf("\n  target %s\n",
                    target.name.empty() ? target.uri.c_str() : target.name.c_str());
        Check reach;
        reach.label = "ldap reachable";
        reach.fatal = false;
        std::string error;
#ifdef SLAPTOP_WITH_LDAP
        auto client = LdapClient::open(target.uri, target.bindDn, target.password,
                                                  &error, target.insecureTls,
                                                  target.startTls);
        reach.ok = client.has_value();
        reach.detail = reach.ok ? "connected" : error;
        reach.fix = "a plain ldap:// listener usually requires TLS (Confidentiality "
                    "required); use ldaps:// and insecure=yes for a self-signed host";
        printCheck(reach);
        if (client) {
            Check monitor;
            monitor.label = "cn=monitor";
            monitor.fatal = false;
            if (auto snapshot = client->fetchMonitor(); snapshot) {
                monitor.ok = true;
                monitor.detail = std::to_string(snapshot->raw.size()) + " entries";
            } else {
                monitor.detail = client->lastError();
                monitor.fix = "anonymous cn=monitor is normally readable; a bind= may be "
                              "needed";
            }
            printCheck(monitor);
        }
        Check procTarget;
        procTarget.label = "process data (/proc)";
        procTarget.ok = false;
        procTarget.fatal = false;
        procTarget.detail = "unavailable over ldap://";
        procTarget.fix = "only an SSH node gives CPU, memory, log and cn=config; a plain "
                         "ldaps:// target is LDAP-only";
        printCheck(procTarget);
#else
        (void)error;
        reach.detail = "built without LDAP support";
        printCheck(reach);
#endif
    }

    if (local.empty() && options.nodes.empty() && options.remoteTargets.empty()) {
        std::printf("\n  nothing configured: give a node, or run slaptop on a slapd host\n");
    }

    std::printf("\n%d failed, %d warning(s)\n", g_failures, g_warnings);
    return g_failures == 0 ? 0 : 1;
}

}  // namespace slaptop
