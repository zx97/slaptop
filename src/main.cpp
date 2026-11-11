#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <execinfo.h>

#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "slaptop/config.hpp"
#include "slaptop/embedded.hpp"
#include "slaptop/diagnose.hpp"
#include "slaptop/engine.hpp"
#include "slaptop/ldaprc.hpp"
#include "slaptop/model/metrics.hpp"

#ifdef SLAPTOP_WITH_LDAP
#include "slaptop/collector/ldap.hpp"
#endif

#ifdef SLAPTOP_WITH_TUI
#include "slaptop/ui/tui.hpp"
#endif

namespace {

constexpr const char* kProgramName = "slaptop";
constexpr const char* kVersion = SLAPTOP_VERSION;
/// Revision the binary was built from, "unknown" for a source tarball.
constexpr const char* kCommit = SLAPTOP_COMMIT;

void printUsage(std::ostream& out) {
    out << "usage: " << kProgramName << " [options]\n"
        << "\n"
        << "  --once              collect one round, print it and exit\n"
        << "  --watch <seconds>   plain-text refresh loop at the given period\n"
        << "  --json              emit JSON instead of a table\n"
        << "  --jsonl             one JSON object per instance per line\n"
        << "  --tui               force the notcurses interface\n"
        << "  --probe-pixels      report the terminal's graphics support and exit\n"
        << "  --no-tui            force plain text (default when stdout is a pipe)\n"
        << "  --interval <sec>    collection period (default 1.0)\n"
        << "  --ldap-interval <s> cn=monitor period (default 2.0)\n"
        << "  --duration <sec>    stop the --watch loop after <sec>\n"
        << "  --uri <spec>        watch a remote instance: URI plus optional\n"
        << "                      bind=DN password-file=PATH starttls=yes insecure=yes\n"
        << "  --uri-file <path>   one such spec per line (# comments allowed)\n"
        << "  --node <spec>       remote host over SSH: [user@]host key=PATH port=N\n"
        << "                      name=LABEL instances=a,b  (four nodes at most)\n"
        << "  --node-file <path>  one such spec per line (# comments allowed)\n"
        << "  --group <name>      use the [group <name>] section of the config\n"
        << "  --list-groups       list the groups defined in the config\n"
        << "  --insecure          accept self-signed TLS certificates\n"
        << "  --config <path>     configuration file (default " << slaptop::Config::defaultPath()
        << ")\n"
#ifdef SLAPTOP_WITH_LDAP
        << "  --ldap <uri>        dump cn=monitor for the given LDAP URI\n"
        << "  --bind <dn>         bind DN (EXTERNAL selects SASL peer credentials)\n"
        << "  --bind-password-file <path>  read the bind password from a file\n"
        << "  --license, -l       print the licence (AGPL v3) and exit\n"
        << "  --doc, -D           print the documentation and exit\n"
#endif
        << "  --help              show this help\n"
        << "  --version           show version\n";
}

std::string humanBytes(std::uint64_t bytes) {
    static constexpr const char* units[] = {"B", "K", "M", "G", "T"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    out << std::fixed << std::setprecision(unit == 0 ? 0 : 1) << value << units[unit];
    return out.str();
}

/// Reads a URI list: one URI per line, blank lines and # comments ignored.
std::string readPasswordFile(const std::string& path, std::string& error);

/// Splits a target specification on spaces, keeping double-quoted values
/// together so a bind DN can contain spaces:
///   ldaps://host:636 bind="cn=monitor,ou=services,dc=example" starttls=no
std::vector<std::string> splitSpec(const std::string& spec) {
    std::vector<std::string> tokens;
    std::string current;
    bool quoted = false;
    for (const char c : spec) {
        if (c == '"') {
            quoted = !quoted;
            continue;
        }
        if (!quoted && (c == ' ' || c == '\t')) {
            if (!current.empty()) {
                tokens.push_back(std::move(current));
                current.clear();
            }
            continue;
        }
        current.push_back(c);
    }
    if (!current.empty()) {
        tokens.push_back(std::move(current));
    }
    return tokens;
}

/// Builds one remote target.  Unknown keys are refused: a typo must not fall
/// back silently to the global credentials, which is how a bind "mysteriously"
/// fails against one server only.
bool parseTarget(const std::string& spec, std::string& error, slaptop::RemoteTarget& target) {
    const std::vector<std::string> tokens = splitSpec(spec);
    if (tokens.empty()) {
        error = "empty target";
        return false;
    }
    target.uri = tokens.front();
    if (target.uri.find("://") == std::string::npos) {
        error = "target '" + target.uri + "' is not an LDAP URI";
        return false;
    }
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        const std::size_t equals = tokens[i].find('=');
        if (equals == std::string::npos) {
            error = "target option '" + tokens[i] + "' is not key=value";
            return false;
        }
        const std::string key = tokens[i].substr(0, equals);
        const std::string value = tokens[i].substr(equals + 1);
        if (key == "bind") {
            target.bindDn = value;
        } else if (key == "name") {
            target.name = value;
        } else if (key == "password") {
            target.password = value;
        } else if (key == "password-file") {
            std::string readError;
            target.password = readPasswordFile(value, readError);
            if (!readError.empty()) {
                error = readError;
                return false;
            }
        } else if (key == "starttls") {
            target.startTls = value == "yes" || value == "true" || value == "1" ||
                              value == "on";
        } else if (key == "insecure") {
            target.insecureTls = value == "yes" || value == "true" || value == "1" ||
                                 value == "on";
        } else {
            error = "unknown target option '" + key + "'";
            return false;
        }
    }
    return true;
}

bool loadUriFile(const std::string& path, std::vector<slaptop::RemoteTarget>& out,
                 std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot read " + path;
        return false;
    }
    std::string line;
    int number = 0;
    while (std::getline(in, line)) {
        ++number;
        const std::size_t start = line.find_first_not_of(" \t\r");
        if (start == std::string::npos || line[start] == '#') {
            continue;
        }
        std::string value = line.substr(start);
        while (!value.empty() &&
               (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
            value.pop_back();
        }
        slaptop::RemoteTarget target;
        std::string parseError;
        if (!parseTarget(value, parseError, target)) {
            error = path + ":" + std::to_string(number) + ": " + parseError;
            return false;
        }
        out.push_back(std::move(target));
    }
    return true;
}

std::string jsonEscape(const std::string& text) {
    std::string out;
    out.reserve(text.size() + 8);
    for (const char c : text) {
        switch (c) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\t':
                out += "\\t";
                break;
            default:
                out += c;
        }
    }
    return out;
}

/// Connection parameters worth reporting: what the bind actually uses, where
/// the password came from, and the ldaprc files libldap applies by itself.
struct ConnectionReport {
    std::string bindMode{"anonymous"};
    std::string passwordSource;
    std::vector<std::string> ldapRcFiles;
};

ConnectionReport connection;

std::string instanceJson(const slaptop::InstanceMetrics& metrics) {
    std::ostringstream out;
    out << '{'
        << "\"name\":\"" << jsonEscape(metrics.instance.name) << "\","
        << "\"node\":\"" << jsonEscape(metrics.instance.nodeLabel) << "\","
        << "\"pid\":" << metrics.instance.pid << ','
        << "\"health\":\"" << slaptop::healthLabel(metrics.health) << "\","
        << "\"connection\":{\"bind\":\""
        << jsonEscape(metrics.instance.bindDn.empty() ? connection.bindMode
                                                      : metrics.instance.bindDn)
        << "\",\"starttls\":" << (metrics.instance.startTls ? "true" : "false")
        << ",\"password\":\"" << jsonEscape(connection.passwordSource) << "\",\"ldaprc\":[";
    {
        bool firstRc = true;
        for (const std::string& file : connection.ldapRcFiles) {
            out << (firstRc ? "" : ",") << '"' << jsonEscape(file) << '"';
            firstRc = false;
        }
    }
    out << "]},"
        << "\"cpuPercent\":" << metrics.proc.cpuPercent << ','
        << "\"cpuCount\":" << metrics.proc.cpuCount << ','
        << "\"cpuCapacityPercent\":"
        << 100 * metrics.proc.cpuCount << ','
        << "\"memTotalBytes\":" << metrics.proc.memTotalBytes << ','
        << "\"memAvailableBytes\":" << metrics.proc.memAvailableBytes << ','
        << "\"threads\":" << metrics.proc.numThreads << ','
        << "\"rssBytes\":" << metrics.proc.rssBytes << ','
        << "\"connectionsTotal\":" << (metrics.hasMonitor ? metrics.monitor.connectionsTotal : 0)
        << ','
        << "\"connectionsCurrent\":"
        << (metrics.hasMonitor ? metrics.monitor.connectionsCurrent : 0) << ','
        << "\"opsInitiated\":" << (metrics.hasMonitor ? metrics.monitor.opsInitiated : 0) << ','
        << "\"monitorErrors\":[";
    {
        bool firstError = true;
        if (metrics.hasMonitor) {
            for (const auto& error : metrics.monitor.errors) {
                out << (firstError ? "" : ",") << '"' << jsonEscape(error) << '"';
                firstError = false;
            }
        }
    }
    out << "],"
        << "\"connectionsListed\":"
        << (metrics.hasMonitor ? metrics.monitor.connections.size() : 0) << ','
        << "\"uptimeSeconds\":" << (metrics.hasMonitor ? metrics.monitor.uptimeSeconds : 0)
        << ','
        << "\"newestCsn\":\"" << jsonEscape(metrics.replication.newestCsn) << "\","
        << "\"lagSeconds\":" << metrics.replication.lagSeconds << ','
        << "\"logPath\":\"" << jsonEscape(metrics.log.path) << "\","
        << "\"logErrors\":" << metrics.log.errors << ','
        << "\"behavior\":{"
        << "\"available\":" << (metrics.behavior.available ? "true" : "false") << ','
        << "\"enoughTraffic\":" << (metrics.behavior.enoughTraffic ? "true" : "false") << ','
        << "\"windowSeconds\":" << metrics.behavior.windowSeconds << ','
        << "\"logLevel\":\"" << jsonEscape(metrics.behavior.logLevel) << "\","
        << "\"searches\":" << metrics.behavior.searches << ','
        << "\"slowSearches\":" << metrics.behavior.slowSearches << ','
        << "\"etimeSeconds\":"
        << static_cast<double>(metrics.behavior.totals.etimeNs) / 1e9 << ','
        << "\"hogs\":[";
    {
        bool firstHog = true;
        for (const auto& hog : metrics.behavior.hogs) {
            out << (firstHog ? "" : ",") << "{\"account\":\"" << jsonEscape(hog.account)
                << "\",\"family\":\"" << jsonEscape(hog.family) << "\",\"ops\":"
                << hog.counters.ops << ",\"etimeSeconds\":" << hog.etimeSeconds
                << ",\"averageSeconds\":" << hog.averageSeconds
                << ",\"sharePercent\":" << hog.sharePercent << '}';
            firstHog = false;
        }
    }
    out << "],\"accounts\":[";
    {
        bool firstAccount = true;
        for (const auto& account : metrics.behavior.accounts) {
            out << (firstAccount ? "" : ",") << "{\"account\":\"" << jsonEscape(account.account)
                << "\",\"ops\":" << account.counters.ops << ",\"etimeSeconds\":"
                << account.etimeSeconds << ",\"averageSeconds\":" << account.averageSeconds
                << ",\"sharePercent\":" << account.sharePercent << '}';
            firstAccount = false;
        }
    }
    out << "],\"families\":[";
    {
        bool firstFamily = true;
        for (const auto& family : metrics.behavior.families) {
            out << (firstFamily ? "" : ",") << "{\"account\":\"" << jsonEscape(family.account)
                << "\",\"family\":\"" << jsonEscape(family.family) << "\",\"slow\":"
                << (family.slow ? "true" : "false") << ",\"ops\":" << family.counters.ops
                << ",\"etimeSeconds\":" << family.etimeSeconds
                << ",\"averageSeconds\":" << family.averageSeconds
                << ",\"sharePercent\":" << family.sharePercent << '}';
            firstFamily = false;
        }
    }
    out << "]},"
        << "\"alerts\":[";
    {
        bool firstAlert = true;
        for (const auto& alert : metrics.alerts) {
            const char* severity = alert.severity == slaptop::collector::AlertSeverity::Critical
                                       ? "critical"
                                       : (alert.severity == slaptop::collector::AlertSeverity::Warning
                                              ? "warning"
                                              : "info");
            out << (firstAlert ? "" : ",") << "{\"type\":\"lmdb-map\",\"severity\":\""
                << severity << "\",\"database\":\"" << jsonEscape(alert.label)
                << "\",\"mapPercent\":" << alert.usagePercent << ",\"hoursToFull\":"
                << alert.hoursToFull << ",\"message\":\"" << jsonEscape(alert.message)
                << "\",\"detail\":\"" << jsonEscape(alert.detail)
                << "\",\"suggestion\":\"" << jsonEscape(alert.suggestion) << "\"}";
            firstAlert = false;
        }
    }
    out << "],"
        << "\"error\":\"" << jsonEscape(metrics.error) << "\","
        << "\"ioDisks\":[";
    {
        bool firstDisk = true;
        for (const auto& disk : metrics.io.disks) {
            out << (firstDisk ? "" : ",") << "{\"for\":\"" << jsonEscape(disk.label)
                << "\",\"path\":\"" << jsonEscape(disk.path) << "\",\"device\":\""
                << jsonEscape(disk.device) << "\",\"apparent\":"
                << static_cast<unsigned long long>(disk.totalBytes - disk.freeBytes)
                << ",\"free\":" << static_cast<unsigned long long>(disk.freeBytes) << "}";
            firstDisk = false;
        }
    }
    out << "],"
        << "\"limits\":{\"available\":" << (metrics.limits.available ? "true" : "false")
        << ",\"fdsOpen\":" << metrics.limits.fdsOpen
        << ",\"fdsLimit\":" << metrics.limits.fdsLimit
        << ",\"systemFilesAllocated\":" << metrics.limits.systemFilesAllocated
        << ",\"systemFilesMax\":" << metrics.limits.systemFilesMax
        << ",\"portFirst\":" << metrics.limits.portFirst
        << ",\"portLast\":" << metrics.limits.portLast
        << ",\"portsInUse\":" << metrics.limits.portsInUse
        << ",\"hostPortsInUse\":" << metrics.limits.hostPortsInUse
        << ",\"timeWait\":" << metrics.limits.timeWait
        << ",\"hostTimeWait\":" << metrics.limits.hostTimeWait << "},"
        << "\"dbFiles\":[";
    {
        bool firstFile = true;
        for (const auto& file : metrics.dbFiles) {
            out << (firstFile ? "" : ",") << "{\"db\":\"" << jsonEscape(file.label)
                << "\",\"path\":\"" << jsonEscape(file.path) << "\",\"apparent\":"
                << static_cast<unsigned long long>(file.apparentBytes) << ",\"real\":"
                << static_cast<unsigned long long>(file.allocatedBytes) << "}";
            firstFile = false;
        }
    }
    out << "],"
        << "\"overlayDatabases\":[";
    {
        bool firstOverlay = true;
        for (const auto& database : metrics.directory.overlayDatabases) {
            out << (firstOverlay ? "" : ",") << "{\"overlay\":\""
                << jsonEscape(database.overlay) << "\",\"directory\":\""
                << jsonEscape(database.directory) << "\"}";
            firstOverlay = false;
        }
    }
    out << "],"
        << "\"databases\":[";
    bool firstDatabase = true;
    for (const auto& database : metrics.directory.databases) {
        out << (firstDatabase ? "" : ",") << "{\"backend\":\"" << jsonEscape(database.backend)
            << "\",\"label\":\"" << jsonEscape(database.label) << "\",\"suffix\":\""
            << jsonEscape(database.suffix) << "\",\"uri\":\"" << jsonEscape(database.uri)
            << "\",\"overlays\":[";
        for (std::size_t index = 0; index < database.overlays.size(); ++index) {
            out << (index == 0 ? "" : ",") << '"' << jsonEscape(database.overlays[index]) << '"';
        }
        out << "],\"cache\":{\"size\":" << database.cacheSize << ",\"free\":"
            << database.cacheFree << ",\"pcache\":\"" << jsonEscape(database.pcacheSpec)
            << "\"}}";
        firstDatabase = false;
    }
    out << "],\"lloadTiers\":[";
    bool firstTier = true;
    for (const auto& tier : metrics.monitor.lloadTiers) {
        out << (firstTier ? "" : ",") << "{\"name\":\"" << jsonEscape(tier.name)
            << "\",\"servers\":[";
        for (std::size_t index = 0; index < tier.servers.size(); ++index) {
            const auto& server = tier.servers[index];
            out << (index == 0 ? "" : ",") << "{\"name\":\"" << jsonEscape(server.name)
                << "\",\"uri\":\"" << jsonEscape(server.uri)
                << "\",\"active\":" << server.activeConnections
                << ",\"pending\":" << server.pendingConnections
                << ",\"received\":" << server.receivedOps
                << ",\"completed\":" << server.completedOps
                << ",\"failed\":" << server.failedOps << '}';
        }
        out << "]}";
        firstTier = false;
    }
    out << ']' << '}';
    return out.str();
}

/// Prints what the engine wants to say once the dashboard is gone: duplicates
/// it discarded and hosts it could not read.  Nothing is printed when the run
/// had nothing to report, so a healthy start stays silent.
void printRunReport(const std::vector<std::string>& notes) {
    if (notes.empty()) {
        return;
    }
    std::cerr << kProgramName << ": " << notes.size() << " note(s) from this run:\n";
    for (const std::string& note : notes) {
        std::cerr << "  - " << note << '\n';
    }
}

void printFleet(const slaptop::FleetSnapshot& fleet, bool json, bool jsonl) {
    if (jsonl) {
        for (const slaptop::InstanceMetrics& metrics : fleet.instances) {
            std::cout << instanceJson(metrics) << '\n';
        }
        std::cout.flush();
        return;
    }
    if (json) {
        std::cout << "[\n";
        for (std::size_t i = 0; i < fleet.instances.size(); ++i) {
            std::cout << "  " << instanceJson(fleet.instances[i])
                      << (i + 1 == fleet.instances.size() ? "\n" : ",\n");
        }
        std::cout << "]\n";
        return;
    }

    if (fleet.instances.empty()) {
        std::cout << "no slapd instance found\n";
        return;
    }

    std::cout << std::left << std::setw(8) << "NAME" << std::right << std::setw(7) << "PID"
              << ' ' << std::left << std::setw(9) << "STATE" << std::right << std::setw(5)
              << "THR" << std::setw(12) << "CPU%/cap" << std::setw(8) << "RSS" << std::setw(7)
              << "SYS%"
              << std::setw(11) << "CONN" << std::setw(8) << "OPS/s" << std::setw(8)
              << "ERR/s" << std::setw(8) << "LAG" << '\n';

    for (std::size_t i = 0; i < fleet.instances.size(); ++i) {
        const slaptop::InstanceMetrics& metrics = fleet.instances[i];
        const slaptop::InstanceHistory* history =
            i < fleet.history.size() ? &fleet.history[i] : nullptr;
        std::cout << std::left << std::setw(8) << metrics.instance.name << std::right
                  << std::setw(7) << metrics.instance.pid << ' ' << std::left << std::setw(9)
                  << slaptop::healthLabel(metrics.health) << std::right << std::setw(5)
                  << metrics.proc.numThreads << std::right << std::setw(12) << std::fixed
                  << std::setprecision(1) << metrics.proc.cpuPercent << '/'
                  // Unknown core count stays unknown: a made-up denominator
                  // would read as "1-CPU machine".
                  << (metrics.proc.cpuCount > 0
                          ? std::to_string(100 * metrics.proc.cpuCount)
                          : std::string("-"))
                  << std::setw(8) << humanBytes(metrics.proc.rssBytes);
        if (metrics.proc.memTotalBytes > 0 && metrics.proc.memAvailableBytes > 0) {
            const double total = static_cast<double>(metrics.proc.memTotalBytes);
            const double used = total - static_cast<double>(metrics.proc.memAvailableBytes);
            std::cout << std::setw(7) << std::setprecision(1) << (100.0 * used / total);
        } else {
            std::cout << std::setw(7) << "-";
        }

        // 11 columns: a proxy legitimately reports "368/255683", and a 9-wide
        // column let the value overflow into the next one, shifting the row.
        if (metrics.hasMonitor) {
            std::cout << std::setw(11)
                      << (std::to_string(metrics.monitor.connectionsCurrent) + "/" +
                          std::to_string(metrics.monitor.connectionsTotal));
        } else {
            std::cout << std::setw(11) << "-";
        }
        std::cout << std::setw(8) << std::setprecision(1)
                  << (history ? history->opsPerSecond.last() : 0.0) << std::setw(8)
                  << (history ? history->errorsPerSecond.last() : 0.0) << std::setw(8);
        if (metrics.replication.lagSeconds >= 0.0) {
            std::cout << static_cast<long long>(metrics.replication.lagSeconds) << 's';
        } else {
            std::cout << "-";
        }
        std::cout << '\n';
    }
}

/// Reads the first line of `path` as the bind password, stripping the line
/// ending.  A password readable by others is reported: it is the kind of thing
/// that works but should not.
std::string readPasswordFile(const std::string& path, std::string& error) {
    struct stat info {};
    if (::stat(path.c_str(), &info) != 0) {
        error = "cannot stat " + path;
        return {};
    }
    if ((info.st_mode & (S_IRGRP | S_IROTH)) != 0) {
        std::cerr << kProgramName << ": warning: " << path
                  << " is readable by group or others; use chmod 600\n";
    }
    std::ifstream in(path);
    if (!in) {
        error = "cannot read " + path;
        return {};
    }
    std::string password;
    std::getline(in, password);
    while (!password.empty() && (password.back() == '\r' || password.back() == '\n')) {
        password.pop_back();
    }
    return password;
}

#ifdef SLAPTOP_WITH_LDAP
int dumpMonitor(const std::string& uri, const std::string& bindDn, const std::string& password,
                bool insecure) {
    std::string connectError;
    auto client = slaptop::LdapClient::open(uri, bindDn, password, &connectError, insecure);
    if (!client) {
        std::cerr << kProgramName << ": cannot connect to " << uri << ": " << connectError
                  << '\n';
        return 1;
    }
    const auto snapshot = client->fetchMonitor();
    if (!snapshot) {
        std::cerr << kProgramName << ": cn=monitor search failed: " << client->lastError()
                  << '\n';
        return 1;
    }

    std::cout << "uri                 " << uri << '\n'
              << "connections         total=" << snapshot->connectionsTotal
              << " current=" << snapshot->connectionsCurrent
              << " maxfd=" << snapshot->maxFileDescriptors << '\n'
              << "operations          initiated=" << snapshot->opsInitiated
              << " completed=" << snapshot->opsCompleted << '\n';
    for (const auto& [type, count] : snapshot->opsByType) {
        std::cout << "  op " << std::left << std::setw(14) << type << std::right << count << '\n';
    }
    for (const slaptop::DatabaseInfo& database : snapshot->databases) {
        std::cout << "database            " << database.label << " [" << database.backend << "]";
        for (const std::string& naming : database.namingContexts) {
            std::cout << ' ' << naming;
        }
        if (!database.overlays.empty()) {
            std::cout << " overlays=";
            for (std::size_t i = 0; i < database.overlays.size(); ++i) {
                std::cout << (i == 0 ? "" : ",") << database.overlays[i];
            }
        }
        std::cout << '\n';
    }
    for (const slaptop::ListenerInfo& listener : snapshot->listeners) {
        std::cout << "listener            " << listener.address << (listener.tls ? " (TLS)" : "")
                  << '\n';
    }
    for (const slaptop::DatabaseInfo& database : snapshot->databases) {
        for (const std::string& naming : database.namingContexts) {
            const auto csn = client->fetchContextCsn(naming);
            if (!csn) {
                continue;
            }
            for (const std::string& value : *csn) {
                std::cout << "contextCSN          " << naming << ' ' << value << '\n';
            }
        }
    }
    if (const auto log = client->fetchLogConfig(); log) {
        std::cout << "log                 " << log->path << " format=" << log->format
                  << " level=" << log->level << '\n';
    }
    return 0;
}
#endif

}  // namespace

namespace {

/// Sequences that give the terminal back before dying: leaving the alternate
/// screen and re-showing the cursor is what makes the message readable when
/// notcurses owned the display.
constexpr char kRestoreTerminal[] = "\x1b[?1049l\x1b[?25h\x1b[0m\r\n";

void writeText(int fd, const char* text) {
    if (text != nullptr && *text != '\0') {
        (void)!::write(fd, text, std::strlen(text));
    }
}

/// Where a crash trace goes, printed with the message so the reader does not
/// have to guess.
void crashLogPath(char* buffer, std::size_t size) {
    const char* base = std::getenv("XDG_RUNTIME_DIR");
    if (base != nullptr && *base != '\0') {
        std::snprintf(buffer, size, "%s/slaptop-crash.log", base);
    } else {
        std::snprintf(buffer, size, "/dev/shm/slaptop-crash.log");
    }
}

const char* signalName(int signal) {
    switch (signal) {
        case SIGSEGV:
            return "segmentation fault";
        case SIGBUS:
            return "bus error";
        case SIGABRT:
            return "abort (an internal check failed)";
        case SIGILL:
            return "illegal instruction";
        case SIGFPE:
            return "arithmetic error";
        default:
            return "fatal signal";
    }
}

/// A fatal signal ends the run with a readable message and a trace file, and
/// never with a core dump: `_exit` here means the signal is not re-raised, so
/// the shell reports an exit status instead of "core dumped".
void onFatalSignal(int signal) {
    void* frames[64];
    const int count = ::backtrace(frames, sizeof(frames) / sizeof(frames[0]));

    char path[256] = {0};
    crashLogPath(path, sizeof(path));
    const int fd = ::open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd >= 0) {
        char header[320];
        const int length = std::snprintf(header, sizeof(header),
                                         "slaptop %s: fatal signal %d (%s)\nbuild: %s %s\n\n",
                                         SLAPTOP_VERSION, signal, signalName(signal), __DATE__,
                                         __TIME__);
        if (length > 0) {
            (void)!::write(fd, header, static_cast<std::size_t>(length));
        }
        backtrace_symbols_fd(frames, count, fd);
        ::close(fd);
    }

    writeText(STDERR_FILENO, kRestoreTerminal);
    std::fprintf(stderr, "\nslaptop: %s (%d) — the run stops here, no core dump was written.\n",
                 signalName(signal), signal);
    std::fprintf(stderr, "slaptop: backtrace written to %s\n", path);
    std::fprintf(stderr,
                 "slaptop: this is a bug in slaptop (version %s); the monitored servers were "
                 "not modified.\n",
                 SLAPTOP_VERSION);
    std::fflush(stderr);
    ::_exit(128 + signal);
}

/// Last resort: an exception escaping a thread would otherwise kill the
/// process with "Aborted (core dumped)" and no core to look at.  Say what
/// happened, on stderr, before dying.
void onTerminate() {
    std::string message = "unknown exception";
    if (const std::exception_ptr error = std::current_exception()) {
        try {
            std::rethrow_exception(error);
        } catch (const std::bad_alloc&) {
            message = "out of memory";
        } catch (const std::exception& thrown) {
            message = thrown.what();
        } catch (...) {
            message = "non-standard exception";
        }
    }
    writeText(STDERR_FILENO, kRestoreTerminal);
    std::fprintf(stderr, "\nslaptop: internal error: %s\n", message.c_str());
    std::fprintf(stderr,
                 "slaptop: the run stops here, the terminal is restored and no core dump was "
                 "written. This is a bug in slaptop; report it with the version %s.\n",
                 SLAPTOP_VERSION);
    std::fflush(stderr);
    ::_exit(EXIT_FAILURE);
}

}  // namespace

int main(int argc, char** argv) {
    // A monitoring client must never die because a server closed a socket
    // mid-request: report the LDAP error and keep the next tick alive.
    std::signal(SIGPIPE, SIG_IGN);
    std::set_terminate(onTerminate);
    // A crash must leave something to read: no core is available on the hosts
    // this runs on, so the handler writes a backtrace itself.
    for (const int signal : {SIGSEGV, SIGABRT, SIGBUS, SIGILL, SIGFPE}) {
        std::signal(signal, onFatalSignal);
    }

    bool json = false;
    bool forceTui = false;
    bool probePixels = false;
    bool forceText = false;
    double watchSeconds = 0.0;
    double interval = 1.0;
    double ldapInterval = 2.0;
    double duration = 0.0;
    bool once = false;
    bool diagnoseMode = false;
    bool insecure = false;
    bool jsonl = false;
    std::string bindDn;
    std::string passwordFile;
    std::vector<slaptop::RemoteTarget> remoteTargets;
    std::vector<slaptop::collector::SshNodeSpec> nodeSpecs;
    std::string groupName;
    std::string configPath;
#ifdef SLAPTOP_WITH_LDAP
    std::string ldapDumpUri;
#endif

    // --config is honoured before the rest of the command line so that file
    // values become the defaults and explicit options still override them.
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--config") {
            configPath = argv[i + 1];
        }
    }
    if (configPath.empty()) {
        configPath = slaptop::Config::defaultPath();
    }
    std::vector<std::string> configWarnings;
    const slaptop::Config config = slaptop::Config::load(configPath, &configWarnings);
    for (const std::string& warning : configWarnings) {
        std::cerr << kProgramName << ": " << warning << '\n';
    }
    if (!config.errors.empty()) {
        // A key in the wrong section means the file does not say what its
        // author meant: starting anyway would watch another environment.
        for (const std::string& error : config.errors) {
            std::cerr << kProgramName << ": " << error << '\n';
        }
        return 2;
    }
    interval = config.interval;
    ldapInterval = config.ldapInterval;
    insecure = config.insecure;
    bindDn = config.bindDn;
    passwordFile = config.passwordFile;
    for (const std::string& path : config.uriFiles) {
        std::string error;
        if (!loadUriFile(path, remoteTargets, error)) {
            std::cerr << kProgramName << ": " << error << '\n';
        }
    }
    // Every command-line option has a configuration twin; the command line is
    // parsed afterwards and simply overwrites these values.
    once = config.once;
    if (config.watchSeconds > 0.0) {
        watchSeconds = config.watchSeconds;
    }
    duration = config.duration;
    json = config.json || config.jsonl;
    jsonl = config.jsonl;
    forceTui = config.forceTui;
    forceText = config.forceText;
    for (const std::string& spec : config.uris) {
        slaptop::RemoteTarget target;
        std::string error;
        if (parseTarget(spec, error, target)) {
            remoteTargets.push_back(std::move(target));
        } else {
            std::cerr << kProgramName << ": --uri " << spec << ": " << error << '\n';
        }
    }
    // Every node line remembers where it came from: a duplicate is reported
    // with the file (or flag) that declared it, which is the thing to edit.
    const auto annotate = [](std::vector<slaptop::collector::SshNodeSpec>& specs,
                             std::size_t from, const std::string& origin) {
        for (std::size_t index = from; index < specs.size(); ++index) {
            specs[index].origin = origin;
        }
    };
    for (const std::string& path : config.nodeFiles) {
        const std::size_t before = nodeSpecs.size();
        std::string error;
        if (!loadNodeFile(path, nodeSpecs, error)) {
            std::cerr << kProgramName << ": " << error << '\n';
        }
        annotate(nodeSpecs, before, "node-file " + path);
    }
    // A group replaces the top-level targets: `--group acc` reads the nodes of
    // [group acc] instead of the ones declared at the root.
    groupName = config.defaultGroup;
    for (int i = 1; i + 1 < argc; ++i) {
        if (std::string(argv[i]) == "--group") {
            groupName = argv[i + 1];
        }
    }
    if (!groupName.empty()) {
        const slaptop::NodeGroup* chosen = nullptr;
        for (const slaptop::NodeGroup& candidate : config.groups) {
            if (candidate.name == groupName) {
                chosen = &candidate;
                break;
            }
        }
        if (chosen == nullptr) {
            std::cerr << kProgramName << ": unknown group '" << groupName << "'";
            if (!config.groups.empty()) {
                std::cerr << " (known:";
                for (const slaptop::NodeGroup& known : config.groups) {
                    std::cerr << ' ' << known.name;
                }
                std::cerr << ')';
            }
            std::cerr << '\n';
            return 2;
        }
        remoteTargets.clear();
        nodeSpecs.clear();
        for (const std::string& spec : chosen->uris) {
            slaptop::RemoteTarget target;
            std::string error;
            if (parseTarget(spec, error, target)) {
                remoteTargets.push_back(std::move(target));
            } else {
                std::cerr << kProgramName << ": group " << chosen->name << ": " << error << '\n';
            }
        }
        for (const std::string& path : chosen->uriFiles) {
            std::string error;
            if (!loadUriFile(path, remoteTargets, error)) {
                std::cerr << kProgramName << ": " << error << '\n';
            }
        }
        const std::string groupOrigin =
            "config " + configPath + " [group " + chosen->name + "]";
        for (const std::string& spec : chosen->nodes) {
            slaptop::collector::SshNodeSpec node;
            std::string error;
            if (parseNodeSpec(spec, node, error)) {
                node.origin = groupOrigin;
                nodeSpecs.push_back(std::move(node));
            } else {
                std::cerr << kProgramName << ": group " << chosen->name << ": " << error << '\n';
            }
        }
        for (const std::string& path : chosen->nodeFiles) {
            const std::size_t before = nodeSpecs.size();
            std::string error;
            if (!loadNodeFile(path, nodeSpecs, error)) {
                std::cerr << kProgramName << ": " << error << '\n';
            }
            annotate(nodeSpecs, before, groupOrigin + " node-file " + path);
        }
    }

    for (const std::string& spec : config.nodes) {
        slaptop::collector::SshNodeSpec node;
        std::string error;
        if (parseNodeSpec(spec, node, error)) {
            node.origin = "config " + configPath;
            nodeSpecs.push_back(std::move(node));
        } else {
            std::cerr << kProgramName << ": --node " << spec << ": " << error << '\n';
        }
    }

    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--help" || arg == "-h") {
            printUsage(std::cout);
            return 0;
        }
        if (arg == "--version") {
            std::cout << kProgramName << ' ' << kVersion << " (" << kCommit << ")\n";
            return 0;
        }
        if (arg == "--license" || arg == "-l") {
            std::cout << slaptop::embedded::licenseText();
            return 0;
        }
        if (arg == "--doc" || arg == "--documentation" || arg == "-D") {
            std::cout << slaptop::embedded::documentationText();
            return 0;
        }
        if (arg == "--json") {
            json = true;
            continue;
        }
        if (arg == "--jsonl") {
            json = true;
            jsonl = true;
            continue;
        }
        if (arg == "--once") {
            once = true;
            continue;
        }
        if (arg == "--tui") {
            forceTui = true;
            continue;
        }
        if (arg == "--diagnose") {
            diagnoseMode = true;
            continue;
        }
        if (arg == "--probe-pixels") {
            probePixels = true;
            continue;
        }
        if (arg == "--no-tui") {
            forceText = true;
            continue;
        }
        if (arg == "--uri-file") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --uri-file requires a path\n";
                return 2;
            }
            std::string error;
            if (!loadUriFile(argv[++i], remoteTargets, error)) {
                std::cerr << kProgramName << ": " << error << '\n';
                return 2;
            }
            continue;
        }
        if (arg == "--list-groups") {
            if (config.groups.empty()) {
                std::cout << "no group defined in " << configPath << '\n';
                return 0;
            }
            for (const slaptop::NodeGroup& group : config.groups) {
                std::cout << group.name << "  (" << group.nodes.size() << " node(s), "
                          << group.uris.size() << " uri(s))"
                          << (group.name == config.defaultGroup ? "  [default]" : "") << '\n';
                for (const std::string& node : group.nodes) {
                    std::cout << "  node " << node << '\n';
                }
                for (const std::string& file : group.nodeFiles) {
                    std::vector<slaptop::collector::SshNodeSpec> loaded;
                    std::string error;
                    if (!loadNodeFile(file, loaded, error)) {
                        std::cout << "  node-file " << file << "  (" << error << ")\n";
                        continue;
                    }
                    for (const auto& node : loaded) {
                        std::cout << "  node " << (node.user.empty() ? "" : node.user + "@")
                                  << node.host
                                  << (node.name.empty() ? "" : " name=" + node.name)
                                  << "   [from " << file << "]\n";
                    }
                }
                for (const std::string& uri : group.uris) {
                    std::cout << "  uri  " << uri << '\n';
                }
            }
            return 0;
        }
        if (arg == "--group") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --group requires a name\n";
                return 2;
            }
            groupName = argv[++i];
            continue;
        }
        if (arg == "--node" || arg == "--node-file") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": " << arg << " requires a value\n";
                return 2;
            }
            const std::string value = argv[++i];
            std::string error;
            if (arg == "--node-file") {
                const std::size_t before = nodeSpecs.size();
                if (!loadNodeFile(value, nodeSpecs, error)) {
                    std::cerr << kProgramName << ": " << error << '\n';
                    return 2;
                }
                annotate(nodeSpecs, before, "--node-file " + value);
            } else {
                slaptop::collector::SshNodeSpec node;
                if (!parseNodeSpec(value, node, error)) {
                    std::cerr << kProgramName << ": --node " << value << ": " << error << '\n';
                    return 2;
                }
                node.origin = "--node";
                nodeSpecs.push_back(std::move(node));
            }
            continue;
        }
        if (arg == "--config") {
            // Already loaded during the pre-scan; consume the value.
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --config requires a path\n";
                return 2;
            }
            ++i;
            continue;
        }
        if (arg == "--insecure") {
            insecure = true;
            continue;
        }
        if (arg == "--uri") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --uri requires a value\n";
                return 2;
            }
            // The same "uri key=value…" syntax as a line of --uri-file.
            slaptop::RemoteTarget target;
            std::string error;
            if (!parseTarget(argv[++i], error, target)) {
                std::cerr << kProgramName << ": " << error << '\n';
                return 2;
            }
            remoteTargets.push_back(std::move(target));
            continue;
        }
        if (arg == "--interval" || arg == "--watch" || arg == "--ldap-interval" ||
            arg == "--duration") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": " << arg << " requires a value\n";
                return 2;
            }
            try {
                const double value = std::stod(argv[++i]);
                if (arg == "--watch") {
                    watchSeconds = value;
                } else if (arg == "--ldap-interval") {
                    ldapInterval = value;
                } else if (arg == "--duration") {
                    duration = value;
                } else {
                    interval = value;
                }
            } catch (...) {
                std::cerr << kProgramName << ": invalid number\n";
                return 2;
            }
            continue;
        }
#ifdef SLAPTOP_WITH_LDAP
        if (arg == "--ldap") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --ldap requires a URI\n";
                return 2;
            }
            ldapDumpUri = argv[++i];
            continue;
        }
        if (arg == "--bind") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --bind requires a DN\n";
                return 2;
            }
            bindDn = argv[++i];
            continue;
        }
        if (arg == "--bind-password-file") {
            if (i + 1 >= argc) {
                std::cerr << kProgramName << ": --bind-password-file requires a path\n";
                return 2;
            }
            passwordFile = argv[++i];
            continue;
        }
#endif
        std::cerr << kProgramName << ": unknown option '" << arg << "'\n";
        printUsage(std::cerr);
        return 2;
    }

    // Password sources, most explicit first: --bind-password-file, then the
    // environment (never visible in ps), then the configuration file.
    std::string password;
    std::string passwordSource;
    if (!passwordFile.empty()) {
        std::string error;
        password = readPasswordFile(passwordFile, error);
        if (!error.empty()) {
            std::cerr << kProgramName << ": " << error << '\n';
            return 2;
        }
        passwordSource = "file:" + passwordFile;
    } else if (const char* fromEnv = std::getenv("SLAPTOP_BIND_PW");
               fromEnv != nullptr && *fromEnv != '\0') {
        password = fromEnv;
        passwordSource = "env:SLAPTOP_BIND_PW";
    }
    if (!password.empty() && bindDn.empty()) {
        std::cerr << kProgramName
                  << ": a bind password was given without --bind; it is ignored\n";
    }

    // libldap reads ldaprc files on its own when the connection opens.  They
    // are reported because an unexpected TLS_CACERT or SASL_MECH there is a
    // classic reason for a bind that the command line cannot explain.
    const std::vector<slaptop::LdapRcFile> ldapRcFiles = slaptop::readLdapRcFiles();
    for (const slaptop::LdapRcFile& file : ldapRcFiles) {
        std::cerr << kProgramName << ": reading " << file.path << " ("
                  << slaptop::ldapRcKeys(file) << "); LDAPNOINIT=1 ignores it\n";
    }
    if (const char* noInit = std::getenv("LDAPNOINIT"); noInit != nullptr) {
        std::cerr << kProgramName << ": LDAPNOINIT is set, ldaprc files are ignored\n";
    }

    // Kept for the help screen and the JSON output.
    connection.bindMode = bindDn.empty() ? "anonymous" : bindDn;
    connection.passwordSource = passwordSource;
    for (const slaptop::LdapRcFile& file : ldapRcFiles) {
        connection.ldapRcFiles.push_back(file.path + " (" + slaptop::ldapRcKeys(file) + ")");
    }

#ifdef SLAPTOP_WITH_LDAP
    if (!ldapDumpUri.empty()) {
        return dumpMonitor(ldapDumpUri, bindDn, password, insecure);
    }
#endif

    if (interval <= 0.0 || interval > 60.0) {
        std::cerr << kProgramName << ": interval must be in ]0, 60]\n";
        return 2;
    }

    slaptop::EngineOptions options;
    options.intervalSeconds = interval;
    options.ldapIntervalSeconds = ldapInterval;
    options.bindDn = bindDn;
    options.password = password;
    options.remoteTargets = remoteTargets;
    if (nodeSpecs.size() > 6) {
        std::cerr << kProgramName << ": " << nodeSpecs.size()
                  << " SSH nodes declared, 6 at most\n";
        return 2;
    }
    options.nodes = nodeSpecs;
    options.insecureTls = insecure;

    // Footnote: the diagnostic reads the same options the dashboard would, so
    // what it reports is what the run would have had.
    if (diagnoseMode) {
        return slaptop::diagnose(options, configPath);
    }

    // One-shot and plain-text runs want a rate on the first output, so they
    // read cn=monitor on every tick instead of every ldapInterval.
    if (once || watchSeconds > 0.0) {
        options.ldapIntervalSeconds = std::min(options.ldapIntervalSeconds, interval);
    }

    // Rates need two collection rounds: wait for two periods, not one.
    const auto settle = std::chrono::milliseconds(static_cast<long>(
        std::max(400.0, 2000.0 * std::max(options.intervalSeconds, options.ldapIntervalSeconds) +
                            200.0)));

    if (once) {
        slaptop::MonitorEngine engine(options);
        engine.start();
        std::this_thread::sleep_for(settle);
        const slaptop::FleetSnapshot fleet = engine.snapshot();
        engine.stop();
        printRunReport(engine.report());
        printFleet(fleet, json, jsonl);
        return 0;
    }

    if (watchSeconds > 0.0) {
        slaptop::MonitorEngine engine(options);
        engine.start();
        std::this_thread::sleep_for(settle);
        const auto started = std::chrono::steady_clock::now();
        while (true) {
            if (!json) {
                std::cout << "\x1b[H\x1b[2J";
            }
            printFleet(engine.snapshot(), json, jsonl);
            std::cout.flush();
            std::this_thread::sleep_for(std::chrono::duration<double>(watchSeconds));
            if (duration > 0.0 &&
                std::chrono::duration<double>(std::chrono::steady_clock::now() - started).count() >
                    duration) {
                break;
            }
        }
        engine.stop();
        printRunReport(engine.report());
        return 0;
    }

#ifdef SLAPTOP_WITH_TUI
    if (probePixels) {
        return slaptop::ui::probePixelSupport();
    }
    const bool tty = ::isatty(STDOUT_FILENO) != 0;
    if (forceTui || (tty && !forceText && !json)) {
        slaptop::MonitorEngine engine(options);
        engine.start();
        std::string summary = "bind " + connection.bindMode;
        if (!connection.passwordSource.empty()) {
            summary += "   password " + connection.passwordSource;
        }
        for (const std::string& file : connection.ldapRcFiles) {
            summary += "   ldaprc " + file;
        }
        slaptop::ui::setConnectionInfo(summary);
        const int rc = slaptop::ui::runDashboard(engine, config.theme);
        engine.stop();
        printRunReport(engine.report());
        return rc;
    }
#endif

    // No TUI available or explicitly disabled: behave like --once.
    slaptop::MonitorEngine engine(options);
    engine.start();
    std::this_thread::sleep_for(settle);
    const slaptop::FleetSnapshot fleet = engine.snapshot();
    engine.stop();
    printRunReport(engine.report());
    printFleet(fleet, json, jsonl);
    return 0;
}
