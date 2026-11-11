#include "slaptop/collector/sshnode.hpp"

#include "slaptop/collector/discovery.hpp"

#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <map>
#include <sstream>

namespace slaptop::collector {
namespace {

std::string trim(std::string_view text) {
    const std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string_view::npos) {
        return {};
    }
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return std::string(text.substr(start, end - start + 1));
}

/// Single-quotes a string for the remote shell.
std::string shellQuote(const std::string& text) {
    std::string out = "'";
    for (const char c : text) {
        if (c == '\'') {
            out += "'\\''";
        } else {
            out += c;
        }
    }
    out += '\'';
    return out;
}

/// Percent-encodes a path for an ldapi:// URI ("/" -> %2F).
std::string encodeLdapiPath(const std::string& path) {
    static const char* hex = "0123456789ABCDEF";
    std::string out;
    out.reserve(path.size());
    for (const char c : path) {
        const unsigned char byte = static_cast<unsigned char>(c);
        if (std::isalnum(byte) != 0 || c == '-' || c == '_' || c == '.' || c == '~') {
            out += c;
        } else {
            out += '%';
            out += hex[(byte >> 4) & 0x0f];
            out += hex[byte & 0x0f];
        }
    }
    return out;
}

/// Reads a whole command's output.
bool runShell(const std::string& command, std::string& out, std::string& error) {
    FILE* pipe = ::popen(command.c_str(), "r");
    if (pipe == nullptr) {
        error = "popen: " + std::string(std::strerror(errno));
        return false;
    }
    out.clear();
    char buffer[8192];
    std::size_t count = 0;
    while ((count = std::fread(buffer, 1, sizeof(buffer), pipe)) > 0) {
        out.append(buffer, count);
    }
    const int status = ::pclose(pipe);
    if (status != 0) {
        // 255 is ssh itself failing, not the remote command: unreachable host,
        // refused key or a broken ControlMaster.  Saying so saves the operator
        // from looking for a problem in slapd.
        if (WIFEXITED(status) && WEXITSTATUS(status) == 255) {
            error = "ssh could not reach the host (exit 255: unreachable, key refused or "
                    "connection dropped)";
            return false;
        }
        error = "ssh/tar exited with " + std::to_string(WIFEXITED(status) ? WEXITSTATUS(status)
                                                                         : status);
        return false;
    }
    return true;
}

std::string runtimeDir() {
    const char* xdg = std::getenv("XDG_RUNTIME_DIR");
    std::string base = xdg != nullptr && *xdg != '\0' ? xdg : "/tmp";
    base += "/slaptop-" + std::to_string(static_cast<long>(::getuid()));
    ::mkdir(base.c_str(), 0700);
    return base;
}

std::string cacheRoot() {
    const char* xdg = std::getenv("XDG_CACHE_HOME");
    std::string base = xdg != nullptr && *xdg != '\0'
                           ? xdg
                           : std::string(std::getenv("HOME") == nullptr ? "/tmp" : std::getenv("HOME")) +
                                 "/.cache";
    base += "/slaptop/nodes";
    std::string path;
    for (const char c : base) {
        path += c;
        if (c == '/') {
            ::mkdir(path.c_str(), 0700);
        }
    }
    ::mkdir(path.c_str(), 0700);
    return path;
}

/// "user@host" -> user/host; both sides optional.
bool splitTarget(const std::string& token, std::string& user, std::string& host) {
    const std::size_t at = token.rfind('@');
    if (at == std::string::npos) {
        user.clear();
        host = token;
    } else {
        user = token.substr(0, at);
        host = token.substr(at + 1);
    }
    return !host.empty();
}

}  // namespace

std::string sshEffectiveHost(const std::string& target) {
    // `ssh -G` evaluates ~/.ssh/config and prints the result; it never
    // connects.  This is what makes an alias ("Host lab" -> "HostName 192.0.2.1")
    // comparable with this machine's addresses.
    std::string out;
    std::string error;
    if (!runShell("ssh -G " + shellQuote(target) + " 2>/dev/null", out, error)) {
        return target;
    }
    std::istringstream lines(out);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.rfind("hostname ", 0) == 0) {
            const std::string name = trim(line.substr(9));
            return name.empty() ? target : name;
        }
    }
    return target;
}

bool parseNodeSpec(std::string_view text, SshNodeSpec& out, std::string& error) {
    out = SshNodeSpec{};
    std::vector<std::string> tokens;
    std::string current;
    for (const char c : std::string(text)) {
        if (c == ' ' || c == '\t') {
            if (!current.empty()) {
                tokens.push_back(std::move(current));
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        tokens.push_back(std::move(current));
    }
    if (tokens.empty()) {
        error = "empty node";
        return false;
    }
    if (!splitTarget(tokens.front(), out.user, out.host)) {
        error = "node '" + tokens.front() + "' has no host";
        return false;
    }
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        const std::size_t equals = tokens[i].find('=');
        if (equals == std::string::npos) {
            error = "node option '" + tokens[i] + "' is not key=value";
            return false;
        }
        const std::string key = tokens[i].substr(0, equals);
        const std::string value = tokens[i].substr(equals + 1);
        if (key == "key") {
            out.keyPath = value;
        } else if (key == "port") {
            try {
                out.port = std::stoi(value);
            } catch (...) {
                error = "node port '" + value + "' is not a number";
                return false;
            }
        } else if (key == "name") {
            out.name = value;
        } else if (key == "instances") {
            out.instances = value;
        } else if (key == "compress") {
            if (value == "on" || value == "yes" || value == "true" || value == "1") {
                out.compress = true;
            } else if (value == "off" || value == "no" || value == "false" || value == "0") {
                out.compress = false;
            } else {
                error = "node compress '" + value + "' is not on/off";
                return false;
            }
        } else {
            error = "unknown node option '" + key + "'";
            return false;
        }
    }
    return true;
}

bool loadNodeFile(const std::string& path, std::vector<SshNodeSpec>& out, std::string& error) {
    std::ifstream in(path);
    if (!in) {
        error = "cannot read " + path;
        return false;
    }
    std::string line;
    int number = 0;
    while (std::getline(in, line)) {
        ++number;
        const std::string value = trim(line);
        if (value.empty() || value.front() == '#') {
            continue;
        }
        SshNodeSpec spec;
        std::string parseError;
        if (!parseNodeSpec(value, spec, parseError)) {
            error = path + ":" + std::to_string(number) + ": " + parseError;
            return false;
        }
        out.push_back(std::move(spec));
    }
    return true;
}

bool nodeSelectsInstance(const SshNodeSpec& spec, const std::string& name) {
    if (spec.instances.empty()) {
        return true;
    }
    std::size_t pos = 0;
    while (pos <= spec.instances.size()) {
        const std::size_t comma = spec.instances.find(',', pos);
        const std::string item = trim(spec.instances.substr(
            pos, comma == std::string::npos ? std::string::npos : comma - pos));
        if (item == name) {
            return true;
        }
        if (comma == std::string::npos) {
            break;
        }
        pos = comma + 1;
    }
    return false;
}

SshNode::SshNode(SshNodeSpec spec) : spec_(std::move(spec)) {
    const std::string base = runtimeDir();
    const std::string key = spec_.user + "@" + spec_.host + ":" + std::to_string(spec_.port);
    const std::size_t hash = std::hash<std::string>{}(key);
    char suffix[32];
    std::snprintf(suffix, sizeof(suffix), "%08zx", hash);
    // Both paths carry the pid: two slaptops on the same machine monitoring the
    // same host must not share them.  A shared ControlPath meant the second
    // process could `ssh -O exit` the first one's master, and a shared socket
    // directory meant this constructor unlinked the other process' forwarded
    // sockets — the first instance then silently lost its LDAP connection.
    const std::string pid = std::to_string(static_cast<long>(::getpid()));
    controlPath_ = base + "/cm-" + suffix + "-" + pid;
    socketDir_ = base + "/sock-" + suffix + "-" + pid;
    ::mkdir(socketDir_.c_str(), 0700);
    // A socket file left by a previous run looks identical to a live one, so
    // `forwardSharedSocket` would trust it and hand a dead URI to libldap.
    // This directory is ours alone (pid in the name): clear it.
    if (DIR* dir = ::opendir(socketDir_.c_str())) {
        while (const dirent* entry = ::readdir(dir)) {
            const std::string entryName = entry->d_name;
            if (entryName == "." || entryName == "..") {
                continue;
            }
            ::unlink((socketDir_ + "/" + entryName).c_str());
        }
        ::closedir(dir);
    }
}

SshNode::~SshNode() {
    // Close the master so no ssh process outlives the dashboard.
    const std::string cmd = "ssh -o ControlPath=" + shellQuote(controlPath_) + " -O exit " +
                            shellQuote(spec_.host) + " >/dev/null 2>&1";
    (void)std::system(cmd.c_str());
    // Remove our own directory: pid-scoped, so emptying it is safe.
    if (DIR* dir = ::opendir(socketDir_.c_str())) {
        while (const dirent* entry = ::readdir(dir)) {
            const std::string name = entry->d_name;
            if (name == "." || name == "..") {
                continue;
            }
            ::unlink((socketDir_ + "/" + name).c_str());
        }
        ::closedir(dir);
    }
    ::rmdir(socketDir_.c_str());
}

std::string SshNode::sshCommand(const std::string& remoteCommand) const {
    // `-n` sends stdin from /dev/null: without it every ssh call reads the
    // terminal and swallows the user's keystrokes, which is exactly what the
    // dashboard needs.
    std::string cmd = "ssh -n -T -o BatchMode=yes -o ConnectTimeout=8";
    cmd += " -o ControlMaster=auto -o ControlPath=" + shellQuote(controlPath_);
    cmd += " -o ControlPersist=300";
    if (!spec_.keyPath.empty()) {
        cmd += " -i " + shellQuote(spec_.keyPath);
    }
    if (spec_.port > 0) {
        cmd += " -p " + std::to_string(spec_.port);
    }
    if (spec_.compress) {
        // The master carries the option; a multiplexed slave inherits it.
        cmd += " -o Compression=yes";
    }
    cmd += " " + shellQuote(spec_.user.empty() ? spec_.host : spec_.user + "@" + spec_.host);
    // stderr must never reach the dashboard's terminal: a node that cannot be
    // resolved would write over the UI.  The exit status still reports the
    // failure, and SLAPTOP_SSH_DEBUG prints the command when diagnosing.
    cmd += " " + shellQuote(remoteCommand) + " 2>/dev/null";
    return cmd;
}

bool SshNode::run(std::string_view command, std::string& out, std::string& error) const {
    const std::string shell = sshCommand(std::string(command));
    if (std::getenv("SLAPTOP_SSH_DEBUG") != nullptr) {
        std::fprintf(stderr, "ssh: %s\n", shell.c_str());
    }
    if (!runShell(shell, out, error)) {
        lastError_ = error;
        return false;
    }
    return true;
}

std::string SshNode::runOrEmpty(std::string_view command, std::string& error) const {
    std::string out;
    if (!run(command, out, error)) {
        return {};
    }
    return out;
}

std::string SshNode::forwardSharedSocket(const std::string& instance,
                                         const std::string& remotePath, std::string& error) {
    const std::string local = socketDir_ + "/" + instance + ".sock";
    std::string trimmed = remotePath;
    while (!trimmed.empty() && trimmed.back() == '/') {
        trimmed.pop_back();
    }
    if (trimmed.empty()) {
        error = "no ldapi socket for " + instance;
        return {};
    }
    // Reuse a live forward: connecting to the socket tells us it works.
    struct stat info {};
    if (::stat(local.c_str(), &info) == 0 && S_ISSOCK(info.st_mode)) {
        return "ldapi://" + encodeLdapiPath(local);
    }
    ::unlink(local.c_str());

    std::string cmd = sshCommand("true");
    // Turn `ssh ... true` into the forwarding invocation.
    const std::string suffix = " " + shellQuote("true");
    if (cmd.size() > suffix.size() &&
        cmd.compare(cmd.size() - suffix.size(), suffix.size(), suffix) == 0) {
        cmd.resize(cmd.size() - suffix.size());
    }
    cmd += " -o ExitOnForwardFailure=yes -N -f -L " + shellQuote(local) + ":" +
           shellQuote(trimmed);
    // -f detaches, so the command must be reordered: options before the target.
    cmd = "ssh -n -T -o BatchMode=yes -o ConnectTimeout=8 -o ControlMaster=auto -o ControlPath=" +
          shellQuote(controlPath_) + " -o ControlPersist=300";
    if (!spec_.keyPath.empty()) {
        cmd += " -i " + shellQuote(spec_.keyPath);
    }
    if (spec_.port > 0) {
        cmd += " -p " + std::to_string(spec_.port);
    }
    if (spec_.compress) {
        // The master carries the option; a multiplexed slave inherits it.
        cmd += " -o Compression=yes";
    }
    cmd += " -o ExitOnForwardFailure=yes -N -f -L " + shellQuote(local) + ":" +
           shellQuote(trimmed) + " " +
           shellQuote(spec_.user.empty() ? spec_.host : spec_.user + "@" + spec_.host) +
           " </dev/null >/dev/null 2>&1";

    std::string out;
    std::string forError;
    if (!runShell(cmd, out, forError)) {
        error = "cannot forward " + instance + " socket: " + forError;
        return {};
    }
    // Give the forward a moment to appear.
    for (int i = 0; i < 50; ++i) {
        if (::stat(local.c_str(), &info) == 0 && S_ISSOCK(info.st_mode)) {
            return "ldapi://" + encodeLdapiPath(local);
        }
        ::usleep(20000);
    }
    error = "forwarded socket " + local + " did not appear";
    return {};
}

SocketLimits SshNode::socketLimits(pid_t pid, int maxAgeMs, std::string& error) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(limitsMutex_);
    const bool fresh =
        limitsAt_.time_since_epoch().count() != 0 &&
        std::chrono::duration_cast<std::chrono::milliseconds>(now - limitsAt_).count() < maxAgeMs;
    const auto cached = limitsCache_.find(pid);
    if (fresh && cached != limitsCache_.end()) {
        return cached->second;
    }

    std::vector<pid_t> pids = knownPids_;
    if (pid > 0 && std::find(pids.begin(), pids.end(), pid) == pids.end()) {
        pids.push_back(pid);
    }
    if (pids.empty()) {
        return {};
    }

    // One call for the whole node: the system files once, then the per-process
    // pair.  Markers cannot appear in the files themselves, and every read is
    // silenced so a restricted node yields an empty section rather than a
    // message in the middle of the other ones.
    std::string command;
    command += "echo '=@tcp4'; cat /proc/net/tcp 2>/dev/null";
    command += "; echo '=@tcp6'; cat /proc/net/tcp6 2>/dev/null";
    command += "; echo '=@filenr'; cat /proc/sys/fs/file-nr 2>/dev/null";
    command += "; echo '=@ports'; cat /proc/sys/net/ipv4/ip_local_port_range 2>/dev/null";
    for (const pid_t one : pids) {
        const std::string path = "/proc/" + std::to_string(static_cast<long long>(one));
        command += "; echo '=@limits " + std::to_string(static_cast<long long>(one)) +
                   "'; cat " + path + "/limits 2>/dev/null";
        command += "; echo '=@fds " + std::to_string(static_cast<long long>(one)) +
                   "'; ls " + path + "/fd 2>/dev/null | wc -l";
        // Socket inodes of this process: what ties a /proc/net/tcp row to this
        // instance rather than to the machine.
        command += "; echo '=@sock " + std::to_string(static_cast<long long>(one)) +
                   "'; ls -l " + path + "/fd 2>/dev/null | grep -o 'socket:\\[[0-9]*\\]' | "
                   "tr -cd '0-9\\n'";
    }
    command += "; echo '=@end'";

    std::string out;
    if (!run(command, out, error)) {
        return {};
    }
    const auto section = [&out](const std::string& marker) {
        const std::string start = "=@" + marker + "\n";
        const std::size_t begin = out.find(start);
        if (begin == std::string::npos) {
            return std::string();
        }
        const std::size_t content = begin + start.size();
        const std::size_t end = out.find("=@", content);
        return out.substr(content, end == std::string::npos ? std::string::npos : end - content);
    };
    const std::string netTcp = section("tcp4");
    const std::string netTcp6 = section("tcp6");
    const std::string fileNr = section("filenr");
    const std::string portRange = section("ports");

    limitsCache_.clear();
    for (const pid_t one : pids) {
        const std::string id = std::to_string(static_cast<long long>(one));
        std::uint64_t fdCount = 0;
        try {
            fdCount = std::stoull(trim(section("fds " + id)));
        } catch (...) {
            fdCount = 0;
        }
        std::vector<std::uint64_t> inodes;
        {
            std::istringstream rows(section("sock " + id));
            std::string row;
            while (std::getline(rows, row)) {
                try {
                    if (!row.empty()) {
                        inodes.push_back(std::stoull(row));
                    }
                } catch (...) {
                }
            }
        }
        limitsCache_[one] = parseSocketLimits(section("limits " + id), fdCount, netTcp,
                                              netTcp6, fileNr, portRange, inodes);
    }
    limitsAt_ = now;
    const auto found = limitsCache_.find(pid);
    return found == limitsCache_.end() ? SocketLimits{} : found->second;
}

std::string SshNode::mirrorConfigDir(const std::string& instance, const std::string& remoteDir,
                                     int maxAgeSeconds, std::string& error) {
    static std::map<std::string, std::chrono::steady_clock::time_point> synced;
    const std::string key = label() + "/" + instance;
    const std::string target = cacheRoot() + "/" + label() + "/" + instance;

    const auto now = std::chrono::steady_clock::now();
    const auto it = synced.find(key);
    if (it != synced.end() &&
        std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count() <
            maxAgeSeconds) {
        return target;
    }
    ::mkdir((cacheRoot() + "/" + label()).c_str(), 0700);
    ::mkdir(target.c_str(), 0700);

    // Pull the tree and untar it here: the on-disk parsers then work unchanged.
    const std::string cmd = sshCommand("tar -C " + shellQuote(remoteDir) + " -cf - . 2>/dev/null") +
                            " | tar -xf - -C " + shellQuote(target) + " 2>/dev/null";
    std::string out;
    std::string why;
    if (!runShell(cmd, out, why)) {
        error = "cannot mirror " + remoteDir + ": " + why;
        return {};
    }
    synced[key] = now;
    return target;
}

std::vector<SshNode::ProcSnapshot> SshNode::sampleProcesses(const std::vector<pid_t>& pids,
                                                            std::string& error) const {
    std::vector<ProcSnapshot> out;
    if (pids.empty()) {
        return out;
    }
    std::string command = "for p in";
    for (const pid_t pid : pids) {
        command += " " + std::to_string(static_cast<long>(pid));
    }
    command += "; do echo \"@$p\"; cat /proc/$p/stat 2>/dev/null; cat /proc/$p/status 2>/dev/null;";
    command += " done";
    // The node's core count rides along: without it a remote instance using
    // three cores is reported against this machine's cores, which is simply
    // wrong.  `getconf` is POSIX; the cpuinfo count is the fallback.
    command += "; echo '@cpus'; getconf _NPROCESSORS_ONLN 2>/dev/null || "
               "grep -c '^processor' /proc/cpuinfo 2>/dev/null";
    // Same reason for the RAM: a memory graph drawn against this machine's RAM
    // would describe the wrong host.
    command += "; echo '@memtotal'; awk '/^MemTotal:|^MemAvailable:/' /proc/meminfo "
               "2>/dev/null";
    std::string text;
    if (!run(command, text, error)) {
        return out;
    }
    std::istringstream lines(text);
    std::string line;
    ProcSnapshot current;
    bool inStat = false;
    int cpuCount = 0;
    std::uint64_t memTotalBytes = 0;
    std::uint64_t memAvailableBytes = 0;
    bool pendingCpus = false;
    bool pendingMem = false;
    while (std::getline(lines, line)) {
        if (!line.empty() && line.front() == '@') {
            if (current.pid != 0) {
                out.push_back(current);
            }
            current = ProcSnapshot{};
            // Markers whose value is the next line: not a pid block.
            if (line.substr(1) == "cpus") {
                pendingCpus = true;
                inStat = false;
                continue;
            }
            if (line.substr(1) == "memtotal") {
                pendingMem = true;
                inStat = false;
                continue;
            }
            try {
                current.pid = static_cast<pid_t>(std::stol(line.substr(1)));
            } catch (...) {
                current.pid = 0;
            }
            inStat = true;
            continue;
        }
        if (current.pid == 0) {
            if (pendingCpus) {
                try {
                    cpuCount = std::stoi(line);
                } catch (...) {
                    cpuCount = 0;
                }
                pendingCpus = false;
            } else if (pendingMem) {
                // "MemTotal:       16384000 kB" then "MemAvailable: ..."
                std::istringstream fields(line);
                std::string key;
                double value = 0.0;
                std::string unit;
                if (fields >> key >> value >> unit) {
                    if (key == "MemTotal:") {
                        memTotalBytes = static_cast<std::uint64_t>(value * 1024.0);
                        pendingMem = true;  // the MemAvailable line follows
                    } else if (key == "MemAvailable:") {
                        memAvailableBytes = static_cast<std::uint64_t>(value * 1024.0);
                        pendingMem = false;
                    }
                } else {
                    pendingMem = false;
                }
            }
            continue;
        }
        if (inStat) {
            // Fields after the last ')': state ppid ... utime(14) stime(15).
            const std::size_t close = line.rfind(')');
            if (close == std::string::npos) {
                continue;
            }
            std::istringstream fields(line.substr(close + 1));
            std::string field;
            int index = 0;
            while (fields >> field) {
                ++index;
                if (index == 12) {
                    try {
                        current.utimeTicks = std::stoull(field);
                    } catch (...) {
                    }
                } else if (index == 13) {
                    try {
                        current.stimeTicks = std::stoull(field);
                    } catch (...) {
                    }
                }
            }
            inStat = false;
            continue;
        }
        if (line.rfind("Threads:", 0) == 0) {
            current.threads = static_cast<std::uint64_t>(std::strtoull(line.c_str() + 8, nullptr, 10));
        } else if (line.rfind("VmRSS:", 0) == 0) {
            current.rssBytes = std::strtoull(line.c_str() + 6, nullptr, 10) * 1024ULL;
        } else if (line.rfind("VmSize:", 0) == 0) {
            current.vszBytes = std::strtoull(line.c_str() + 7, nullptr, 10) * 1024ULL;
        }
    }
    if (current.pid != 0) {
        out.push_back(current);
    }
    for (ProcSnapshot& snapshot : out) {
        snapshot.valid = snapshot.utimeTicks != 0 || snapshot.stimeTicks != 0;
        snapshot.cpuCount = cpuCount;
        snapshot.memTotalBytes = memTotalBytes;
        snapshot.memAvailableBytes = memAvailableBytes;
    }
    return out;
}

bool SshNode::readIoFiles(std::string& netDev, std::string& diskStats, std::string& error) const {
    std::string text;
    if (!run("cat /proc/net/dev; echo '@@@'; cat /proc/diskstats", text, error)) {
        return false;
    }
    const std::size_t split = text.find("@@@");
    if (split == std::string::npos) {
        error = "unexpected /proc output";
        return false;
    }
    netDev = text.substr(0, split);
    diskStats = text.substr(split + 3);
    return true;
}

bool SshNode::cachedIoFiles(std::string& netDev, std::string& diskStats, int maxAgeMs,
                            std::string& error) const {
    const auto now = std::chrono::steady_clock::now();
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        if (!cachedNet_.empty() &&
            std::chrono::duration_cast<std::chrono::milliseconds>(now - cachedAt_).count() <
                maxAgeMs) {
            netDev = cachedNet_;
            diskStats = cachedDisk_;
            return true;
        }
    }
    std::string net;
    std::string disk;
    if (!readIoFiles(net, disk, error)) {
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(cacheMutex_);
        cachedNet_ = net;
        cachedDisk_ = disk;
        cachedAt_ = now;
    }
    netDev = std::move(net);
    diskStats = std::move(disk);
    return true;
}

std::vector<SshNode::PathUsage> SshNode::pathUsages(const std::vector<std::string>& paths,
                                                    std::string& error) const {
    std::vector<PathUsage> out;
    if (paths.empty()) {
        return out;
    }
    // One round trip for every path: print a marker, the source, its kernel
    // name (an LVM volume is /dev/mapper/x but /proc/diskstats knows dm-N) and
    // the figures, then move on.
    std::string command = "for p in";
    for (const std::string& path : paths) {
        command += " " + shellQuote(path);
    }
    command += "; do src=$(df -B1 --output=source -- \"$p\" 2>/dev/null | tail -1);";
    command += " echo \"@$p\"; echo \"$src\"; readlink -f \"$src\" 2>/dev/null || echo \"$src\";";
    command += " df -B1 --output=size,avail,target -- \"$p\" 2>/dev/null | tail -1; done";
    std::string text;
    if (!run(command, text, error)) {
        return out;
    }
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        if (line.empty() || line.front() != '@') {
            continue;
        }
        PathUsage usage;
        usage.path = line.substr(1);
        std::string source;
        std::string resolved;
        std::string figures;
        if (!std::getline(lines, source) || !std::getline(lines, resolved) ||
            !std::getline(lines, figures)) {
            break;
        }
        std::istringstream fields(figures);
        std::string sizeText;
        std::string availText;
        if (!(fields >> sizeText >> availText >> usage.mountPoint)) {
            continue;
        }
        const std::size_t slash = resolved.rfind('/');
        usage.source = slash == std::string::npos ? resolved : resolved.substr(slash + 1);
        if (usage.source.empty()) {
            usage.source = resolved;
        }
        usage.total = std::strtoull(sizeText.c_str(), nullptr, 10);
        usage.free = std::strtoull(availText.c_str(), nullptr, 10);
        usage.valid = true;
        out.push_back(std::move(usage));
    }
    return out;
}

std::vector<SshNode::FileSize> SshNode::fileSizes(const std::vector<std::string>& paths,
                                                  std::string& error) const {
    std::vector<FileSize> out;
    if (paths.empty()) {
        return out;
    }
    std::string command = "stat -c '%n %s %b'";
    for (const std::string& path : paths) {
        command += " " + shellQuote(path);
    }
    command += " 2>/dev/null";
    std::string text;
    if (!run(command, text, error)) {
        return out;
    }
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        std::istringstream fields(line);
        FileSize size;
        std::string blocks;
        if (!(fields >> size.path >> size.apparent >> blocks)) {
            continue;
        }
        size.allocated = std::strtoull(blocks.c_str(), nullptr, 10) * 512ULL;
        size.valid = true;
        out.push_back(std::move(size));
    }
    return out;
}

std::optional<SshNode::ProcSnapshot> SshNode::cachedSample(pid_t pid, int maxAgeMs,
                                                          std::string& error) {
    const auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(procMutex_);
    const bool fresh = procAt_.time_since_epoch().count() != 0 &&
                       std::chrono::duration_cast<std::chrono::milliseconds>(now - procAt_)
                               .count() < maxAgeMs;
    const auto cached = procCache_.find(pid);
    if (fresh && cached != procCache_.end()) {
        return cached->second;
    }
    std::vector<pid_t> pids = knownPids_;
    if (std::find(pids.begin(), pids.end(), pid) == pids.end()) {
        pids.push_back(pid);
    }
    if (pids.empty()) {
        return std::nullopt;
    }
    const std::vector<ProcSnapshot> batch = sampleProcesses(pids, error);
    if (batch.empty()) {
        return std::nullopt;
    }
    procCache_.clear();
    for (const ProcSnapshot& snapshot : batch) {
        procCache_[snapshot.pid] = snapshot;
    }
    procAt_ = now;
    const auto found = procCache_.find(pid);
    if (found == procCache_.end()) {
        return std::nullopt;
    }
    return found->second;
}

std::vector<Instance> SshNode::discoverInstances(std::string& error) {
    knownPids_.clear();
    std::vector<Instance> instances;
    std::string text;
    if (!run("ps -eo pid=,args=", text, error)) {
        return instances;
    }
    std::istringstream lines(text);
    std::string line;
    while (std::getline(lines, line)) {
        const std::size_t space = line.find_first_not_of(' ');
        if (space == std::string::npos) {
            continue;
        }
        const std::size_t end = line.find(' ', space);
        pid_t pid = 0;
        try {
            pid = static_cast<pid_t>(std::stol(line.substr(space, end == std::string::npos
                                                                  ? std::string::npos
                                                                  : end - space)));
        } catch (...) {
            continue;
        }
        const std::string args = end == std::string::npos ? std::string() : line.substr(end + 1);
        // Only argv[0] identifies the program: the rest of the line contains
        // paths that also have slashes, so rfind('/') on the whole line would
        // return a directory.
        const std::size_t argvEnd = args.find(' ');
        const std::string argv0 = args.substr(0, argvEnd);
        const std::size_t slash = argv0.rfind('/');
        const std::string binary = slash == std::string::npos ? argv0 : argv0.substr(slash + 1);
        if (binary != "slapd") {
            continue;
        }
        Instance instance;
        instance.pid = pid;
        std::istringstream tokenStream(args);
        std::vector<std::string> tokens;
        std::string token;
        while (tokenStream >> token) {
            tokens.push_back(std::move(token));
        }
        for (std::size_t i = 0; i + 1 < tokens.size(); ++i) {
            if (tokens[i] == "-F") {
                instance.configDir = tokens[++i];
            } else if (tokens[i] == "-f") {
                instance.configFile = tokens[++i];
            } else if (tokens[i] == "-l") {
                instance.logArg = tokens[++i];
            } else if (tokens[i] == "-h") {
                // `ps` flattens argv, so the listener list is every following
                // token that does not look like another option.
                while (i + 1 < tokens.size() && !tokens[i + 1].empty() &&
                       tokens[i + 1].front() != '-') {
                    instance.listeners.push_back(tokens[++i]);
                }
            }
        }
        // `slapd_<name>.d` gives a usable label; a bare `slapd.d` (the default
        // configuration directory) does not, and three nodes would then show
        // three cards with the same name.  Fall back to the node's label.
        const std::string derived = instanceNameFromConfigDir(instance.configDir);
        const std::size_t dirSlash = instance.configDir.rfind('/');
        const std::string base = dirSlash == std::string::npos
                                     ? instance.configDir
                                     : instance.configDir.substr(dirSlash + 1);
        knownPids_.push_back(pid);
        instance.name = derived.empty() || derived == base
                            ? (spec_.name.empty() ? spec_.host : spec_.name)
                            : derived;
        if (instance.name.empty()) {
            instance.name = "slapd-" + std::to_string(static_cast<long>(pid));
        }
        if (!nodeSelectsInstance(spec_, instance.name)) {
            continue;
        }
        instances.push_back(std::move(instance));
    }
    std::sort(instances.begin(), instances.end(),
              [](const Instance& a, const Instance& b) { return a.name < b.name; });
    return instances;
}

// ---------------------------------------------------------------------------
// RemoteTailer
// ---------------------------------------------------------------------------

RemoteTailer::RemoteTailer(std::shared_ptr<SshNode> node, std::string path,
                           std::uintmax_t backlog)
    : node_(std::move(node)), path_(std::move(path)), backlog_(backlog) {}

std::vector<std::string> RemoteTailer::poll(std::size_t maxLines) {
    std::vector<std::string> lines;
    if (!node_) {
        return lines;
    }
    std::string error;
    if (!started_) {
        // First poll: jump to the end, minus a small backlog so the panel is
        // not empty on the first frame.
        std::string probe;
        if (!node_->run("stat -c '%i %s' " + shellQuote(path_), probe, error)) {
            return lines;
        }
        std::istringstream fields(probe);
        if (!(fields >> inode_ >> offset_)) {
            return lines;
        }
        offset_ = offset_ > backlog_ ? offset_ - backlog_ : 0;
        started_ = true;
        pending_.clear();
    }
    const std::string command = "stat -c '%i %s' " + shellQuote(path_) + "; tail -c +" +
                                std::to_string(static_cast<unsigned long long>(offset_ + 1)) +
                                " " + shellQuote(path_) + " 2>/dev/null | head -c 524288";
    std::string text;
    if (!node_->run(command, text, error)) {
        return lines;
    }
    const std::size_t newline = text.find('\n');
    if (newline == std::string::npos) {
        return lines;
    }
    std::istringstream header(text.substr(0, newline));
    std::uintmax_t inode = 0;
    std::uintmax_t size = 0;
    if (!(header >> inode >> size)) {
        return lines;
    }
    if (inode != 0 && inode_ != 0 && inode != inode_) {
        // Rotation: restart from the beginning of the new file.
        inode_ = inode;
        offset_ = 0;
        pending_.clear();
        return lines;
    }
    inode_ = inode;
    if (offset_ > size) {
        offset_ = 0;
        pending_.clear();
    }
    std::string chunk = pending_ + text.substr(newline + 1);
    std::size_t consumed = 0;
    std::size_t start = 0;
    while (lines.size() < maxLines) {
        const std::size_t end = chunk.find('\n', start);
        if (end == std::string::npos) {
            break;
        }
        std::string line = chunk.substr(start, end - start);
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(std::move(line));
        start = end + 1;
        consumed = start;
    }
    pending_ = chunk.substr(consumed);
    offset_ += consumed;
    return lines;
}

}  // namespace slaptop::collector
