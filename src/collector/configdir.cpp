#include "slaptop/collector/configdir.hpp"

#include <dirent.h>
#include <sys/stat.h>

#include <algorithm>
#include <cctype>
#include <unistd.h>

#include <cctype>
#include <cstdlib>
#include <fstream>
#include <sstream>
#include <map>

namespace slaptop::collector {
namespace {

struct LdifEntry {
    std::string dn;
    int depth{0};             ///< 0/1 = directly under the config tree, deeper = nested
    std::string parent;       ///< enclosing olcDatabase={N}type directory, if any
    std::map<std::string, std::vector<std::string>> attributes;

    std::string first(const std::string& name) const {
        const auto it = attributes.find(name);
        return it == attributes.end() || it->second.empty() ? std::string() : it->second.front();
    }

    bool has(const std::string& name) const { return attributes.count(name) != 0; }

    std::vector<std::string> all(const std::string& name) const {
        const auto it = attributes.find(name);
        return it == attributes.end() ? std::vector<std::string>() : it->second;
    }
};

std::string lower(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

/// Appends one file's entries to `entries`, following LDIF folding rules.
void parseLdifFile(const std::string& path, std::vector<LdifEntry>& entries, int depth,
                   const std::string& parent, const std::string& ancestry) {
    std::ifstream in(path);
    if (!in) {
        return;
    }
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        lines.push_back(line);
    }

    LdifEntry current;
    bool started = false;
    std::size_t index = 0;
    while (index < lines.size()) {
        if (lines[index].empty()) {
            if (started) {
                entries.push_back(std::move(current));
                current = LdifEntry{};
                started = false;
            }
            ++index;
            continue;
        }
        if (lines[index].front() == '#') {
            ++index;
            continue;
        }
        const std::size_t colon = lines[index].find(':');
        if (colon == std::string::npos) {
            ++index;
            continue;
        }
        std::string key = lower(lines[index].substr(0, colon));
        std::string value = lines[index].substr(colon + 1);
        if (!value.empty() && value.front() == ' ') {
            value.erase(0, 1);
        }
        // Folded continuation lines start with a single space.
        while (index + 1 < lines.size() && !lines[index + 1].empty() &&
               lines[index + 1].front() == ' ') {
            value += lines[++index].substr(1);
        }
        if (key == "dn") {
            current.dn = value;
            started = true;
        } else {
            current.attributes[key].push_back(value);
            started = true;
        }
        ++index;
    }
    if (started) {
        entries.push_back(std::move(current));
    }
    for (LdifEntry& entry : entries) {
        if (entry.depth == 0) {
            entry.depth = depth;
        }
        if (entry.parent.empty()) {
            entry.parent = parent;
        }
        // Inside a nested directory slapd writes only the RDN on the `dn:`
        // line (`dn: olcDatabase={0}mdb`) and the rest comes from the path.
        // Without rebuilding the full DN, an overlay-owned database looks like
        // a top-level one and its directory is never found.
        if (!ancestry.empty() && entry.dn.find(',') == std::string::npos) {
            entry.dn += "," + ancestry;
        }
    }
}

/// slapd keeps rotated copies next to the live tree
/// (`olcOverlay={0}chain.bak_121833/`, `*.orig`, `*~`).  Reading them invents
/// databases that no longer exist.
bool isBackupName(const std::string& name) {
    const std::string lowered = lower(name);
    return lowered.find(".bak") != std::string::npos ||
           lowered.find(".orig") != std::string::npos ||
           lowered.find(".save") != std::string::npos ||
           lowered.find(".rpmnew") != std::string::npos ||
           lowered.find(".rpmsave") != std::string::npos ||
           lowered.find(".old") != std::string::npos ||
           (!name.empty() && name.back() == '~');
}

void walk(const std::string& directory, std::vector<LdifEntry>& entries, int depth,
          const std::string& ancestry) {
    if (depth > 4) {
        return;
    }
    DIR* dir = ::opendir(directory.c_str());
    if (dir == nullptr) {
        return;
    }
    std::vector<std::string> subdirectories;
    std::vector<std::string> files;
    while (const dirent* entry = ::readdir(dir)) {
        const std::string name = entry->d_name;
        if (name == "." || name == ".." || isBackupName(name)) {
            continue;
        }
        const std::string path = directory + "/" + name;
        struct stat info {};
        if (::stat(path.c_str(), &info) != 0) {
            continue;
        }
        if (S_ISDIR(info.st_mode)) {
            subdirectories.push_back(path);
        } else if (name.size() > 5 && name.compare(name.size() - 5, 5, ".ldif") == 0) {
            files.push_back(path);
        }
    }
    ::closedir(dir);
    std::sort(files.begin(), files.end());
    // slapd writes overlay files as `olcOverlay={0}syncprov.ldif` inside an
    // `olcDatabase={N}type/` directory: the DN carries no parent, the path does.
    std::string parent;
    const std::size_t slash = directory.rfind('/');
    const std::string base = slash == std::string::npos ? directory : directory.substr(slash + 1);
    if (base.rfind("olcDatabase=", 0) == 0) {
        parent = base;
    }
    for (const std::string& file : files) {
        parseLdifFile(file, entries, depth, parent, ancestry);
    }
    std::sort(subdirectories.begin(), subdirectories.end());
    for (const std::string& sub : subdirectories) {
        // The DN the subdirectory stands for: its name, then the chain above.
        const std::size_t cut = sub.rfind('/');
        const std::string name = cut == std::string::npos ? sub : sub.substr(cut + 1);
        const std::string childAncestry =
            ancestry.empty() ? name : name + "," + ancestry;
        walk(sub, entries, depth + 1, childAncestry);
    }
}

/// "ldaps://host:2636/???" -> "ldaps://host:2636"
std::string cleanUri(std::string uri) {
    if (!uri.empty() && uri.front() == '"') {
        uri.erase(0, 1);
    }
    if (!uri.empty() && uri.back() == '"') {
        uri.pop_back();
    }
    const std::size_t slash = uri.find('/', uri.find("://") + 3);
    if (slash != std::string::npos) {
        uri = uri.substr(0, slash);
    }
    return uri;
}

/// Extracts the provider URIs from an olcSyncrepl value.
std::vector<std::string> syncreplProviders(const std::vector<std::string>& syncrepl) {
    std::vector<std::string> providers;
    for (const std::string& line : syncrepl) {
        std::size_t position = 0;
        while ((position = line.find("provider=", position)) != std::string::npos) {
            position += 9;
            std::size_t end = line.find_first_of(" \t", position);
            if (end == std::string::npos) {
                end = line.size();
            }
            providers.push_back(cleanUri(line.substr(position, end - position)));
            position = end;
        }
    }
    return providers;
}

/// Every `olcSyncrepl` value parsed into the fields the replication view needs.
std::vector<DirectoryDatabase::Syncrepl> parseSyncrepl(
    const std::vector<std::string>& syncrepl) {
    std::vector<DirectoryDatabase::Syncrepl> consumers;
    for (const std::string& line : syncrepl) {
        DirectoryDatabase::Syncrepl consumer;
        std::size_t position = 0;
        // Each line is a space separated list of key=value pairs.
        while (position < line.size()) {
            while (position < line.size() && line[position] == ' ') {
                ++position;
            }
            const std::size_t equals = line.find('=', position);
            if (equals == std::string::npos) {
                break;
            }
            std::string key = lower(line.substr(position, equals - position));
            // The first pair carries the index: "{0}rid=112".
            if (!key.empty() && key.front() == '{') {
                const std::size_t brace = key.find('}');
                if (brace != std::string::npos) {
                    key = key.substr(brace + 1);
                }
            }
            std::size_t end = line.find(' ', equals);
            if (end == std::string::npos) {
                end = line.size();
            }
            std::string value = line.substr(equals + 1, end - equals - 1);
            // "searchbase=\"dc=example,dc=com\"" arrives quoted: keeping the
            // quotes made the context compare unequal to the naming context
            // cn=monitor publishes, so a perfectly valid agreement was ignored.
            if (value.size() >= 2 && value.front() == '"' && value.back() == '"') {
                value = value.substr(1, value.size() - 2);
            }
            if (key == "rid") {
                consumer.rid = static_cast<int>(std::strtol(value.c_str(), nullptr, 10));
            } else if (key == "provider") {
                consumer.provider = cleanUri(value);
            } else if (key == "searchbase") {
                consumer.searchBase = value;
            } else if (key == "type") {
                consumer.type = value;
            }
            position = end;
        }
        if (!consumer.provider.empty()) {
            consumers.push_back(std::move(consumer));
        }
    }
    return consumers;
}

/// "{-1}frontend" -> "frontend", "{3}mdb" -> "mdb"
std::string backendOf(const std::string& olcDatabase) {
    const std::size_t brace = olcDatabase.find('}');
    return brace == std::string::npos ? olcDatabase : olcDatabase.substr(brace + 1);
}

}  // namespace

DirectoryConfig readDirectoryConfig(const std::string& configDir) {
    DirectoryConfig config;
    if (configDir.empty()) {
        return config;
    }
    std::vector<LdifEntry> entries;
    walk(configDir, entries, 0, std::string());

    // Overlays live either as files dn: olcOverlay=...,olcDatabase=... or as
    // their own entries; attach them to the database from their DN.
    for (const LdifEntry& entry : entries) {
        const std::string dn = lower(entry.dn);
        // A live database is a direct child of cn=config:
        //   olcDatabase={3}mdb,cn=config
        // deeper entries (inside a backup or an overlay subtree) are ignored.
        // A live database is declared at the top of the tree; entries nested
        // deeper belong to an overlay subtree (e.g. the chain overlay declares
        // its own olcDatabase={0}ldap) or to an archived copy.
        const bool directChild = entry.depth <= 1 && dn.rfind("olcdatabase=", 0) == 0 &&
                                 dn.find(",olcdatabase=") == std::string::npos &&
                                 !entry.has("olcoverlay");
        if (directChild) {
            const std::string label = entry.first("olcdatabase");
            const bool duplicate =
                std::any_of(config.databases.begin(), config.databases.end(),
                            [&label](const DirectoryDatabase& existing) {
                                return existing.label == label;
                            });
            if (duplicate) {
                continue;
            }
            DirectoryDatabase database;
            database.label = label;
            database.backend = backendOf(database.label);
            database.suffix = entry.first("olcsuffix");
            database.uri = cleanUri(entry.first("olcdburi"));
            database.directory = entry.first("olcdbdirectory");
            database.multiProvider = lower(entry.first("olcmultiprovider")) == "true";
            // olcDbIndex lines, verbatim: this is the database's own index set.
            // Reading them from the overlay entries (as an earlier version did)
            // made every database look unindexed, which is worse than no
            // screen at all.
            for (const std::string& value : entry.all("olcdbindex")) {
                database.indexes.push_back(value);
            }
            if (const auto it = entry.attributes.find("olcsyncrepl");
                it != entry.attributes.end()) {
                database.syncreplProviders = syncreplProviders(it->second);
                database.syncrepl = parseSyncrepl(it->second);
            }
            config.databases.push_back(std::move(database));
        } else if (dn.find(",olcoverlay=") != std::string::npos &&
                   entry.has("olcdbdirectory")) {
            // A database nested under an overlay: pcache's cache, for one.
            OverlayDatabase database;
            const std::size_t at = dn.find("olcoverlay=");
            const std::size_t end = dn.find(',', at);
            std::string overlay = dn.substr(at + 11, end == std::string::npos
                                                       ? std::string::npos
                                                       : end - at - 11);
            if (const std::size_t brace = overlay.find('}'); brace != std::string::npos) {
                overlay = overlay.substr(brace + 1);
            }
            database.overlay = overlay;
            database.label = entry.first("olcdatabase");
            for (const std::string& value : entry.all("olcdbindex")) {
                database.indexes.push_back(value);
            }
            database.directory = entry.first("olcdbdirectory");
            config.overlayDatabases.push_back(std::move(database));
        } else if (entry.has("olcserverid")) {
            config.serverId = entry.first("olcserverid");
            // Every value counts: "1 ldap://host1" and "2 ldap://host2" in the
            // same entry mean this slapd owns both SIDs.
            const auto values = entry.all("olcserverid");
            for (const std::string& value : values) {
                ServerId server;
                std::size_t position = 0;
                while (position < value.size() &&
                       std::isdigit(static_cast<unsigned char>(value[position]))) {
                    server.sid = server.sid * 10 + (value[position] - '0');
                    ++position;
                }
                while (position < value.size() && value[position] == ' ') {
                    ++position;
                }
                server.uri = cleanUri(value.substr(position));
                if (server.sid != 0) {
                    config.serverIds.push_back(std::move(server));
                }
            }
        }
    }

    // lloadd (the LDAP load balancer) is declared as a backend, not a database:
    //   olcBackend={0}lload,cn=config
    //   cn={0}tier 1,olcBackend={0}lload,cn=config
    //   cn={0}server 1,cn={0}tier 1,olcBackend={0}lload,cn=config
    for (const LdifEntry& entry : entries) {
        const std::string dn = lower(entry.dn);
        const std::string backend = lower(entry.first("olcbackend"));
        if (backend == "{0}lload" || backend.rfind("{0}lload", 0) == 0) {
            config.hasLload = true;
            continue;
        }
        if (dn.find("olcbackend=") == std::string::npos ||
            dn.find("lload") == std::string::npos) {
            continue;
        }
        config.hasLload = true;
        const std::string label = lower(entry.first("cn"));
        const std::size_t tierMarker = dn.find(",cn=");
        if (tierMarker != std::string::npos) {
            // "cn={0}server 1,cn={0}tier 1,...": a server inside a tier.
            const std::string tierLeaf = dn.substr(tierMarker + 4, dn.find(',', tierMarker + 4) -
                                                                        (tierMarker + 4));
            for (LloadTier& tier : config.lloadTiers) {
                if (lower(tier.name) == tierLeaf) {
                    tier.servers.push_back(label);
                }
            }
        } else if (!label.empty()) {
            config.lloadTiers.push_back(LloadTier{label, {}});
        }
    }

    // Second pass: overlays, now that every database exists.
    for (const LdifEntry& entry : entries) {
        const std::string dn = lower(entry.dn);
        if (const std::string overlays = entry.first("olcoverlay"); !overlays.empty()) {
            // The DN names the database this overlay belongs to:
            // olcOverlay={0}syncprov,olcDatabase={3}mdb,cn=config
            std::string target;
            if (const std::size_t marker = dn.find("olcdatabase="); marker != std::string::npos) {
                std::size_t end = dn.find(',', marker);
                if (end == std::string::npos) {
                    end = dn.size();
                }
                target = dn.substr(marker + 12, end - marker - 12);
            } else {
                target = lower(entry.parent);  // "olcDatabase={2}mdb"
            }
            if (target.rfind("olcdatabase=", 0) == 0) {
                target = target.substr(12);
            }
            if (target.empty()) {
                continue;
            }
            const std::string name = backendOf(overlays);
            for (DirectoryDatabase& database : config.databases) {
                if (lower(database.label) != target) {
                    continue;
                }
                database.overlays.push_back(name);
                // Entry cache of the backend that owns this database.
                if (const std::string cache = entry.first("olcdbcachesize");
                    !cache.empty()) {
                    database.cacheSize = std::strtoull(cache.c_str(), nullptr, 10);
                }
                if (const std::string free = entry.first("olcdbcachefree");
                    !free.empty()) {
                    database.cacheFree = std::strtoull(free.c_str(), nullptr, 10);
                }
                if (name == "pcache") {
                    // The overlay carries the whole proxy-cache setup.
                    database.pcacheSpec = entry.first("olcpcache");
                    if (const std::string cache = entry.first("olcdbcachesize");
                        !cache.empty() && database.cacheSize == 0) {
                        database.cacheSize = std::strtoull(cache.c_str(), nullptr, 10);
                    }
                    if (const std::string free = entry.first("olcdbcachefree");
                        !free.empty() && database.cacheFree == 0) {
                        database.cacheFree = std::strtoull(free.c_str(), nullptr, 10);
                    }
                }
                // The chain overlay declares its upstream and the suffix it
                // forwards: the only reliable source, since the referral entry
                // sits at an arbitrary depth (cn=non_auth_referral,...).
                if (name == "chain") {
                    database.chainUri = entry.first("olcdburi");
                    const std::string rewrite = entry.first("olcdbrewritE");
                    const std::string rule = rewrite.empty() ? entry.first("olcdbRewritE")
                                                             : rewrite;
                    const std::size_t massage = lower(rule).find("suffixmassage=");
                    if (massage != std::string::npos) {
                        const std::size_t quote = rule.find('"', massage);
                        if (quote != std::string::npos) {
                            const std::size_t close = rule.find('"', quote + 1);
                            if (close != std::string::npos) {
                                database.chainSuffix = rule.substr(quote + 1, close - quote - 1);
                            }
                        }
                    }
                }
            }
        }
    }

    std::sort(config.databases.begin(), config.databases.end(),
              [](const DirectoryDatabase& a, const DirectoryDatabase& b) {
                  return a.label < b.label;
              });
    return config;
}

DirectoryConfig readSlapdConf(const std::string& path) {
    DirectoryConfig config;
    std::ifstream in(path);
    if (!in) {
        return config;
    }
    std::string line;
    DirectoryDatabase* current = nullptr;
    while (std::getline(in, line)) {
        const std::size_t start = line.find_first_not_of(" \t\r");
        if (start == std::string::npos || line[start] == '#') {
            continue;
        }
        std::istringstream fields(line.substr(start));
        std::string directive;
        fields >> directive;
        // A directive value may be quoted and contain spaces.
        std::string rest;
        std::getline(fields, rest);
        const std::size_t first = rest.find_first_not_of(" \t");
        rest = first == std::string::npos ? std::string() : rest.substr(first);
        if (rest.size() >= 2 && rest.front() == '"' && rest.back() == '"') {
            rest = rest.substr(1, rest.size() - 2);
        }
        if (directive == "database") {
            DirectoryDatabase database;
            database.backend = rest;
            database.label = "database " + std::to_string(config.databases.size() + 1);
            config.databases.push_back(std::move(database));
            current = &config.databases.back();
            continue;
        }
        if (current == nullptr) {
            continue;
        }
        if (directive == "suffix") {
            current->suffix = rest;
        } else if (directive == "directory") {
            current->directory = rest;
        } else if (directive == "uri") {
            // back-ldap: the first value is the upstream, the same field the
            // cn=config view calls olcDbURI.
            current->uri = rest;
        } else if (directive == "index") {
            current->indexes.push_back(rest);
        } else if (directive == "overlay") {
            current->overlays.push_back(rest);
            if (rest == "chain") {
                current->chainUri = current->uri;
            }
        } else if (directive == "serverID") {
            ServerId server;
            std::istringstream value(rest);
            value >> server.sid;
            value >> server.uri;
            if (server.sid != 0) {
                config.serverIds.push_back(std::move(server));
            }
        }
    }
    // The config and monitor backends are always loaded and never interesting.
    config.databases.erase(
        std::remove_if(config.databases.begin(), config.databases.end(),
                       [](const DirectoryDatabase& database) {
                           return database.backend == "config" || database.backend == "monitor" ||
                                  database.backend == "frontend";
                       }),
        config.databases.end());
    return config;
}

std::string logFileFromSlapdConf(const std::string& path) {
    std::ifstream in(path);
    if (!in) {
        return {};
    }
    std::string line;
    while (std::getline(in, line)) {
        const std::size_t start = line.find_first_not_of(" \t\r");
        if (start == std::string::npos || line[start] == '#') {
            continue;
        }
        if (line.compare(start, 7, "logfile") != 0) {
            continue;
        }
        std::string value = line.substr(start + 7);
        const std::size_t first = value.find_first_not_of(" \t");
        if (first == std::string::npos) {
            return {};
        }
        value = value.substr(first);
        while (!value.empty() && (value.back() == '\r' || value.back() == '\n' || value.back() == ' ')) {
            value.pop_back();
        }
        return value;
    }
    return {};
}

std::string configDirFromEnvironment(const std::string& instanceName) {
    std::string suffix;
    for (const char c : instanceName) {
        if (std::isalnum(static_cast<unsigned char>(c)) != 0) {
            suffix.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(c))));
        }
    }
    for (const std::string& name :
         {std::string("LDAPCONF") + suffix, std::string("LDAPCONF")}) {
        const char* value = std::getenv(name.c_str());
        if (value == nullptr || *value == '\0') {
            continue;
        }
        if (::access(value, R_OK) == 0) {
            return value;
        }
    }
    return {};
}

}  // namespace slaptop::collector
