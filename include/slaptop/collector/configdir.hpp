#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace slaptop::collector {

/// One database declared in a slapd `cn=config` tree.
struct DirectoryDatabase {
    std::string label;      ///< "{3}mdb" as written in olcDatabase
    std::string backend;    ///< mdb, ldap, config, monitor, null, ...
    std::string suffix;     ///< olcSuffix
    std::string uri;        ///< olcDbURI (back-ldap proxy target)
    std::string directory;  ///< olcDbDirectory
    std::vector<std::string> overlays;
    /// Providers named in olcSyncrepl ("provider=ldaps://...").
    std::vector<std::string> syncreplProviders;
    /// The same declarations, parsed: rid, provider URI, search base and type.
    /// The configured topology is known even when contextCSN cannot be read,
    /// which is exactly when the operator needs it most.
    struct Syncrepl {
        int rid{0};
        std::string provider;
        std::string searchBase;
        std::string type;  ///< refreshAndPersist, refreshOnly, ...
    };
    std::vector<Syncrepl> syncrepl;
    /// Target of the `chain` overlay on this database (olcDbURI), empty when
    /// there is none.  It is a referral to another server, not a replication
    /// link, but it is a real dependency worth drawing.
    std::string chainUri;
    /// The suffix the chain handles, read from suffixmassage in olcDbRewrite.
    std::string chainSuffix;
    /// olcDbCacheSize / olcDbCacheFree: the entry cache of the backend (mdb)
    /// and how many entries it frees when full.  0 when not configured.
    std::uint64_t cacheSize{0};
    std::uint64_t cacheFree{0};
    /// Raw `olcDbIndex` lines ("uid eq", "default sub", ...), verbatim: the
    /// index cross-reference screen splits them, and that logic is testable on
    /// its own.
    std::vector<std::string> indexes;
    /// olcPcache of a pcache overlay ("mdb 100000 4 1000 100"): the proxy
    /// cache parameters, kept verbatim because their fields are positional.
    std::string pcacheSpec;
    bool multiProvider{false};
};

/// A database declared *inside* an overlay, such as the MDB file pcache uses
/// for its cache:
///   olcDatabase={0}mdb,olcOverlay={0}pcache,olcDatabase={1}ldap,cn=config
/// It is not a served database (no suffix), so it never shows in cn=monitor's
/// Databases list, but it has a directory and therefore a disk.
struct OverlayDatabase {
    std::string overlay;    ///< pcache, syncprov, ...
    std::string label;      ///< "{0}mdb"
    std::string directory;  ///< olcDbDirectory
    /// The backend keeps its own `olcDbIndex` lines, even when its only writer
    /// is the overlay.  Read them: whether they are useful is a separate
    /// question, but pretending they do not exist is wrong.
    std::vector<std::string> indexes;
};

/// One lloadd backend tier, as declared in cn=config.
struct LloadTier {
    std::string name;
    std::vector<std::string> servers;  ///< backend names (cn={0}server 1, ...)
};

/// One `olcServerID` value.  The attribute is multi-valued when several URLs
/// are served by the same instance: "1 ldap://host1" and "2 ldap://host2".
struct ServerId {
    int sid{0};
    std::string uri;  ///< empty when the value carries only the SID
};

/// Everything the dashboard needs to draw the architecture of one instance.
struct DirectoryConfig {
    std::vector<DirectoryDatabase> databases;
    std::string serverId;  ///< first olcServerID, as written
    /// Every olcServerID value: the SID each naming context owns, which is
    /// what lets the replication view attribute a contextCSN to a server.
    std::vector<ServerId> serverIds;
    /// True when the instance loads the lloadd module (LDAP load balancer).
    bool hasLload{false};
    std::vector<LloadTier> lloadTiers;
    /// Databases owned by an overlay (the pcache cache file, for instance).
    std::vector<OverlayDatabase> overlayDatabases;
};

/// Reads `<configDir>/cn=config` (the directory given to `slapd -F`).
///
/// Plain file access: `cn=config` is usually not readable over LDAP without
/// credentials, while slapd's own directory is readable by its owner.
/// Returns an empty config when the tree cannot be read.
DirectoryConfig readDirectoryConfig(const std::string& configDir);

/// Reads a `slapd.conf` style file, the layout used when slapd runs with `-f`
/// instead of `-F`.  Only what slaptop displays is extracted: databases with
/// their suffix, directory, upstream URI and overlays.
DirectoryConfig readSlapdConf(const std::string& path);

/// `logfile <path>` of a slapd.conf style file, empty when absent.
std::string logFileFromSlapdConf(const std::string& path);

/// Config directory of an instance whose command line has no `-F`:
/// `$LDAPCONF<NAME>` then `$LDAPCONF`, where NAME is the instance name in
/// capitals without punctuation ("proxy" -> LDAPCONFPC).  Empty when neither is
/// set or the directory does not exist.
std::string configDirFromEnvironment(const std::string& instanceName);

}  // namespace slaptop::collector
