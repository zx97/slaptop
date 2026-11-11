#include "slaptop/collector/ldap.hpp"

#include <ldap.h>
#include <sys/time.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <utility>

namespace slaptop {
namespace {

std::string toLower(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return text;
}

/// Splits a DN on unescaped commas and lowercases each component.
std::vector<std::string> dnComponents(const std::string& dn) {
    std::vector<std::string> parts;
    std::string current;
    bool escaped = false;
    for (const char c : dn) {
        if (escaped) {
            current.push_back(c);
            escaped = false;
            continue;
        }
        if (c == '\\') {
            current.push_back(c);
            escaped = true;
            continue;
        }
        if (c == ',') {
            parts.push_back(toLower(current));
            current.clear();
            continue;
        }
        current.push_back(c);
    }
    if (!current.empty()) {
        parts.push_back(toLower(current));
    }
    return parts;
}

bool startsWith(const std::string& text, const std::string& prefix) {
    return text.size() >= prefix.size() && text.compare(0, prefix.size(), prefix) == 0;
}

/// "cn=connection 1025" -> 1025 ; 0 when the shape differs.
unsigned long trailingNumber(const std::string& component) {
    const std::size_t space = component.rfind(' ');
    if (space == std::string::npos || space + 1 >= component.size()) {
        return 0;
    }
    try {
        return std::stoul(component.substr(space + 1));
    } catch (...) {
        return 0;
    }
}

std::string valueOrDefault(const std::string& value, const char* fallback) {
    return value.empty() ? std::string(fallback) : value;
}

/// SASL interaction callback for EXTERNAL, which needs no prompt.
///
/// OpenLDAP's LDAP_SASL_INTERACT_PROC takes (ld, flags, defaults, interact):
/// passing a NULL callback makes libldap fail with "Local error" instead of
/// completing the peer-credential exchange.
int saslInteract(LDAP* /*ld*/, unsigned /*flags*/, void* /*defaults*/, void* /*interact*/) {
    return LDAP_SUCCESS;
}

}  // namespace

// ---------------------------------------------------------------------------
// LdapEntry
// ---------------------------------------------------------------------------

const std::string& LdapEntry::first(const std::string& name) const {
    static const std::string empty;
    const std::string wanted = toLower(name);
    for (const auto& [attribute, values] : attributes) {
        if (toLower(attribute) == wanted) {
            if (!values.empty()) {
                return values.front();
            }
        }
    }
    return empty;
}

std::vector<std::string> LdapEntry::all(const std::string& name) const {
    const std::string wanted = toLower(name);
    for (const auto& [attribute, values] : attributes) {
        if (toLower(attribute) == wanted) {
            return values;
        }
    }
    return {};
}

std::uint64_t LdapEntry::number(const std::string& name) const {
    const std::string& raw = first(name);
    if (raw.empty()) {
        return 0;
    }
    try {
        return std::stoull(raw);
    } catch (...) {
        return 0;
    }
}

bool LdapEntry::flag(const std::string& name) const {
    const std::string& raw = first(name);
    return toLower(raw) == "true" || toLower(raw) == "yes";
}

// ---------------------------------------------------------------------------
// LdapClient
// ---------------------------------------------------------------------------

LdapClient::LdapClient(void* handle) : handle_(handle) {}

LdapClient::~LdapClient() {
    if (handle_ != nullptr) {
        ldap_unbind_ext_s(static_cast<LDAP*>(handle_), nullptr, nullptr);
    }
}

LdapClient::LdapClient(LdapClient&& other) noexcept
    : handle_(other.handle_), error_(std::move(other.error_)) {
    other.handle_ = nullptr;
}

LdapClient& LdapClient::operator=(LdapClient&& other) noexcept {
    if (this != &other) {
        if (handle_ != nullptr) {
            ldap_unbind_ext_s(static_cast<LDAP*>(handle_), nullptr, nullptr);
        }
        handle_ = other.handle_;
        error_ = std::move(other.error_);
        other.handle_ = nullptr;
    }
    return *this;
}

std::optional<LdapClient> LdapClient::open(const std::string& uri,
                                          const std::string& bindDn,
                                          const std::string& password,
                                          std::string* error,
                                          bool insecureTls,
                                          bool startTls) {
    // TLS settings are read from the *global* context when ldap_initialize
    // builds the handle's context, so they must be set before it — setting
    // them afterwards silently leaves the default verification in place and an
    // ldaps:// connection to a self-signed server fails with "Can't contact
    // LDAP server".
    if (insecureTls) {
        int requireCert = LDAP_OPT_X_TLS_NEVER;
        ldap_set_option(nullptr, LDAP_OPT_X_TLS_REQUIRE_CERT, &requireCert);
        int newContext = 1;
        ldap_set_option(nullptr, LDAP_OPT_X_TLS_NEWCTX, &newContext);
    }

    LDAP* ld = nullptr;
    const int init = ldap_initialize(&ld, uri.c_str());
    if (init != LDAP_SUCCESS || ld == nullptr) {
        if (error != nullptr) {
            *error = "ldap_initialize: " + std::string(ldap_err2string(init));
        }
        return std::nullopt;
    }

    int version = LDAP_VERSION3;
    ldap_set_option(ld, LDAP_OPT_PROTOCOL_VERSION, &version);

    // Bound every call: a monitoring loop must never hang on a dead socket.
    timeval timeout{3, 0};
    ldap_set_option(ld, LDAP_OPT_NETWORK_TIMEOUT, &timeout);
    ldap_set_option(ld, LDAP_OPT_TIMEOUT, &timeout);

    // StartTLS upgrades an ldap:// socket in place; ldaps:// is already TLS.
    if (startTls) {
        const int tls = ldap_start_tls_s(ld, nullptr, nullptr);
        if (tls != LDAP_SUCCESS) {
            if (error != nullptr) {
                *error = "starttls: " + std::string(ldap_err2string(tls));
            }
            ldap_unbind_ext_s(ld, nullptr, nullptr);
            return std::nullopt;
        }
    }

    int rc = LDAP_SERVER_DOWN;
    std::string externalError;
    if (bindDn == "EXTERNAL") {
        // SASL EXTERNAL (peer credentials on ldapi://).  Two libldap quirks
        // bite here: the raw ldap_sasl_bind_s stops at
        // LDAP_SASL_BIND_IN_PROGRESS, and the interactive helper needs a
        // non-NULL interaction callback even when nothing is prompted.
        rc = ldap_sasl_interactive_bind_s(ld, nullptr, "EXTERNAL", nullptr, nullptr,
                                          LDAP_SASL_QUIET, saslInteract, nullptr);
    } else if (!bindDn.empty()) {
        berval credential{};
        credential.bv_val = const_cast<char*>(password.data());
        credential.bv_len = static_cast<ber_len_t>(password.size());
        rc = ldap_sasl_bind_s(ld, bindDn.c_str(), LDAP_SASL_SIMPLE, &credential, nullptr,
                              nullptr, nullptr);
    } else {
        // Anonymous simple bind.  cred must be a *non-NULL* empty berval:
        // libldap rejects a NULL credential with LDAP_PROTOCOL_ERROR.
        berval anonymous{};
        anonymous.bv_val = const_cast<char*>("");
        anonymous.bv_len = 0;
        rc = ldap_sasl_bind_s(ld, "", LDAP_SASL_SIMPLE, &anonymous, nullptr, nullptr, nullptr);
        externalError.clear();
    }

    if (rc != LDAP_SUCCESS) {
        if (error != nullptr) {
            *error = "bind: " + std::string(ldap_err2string(rc));
            if (!externalError.empty()) {
                *error += " (EXTERNAL: " + externalError + ")";
            }
        }
        ldap_unbind_ext_s(ld, nullptr, nullptr);
        return std::nullopt;
    }
    return LdapClient(ld);
}

std::optional<std::vector<LdapEntry>> LdapClient::search(
    const std::string& base, int scope, const std::vector<std::string>& attributes,
    int sizeLimit, const std::string& filter, void** serverControls) {
    if (handle_ == nullptr) {
        error_ = "not connected";
        return std::nullopt;
    }
    auto* ld = static_cast<LDAP*>(handle_);

    std::vector<char*> requested;
    requested.reserve(attributes.size() + 1);
    for (const std::string& attribute : attributes) {
        requested.push_back(const_cast<char*>(attribute.c_str()));
    }
    requested.push_back(nullptr);

    LDAPMessage* result = nullptr;
    const int rc = ldap_search_ext_s(ld, base.c_str(), scope, filter.c_str(),
                                     requested.data(), 0,
                                     reinterpret_cast<LDAPControl**>(serverControls), nullptr,
                                     nullptr, sizeLimit, &result);
    // A size limit is a normal answer for the bounded queries (the server
    // stops at N entries and says so): the entries received are still valid.
    if (rc != LDAP_SUCCESS && rc != LDAP_SIZELIMIT_EXCEEDED) {
        error_ = ldap_err2string(rc);
        if (result != nullptr) {
            ldap_msgfree(result);
        }
        return std::nullopt;
    }
    if (rc == LDAP_SIZELIMIT_EXCEEDED && result == nullptr) {
        error_ = "size limit exceeded";
        return std::nullopt;
    }

    std::vector<LdapEntry> entries;
    for (LDAPMessage* message = ldap_first_entry(ld, result); message != nullptr;
         message = ldap_next_entry(ld, message)) {
        LdapEntry entry;
        if (char* dn = ldap_get_dn(ld, message); dn != nullptr) {
            entry.dn = dn;
            ldap_memfree(dn);
        }
        BerElement* ber = nullptr;
        for (char* attribute = ldap_first_attribute(ld, message, &ber); attribute != nullptr;
             attribute = ldap_next_attribute(ld, message, ber)) {
            std::vector<std::string> values;
            if (berval** raw = ldap_get_values_len(ld, message, attribute); raw != nullptr) {
                for (int i = 0; raw[i] != nullptr; ++i) {
                    values.emplace_back(raw[i]->bv_val,
                                        static_cast<std::size_t>(raw[i]->bv_len));
                }
                ldap_value_free_len(raw);
            }
            entry.attributes.emplace_back(attribute, std::move(values));
            ldap_memfree(attribute);
        }
        if (ber != nullptr) {
            ber_free(ber, 0);
        }
        entries.push_back(std::move(entry));
    }

    ldap_msgfree(result);
    error_.clear();
    return entries;
}

std::optional<MonitorSnapshot> LdapClient::fetchMonitor() {
    MonitorSnapshot snapshot;
    snapshot.collectedAt = std::chrono::system_clock::now();

    // Targeted searches, one per monitoring subtree, with explicit attribute
    // lists.  Never a subtree over cn=monitor: a production server can hold
    // 7000+ cn=Connection entries, and walking them on every poll would cost
    // the server we are watching.
    struct Lookup {
        const char* base;
        int scope;
        std::vector<std::string> attributes;
        /// Filter narrowing the subtree, or nullptr for (objectClass=*).
        const char* filter;
    };
    const std::vector<Lookup> lookups = {
        {"cn=Total,cn=Connections,cn=Monitor", LDAP_SCOPE_BASE, {"monitorCounter"}, nullptr},
        {"cn=Current,cn=Connections,cn=Monitor", LDAP_SCOPE_BASE, {"monitorCounter"},
         nullptr},
        {"cn=Max File Descriptors,cn=Connections,cn=Monitor", LDAP_SCOPE_BASE,
         {"monitorCounter"}, nullptr},
        {"cn=Operations,cn=Monitor", LDAP_SCOPE_SUBTREE,
         {"monitorOpInitiated", "monitorOpCompleted"}, nullptr},
        {"cn=Databases,cn=Monitor", LDAP_SCOPE_SUBTREE,
         {"monitoredInfo", "namingContexts", "monitorIsShadow", "readOnly", "monitorOverlay",
          "olmDbDirectory", "olmDbOperation", "olmMDBEntries", "olmMDBPagesMax",
          "olmMDBPagesUsed", "olmMDBPagesFree", "olmMDBPageSize", "olmMDBReadersMax",
          "olmMDBReadersUsed",
          "pcacheNumQueries", "pcacheNumEntries", "pcacheQueryURL"},
         // A proxy publishes one subtree per backend connection under
         // cn=Databases; without this filter they fill the size limit and the
         // real database entries never come back.
         "(!(cn=Connection*))"},
        {"cn=Listeners,cn=Monitor", LDAP_SCOPE_ONE,
         {"monitorConnectionLocalAddress", "monitoredInfo"}, nullptr},
        {"cn=Log,cn=Monitor", LDAP_SCOPE_BASE,
         {"monitorLogConnections", "monitorLogOps", "monitorLogEntries", "monitorLogRead",
          "monitorLogWrite", "monitorLogLevel"}, nullptr},
        // cn=Start and cn=Uptime, the only two entries worth reading here.
        {"cn=Time,cn=Monitor", LDAP_SCOPE_ONE, {"monitorTimestamp", "monitoredInfo"}, nullptr},
        // lloadd publishes its tiers and backend servers here.  The filter
        // drops its per-connection entries, which can be numerous.
        {"cn=Load Balancer,cn=Backends,cn=Monitor", LDAP_SCOPE_SUBTREE,
         {"cn", "olmServerURI", "olmActiveConnections", "olmPendingConnections",
          "olmPendingOps", "olmReceivedOps", "olmCompletedOps", "olmFailedOps"},
         "(!(cn=Connection*))"},
    };

    bool any = false;
    for (const Lookup& lookup : lookups) {
        const auto entries = lookup.filter == nullptr
                                 ? search(lookup.base, lookup.scope, lookup.attributes)
                                 : search(lookup.base, lookup.scope, lookup.attributes, 0,
                                          lookup.filter);
        if (!entries) {
            continue;  // a missing subtree must not abort the round
        }
        any = true;
        snapshot.raw.insert(snapshot.raw.end(), entries->begin(), entries->end());
    }
    if (!any) {
        return std::nullopt;
    }

    for (const LdapEntry& entry : snapshot.raw) {
        const std::vector<std::string> parts = dnComponents(entry.dn);
        if (parts.empty()) {
            continue;
        }
        // lloadd backend server: cn=<server>,cn=<tier>,cn=Backend Tiers,...
        if (!entry.first("olmServerURI").empty() && parts.size() >= 2) {
            LloadServer server;
            server.name = entry.first("cn").empty() ? parts[0] : entry.first("cn");
            if (const std::size_t brace = server.name.find('}'); brace != std::string::npos) {
                server.name = server.name.substr(brace + 1);
            }
            server.uri = entry.first("olmServerURI");
            server.activeConnections = entry.number("olmActiveConnections");
            server.pendingConnections = entry.number("olmPendingConnections");
            server.pendingOps = entry.number("olmPendingOps");
            server.receivedOps = entry.number("olmReceivedOps");
            server.completedOps = entry.number("olmCompletedOps");
            server.failedOps = entry.number("olmFailedOps");
            std::string tierKey = parts[1];
            if (tierKey.rfind("cn=", 0) == 0) {
                tierKey = tierKey.substr(3);
            }
            if (const std::size_t brace = tierKey.find('}'); brace != std::string::npos) {
                tierKey = tierKey.substr(brace + 1);  // "{0}tier 1" -> "tier 1"
            }
            bool attached = false;
            for (LloadTier& tier : snapshot.lloadTiers) {
                if (tier.name == tierKey) {
                    tier.servers.push_back(std::move(server));
                    attached = true;
                    break;
                }
            }
            if (!attached) {
                snapshot.lloadTiers.push_back(LloadTier{tierKey, {std::move(server)}});
            }
            continue;
        }
        const std::string& leaf = parts[0];
        const auto component = [&parts](std::size_t index) -> std::string {
            return index < parts.size() ? parts[index] : std::string();
        };

        if (leaf == "cn=total" && component(1) == "cn=connections") {
            snapshot.connectionsTotal = entry.number("monitorCounter");
        } else if (leaf == "cn=current" && component(1) == "cn=connections") {
            snapshot.connectionsCurrent = entry.number("monitorCounter");
        } else if (leaf == "cn=max file descriptors") {
            snapshot.maxFileDescriptors = entry.number("monitorCounter");
        } else if (leaf == "cn=operations" && component(1) == "cn=monitor") {
            snapshot.opsInitiated = entry.number("monitorOpInitiated");
            snapshot.opsCompleted = entry.number("monitorOpCompleted");
        } else if (component(1) == "cn=operations" && component(2) == "cn=monitor") {
            std::string type = leaf;
            if (startsWith(type, "cn=")) {
                type = type.substr(3);
            }
            if (const std::uint64_t initiated = entry.number("monitorOpInitiated"); initiated != 0) {
                snapshot.opsByType[type] = initiated;
            }
        } else if (startsWith(leaf, "cn=database ") && component(1) == "cn=databases") {
            DatabaseInfo database;
            database.label = leaf.substr(3);
            database.backend = entry.first("monitoredInfo");
            database.namingContexts = entry.all("namingContexts");
            database.shadow = entry.flag("monitorIsShadow");
            database.readOnly = entry.flag("readOnly");
            database.overlays = entry.all("monitorOverlay");
            database.directory = entry.first("olmDbDirectory");
            database.entries = entry.number("olmMDBEntries");
            database.pagesMax = entry.number("olmMDBPagesMax");
            database.pagesUsed = entry.number("olmMDBPagesUsed");
            database.pagesFree = entry.number("olmMDBPagesFree");
            database.pageSize = entry.number("olmMDBPageSize");
            database.readersUsed = entry.number("olmMDBReadersUsed");
            database.readersMax = entry.number("olmMDBReadersMax");
            database.pcacheQueries = entry.number("pcacheNumQueries");
            database.pcacheEntries = entry.number("pcacheNumEntries");
            for (const std::string& url : entry.all("pcacheQueryURL")) {
                // ldap:///<base>??<scope>?<filter>?x-uuid=..,x-expiry=..,x-answerable=N
                const std::size_t afterScheme = url.find(":///");
                if (afterScheme == std::string::npos) {
                    continue;
                }
                std::vector<std::string> fields;
                std::size_t begin = afterScheme + 4;
                while (begin <= url.size()) {
                    const std::size_t next = url.find('?', begin);
                    fields.push_back(url.substr(begin, next == std::string::npos
                                                          ? std::string::npos
                                                          : next - begin));
                    if (next == std::string::npos) {
                        break;
                    }
                    begin = next + 1;
                }
                if (fields.size() < 5) {
                    continue;
                }
                PcacheQuery query;
                query.base = fields[0];
                query.scope = fields[2];
                query.filter = fields[3];
                // parts[4] is the comma separated extension list.
                std::size_t position = 0;
                while (position < fields[4].size()) {
                    const std::size_t comma = fields[4].find(',', position);
                    const std::string item = fields[4].substr(
                        position, comma == std::string::npos ? std::string::npos
                                                             : comma - position);
                    const std::size_t equals = item.find('=');
                    if (equals != std::string::npos) {
                        const std::string key = item.substr(0, equals);
                        const std::string value = item.substr(equals + 1);
                        if (key == "x-uuid") {
                            query.uuid = value;
                        } else if (key == "x-answerable") {
                            try {
                                query.answerable = std::stoull(value);
                            } catch (const std::exception&) {
                            }
                        } else if (key == "x-expiry") {
                            try {
                                query.expiry = std::stoll(value);
                            } catch (const std::exception&) {
                            }
                        }
                    }
                    if (comma == std::string::npos) {
                        break;
                    }
                    position = comma + 1;
                }
                if (!query.uuid.empty()) {
                    database.pcache.push_back(std::move(query));
                }
            }
            snapshot.databases.push_back(std::move(database));
        } else if (component(1) == "cn=operations" && component(2).rfind("cn=database ", 0) == 0 &&
                   component(3) == "cn=databases") {
            for (DatabaseInfo& database : snapshot.databases) {
                if ("cn=" + database.label != component(2)) {
                    continue;
                }
                std::string type = leaf;
                if (startsWith(type, "cn=")) {
                    type = type.substr(3);
                }
                database.ops[type] = entry.number("olmDbOperation");
            }
        } else if (startsWith(leaf, "cn=listener ") && component(1) == "cn=listeners") {
            ListenerInfo listener;
            listener.address = entry.first("monitorConnectionLocalAddress");
            listener.tls = toLower(entry.first("monitoredInfo")) == "tls";
            snapshot.listeners.push_back(std::move(listener));
        } else if (leaf == "cn=log" && component(1) == "cn=monitor") {
            snapshot.logConnections = entry.number("monitorLogConnections");
            snapshot.logOps = entry.number("monitorLogOps");
            snapshot.logEntries = entry.number("monitorLogEntries");
            snapshot.logRead = entry.number("monitorLogRead");
            snapshot.logWrite = entry.number("monitorLogWrite");
            snapshot.logLevel = entry.first("monitorLogLevel");
        } else if (leaf == "cn=start" && component(1) == "cn=time") {
            // cn=Start carries the boot time in monitorTimestamp; there is no
            // monitorStartTime attribute, whatever the documentation says.
            snapshot.startTime = entry.first("monitorTimestamp");
        } else if (leaf == "cn=uptime" && component(1) == "cn=time") {
            snapshot.uptimeSeconds = entry.number("monitoredInfo");
        }
    }

    return snapshot;
}

std::optional<std::vector<ConnectionInfo>> LdapClient::fetchConnections(unsigned limit) {
    auto* ld = static_cast<LDAP*>(handle_);
    if (ld == nullptr) {
        error_ = "not connected";
        return std::nullopt;
    }

    // Only the attributes rendered by the dashboard: asking for "*" "+" costs
    // the server far more than this handful.
    static const std::vector<std::string> kAttributes = {
        "monitorConnectionNumber",        "monitorConnectionProtocol",
        "monitorConnectionListener",      "monitorConnectionPeerAddress",
        "monitorConnectionPeerDomain",    "monitorConnectionLocalAddress",
        "monitorConnectionOpsReceived",   "monitorConnectionOpsExecuting",
        "monitorConnectionOpsPending",    "monitorConnectionOpsCompleted",
        "monitorConnectionGet",           "monitorConnectionRead",
        "monitorConnectionWrite",         "monitorConnectionStartTime",
        "monitorConnectionActivityTime",
        "monitorConnectionAuthzDN",
        "monitorConnectionMask",
        "olmDbBoundDN",
        "olmDbConnURI",
        "olmDbConnPeerAddress",
        "olmDbConnFlags",
    };

    // No RFC 2891 sort: OpenLDAP answers "inappropriate matching" for the
    // operational attributes of cn=monitor, which made the whole search fail
    // and the connection list empty.  Neither can the filter use
    // monitorConnectionNumber (operational, no matching rule in filters), so
    // the RDN does the job and the ordering is done here.
    //
    // The server returns its entries in an unspecified order, so asking for
    // exactly `limit` would return an arbitrary slice and could miss every
    // recent connection.  Ask for a wide slice, then keep the newest: the list
    // is refreshed every 30 s, a few hundred entries cost nothing next to the
    // thousands a busy server holds.
    const int candidates = std::min(400, std::max<int>(static_cast<int>(limit) * 4, 40));
    const auto entries = search("cn=Connections,cn=Monitor", LDAP_SCOPE_ONE, kAttributes,
                                candidates, "(cn=Connection*)");

    if (!entries) {
        return std::nullopt;
    }

    std::vector<ConnectionInfo> connections;
    for (const LdapEntry& entry : *entries) {
        const std::vector<std::string> parts = dnComponents(entry.dn);
        if (parts.empty() || !startsWith(parts[0], "cn=connection ")) {
            continue;
        }
        ConnectionInfo info;
        info.number = trailingNumber(parts[0]);
        if (info.number == 0) {
            continue;
        }
        info.protocol = entry.first("monitorConnectionProtocol");
        info.listener = entry.first("monitorConnectionListener");
        info.peerAddress = entry.first("monitorConnectionPeerAddress");
        info.peerDomain = entry.first("monitorConnectionPeerDomain");
        info.localAddress = entry.first("monitorConnectionLocalAddress");
        info.opsReceived = entry.number("monitorConnectionOpsReceived");
        info.opsExecuting = entry.number("monitorConnectionOpsExecuting");
        info.opsPending = entry.number("monitorConnectionOpsPending");
        info.opsCompleted = entry.number("monitorConnectionOpsCompleted");
        info.ioGet = entry.number("monitorConnectionGet");
        info.ioRead = entry.number("monitorConnectionRead");
        info.ioWrite = entry.number("monitorConnectionWrite");
        info.startTime = entry.first("monitorConnectionStartTime");
        info.activityTime = entry.first("monitorConnectionActivityTime");
        info.authzDn = entry.first("monitorConnectionAuthzDN");
        info.mask = entry.first("monitorConnectionMask");
        info.backendBoundDn = entry.first("olmDbBoundDN");
        info.backendUri = entry.first("olmDbConnURI");
        info.backendPeerAddress = entry.first("olmDbConnPeerAddress");
        info.backendFlags = entry.first("olmDbConnFlags");
        connections.push_back(std::move(info));
    }
    // Keep the newest ones: the screen offers "newest" as its default order,
    // and that must mean the newest that exist, not the newest of a random
    // slice.
    std::sort(connections.begin(), connections.end(),
              [](const ConnectionInfo& a, const ConnectionInfo& b) {
                  return a.number > b.number;
              });
    if (connections.size() > limit) {
        connections.resize(limit);
    }
    return connections;
}

std::optional<std::vector<ConnectionInfo>> LdapClient::fetchBackendConnections(unsigned limit) {
    static const std::vector<std::string> kAttributes = {
        "monitorConnectionNumber",      "monitorConnectionProtocol",
        "monitorConnectionListener",    "monitorConnectionPeerAddress",
        "monitorConnectionPeerDomain",  "monitorConnectionLocalAddress",
        "monitorConnectionOpsReceived", "monitorConnectionOpsExecuting",
        "monitorConnectionOpsPending",  "monitorConnectionOpsCompleted",
        "monitorConnectionGet",         "monitorConnectionRead",
        "monitorConnectionWrite",       "monitorConnectionStartTime",
        "monitorConnectionActivityTime", "monitorConnectionAuthzDN",
        "monitorConnectionMask",        "olmDbBoundDN",
        "olmDbConnURI",                 "olmDbConnPeerAddress",
        "olmDbConnFlags",
    };
    // Backend connections hang under each database's own Connections subtree.
    const int candidates = std::min(200, std::max<int>(static_cast<int>(limit) * 3, 30));
    const auto entries = search("cn=Databases,cn=Monitor", LDAP_SCOPE_SUBTREE, kAttributes,
                                candidates, "(cn=Connection*)");
    if (!entries) {
        return std::nullopt;
    }
    std::vector<ConnectionInfo> connections;
    for (const LdapEntry& entry : *entries) {
        const std::vector<std::string> parts = dnComponents(entry.dn);
        if (parts.empty() || !startsWith(parts[0], "cn=connection ")) {
            continue;
        }
        ConnectionInfo info;
        info.number = trailingNumber(parts[0]);
        if (info.number == 0) {
            continue;
        }
        info.protocol = entry.first("monitorConnectionProtocol");
        info.listener = entry.first("monitorConnectionListener");
        info.peerAddress = entry.first("monitorConnectionPeerAddress");
        info.peerDomain = entry.first("monitorConnectionPeerDomain");
        info.localAddress = entry.first("monitorConnectionLocalAddress");
        info.opsReceived = entry.number("monitorConnectionOpsReceived");
        info.opsExecuting = entry.number("monitorConnectionOpsExecuting");
        info.opsPending = entry.number("monitorConnectionOpsPending");
        info.opsCompleted = entry.number("monitorConnectionOpsCompleted");
        info.ioGet = entry.number("monitorConnectionGet");
        info.ioRead = entry.number("monitorConnectionRead");
        info.ioWrite = entry.number("monitorConnectionWrite");
        info.startTime = entry.first("monitorConnectionStartTime");
        info.activityTime = entry.first("monitorConnectionActivityTime");
        info.authzDn = entry.first("monitorConnectionAuthzDN");
        info.mask = entry.first("monitorConnectionMask");
        info.backendBoundDn = entry.first("olmDbBoundDN");
        info.backendUri = entry.first("olmDbConnURI");
        info.backendPeerAddress = entry.first("olmDbConnPeerAddress");
        info.backendFlags = entry.first("olmDbConnFlags");
        info.isBackend = true;
        connections.push_back(std::move(info));
    }
    std::sort(connections.begin(), connections.end(),
              [](const ConnectionInfo& a, const ConnectionInfo& b) {
                  return a.number > b.number;
              });
    if (connections.size() > limit) {
        connections.resize(limit);
    }
    return connections;
}

std::optional<LogFileConfig> LdapClient::fetchLogConfig() {
    const auto entries = search("cn=config", LDAP_SCOPE_BASE,
                                {"olcLogFile", "olcLogFileFormat", "olcLogLevel"});
    if (!entries || entries->empty()) {
        return std::nullopt;
    }
    LogFileConfig config;
    config.path = (*entries)[0].first("olcLogFile");
    config.format = valueOrDefault((*entries)[0].first("olcLogFileFormat"), "debug");
    // olcLogLevel is multi-valued: one value per level ("stats", "sync", ...).
    // Reading only the first would be luck, and cn=config does not guarantee
    // an order.
    std::string levels;
    for (const std::string& value : (*entries)[0].all("olcLogLevel")) {
        if (!levels.empty()) {
            levels.push_back(' ');
        }
        levels += value;
    }
    config.level = levels.empty() ? "stats" : levels;
    return config;
}

std::optional<std::vector<std::string>> LdapClient::fetchContextCsn(const std::string& baseDn) {
    if (baseDn.empty()) {
        return std::vector<std::string>{};
    }
    const auto entries = search(baseDn, LDAP_SCOPE_BASE, {"contextCSN"});
    if (!entries) {
        return std::nullopt;
    }
    if (entries->empty()) {
        return std::vector<std::string>{};
    }
    return (*entries)[0].all("contextCSN");
}

}  // namespace slaptop
