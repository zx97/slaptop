#include "slaptop/topology.hpp"

#include <algorithm>
#include <cctype>
#include <string>
#include <vector>

#include "slaptop/collector/configdir.hpp"
#include "slaptop/collector/ldap.hpp"

namespace slaptop {

/// Host and port of a listener or of a declared URI.  Handles both shapes the
/// tree carries: "IP=0.0.0.0:1389" from cn=monitor, "ldaps://host:636/" from
/// olcDbURI/olcSyncrepl.
void endpointOf(const std::string& text, std::string& host, int& port) {
    std::string value = text;
    if (value.rfind("IP=", 0) == 0) {
        value = value.substr(3);
    }
    const std::size_t scheme = value.find("://");
    if (scheme != std::string::npos) {
        value = value.substr(scheme + 3);
    }
    const std::size_t slash = value.find_first_of("/?#");
    if (slash != std::string::npos) {
        value.resize(slash);
    }
    const std::size_t colon = value.rfind(':');
    host = colon == std::string::npos ? value : value.substr(0, colon);
    port = 0;
    if (colon != std::string::npos) {
        try {
            port = std::stoi(value.substr(colon + 1));
        } catch (...) {
            port = 0;
        }
    }
    // A bracketed IPv6 literal keeps its brackets off the comparison.
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    for (char& c : host) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
}

bool wildcardHost(const std::string& host) {
    return host.empty() || host == "0.0.0.0" || host == "::" || host == "*" ||
           host == "localhost" || host == "127.0.0.1" || host == "::1";
}

/// Short name of an FQDN, lowercased: "ldap1.example.com" -> "ldap1".
std::string shortHost(std::string host) {
    const std::size_t dot = host.find('.');
    if (dot != std::string::npos) {
        host.resize(dot);
    }
    for (char& character : host) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return host;
}

/// True when an FQDN ends with the label an instance was discovered under:
/// "ldap2.example.com" ends with "ldap2".  Labels shorter than three
/// characters are ignored: they would match half the fleet by accident.
bool hostMatchesName(const std::string& host, const std::string& label) {
    if (label.size() < 3) {
        return false;
    }
    // The name sits in the first label of the FQDN ("ldap2" in
    // "ldap2.example.com"), not at the end of the whole name.
    const std::string shortName = shortHost(host);
    if (shortName.size() < label.size()) {
        return false;
    }
    std::string lowered = label;
    for (char& character : lowered) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return shortName.compare(shortName.size() - lowered.size(), lowered.size(), lowered) == 0;
}

/// Instance a declared URI points at.  The host name comes first — the fleet
/// discovered every instance under its own name, and every node here listens on
/// the same four ports, so matching the port alone picked whichever instance
/// was examined first (it linked the third node to the first instead of the second).  Then host:port,
/// then the port alone when exactly one instance listens on it, otherwise -1:
/// the caller draws an unresolved label instead of a wrong arrow.
int resolveInstance(const FleetSnapshot& fleet, std::size_t from, const std::string& uri) {
    std::string host;
    int port = 0;
    endpointOf(uri, host, port);
    if (!wildcardHost(host)) {
        int byName = -1;
        int candidates = 0;
        for (std::size_t j = 0; j < fleet.instances.size(); ++j) {
            if (j == from) {
                continue;
            }
            const Instance& other = fleet.instances[j].instance;
            if (hostMatchesName(host, other.name) || hostMatchesName(host, other.nodeLabel)) {
                ++candidates;
                byName = static_cast<int>(j);
            }
        }
        if (candidates == 1) {
            return byName;
        }
    }
    if (port == 0) {
        return -1;
    }
    int byPort = -1;
    int portCandidates = 0;
    for (std::size_t j = 0; j < fleet.instances.size(); ++j) {
        if (j == from) {
            continue;
        }
        for (const ListenerInfo& listener : fleet.instances[j].monitor.listeners) {
            std::string lhost;
            int lport = 0;
            endpointOf(listener.address, lhost, lport);
            if (lport != port) {
                continue;
            }
            if (!wildcardHost(host) && !wildcardHost(lhost) &&
                shortHost(host) == shortHost(lhost)) {
                return static_cast<int>(j);
            }
            ++portCandidates;
            byPort = static_cast<int>(j);
        }
    }
    return portCandidates == 1 ? byPort : -1;
}

/// Replica set of each instance: the connected component of the declared
/// olcSyncRepl graph.  A SID means nothing outside the set that replicates it —
/// ldap1/ldap2 and ldap3/ldap4 are two independent pairs, and comparing one pair's
/// SID with the other pair's year-old leftover reported a year of lag that no
/// agreement will ever close.
std::vector<int> replicaSets(const FleetSnapshot& fleet) {
    std::vector<int> parent(fleet.instances.size());
    for (std::size_t index = 0; index < parent.size(); ++index) {
        parent[index] = static_cast<int>(index);
    }
    const auto find = [&parent](int index) {
        while (parent[static_cast<std::size_t>(index)] != index) {
            parent[static_cast<std::size_t>(index)] =
                parent[static_cast<std::size_t>(parent[static_cast<std::size_t>(index)])];
            index = parent[static_cast<std::size_t>(index)];
        }
        return index;
    };
    for (std::size_t index = 0; index < fleet.instances.size(); ++index) {
        for (const auto& database : fleet.instances[index].directory.databases) {
            for (const std::string& provider : database.syncreplProviders) {
                const int target = resolveInstance(fleet, index, provider);
                if (target >= 0) {
                    parent[static_cast<std::size_t>(find(target))] =
                        find(static_cast<int>(index));
                }
            }
        }
    }
    std::vector<int> sets(fleet.instances.size());
    for (std::size_t index = 0; index < parent.size(); ++index) {
        sets[index] = find(static_cast<int>(index));
    }
    return sets;
}



/// Instance that owns `sid` according to olcServerID, -1 when the
/// configuration does not say.  The value carries the URL of the machine that
/// writes with that SID, so it is resolved like any other declared URI: every
/// instance declares the same SID list, and a port-only match attributed all of
/// them to the first instance of the fleet.
int sidOwner(const FleetSnapshot& fleet, int sid) {
    for (std::size_t index = 0; index < fleet.instances.size(); ++index) {
        for (const auto& id : fleet.instances[index].directory.serverIds) {
            if (id.sid != sid) {
                continue;
            }
            if (id.uri.empty()) {
                // "olcServerID: 3" without a URL: the SID is this instance's own.
                return static_cast<int>(index);
            }
            // Not `index`: the SID may belong to the instance that declares it,
            // and a fleet where only that one instance carries the list would
            // otherwise resolve nothing.
            const int owner = resolveInstance(fleet, fleet.instances.size(), id.uri);
            if (owner >= 0) {
                return owner;
            }
        }
    }
    return -1;
}

}  // namespace slaptop
