#pragma once

#include <cstddef>
#include <string>
#include <vector>

#include "slaptop/engine.hpp"

namespace slaptop {

/// Host and port of a listener or of a declared URI.  Both shapes the tree
/// carries are handled: "IP=0.0.0.0:1389" from cn=monitor and
/// "ldaps://host:636/" from olcDbURI/olcSyncrepl.
void endpointOf(const std::string& text, std::string& host, int& port);

/// True for a listener that accepts any address (or a loopback alias).
bool wildcardHost(const std::string& host);

/// First label of an FQDN, lowercased: "ldap1.example.com" -> "ldap1".
std::string shortHost(std::string host);

/// True when the first label of `host` ends with `label` ("ldap1.example.com"
/// ends with "ldap1").  Labels shorter than three characters are ignored.
bool hostMatchesName(const std::string& host, const std::string& label);

/// Instance a declared URI points at: host name first, then host:port, then
/// the port alone when it is unambiguous; -1 when the fleet cannot tell.
int resolveInstance(const FleetSnapshot& fleet, std::size_t from, const std::string& uri);

/// Instance that owns `sid` according to olcServerID, -1 when the configuration
/// does not say.
int sidOwner(const FleetSnapshot& fleet, int sid);

/// Replica set of each instance: the connected component of the declared
/// olcSyncRepl graph.  Index i holds the component id of instance i.
std::vector<int> replicaSets(const FleetSnapshot& fleet);

}  // namespace slaptop
