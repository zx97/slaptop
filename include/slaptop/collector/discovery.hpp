#pragma once

#include <string>
#include <string_view>
#include <vector>

#include "slaptop/types.hpp"

namespace slaptop::collector {

/// Enumerates running slapd processes by scanning /proc/<pid>/cmdline.
///
/// The scan is the source of truth rather than a config file walk: it reports
/// exactly what runs now, including instances started by hand and instances
/// whose `-F` directory was moved.  Results are sorted by name for stable
/// output.
std::vector<Instance> discoverInstances();

/// Converts a config directory into a short instance label.
///
/// ".../slapd_proxy.d" -> "proxy"; anything unmatched yields the raw basename.
std::string instanceNameFromConfigDir(std::string_view configDir);

/// Returns the ldapi:// listener of an instance, suitable for an LDAP bind
/// over the local unix socket.  Empty when the instance has none.
std::string ldapiUri(const Instance& instance);

}  // namespace slaptop::collector
