#pragma once

#include <functional>
#include <string>
#include <vector>

#include "slaptop/engine.hpp"

namespace slaptop {

/// `--diagnose`: checks what slaptop itself needs, and prints why a part of
/// the dashboard would be empty.
///
/// The checks follow the data sources, in the order they are used: the process
/// (/proc), the directory (ldapi:// + EXTERNAL + cn=monitor + cn=config), the
/// log file, and — for a remote node — the transport that carries all of them.
/// Every failure is printed with the fix, because "no ldapi listener" alone
/// sends the reader looking in the wrong place.
///
/// Returns 0 when nothing is broken, 1 when at least one check failed.
int diagnose(const EngineOptions& options, const std::string& configPath);

}  // namespace slaptop
