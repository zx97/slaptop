#pragma once

#include <sys/types.h>

#include <chrono>
#include <optional>
#include <unordered_map>

#include "slaptop/types.hpp"

namespace slaptop::collector {

/// Reads a single snapshot of /proc/<pid>/{stat,statm}.
///
/// Returns std::nullopt when the process is gone or unreadable (permissions,
/// races on exit), which callers must treat as "instance vanished".
std::optional<ProcSample> sampleProcess(pid_t pid);

/// Stateful sampler computing CPU usage between two snapshots of one pid.
///
/// CPU percentage needs a delta, so the very first sample for a pid reports
/// 0.0.  The map is keyed by pid: call forget() when an instance disappears so
/// a recycled pid cannot inherit stale counters.
class ProcSampler {
public:
    std::optional<ProcSample> sample(
        pid_t pid,
        std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now());

    void forget(pid_t pid);
    void clear();

private:
    struct Previous {
        std::uint64_t totalTicks{0};
        std::chrono::steady_clock::time_point at{};
    };

    std::unordered_map<pid_t, Previous> previous_;
};

}  // namespace slaptop::collector
