#include "slaptop/collector/proc.hpp"

#include <unistd.h>

#include <cstddef>
#include <fstream>
#include <sstream>
#include <string>

namespace slaptop::collector {
namespace {

/// Clock ticks per second, needed to turn utime/stime into seconds.
long clockTicksPerSecond() {
    static const long hz = ::sysconf(_SC_CLK_TCK) > 0 ? ::sysconf(_SC_CLK_TCK) : 100;
    return hz;
}

/// Online CPUs of this host: the denominator of a CPU percentage.
///
/// Cached: it only changes on hotplug, and sysconf() is a syscall per sample.
int onlineCpus() {
    static const int count = static_cast<int>(::sysconf(_SC_NPROCESSORS_ONLN));
    return count > 0 ? count : 1;
}

/// MemTotal and MemAvailable of this host, in bytes.  MemTotal is stable, so
/// it is read once; MemAvailable moves, so it is read on every sample.
std::uint64_t totalMemoryBytes() {
    static const std::uint64_t total = [] {
        std::ifstream in("/proc/meminfo");
        std::string key;
        std::uint64_t kilobytes = 0;
        std::string unit;
        while (in >> key >> kilobytes >> unit) {
            if (key == "MemTotal:") {
                return kilobytes * 1024ULL;
            }
        }
        return 0ULL;
    }();
    return total;
}

std::uint64_t availableMemoryBytes() {
    std::ifstream in("/proc/meminfo");
    std::string key;
    std::uint64_t kilobytes = 0;
    std::string unit;
    while (in >> key >> kilobytes >> unit) {
        if (key == "MemAvailable:") {
            return kilobytes * 1024ULL;
        }
    }
    return 0ULL;
}

long pageSize() {
    static const long ps = ::sysconf(_SC_PAGESIZE) > 0 ? ::sysconf(_SC_PAGESIZE) : 4096;
    return ps;
}

bool readWholeFile(const std::string& path, std::string& out) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return false;
    }
    std::ostringstream buffer;
    buffer << in.rdbuf();
    out = buffer.str();
    return true;
}

/// Splits a whitespace separated line, skipping empty fields.
std::vector<std::string> splitFields(const std::string& line) {
    std::vector<std::string> fields;
    std::istringstream stream(line);
    std::string field;
    while (stream >> field) {
        fields.push_back(field);
    }
    return fields;
}

std::uint64_t toU64(const std::string& text) {
    try {
        return std::stoull(text);
    } catch (...) {
        return 0;
    }
}

}  // namespace

std::optional<ProcSample> sampleProcess(pid_t pid) {
    const std::string base = "/proc/" + std::to_string(pid);

    std::string stat;
    if (!readWholeFile(base + "/stat", stat)) {
        return std::nullopt;
    }

    // The comm field is parenthesised and may itself contain spaces or ')'.
    // Everything of interest starts after the last ')': that is field 3
    // (state), so utime (field 14) is at index 11 of the remainder.
    const std::size_t paren = stat.rfind(')');
    if (paren == std::string::npos || paren + 2 >= stat.size()) {
        return std::nullopt;
    }
    const std::vector<std::string> fields = splitFields(stat.substr(paren + 2));
    if (fields.size() < 22) {
        return std::nullopt;
    }

    ProcSample sample;
    sample.pid = pid;
    sample.utimeTicks = toU64(fields[11]);
    sample.stimeTicks = toU64(fields[12]);
    sample.numThreads = 1;
    if (const std::uint64_t threads = toU64(fields[17]); threads > 0) {
        sample.numThreads = threads;
    }
    sample.vszBytes = toU64(fields[20]);
    sample.rssBytes = toU64(fields[21]) * static_cast<std::uint64_t>(pageSize());
    sample.cpuCount = onlineCpus();
    sample.memTotalBytes = totalMemoryBytes();
    sample.memAvailableBytes = availableMemoryBytes();
    sample.at = std::chrono::steady_clock::now();

    // statm is refreshed by the kernel alongside stat; rss there is in pages.
    if (std::string statm; readWholeFile(base + "/statm", statm)) {
        const std::vector<std::string> statmFields = splitFields(statm);
        if (statmFields.size() >= 2) {
            sample.rssBytes = toU64(statmFields[1]) * static_cast<std::uint64_t>(pageSize());
        }
    }

    return sample;
}

std::optional<ProcSample> ProcSampler::sample(pid_t pid,
                                             std::chrono::steady_clock::time_point now) {
    std::optional<ProcSample> current = sampleProcess(pid);
    if (!current) {
        previous_.erase(pid);
        return std::nullopt;
    }

    const std::uint64_t totalTicks = current->utimeTicks + current->stimeTicks;
    const auto it = previous_.find(pid);
    if (it != previous_.end()) {
        const double seconds =
            std::chrono::duration<double>(now - it->second.at).count();
        const std::uint64_t deltaTicks =
            totalTicks >= it->second.totalTicks ? totalTicks - it->second.totalTicks : 0;
        if (seconds > 0.0) {
            const double ticksPerSecond = static_cast<double>(clockTicksPerSecond());
            current->cpuPercent = 100.0 * static_cast<double>(deltaTicks) / (seconds * ticksPerSecond);
        }
        it->second = Previous{totalTicks, now};
    } else {
        previous_.emplace(pid, Previous{totalTicks, now});
    }

    return current;
}

void ProcSampler::forget(pid_t pid) {
    previous_.erase(pid);
}

void ProcSampler::clear() {
    previous_.clear();
}

}  // namespace slaptop::collector
