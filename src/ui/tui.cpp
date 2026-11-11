#include "slaptop/ui/tui.hpp"

#include <notcurses/notcurses.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cmath>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <deque>
#include <fstream>
#include <map>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include "slaptop/collector/indexcheck.hpp"
#include "slaptop/topology.hpp"
#include "slaptop/collector/lmdb.hpp"
#include "slaptop/collector/logfile.hpp"
#include "slaptop/engine.hpp"
#include "slaptop/model/metrics.hpp"
#include "slaptop/ui/text.hpp"

namespace slaptop::ui {
namespace {

/// Set by SIGINT/SIGTERM so the render loop can leave notcurses cleanly
/// (calling notcurses_stop from a signal handler is not async-signal-safe).
std::atomic<bool> g_interrupted{false};

extern "C" void onInterrupt(int) {
    g_interrupted.store(true);
}

/// Total RAM of this host, in MiB: the reference for a memory graph drawn
/// "relative to what is available".  Read once, it does not change.
double hostMemoryMiB() {
    static const double total = [] {
        std::ifstream in("/proc/meminfo");
        std::string key;
        double kib = 0.0;
        std::string unit;
        while (in >> key >> kib >> unit) {
            if (key == "MemTotal:") {
                return kib / 1024.0;
            }
        }
        return 0.0;
    }();
    return total;
}

/// Cores on this host: a process can use more than 100 % of one core, so the
/// dashboard shows both the cores used and the share of the whole machine.
int hostCores() {
    static const int cores =
        std::max(1, static_cast<int>(::sysconf(_SC_NPROCESSORS_ONLN)));
    return cores;
}

/// True when the instance runs on this machine, where hostCores() and
/// hostMemoryMiB() are facts rather than guesses about another host.
bool isLocalInstance(const InstanceMetrics& metrics) {
    return metrics.instance.nodeLabel.empty() && metrics.instance.pid > 0;
}

/// CPUs of the host that runs `metrics`, 0 when unknown.  CPU percentages are
/// expressed per core, so this is the denominator (800 for 8 cores).  For a
/// node the count comes from the node itself: substituting this machine's
/// would describe a different host.
int cpuCapacity(const InstanceMetrics& metrics) {
    if (metrics.proc.cpuCount > 0) {
        return metrics.proc.cpuCount;
    }
    return isLocalInstance(metrics) ? hostCores() : 0;
}

/// RAM of the host that runs `metrics`, in MiB, 0 when unknown.  Same rule as
/// the cores: this machine's total only answers for a local instance.
double memCapacityMiB(const InstanceMetrics& metrics) {
    if (metrics.proc.memTotalBytes > 0) {
        return static_cast<double>(metrics.proc.memTotalBytes) / (1024.0 * 1024.0);
    }
    return isLocalInstance(metrics) ? hostMemoryMiB() : 0.0;
}

/// "248% / 800%": the raw figure and what the machine can give, so a value
/// above 100 reads as "three cores busy", not as a broken measurement.
std::string cpuText(const InstanceMetrics& metrics) {
    char text[48];
    const int capacity = cpuCapacity(metrics);
    if (capacity <= 0) {
        // Unknown core count: a single number, rather than a made-up ceiling.
        std::snprintf(text, sizeof(text), "%.1f%%", metrics.proc.cpuPercent);
    } else {
        std::snprintf(text, sizeof(text), "%.1f%% / %d%%", metrics.proc.cpuPercent,
                      100 * capacity);
    }
    return text;
}

/// Active theme, set once by runDashboard before the first frame.
Theme g_theme{};

/// Colour of a CPU figure against the machine's capacity: green while there is
/// room, amber from 70 %, red from 90 %.
std::uint32_t cpuColor(const InstanceMetrics& metrics) {
    const int capacity = cpuCapacity(metrics);
    if (capacity <= 0) {
        return g_theme.text;  // nothing to compare against
    }
    const double ratio = metrics.proc.cpuPercent / static_cast<double>(100 * capacity);
    if (ratio >= 0.9) {
        return g_theme.error;
    }
    return ratio >= 0.7 ? g_theme.warn : g_theme.ok;
}

/// Share of the host's RAM in use, 0..100, -1 when /proc/meminfo did not
/// answer.  "Used" means MemTotal - MemAvailable: page cache is reusable, so
/// counting it as used would show a healthy machine at 95 %.
double systemMemoryPercent(const InstanceMetrics& metrics) {
    if (metrics.proc.memTotalBytes == 0 || metrics.proc.memAvailableBytes == 0) {
        return -1.0;
    }
    const double total = static_cast<double>(metrics.proc.memTotalBytes);
    const double available = static_cast<double>(metrics.proc.memAvailableBytes);
    if (total <= 0.0) {
        return -1.0;
    }
    return std::clamp(100.0 * (total - available) / total, 0.0, 100.0);
}

/// Colour of a memory figure: green while there is room, amber from 80 %,
/// red from 92 % — the point where the kernel starts reclaiming hard.
std::uint32_t memoryColor(double percent) {
    if (percent < 0.0) {
        return g_theme.dim;
    }
    if (percent >= 92.0) {
        return g_theme.error;
    }
    return percent >= 80.0 ? g_theme.warn : g_theme.ok;
}

/// Connection parameters, shown by the help screen.
std::string g_connectionInfo;

/// True while at least one worker is collecting (or the snapshot was busy):
/// the header then shows a moving spinner instead of leaving the operator
/// wondering whether the dashboard is alive.
bool g_refreshing = false;
std::uint64_t g_spinFrame = 0;

/// Pixel planes created for the current frame.  A blit needs a plane created
/// with NCBLIT_PIXEL: on the standard plane notcurses degrades to a cell
/// blitter, which is what produced coarse amber rectangles instead of curves.
/// They are destroyed at the start of the next frame, after the render.
std::vector<ncplane*> g_pixelPlanes;

/// Outcome of the pixel blits since startup: the F12 panel reports them, so
/// "supported but nothing on screen" has an answer instead of a guess.
std::uint64_t g_pixelBlitsOk = 0;
std::uint64_t g_pixelBlitsFailed = 0;
/// Why a pixel band drew nothing: the three guards that return before the
/// blit, counted separately so the F12 panel can name the culprit.
std::uint64_t g_pixelNoSamples = 0;
std::uint64_t g_pixelNoRange = 0;
std::uint64_t g_pixelNoGeometry = 0;
std::uint64_t g_pixelCalls = 0;
/// Last reason a band could not be turned into a bitmap, shown by F12: the
/// paths between the guards and the blit used to fail without a word.
std::string g_pixelLastError;
std::uint64_t g_pixelVisualFailed = 0;
std::uint64_t g_pixelPlaneFailed = 0;

/// notcurses handle and detected pixel protocol (0 = none), set by
/// runDashboard.  Graphs become real bitmaps when a protocol is available
/// (kitty graphics or sixel) and stay block runes otherwise.
notcurses* g_nc = nullptr;
unsigned g_pixelSupport = 0;

// ---------------------------------------------------------------------------
// Colours
// ---------------------------------------------------------------------------

std::uint32_t rgb(unsigned r, unsigned g, unsigned b) {
    return ((r & 0xffU) << 16U) | ((g & 0xffU) << 8U) | (b & 0xffU);
}

/// Three-point palette, interpolated on demand.  Used both for the vertical
/// gradient inside a graph and for value-based colouring.
struct Palette {
    std::uint32_t low;
    std::uint32_t mid;
    std::uint32_t high;
};

constexpr Palette kCpuPalette{0x2e8b57, 0xd8c040, 0xe0503a};    // sea green → amber → red
constexpr Palette kMemPalette{0x2b5f9e, 0x3fa9d8, 0x9b6ee0};    // blue → cyan → violet
constexpr Palette kOpsPalette{0x1f6f4a, 0x2fbf8f, 0xf0e060};    // deep green → mint → gold
constexpr Palette kErrPalette{0x505050, 0xc06040, 0xff3020};    // grey → orange → red

unsigned channel(std::uint32_t color, unsigned shift) {
    return (color >> shift) & 0xffU;
}

/// Interpolates a palette at t in [0,1] (0 = low, 0.5 = mid, 1 = high).
std::uint32_t shade(const Palette& palette, double t) {
    t = std::clamp(t, 0.0, 1.0);
    const std::uint32_t from = t < 0.5 ? palette.low : palette.mid;
    const std::uint32_t to = t < 0.5 ? palette.mid : palette.high;
    const double k = t < 0.5 ? t * 2.0 : (t - 0.5) * 2.0;
    return rgb(static_cast<unsigned>(channel(from, 16) * (1.0 - k) + channel(to, 16) * k),
               static_cast<unsigned>(channel(from, 8) * (1.0 - k) + channel(to, 8) * k),
               static_cast<unsigned>(channel(from, 0) * (1.0 - k) + channel(to, 0) * k));
}

/// Linear blend between two colours (k=0 -> a, k=1 -> b).
std::uint32_t blend(std::uint32_t a, std::uint32_t b, double k) {
    k = std::clamp(k, 0.0, 1.0);
    return rgb(static_cast<unsigned>(channel(a, 16) * (1.0 - k) + channel(b, 16) * k),
               static_cast<unsigned>(channel(a, 8) * (1.0 - k) + channel(b, 8) * k),
               static_cast<unsigned>(channel(a, 0) * (1.0 - k) + channel(b, 0) * k));
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

void put(ncplane* plane, int y, int x, const std::string& text, std::uint32_t color = 0,
         bool bold = false, std::uint32_t background = 0) {
    if (color != 0) {
        ncplane_set_fg_rgb(plane, color);
    } else {
        ncplane_set_fg_default(plane);
    }
    if (background != 0) {
        ncplane_set_bg_rgb(plane, background);
    } else {
        ncplane_set_bg_default(plane);
    }
    ncplane_set_styles(plane, bold ? NCSTYLE_BOLD : NCSTYLE_NONE);
    ncplane_putstr_yx(plane, y, x, text.c_str());
    ncplane_set_styles(plane, NCSTYLE_NONE);
    ncplane_set_bg_default(plane);
}

std::string repeat(const std::string& chunk, std::size_t count) {
    // Frames rebuild the same rules constantly; cache the last few by length
    // so a redraw does not allocate a string per border cell.
    static std::map<std::pair<std::string, std::size_t>, std::string> cache;
    const auto key = std::make_pair(chunk, count);
    if (const auto it = cache.find(key); it != cache.end()) {
        return it->second;
    }
    std::string out;
    out.reserve(chunk.size() * count);
    for (std::size_t i = 0; i < count; ++i) {
        out += chunk;
    }
    if (cache.size() > 64) {
        cache.clear();  // pathological widths must not grow forever
    }
    cache.emplace(key, out);
    return out;
}

std::string humanBytes(std::uint64_t bytes) {
    static constexpr const char* units[] = {"B", "K", "M", "G", "T"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < sizeof(units) / sizeof(units[0])) {
        value /= 1024.0;
        ++unit;
    }
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), unit == 0 ? "%.0f%s" : "%.1f%s", value, units[unit]);
    return buffer;
}

std::string clockNow() {
    const std::time_t now = std::time(nullptr);
    std::tm tm{};
    localtime_r(&now, &tm);
    char buffer[16];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm);
    return buffer;
}

/// Clock time `offsetSeconds` away from now: the oldest end of a graph's time
/// axis, so the window can be read as "12:34:05 -> 12:35:05".
std::string clockAt(double offsetSeconds) {
    const std::time_t when =
        std::time(nullptr) + static_cast<std::time_t>(std::lround(offsetSeconds));
    std::tm tm{};
    localtime_r(&when, &tm);
    char buffer[16];
    std::strftime(buffer, sizeof(buffer), "%H:%M:%S", &tm);
    return buffer;
}

/// Shares `extra` rows between frames in proportion to their weights: a frame
/// holding twice the data gets twice the extra rows.  Largest-remainder method,
/// so the rows handed out add up exactly to `extra` and nothing is lost.
void distributeExtra(std::vector<int>& heights, const std::vector<int>& weights, int extra) {
    if (heights.empty() || extra <= 0) {
        return;
    }
    long long total = 0;
    for (const int weight : weights) {
        total += std::max(0, weight);
    }
    if (total <= 0) {
        for (int index = 0; index < extra; ++index) {
            ++heights[static_cast<std::size_t>(index) % heights.size()];
        }
        return;
    }
    std::vector<std::pair<double, std::size_t>> remainders;
    remainders.reserve(heights.size());
    int allocated = 0;
    for (std::size_t index = 0; index < heights.size(); ++index) {
        const int weight = std::max(0, index < weights.size() ? weights[index] : 1);
        const double ideal = static_cast<double>(extra) * static_cast<double>(weight) /
                             static_cast<double>(total);
        const int whole = static_cast<int>(ideal);
        heights[index] += whole;
        allocated += whole;
        remainders.emplace_back(ideal - static_cast<double>(whole), index);
    }
    std::sort(remainders.begin(), remainders.end(),
              [](const auto& a, const auto& b) { return a.first > b.first; });
    for (int left = extra - allocated, index = 0; left > 0; --left, ++index) {
        ++heights[remainders[static_cast<std::size_t>(index) % remainders.size()].second];
    }
}

/// Right-aligns a string in exactly `width` columns.
std::string padLeft(const std::string& text, int width) {
    if (width <= 0) {
        return std::string();
    }
    const std::string fitted = text::fit(text, static_cast<std::size_t>(width));
    const int used = text::width(fitted);
    return used >= width ? fitted : std::string(static_cast<std::size_t>(width - used), ' ') +
                                             fitted;
}

/// Shortens a path to `width` columns by dropping leading components, so the
/// part that identifies the directory survives: "…/openldap-data/dir_main"
/// rather than "/opt/openldap/openld…".
std::string shortenPath(const std::string& path, int width) {
    if (width <= 0) {
        return std::string();
    }
    if (text::width(path) <= width) {
        return path;
    }
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= path.size()) {
        const std::size_t slash = path.find('/', start);
        parts.push_back(path.substr(start, slash == std::string::npos ? std::string::npos
                                                                     : slash - start));
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    std::string result;
    for (auto it = parts.rbegin(); it != parts.rend(); ++it) {
        if (it->empty()) {
            continue;
        }
        const std::string candidate = result.empty() ? *it : *it + "/" + result;
        if (text::width("\u2026/" + candidate) > width) {
            break;
        }
        result = candidate;
    }
    if (result.empty()) {
        return text::fit(path, static_cast<std::size_t>(width));
    }
    return "\u2026/" + result;
}

/// Pads a string to exactly `width` columns (truncating when longer), so a
/// column of DNs stays aligned whatever the multi-byte content.
std::string padTo(const std::string& text, int width) {
    if (width <= 0) {
        return std::string();
    }
    const std::string fitted = text::fit(text, static_cast<std::size_t>(width));
    const int used = text::width(fitted);
    return used >= width ? fitted
                         : fitted + std::string(static_cast<std::size_t>(width - used), ' ');
}

std::string basename(const std::string& path) {
    const std::size_t slash = path.rfind('/');
    return slash == std::string::npos ? path : path.substr(slash + 1);
}

/// Repeats a UTF-8 chunk `count` times.

/// Formats a CSN timestamp ("20261104020651.123456Z#...") as "2026-11-04 02:06:51".
std::string formatCsn(const std::string& csn) {
    if (csn.size() < 14) {
        return csn.empty() ? "--" : csn;
    }
    for (std::size_t i = 0; i < 14; ++i) {
        if (csn[i] < '0' || csn[i] > '9') {
            return csn.substr(0, 19);
        }
    }
    return csn.substr(0, 4) + "-" + csn.substr(4, 2) + "-" + csn.substr(6, 2) + " " +
           csn.substr(8, 2) + ":" + csn.substr(10, 2) + ":" + csn.substr(12, 2);
}

/// Age in seconds of a generalizedTime ("20261104020651Z"), -1 when unreadable.
double generalizedAge(const std::string& stamp) {
    if (stamp.size() < 14) {
        return -1.0;
    }
    for (std::size_t i = 0; i < 14; ++i) {
        if (!std::isdigit(static_cast<unsigned char>(stamp[i]))) {
            return -1.0;
        }
    }
    std::tm tm{};
    tm.tm_year = std::stoi(stamp.substr(0, 4)) - 1900;
    tm.tm_mon = std::stoi(stamp.substr(4, 2)) - 1;
    tm.tm_mday = std::stoi(stamp.substr(6, 2));
    tm.tm_hour = std::stoi(stamp.substr(8, 2));
    tm.tm_min = std::stoi(stamp.substr(10, 2));
    tm.tm_sec = std::stoi(stamp.substr(12, 2));
    const std::time_t then = timegm(&tm);
    if (then <= 0) {
        return -1.0;
    }
    return std::difftime(std::time(nullptr), then);
}

/// Compact duration: "2d 4h", "3h 12m", "45m", "12s".
std::string humanDuration(double seconds) {
    if (seconds < 0.0) {
        return "--";
    }
    const long long total = static_cast<long long>(seconds);
    const long long days = total / 86400;
    const long long hours = (total % 86400) / 3600;
    const long long minutes = (total % 3600) / 60;
    char buffer[40];
    if (days > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldd %lldh", days, hours);
    } else if (hours > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldh %lldm", hours, minutes);
    } else if (minutes > 0) {
        std::snprintf(buffer, sizeof(buffer), "%lldm", minutes);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%llds", total);
    }
    return buffer;
}

std::string humanAge(double seconds) {
    if (seconds < 0.0) {
        return "--";
    }
    if (seconds < 1.0) {
        return "0s";
    }
    if (seconds < 60.0) {
        return std::to_string(static_cast<long long>(seconds)) + "s";
    }
    if (seconds < 3600.0) {
        return std::to_string(static_cast<long long>(seconds / 60.0)) + "m";
    }
    return std::to_string(static_cast<long long>(seconds / 3600.0)) + "h";
}

// ---------------------------------------------------------------------------
// Area graph: multi-row, 8 sub-levels per cell, vertical gradient
// ---------------------------------------------------------------------------

const char* const kLevels[] = {" ", "\u2581", "\u2582", "\u2583", "\u2584",
                               "\u2585", "\u2586", "\u2587", "\u2588"};

/// Discreet horizontal guides at a quarter, half and three quarters of the
/// band, drawn before the graph: the area covers them where there is data and
/// they stay visible in the empty part, which is what makes the height of a
/// spike readable.
void drawBandGrid(ncplane* plane, int y, int x, int cols, int rows) {
    if (rows < 3 || cols < 8) {
        return;
    }
    const double fractions[] = {0.25, 0.5, 0.75};
    int previous = -2;
    for (const double fraction : fractions) {
        const int row = rows - 1 - static_cast<int>(std::lround(fraction * (rows - 1)));
        if (row < 0 || row >= rows || std::abs(row - previous) < 2) {
            continue;
        }
        previous = row;
        for (int column = 0; column < cols; column += 2) {
            put(plane, y + row, x + column, "\u00b7", g_theme.frame);
        }
    }
}

/// Draws `samples` as a filled area `height` rows high.
///
/// Each cell holds 8 vertical levels, so a 3-row graph resolves 24 steps —
/// enough to read a shape instead of a squiggle.  The colour is interpolated
/// along the vertical axis (dark at the baseline, bright at the top), which
/// makes absolute height readable at a glance.
void drawAreaGraph(ncplane* plane, int y, int x, int width, int height,
                   const std::deque<double>& samples, double floor, double ceiling,
                   const Palette& palette, bool animate, double pulse) {
    if (width <= 0 || height <= 0 || ceiling <= floor) {
        return;
    }
    const std::size_t available = samples.size();
    const std::size_t first = available > static_cast<std::size_t>(width)
                                  ? available - static_cast<std::size_t>(width)
                                  : 0;
    // When the graph is wider than the series, interpolate between samples
    // instead of leaving the right part empty.
    const bool stretch = available > 1 && available < static_cast<std::size_t>(width);

    const double brighten = animate ? 1.0 + 0.18 * pulse : 1.0;
    ncplane_set_styles(plane, NCSTYLE_NONE);

    // Column by column, bottom row first: the last written rune wins, so the
    // partial top cell must be drawn after the full ones.
    for (int column = 0; column < width; ++column) {
        double value = floor;
        bool haveSample = false;
        if (stretch) {
            const double t = width > 1 ? static_cast<double>(column) / (width - 1) : 0.0;
            const double position = t * static_cast<double>(available - 1);
            const std::size_t low = static_cast<std::size_t>(position);
            const std::size_t high = std::min(low + 1, available - 1);
            const double fraction = position - static_cast<double>(low);
            value = samples[low] * (1.0 - fraction) + samples[high] * fraction;
            haveSample = true;
        } else {
            const std::size_t index = first + static_cast<std::size_t>(column);
            if (index < available) {
                value = samples[index];
                haveSample = true;
            }
        }
        const double ratio = std::clamp((value - floor) / (ceiling - floor), 0.0, 1.0);
        // A sample at the floor still gets its lowest row: the graph must read
        // as a continuous strip, not as disconnected columns.
        const double levels =
            haveSample ? std::max(1.0, ratio * static_cast<double>(height) * 8.0) : 0.0;

        for (int row = 0; row < height; ++row) {
            const int fromBottom = height - 1 - row;
            const double base = static_cast<double>(fromBottom) * 8.0;
            const double fill = levels - base;
            if (fill <= 0.0) {
                // Leave the cell alone: the plane is erased every frame, and
                // the grid drawn underneath must stay visible where the area
                // has no data.
                continue;
            }
            const int level = fill >= 8.0 ? 8 : std::max(1, static_cast<int>(std::lround(fill)));
            // Vertical position drives the gradient: 0 at the baseline.
            const double t = (base + static_cast<double>(level)) /
                             (static_cast<double>(height) * 8.0);
            std::uint32_t color = shade(palette, t);
            if (brighten != 1.0) {
                color = rgb(static_cast<unsigned>(std::min(255.0, channel(color, 16) * brighten)),
                            static_cast<unsigned>(std::min(255.0, channel(color, 8) * brighten)),
                            static_cast<unsigned>(std::min(255.0, channel(color, 0) * brighten)));
            }
            ncplane_set_fg_rgb(plane, color);
            ncplane_putstr_yx(plane, y + row, x + column, kLevels[level]);
        }
    }
}

/// Compact single-row sparkline (used by the compact layout).
void drawSpark(ncplane* plane, int y, int x, int width, const std::deque<double>& samples,
               double maxValue, const Palette& palette) {
    if (width <= 0) {
        return;
    }
    const std::size_t available = samples.size();
    const std::size_t first = available > static_cast<std::size_t>(width)
                                  ? available - static_cast<std::size_t>(width)
                                  : 0;
    const double ceiling = std::max(maxValue, 1e-9);

    ncplane_set_styles(plane, NCSTYLE_NONE);
    int column = 0;
    for (std::size_t i = first; i < available; ++i, ++column) {
        const double ratio = std::clamp(samples[i] / ceiling, 0.0, 1.0);
        const int level = std::max(1, static_cast<int>(std::lround(ratio * 8.0)));
        ncplane_set_fg_rgb(plane, shade(palette, ratio));
        ncplane_putstr_yx(plane, y, x + column, kLevels[std::clamp(level, 1, 8)]);
    }
    ncplane_set_fg_default(plane);
    for (int i = column; i < width; ++i) {
        ncplane_putchar_yx(plane, y, x + i, ' ');
    }
}

/// Chooses a display window so a flat series still shows its variations:
/// zero-based for CPU and activity, zoomed around the mean for memory (where
/// an absolute scale would paint a solid block).
struct Scale {
    double floor{0.0};
    double ceiling{1.0};
};

Scale scaleFor(const std::deque<double>& samples, bool zoomed, double minimumSpan,
               bool ignoreZero = false) {
    Scale scale;
    if (samples.empty()) {
        scale.ceiling = minimumSpan;
        return scale;
    }
    // Memory series start at 0 while the first samples are missing; keeping
    // those zeroes in the window would flatten every real value to the top.
    double lowest = 0.0;
    double highest = 0.0;
    bool seen = false;
    for (const double value : samples) {
        if (ignoreZero && value <= 0.0) {
            continue;
        }
        lowest = seen ? std::min(lowest, value) : value;
        highest = seen ? std::max(highest, value) : value;
        seen = true;
    }
    if (!seen) {
        scale.ceiling = minimumSpan;
        return scale;
    }
    if (zoomed) {
        // Memory: frame the variations instead of the absolute size.
        const double span = std::max(highest - lowest, highest * 0.02);
        scale.floor = lowest - span * 0.15;
        scale.ceiling = highest + span * 0.15;
        if (scale.ceiling - scale.floor < minimumSpan) {
            const double middle = (scale.floor + scale.ceiling) / 2.0;
            scale.floor = middle - minimumSpan / 2.0;
            scale.ceiling = middle + minimumSpan / 2.0;
        }
    } else {
        scale.floor = 0.0;
        scale.ceiling = std::max(minimumSpan, highest * 1.08);
    }
    return scale;
}

// ---------------------------------------------------------------------------
// Compact row (many instances or small terminal)
// ---------------------------------------------------------------------------

void drawCompactRow(ncplane* plane, int row, int left, int width,
                    const InstanceMetrics& metrics, const InstanceHistory& history,
                    double pulse) {
    (void)pulse;  // compact rows stay static: the colour already reads the load
    char text[256];
    std::snprintf(text, sizeof(text),
                  "%-8.8s %7d %-8.8s cpu %5.1f/%-4d%% rss %-6s  thr %3llu",
                  metrics.instance.name.c_str(), static_cast<int>(metrics.instance.pid),
                  healthLabel(metrics.health), metrics.proc.cpuPercent,
                  100 * cpuCapacity(metrics), humanBytes(metrics.proc.rssBytes).c_str(),
                  static_cast<unsigned long long>(metrics.proc.numThreads));

    const std::uint32_t color = metrics.health == Health::Running ? g_theme.text : g_theme.error;
    put(plane, row, left, text::fit(text, static_cast<std::size_t>(width)), color);

    const int used = static_cast<int>(std::strlen(text));
    const int sparkWidth = width - used - 24;
    if (sparkWidth > 6) {
        // Drawn against the host's capacity: the sparkline fills up only when
        // the machine does, whatever the core count.  Unknown capacity falls
        // back to the observed maximum, never to this machine's core count.
        const int capacity = cpuCapacity(metrics);
        const double ceiling = capacity > 0
                                   ? 100.0 * capacity
                                   : std::max(25.0, history.cpuPercent.maximum() * 1.1);
        drawSpark(plane, row, left + used + 1, sparkWidth, history.cpuPercent.values(), ceiling,
                  kCpuPalette);
    }

#ifdef SLAPTOP_WITH_LDAP
    if (metrics.hasMonitor) {
        std::snprintf(text, sizeof(text), "conn %llu/%llu",
                      static_cast<unsigned long long>(metrics.monitor.connectionsCurrent),
                      static_cast<unsigned long long>(metrics.monitor.connectionsTotal));
        const int right = left + width - static_cast<int>(std::strlen(text));
        if (right > left + used + sparkWidth + 1) {
            put(plane, row, right, text, rgb(0x90, 0xb0, 0xc0));
        }
    }
#endif
}

/// A 5x7 bitmap font, just enough for axis labels: digits, a few letters and
/// the separators a value needs.  Seven pixels is under half a text cell, so a
/// label reads as annotation next to the curve, and the strokes stay one pixel
/// wide: scaling the old 3x5 font up gave thick, blocky digits — the size of
/// the body text and harder to read than it.
constexpr int kTinyColumns = 5;
constexpr int kTinyRows = 7;
constexpr int kTinyAdvance = kTinyColumns + 1;  ///< one blank column between glyphs
constexpr int kTinyPad = 1;                     ///< dark plate around the text

struct TinyGlyph {
    char character;
    std::uint8_t rows[kTinyRows];
};

const TinyGlyph* tinyGlyph(char character) {
    static const TinyGlyph kGlyphs[] = {
        {'0', {0b01110, 0b10001, 0b10011, 0b10101, 0b11001, 0b10001, 0b01110}},
        {'1', {0b00100, 0b01100, 0b00100, 0b00100, 0b00100, 0b00100, 0b01110}},
        {'2', {0b01110, 0b10001, 0b00001, 0b00010, 0b00100, 0b01000, 0b11111}},
        {'3', {0b11111, 0b00010, 0b00100, 0b00010, 0b00001, 0b10001, 0b01110}},
        {'4', {0b00010, 0b00110, 0b01010, 0b10010, 0b11111, 0b00010, 0b00010}},
        {'5', {0b11111, 0b10000, 0b11110, 0b00001, 0b00001, 0b10001, 0b01110}},
        {'6', {0b00110, 0b01000, 0b10000, 0b11110, 0b10001, 0b10001, 0b01110}},
        {'7', {0b11111, 0b00001, 0b00010, 0b00100, 0b01000, 0b01000, 0b01000}},
        {'8', {0b01110, 0b10001, 0b10001, 0b01110, 0b10001, 0b10001, 0b01110}},
        {'9', {0b01110, 0b10001, 0b10001, 0b01111, 0b00001, 0b00010, 0b01100}},
        {':', {0b00000, 0b01100, 0b01100, 0b00000, 0b01100, 0b01100, 0b00000}},
        {'.', {0b00000, 0b00000, 0b00000, 0b00000, 0b00000, 0b01100, 0b01100}},
        {'/', {0b00001, 0b00010, 0b00010, 0b00100, 0b01000, 0b01000, 0b10000}},
        {'%', {0b11001, 0b11011, 0b00010, 0b00100, 0b01000, 0b11011, 0b10011}},
        {'s', {0b00000, 0b00000, 0b01111, 0b10000, 0b01110, 0b00001, 0b11110}},
        {'G', {0b01110, 0b10001, 0b10000, 0b10111, 0b10001, 0b10001, 0b01110}},
        {'M', {0b10001, 0b11011, 0b10101, 0b10101, 0b10001, 0b10001, 0b10001}},
        {'K', {0b10001, 0b10010, 0b10100, 0b11000, 0b10100, 0b10010, 0b10001}},
        {'B', {0b11110, 0b10001, 0b10001, 0b11110, 0b10001, 0b10001, 0b11110}},
        {'-', {0b00000, 0b00000, 0b00000, 0b11111, 0b00000, 0b00000, 0b00000}},
        {' ', {0, 0, 0, 0, 0, 0, 0}},
    };
    for (const TinyGlyph& glyph : kGlyphs) {
        if (glyph.character == character) {
            return &glyph;
        }
    }
    return nullptr;
}

/// Width in pixels of `text`.
unsigned tinyWidth(const std::string& text) {
    if (text.empty()) {
        return 0;
    }
    return static_cast<unsigned>(text.size()) * kTinyAdvance - 1;
}

/// Writes `text` into the pixel buffer, with a one-pixel dark plate behind it so
/// it stays readable on top of the curve.
void drawTinyText(std::vector<std::uint32_t>& pixels, unsigned width, unsigned height,
                  int x, int y, const std::string& text, std::uint32_t colour) {
    const int plateWidth = static_cast<int>(tinyWidth(text)) + kTinyPad * 2;
    const int plateHeight = kTinyRows + kTinyPad * 2;
    for (int py = y - kTinyPad; py < y - kTinyPad + plateHeight; ++py) {
        if (py < 0 || py >= static_cast<int>(height)) {
            continue;
        }
        for (int px = x - kTinyPad; px < x - kTinyPad + plateWidth; ++px) {
            if (px < 0 || px >= static_cast<int>(width)) {
                continue;
            }
            pixels[static_cast<std::size_t>(py) * width + static_cast<std::size_t>(px)] =
                0xff101218u;
        }
    }
    int cursor = x;
    for (const char character : text) {
        const TinyGlyph* glyph = tinyGlyph(character);
        if (glyph != nullptr) {
            for (int row = 0; row < kTinyRows; ++row) {
                for (int column = 0; column < kTinyColumns; ++column) {
                    if ((glyph->rows[row] & (1 << (kTinyColumns - 1 - column))) == 0) {
                        continue;
                    }
                    const int py = y + row;
                    const int px = cursor + column;
                    if (py < 0 || py >= static_cast<int>(height) || px < 0 ||
                        px >= static_cast<int>(width)) {
                        continue;
                    }
                    pixels[static_cast<std::size_t>(py) * width +
                           static_cast<std::size_t>(px)] = colour;
                }
            }
        }
        cursor += kTinyAdvance;
    }
}

/// A label placed along an axis: `at` is 0 at the origin and 1 at the far end.
using AxisLabel = std::pair<double, std::string>;

/// Labels for a vertical axis: one per grid line, from the floor to the
/// ceiling.  `format` decides the unit, so every page writes its own scale.
/// The pixel renderer decides how many of them fit; the rune renderer ignores
/// them and keeps its own ceiling on the caption row.
template <typename Format>
std::vector<AxisLabel> yAxisLabels(double floor, double ceiling, int rows, Format format) {
    std::vector<AxisLabel> labels;
    const int lines = std::max(1, rows);
    for (int line = 0; line <= lines; ++line) {
        const double fraction = 1.0 - static_cast<double>(line) / static_cast<double>(lines);
        labels.emplace_back(fraction, format(floor + (ceiling - floor) * fraction));
    }
    return labels;
}

/// Three clock times across the window: start, middle, now.
std::vector<AxisLabel> xAxisLabels(std::size_t samples, double sampleSeconds) {
    if (samples == 0 || sampleSeconds <= 0.0) {
        return {};
    }
    const double span = static_cast<double>(samples) * sampleSeconds;
    return {{0.0, clockAt(-span)}, {0.5, clockAt(-span / 2.0)}, {1.0, clockNow()}};
}

/// Draws the same area graph as a bitmap through ncvisual/NCBLIT_PIXEL.
///
/// Only used when the terminal advertises a pixel protocol.  The image is
/// generated at (at most) one pixel per screen pixel, with a vertical gradient
/// and linear interpolation between samples: this is what the block runes
/// cannot express (smooth slopes, real colour ramps).
bool drawPixelGraph(ncplane* plane, int y, int x, int cols, int rows,
                    const std::deque<double>& samples, double floor, double ceiling,
                    const Palette& palette, const std::vector<AxisLabel>& yLabels,
                    const std::vector<AxisLabel>& xLabels) {
    ++g_pixelCalls;
    if (g_nc == nullptr || cols <= 0 || rows <= 0) {
        ++g_pixelNoGeometry;
        return false;
    }
    if (ceiling <= floor) {
        ++g_pixelNoRange;
        return false;
    }
    if (samples.empty()) {
        ++g_pixelNoSamples;
        return false;
    }
    unsigned pxy = 0, pxx = 0, celldimy = 0, celldimx = 0, maxbmapy = 0, maxbmapx = 0;
    ncplane_pixel_geom(plane, &pxy, &pxx, &celldimy, &celldimx, &maxbmapy, &maxbmapx);
    // Konsole does not always answer CSI 16 t, so the cell size in pixels can
    // be unknown; fall back to a common geometry rather than drawing nothing,
    // which produced an empty (black) graph.
    if (celldimx == 0) {
        celldimx = 8;
    }
    if (celldimy == 0) {
        celldimy = 16;
    }

    // Cap the bitmap: 9 graphs redrawn at 10 FPS must stay cheap.
    constexpr unsigned kMaxPixels = 400000;
    unsigned width = static_cast<unsigned>(cols) * celldimx;
    unsigned height = static_cast<unsigned>(rows) * celldimy;
    while (static_cast<unsigned long>(width) * height > kMaxPixels && (width > 16 || height > 8)) {
        width = std::max(16U, width / 2);
        height = std::max(8U, height / 2);
    }

    // Label geometry comes first, because the grid is drawn on the labelled
    // values: placing the two from different rules made the numbers float
    // between the lines.
    constexpr std::uint32_t kLabel = 0xffc8ccd8u;
    constexpr std::uint32_t kGrid = 0xff5a6680u;
    constexpr std::uint32_t kCard = 0xff12141eu;
    // One type size everywhere: the 5x7 annotation font, 7 pixels tall — under
    // half a text cell, so a label never competes with the body text, and one
    // pixel strokes keep it crisp.  When the room is short, fewer labels is the
    // honest answer, not smaller type.
    constexpr int glyphHeight = kTinyRows;
    constexpr unsigned kPlate = kTinyRows + 2 * kTinyPad;  ///< glyph plus its plate
    const unsigned xBand = xLabels.empty() ? 0U : kPlate + 8U;
    const unsigned plotHeight = std::max(2U, height - xBand);

    // Keep every label that fits, always including the floor, and drop the
    // others rather than letting two plates touch.
    std::vector<std::size_t> kept;
    for (unsigned stride = 1;; ++stride) {
        kept.clear();
        for (std::size_t index = 0; index < yLabels.size(); index += stride) {
            kept.push_back(index);
        }
        if (!yLabels.empty() && kept.back() + 1 != yLabels.size()) {
            kept.push_back(yLabels.size() - 1);
        }
        const int spacing = kept.size() > 1
                                ? static_cast<int>((plotHeight - 1) / (kept.size() - 1))
                                : static_cast<int>(plotHeight);
        if (kept.size() <= 2 || spacing >= static_cast<int>(kPlate)) {
            break;
        }
    }
    if (kept.size() > 1 &&
        static_cast<int>((plotHeight - 1) / (kept.size() - 1)) < glyphHeight) {
        // Not even two labels fit: keep the floor alone rather than draw two
        // plates over each other.
        kept.assign(1, kept.back());
    }
    std::vector<unsigned> yRows;
    yRows.reserve(kept.size());
    for (const std::size_t index : kept) {
        yRows.push_back(static_cast<unsigned>(
            (1.0 - std::clamp(yLabels[index].first, 0.0, 1.0)) *
                static_cast<double>(plotHeight - 1) +
            0.5));
    }

    static std::vector<std::uint32_t> pixels;  // reused between frames
    pixels.resize(static_cast<std::size_t>(width) * height);

    const std::size_t count = samples.size();
    for (unsigned px = 0; px < width; ++px) {
        const double t = width > 1 ? static_cast<double>(px) / (width - 1) : 0.0;
        const double position = t * static_cast<double>(count - 1);
        const std::size_t low = static_cast<std::size_t>(position);
        const std::size_t high = std::min(low + 1, count - 1);
        const double fraction = position - static_cast<double>(low);
        const double value = samples[low] * (1.0 - fraction) + samples[high] * fraction;
        const double ratio = std::clamp((value - floor) / (ceiling - floor), 0.0, 1.0);
        const unsigned top = plotHeight - static_cast<unsigned>(ratio * plotHeight);
        for (unsigned py = 0; py < height; ++py) {
            const std::size_t index = static_cast<std::size_t>(py) * width + px;
            if (py < top || py >= plotHeight) {
                // Opaque card background: several kitty implementations paint
                // fully transparent pixels as black, which made the graph look
                // like a void.
                pixels[index] = kCard;
                continue;
            }
            // Gradient along the vertical axis, brighter near the top.
            const double level = 1.0 - static_cast<double>(py) / plotHeight;
            const std::uint32_t color = shade(palette, level);
            pixels[index] = 0xff000000u | color;
        }
    }

    // The rune grid is drawn on the cells underneath, and the bitmap is opaque:
    // it would be invisible.  Bake a fine grid into the pixels instead, so the
    // graph can be read (levels, time marks) instead of admired.
    {
        const unsigned columnStep = std::max(4U, celldimx * 4);
        for (const unsigned py : yRows) {
            for (unsigned px = 0; px < width; ++px) {
                pixels[static_cast<std::size_t>(py) * width + px] = kGrid;
            }
        }
        for (unsigned py = 0; py < plotHeight; ++py) {
            for (unsigned px = 0; px < width; px += columnStep) {
                pixels[static_cast<std::size_t>(py) * width + px] = kGrid;
            }
        }
    }

    // Axis labels, drawn into the bitmap with the 5x7 font, on the grid lines.
    for (std::size_t row = 0; row < kept.size(); ++row) {
        drawTinyText(pixels, width, height, kTinyPad,
                     std::clamp(static_cast<int>(yRows[row]) - glyphHeight / 2, 0,
                                static_cast<int>(plotHeight) - glyphHeight),
                     yLabels[kept[row]].second, kLabel);
    }
    for (const auto& [at, text] : xLabels) {
        const int textWidth = static_cast<int>(tinyWidth(text));
        const int px = std::clamp(static_cast<int>(std::clamp(at, 0.0, 1.0) *
                                                   static_cast<double>(width - 1)) -
                                      textWidth / 2,
                                  1, std::max(1, static_cast<int>(width) - textWidth - 1));
        drawTinyText(pixels, width, height, px, static_cast<int>(height) - glyphHeight - 2,
                     text, kLabel);
    }

    // Diagnostic: SLAPTOP_PIXEL_DUMP=/path writes this bitmap as a PPM before
    // it is blitted, so the pixel rendering can be inspected (and compared with
    // the runes) from a terminal that advertises no pixel protocol.
    if (const char* dumpPath = std::getenv("SLAPTOP_PIXEL_DUMP"); dumpPath != nullptr) {
        // Wait for a filled history: the first frames have no samples and would
        // write an empty grid.  The file keeps the last graph drawn, which is
        // what the dashboard settled on.
        if (samples.size() > 8) {
            if (std::FILE* dump = std::fopen(dumpPath, "wb"); dump != nullptr) {
                std::fprintf(dump, "P6\n%u %u\n255\n", width, height);
                for (const std::uint32_t value : pixels) {
                    const unsigned char rgbOut[3] = {
                        static_cast<unsigned char>((value >> 16) & 0xffU),
                        static_cast<unsigned char>((value >> 8) & 0xffU),
                        static_cast<unsigned char>(value & 0xffU)};
                    std::fwrite(rgbOut, 1, sizeof(rgbOut), dump);
                }
                std::fclose(dump);
            }
        }
        if (g_pixelSupport == 0) {
            return false;  // dump only: this terminal cannot show the bitmap
        }
    }

    ncvisual* visual = ncvisual_from_bgra(pixels.data(), static_cast<int>(height),
                                          static_cast<int>(width * 4), static_cast<int>(width));
    if (visual == nullptr) {
        ++g_pixelVisualFailed;
        g_pixelLastError = "ncvisual_from_bgra refused " + std::to_string(width) + "x" +
                           std::to_string(height) + " at " + std::to_string(y) + "," +
                           std::to_string(x);
        return false;
    }
    // notcurses.h, on ncvisual_blit: "Pixels may not be blitted to the
    // standard plane."  A child plane is created at the band's position and
    // size, clamped to what the parent still has (the last band of a card sits
    // against the bottom edge, and a child that does not fit is refused).
    unsigned parentRows = 0;
    unsigned parentCols = 0;
    ncplane_dim_yx(plane, &parentRows, &parentCols);
    if (y < 0 || x < 0 || static_cast<unsigned>(y) >= parentRows ||
        static_cast<unsigned>(x) >= parentCols) {
        ncvisual_destroy(visual);
        ++g_pixelNoGeometry;
        g_pixelLastError = "band outside the plane at " + std::to_string(y) + "," +
                           std::to_string(x) + " (plane " + std::to_string(parentCols) + "x" +
                           std::to_string(parentRows) + ")";
        return false;
    }
    const unsigned fitRows = std::min<unsigned>(static_cast<unsigned>(rows),
                                                parentRows - static_cast<unsigned>(y));
    const unsigned fitCols = std::min<unsigned>(static_cast<unsigned>(cols),
                                                parentCols - static_cast<unsigned>(x));
    ncplane_options planeOptions{};
    planeOptions.y = y;
    planeOptions.x = x;
    planeOptions.rows = fitRows;
    planeOptions.cols = fitCols;
    ncplane* target = ncplane_create(plane, &planeOptions);
    if (target == nullptr) {
        ncvisual_destroy(visual);
        ++g_pixelPlaneFailed;
        g_pixelLastError = "ncplane_create refused " + std::to_string(fitCols) + "x" +
                           std::to_string(fitRows) + " cells at " + std::to_string(y) + "," +
                           std::to_string(x) + " of " + std::to_string(parentCols) + "x" +
                           std::to_string(parentRows);
        return false;
    }

    ncvisual_options opts{};
    opts.n = target;
    opts.scaling = NCSCALE_NONE;
    opts.y = 0;
    opts.x = 0;
    opts.blitter = NCBLIT_PIXEL;
    // A terminal that announced a protocol it cannot render must fail here
    // rather than degrade into cell art: the runes are better than a lie.
    opts.flags = NCVISUAL_OPTION_NODEGRADE;
    ncplane* drawn = ncvisual_blit(g_nc, visual, &opts);
    ncvisual_destroy(visual);
    if (drawn == nullptr) {
        ncplane_destroy(target);
        ++g_pixelBlitsFailed;
        g_pixelLastError = "ncvisual_blit refused " + std::to_string(width) + "x" +
                           std::to_string(height) + " px in " + std::to_string(fitCols) + "x" +
                           std::to_string(fitRows) + " cells at " + std::to_string(y) + "," +
                           std::to_string(x);
        return false;
    }
    g_pixelPlanes.push_back(target);
    ++g_pixelBlitsOk;
    return true;
}

/// Chooses the pixel renderer when available, the block renderer otherwise.
///
/// The pixel path returns false when the terminal accepted the capability but
/// the blit produced nothing: the runes then draw the curve, so a graph is
/// never replaced by an empty grid.
bool drawGraph(ncplane* plane, int y, int x, int cols, int rows,
               const std::deque<double>& samples, double floor, double ceiling,
               const Palette& palette, bool animate, double pulse,
               const std::vector<AxisLabel>& yLabels = {},
               const std::vector<AxisLabel>& xLabels = {}) {
    // A dump request forces the pixel path: the bitmap is written before the
    // blit, so the rendering can be checked on a terminal without pixels.
    static const bool dumpRequested = std::getenv("SLAPTOP_PIXEL_DUMP") != nullptr;
    if ((g_pixelSupport != 0 || dumpRequested) &&
        drawPixelGraph(plane, y, x, cols, rows, samples, floor, ceiling, palette, yLabels,
                       xLabels)) {
        return true;
    }
    // runes below
    drawAreaGraph(plane, y, x, cols, rows, samples, floor, ceiling, palette, animate, pulse);
    return false;
}

// ---------------------------------------------------------------------------
// Card
// ---------------------------------------------------------------------------

constexpr int kCardCompact = 5;   ///< values only
constexpr int kCardMedium = 9;    ///< one CPU graph
constexpr int kCardRich = 14;     ///< cpu + memory + ops graphs

void drawCard(ncplane* plane, int top, int left, int height, int width,
              const InstanceMetrics& metrics, const InstanceHistory& history, double pulse,
              bool focused, bool relative) {
    const bool running = metrics.health == Health::Running;
    const std::uint32_t frameColor =
        focused ? g_theme.focus : (running ? g_theme.frame : rgb(0xa0, 0x40, 0x40));
    const std::uint32_t titleColor = running ? rgb(0x7a, 0xc8, 0xff) : g_theme.error;

    const std::string rule = repeat("\u2500", static_cast<std::size_t>(std::max(0, width - 2)));
    put(plane, top, left, "\u256D" + rule, frameColor);
    put(plane, top, left + width - 1, "\u256E", frameColor);
    for (int row = 1; row < height - 1; ++row) {
        put(plane, top + row, left, "\u2502", frameColor);
        put(plane, top + row, left + width - 1, "\u2502", frameColor);
    }
    put(plane, top + height - 1, left, "\u2570" + rule, frameColor);
    put(plane, top + height - 1, left + width - 1, "\u256F", frameColor);

    // Title: name ─ pid ─ state ──────────────
    int x = left + 2;
    put(plane, top, x, text::fit(metrics.instance.name, static_cast<std::size_t>(width / 3)),
        titleColor, true);
    x += static_cast<int>(text::width(metrics.instance.name)) + 2;
    const std::string pid = "pid " + std::to_string(metrics.instance.pid);
    put(plane, top, x, pid, g_theme.dim);
    x += static_cast<int>(pid.size()) + 2;
    put(plane, top, x, healthLabel(metrics.health), running ? g_theme.ok : g_theme.error, true);
    x += static_cast<int>(std::strlen(healthLabel(metrics.health))) + 1;
    put(plane, top, x,
        repeat("\u2500", static_cast<std::size_t>(std::max(0, width - x + left - 1))), frameColor);

    const int inner = width - 4;
    if (inner <= 8 || height < 3) {
        return;
    }

    // Subdued vertical gradient inside the card, using the native gradient
    // primitive: the body of each card reads as one soft block instead of a
    // flat background, and the graphs sit on top of it.
    if (height > 3 && inner > 2) {
        std::uint64_t upperBg = 0;
        std::uint64_t lowerBg = 0;
        ncchannels_set_bg_rgb(&upperBg, rgb(0x12, 0x14, 0x1e));
        ncchannels_set_bg_rgb(&lowerBg, rgb(0x1a, 0x1d, 0x2a));
        ncplane_gradient(plane, top + 1, left + 2, static_cast<unsigned>(height - 2),
                         static_cast<unsigned>(inner), " ", 0, upperBg, upperBg, lowerBg,
                         lowerBg);
    }

    if (!metrics.hasProc) {
        put(plane, top + 1, left + 2, text::fit("process not readable", static_cast<std::size_t>(inner)),
            g_theme.error);
        if (!metrics.error.empty() && height > 3) {
            put(plane, top + 2, left + 2, text::fit(metrics.error, static_cast<std::size_t>(inner)),
                rgb(0xa0, 0x80, 0x80));
        }
        return;
    }

    int row = top + 1;
    const int body = height - 2;  // rows between the borders

    // --- Header line: the numbers behind the graphs -----------------------
    std::string lag = "--";
    if (metrics.replication.available && metrics.replication.lagSeconds >= 0.0) {
        lag = humanAge(metrics.replication.lagSeconds);
    }
    std::uint64_t connCurrent = 0;
    std::uint64_t connTotal = 0;
#ifdef SLAPTOP_WITH_LDAP
    if (metrics.hasMonitor) {
        connCurrent = metrics.monitor.connectionsCurrent;
        connTotal = metrics.monitor.connectionsTotal;
    }
#endif
    {
        const std::string cpu = cpuText(metrics);
        char rest[256];
        const double hostMem = systemMemoryPercent(metrics);
        char memField[64];
        if (hostMem >= 0.0) {
            std::snprintf(memField, sizeof(memField), "%s (host %.0f%%)",
                          humanBytes(metrics.proc.rssBytes).c_str(), hostMem);
        } else {
            std::snprintf(memField, sizeof(memField), "%s",
                          humanBytes(metrics.proc.rssBytes).c_str());
        }
        std::snprintf(rest, sizeof(rest),
                      "  mem %-6s  thr %3llu  ops %6.1f/s  conn %llu/%llu  lag %s",
                      memField,
                      static_cast<unsigned long long>(metrics.proc.numThreads),
                      history.opsPerSecond.last(),
                      static_cast<unsigned long long>(connCurrent),
                      static_cast<unsigned long long>(connTotal), lag.c_str());
        int column = left + 2;
        put(plane, row, column, "cpu ", g_theme.dim);
        column += 4;
        put(plane, row, column, cpu, cpuColor(metrics), true);
        column += static_cast<int>(text::width(cpu));
        const int room = inner - (column - left - 2);
        if (room > 0) {
            put(plane, row, column, text::fit(rest, static_cast<std::size_t>(room)),
                g_theme.text);
        }
    }
    ++row;

    // --- Graphs -----------------------------------------------------------
    // One to three bands share the same time axis: cpu on top, then memory,
    // then activity.  The number of bands follows the space available, so a
    // small terminal still gets a readable graph instead of one squeezed line.
    // Two footer lines when the card is tall enough: the second one carries
    // everything the old Detail screen used to add (uptime, listeners,
    // databases, per-operation counters), so there is nothing left to hide.
    const int footerLines = height >= 8 ? 2 : 1;
    int graphRows = std::max(1, body - 1 - footerLines);  // header + footers reserved
    /// Cells of the first band: the time axis of the footer is computed on it.
    int firstGraphWidth = 0;

    if (graphRows > 0) {
        struct Band {
            const char* label;
            const std::deque<double>* values;
            Palette palette;
            bool zoomed;
            double minimumSpan;
            std::string valueText;
            /// Ceiling to draw against when the scale is relative: 100 for the
            /// machine-relative CPU share, the host's RAM for memory.  0 means
            /// "no natural maximum", and the band keeps its automatic scale.
            double capacity;
        };

        std::string cpuValue;
        std::string memValue;
        std::string opsValue;
        cpuValue = cpuText(metrics);
        memValue = humanBytes(metrics.proc.rssBytes);
        {
            char ops[32];
            std::snprintf(ops, sizeof(ops), "%.1f/s", history.opsPerSecond.last());
            opsValue = ops;
        }

        // The denominator is always shown when it is known, like the CPU one:
        // "602.9M / 31.1G" says the same thing whether the graph is scaled to
        // the capacity or to its own maximum.  It is the RAM of the host that
        // runs the instance, never this machine's.
        {
            const double memTotal = memCapacityMiB(metrics);
            if (memTotal > 0.0) {
                char memText[64];
                std::snprintf(memText, sizeof(memText), "%s / %s", memValue.c_str(),
                              humanBytes(static_cast<std::uint64_t>(memTotal * 1024.0 * 1024.0))
                                  .c_str());
                memValue = memText;
            }
        }

        std::vector<Band> bands;
        // The band fills up when the machine saturates, not when one core
        // does: an idle 8-core host stays flat, a busy one climbs to the top.
        // `minimumSpan` only applies when the graph is *not* relative (auto
        // scale): 25 % keeps an idle machine's noise from filling the band.
        bands.push_back({"cpu", &history.cpuPercent.values(), kCpuPalette, false, 25.0, cpuValue,
                         relative ? 100.0 * cpuCapacity(metrics) : 0.0});
        if (graphRows >= 2) {
            bands.push_back({"mem", &history.rssMiB.values(), kMemPalette, false, 1.0, memValue,
                             relative ? memCapacityMiB(metrics) : 0.0});
        }
        if (graphRows >= 3) {
            bands.push_back({"ops", &history.opsPerSecond.values(), kOpsPalette, false, 1.0,
                             opsValue, 0.0});
        }
        // A band needs at least one row; drop from the bottom if space is short.
        while (static_cast<int>(bands.size()) > graphRows) {
            bands.pop_back();
        }

        const int count = static_cast<int>(bands.size());
        const int baseRows = graphRows / std::max(1, count);
        int extra = graphRows - baseRows * count;

        for (int index = 0; index < count; ++index) {
            Band& band = bands[static_cast<std::size_t>(index)];
            const int bandHeight = baseRows + (extra > 0 ? 1 : 0);
            if (extra > 0) {
                --extra;
            }
            if (bandHeight <= 0) {
                continue;
            }
            // The label carries the band colour: the three areas are stacked
            // without a gap, so the coloured caption is what tells them apart.
            put(plane, row, left + 2, band.label, shade(band.palette, 0.9), true);
            // Reserve the value column on the right so the graph and the
            // label never overlap.
            const int valueWidth = static_cast<int>(band.valueText.size());
            // The gutter holds the band label and the axis step, then a blank
            // column, then the graph.  Ten cells because the ceiling also has
            // an entity ("800%") or a size ("125.2G"): the step used to be
            // clipped and written over the label.
            const int axisWidth = 10;
            const int graphLeft = left + 2 + axisWidth + 1;
            const int graphWidth = std::max(10, inner - axisWidth - 3 - valueWidth);
            double floor = 0.0;
            double ceiling = 1.0;
            if (band.capacity > 0.0) {
                ceiling = band.capacity;
            } else {
                const Scale scaleValue =
                    scaleFor(*band.values, band.zoomed, band.minimumSpan, true);
                floor = scaleValue.floor;
                ceiling = scaleValue.ceiling;
            }
            drawBandGrid(plane, row, graphLeft, graphWidth, bandHeight);

            // Axis labels: built once per band.  In pixel mode they are drawn
            // into the bitmap (small font); with runes, in the cell margin.
            const auto axisValue = [&band](double value) {
                char text[16];
                if (band.label == std::string("cpu")) {
                    std::snprintf(text, sizeof(text), "%.0f%%", value);
                } else if (band.label == std::string("mem")) {
                    const std::string size =
                        humanBytes(static_cast<std::uint64_t>(value * 1024.0 * 1024.0));
                    std::snprintf(text, sizeof(text), "%s", size.c_str());
                } else {
                    std::snprintf(text, sizeof(text), "%.1f/s", value);
                }
                return std::string(text);
            };
            const std::vector<AxisLabel> yLabels =
                yAxisLabels(floor, ceiling, bandHeight, axisValue);
            const std::vector<AxisLabel> xLabels =
                xAxisLabels(band.values->size(), history.sampleSeconds);
            const bool pixel =
                drawGraph(plane, row, graphLeft, graphWidth, bandHeight, *band.values, floor,
                          ceiling, band.palette, g_theme.animate, pulse, yLabels, xLabels);
            put(plane, row, graphLeft + graphWidth + 1, band.valueText,
                shade(band.palette, 0.85), true);

            // The cell axis is the fallback: in pixel mode the values are in
            // the bitmap, at every grid line, in a smaller font.  It starts
            // after the label so the band keeps its name on screen.
            if (!pixel && bandHeight >= 1) {
                put(plane, row, left + 2 + 4, padLeft(axisValue(ceiling), axisWidth - 4),
                    g_theme.dim);
                if (bandHeight > 1) {
                    put(plane, row + bandHeight - 1, left + 2 + 4,
                        padLeft("0", axisWidth - 4), g_theme.dim);
                }
            }
            if (firstGraphWidth == 0) {
                firstGraphWidth = graphWidth;
            }
            row += bandHeight;
        }
    }

    // --- Footer: replication, log, then the rest of the instance --------
    const int footerTop = top + height - 1 - footerLines;
    if (row < footerTop) {
        row = footerTop;  // graphs never spill into the footer rows
    }
    int footerRow = footerTop;
    if (footerRow < top + height - 1) {
        std::string detail;
        std::uint32_t color = g_theme.dim;
        if (!metrics.error.empty()) {
            detail = metrics.error;
            color = g_theme.error;
        } else {
            detail = "csn " + formatCsn(metrics.replication.newestCsn) + "  lag " + lag;
            if (metrics.log.available) {
                detail += "  " + basename(metrics.log.path) + "  " +
                          std::to_string(static_cast<long long>(metrics.log.linesPerSecond)) +
                          " l/s";
                if (metrics.log.errors > 0) {
                    detail += "  err " + std::to_string(metrics.log.errors);
                    color = g_theme.error;
                }
            }
        }
        put(plane, footerRow++, left + 2,
            text::fit(detail, static_cast<std::size_t>(inner)), color);
    }

#ifdef SLAPTOP_WITH_LDAP
    if (footerRow < top + height - 1 && metrics.hasMonitor) {
        const MonitorSnapshot& monitor = metrics.monitor;
        std::string extra;
        double up = monitor.uptimeSeconds > 0
                        ? static_cast<double>(monitor.uptimeSeconds)
                        : generalizedAge(monitor.startTime);
        if (up >= 0.0) {
            extra += "up " + humanDuration(up) + "  ";
        }
        // Time step of the vertical grid lines: four cells each, over the span
        // the history covers.
        if (firstGraphWidth > 0 && history.sampleSeconds > 0.0 &&
            !history.cpuPercent.empty()) {
            const double span =
                static_cast<double>(history.cpuPercent.size()) * history.sampleSeconds;
            const double step = span * 4.0 / static_cast<double>(firstGraphWidth);
            // Both ends of the axis, in clock time: "grid 1.3s" alone says the
            // spacing but not what the window covers.
            char axis[64];
            if (g_pixelSupport != 0) {
                // The bitmap carries the times, in its own small font.
                std::snprintf(axis, sizeof(axis),
                              step < 10.0 ? "grid %.1fs  " : "grid %.0fs  ", step);
            } else {
                // Block runes: the axis has no bitmap to live in, so the two
                // ends go in the footer next to the spacing.
                std::snprintf(axis, sizeof(axis), step < 10.0 ? "grid %.1fs  %s \u2192 %s  "
                                                              : "grid %.0fs  %s \u2192 %s  ",
                              step, clockAt(-span).c_str(), clockNow().c_str());
            }
            extra += axis;
        }
        extra += "lis " + std::to_string(monitor.listeners.size()) + "  db " +
                 std::to_string(monitor.databases.size());
        // Per-operation counters, busiest first: three fit on a normal width.
        std::vector<std::pair<std::uint64_t, std::string>> ops;
        ops.reserve(monitor.opsByType.size());
        for (const auto& [name, count] : monitor.opsByType) {
            ops.emplace_back(count, name);
        }
        std::sort(ops.begin(), ops.end(),
                  [](const auto& a, const auto& b) { return a.first > b.first; });
        int shown = 0;
        for (const auto& [count, name] : ops) {
            if (shown == 3) {
                break;
            }
            extra += "  " + name + " " + std::to_string(count);
            ++shown;
        }
        put(plane, footerRow, left + 2, text::fit(extra, static_cast<std::size_t>(inner)),
            g_theme.dim);
    }
#endif
}

// ---------------------------------------------------------------------------
// Log panel
// ---------------------------------------------------------------------------

std::uint32_t logColor(LogLevel level) {
    switch (level) {
        case LogLevel::Error:
            return g_theme.error;
        case LogLevel::Warning:
            return g_theme.warn;
        case LogLevel::Info:
        default:
            return rgb(0x9a, 0xa0, 0xb0);
    }
}

// ---------------------------------------------------------------------------
// Log line colouring
// ---------------------------------------------------------------------------

/// One coloured fragment of a log line.
struct LogRun {
    std::string text;
    std::uint32_t color{0};
    bool bold{false};
};

/// "0.023" -> 0.023, without throwing on a malformed value.
double parseSeconds(const std::string& value) {
    try {
        return std::stod(value);
    } catch (const std::exception&) {
        return -1.0;
    }
}

/// Colour of a `key=value` pair, decided from the field name.  The vocabulary
/// is the OpenLDAP access-log one (the same fields slaptrack highlights), so a
/// reader who knows one tool reads the other.
std::uint32_t logValueColor(const std::string& key, const std::string& value) {
    if (key == "err") {
        // err=0 is the success marker: the single most useful bit of the line.
        return value == "0" ? g_theme.ok : g_theme.error;
    }
    if (key == "etime" || key == "qtime" || key == "wtime") {
        const double seconds = parseSeconds(value);
        if (seconds >= 1.0) {
            return g_theme.error;   // a second of server time is a problem
        }
        if (seconds >= 0.1) {
            return g_theme.warn;
        }
        return rgb(0x8a, 0x90, 0xa0);
    }
    if (key == "conn" || key == "op" || key == "fd" || key == "tag") {
        return rgb(0x5f, 0xb8, 0xc8);        // identifiers
    }
    if (key == "dn" || key == "base" || key == "authzid" || key == "authcDN" ||
        key == "newSuperior") {
        return rgb(0x94, 0xc8, 0x74);        // entries
    }
    if (key == "filter" || key == "attr") {
        return rgb(0xc8, 0xa8, 0x6a);        // what was asked for
    }
    if (key == "IP" || key == "addr" || key == "peer" || key == "sasl_ssf" ||
        key == "ssf") {
        return rgb(0x7a, 0x9a, 0xd8);        // where it came from
    }
    return 0;                                // caller falls back to the base colour
}

std::uint32_t fadeColor(std::uint32_t color, double faded) {
    return faded > 0.0 ? blend(color, rgb(0x24, 0x28, 0x30), faded) : color;
}

/// True when `text` starts with an ISO-8601 (rfc3339) stamp; returns its length.
std::size_t isoTimestampLength(const std::string& text) {
    if (text.size() < 20 || !std::isdigit(static_cast<unsigned char>(text[0])) ||
        text[4] != '-' || text[7] != '-' || text[10] != 'T' || text[13] != ':' ||
        text[16] != ':') {
        return 0;
    }
    std::size_t end = 19;
    if (end < text.size() && text[end] == '.') {
        ++end;
        while (end < text.size() && std::isdigit(static_cast<unsigned char>(text[end]))) {
            ++end;
        }
    }
    if (end < text.size() && text[end] == 'Z') {
        ++end;
    }
    return end;
}

/// Splits one log line into coloured runs: timestamp, thread id, `key=value`
/// fields and the operation keywords.  Anything unrecognised keeps `base`.
std::vector<LogRun> logRuns(const std::string& line, std::uint32_t base, double faded) {
    std::vector<LogRun> runs;
    runs.reserve(12);
    const auto add = [&runs, base, faded](std::string text, std::uint32_t color,
                                          bool bold = false) {
        if (text.empty()) {
            return;
        }
        runs.push_back(LogRun{std::move(text), fadeColor(color == 0 ? base : color, faded), bold});
    };

    std::size_t i = 0;
    // Timestamp: context, not content, so it stays dim.
    const std::size_t stamp = isoTimestampLength(line);
    if (stamp > 0) {
        add(line.substr(0, stamp), rgb(0x5a, 0x62, 0x74));
        i = stamp;
    }

    while (i < line.size()) {
        if (line[i] == ' ' || line[i] == '\t') {
            const std::size_t start = i;
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t')) {
                ++i;
            }
            add(line.substr(start, i - start), base);
            continue;
        }
        // One word, keeping quoted values (dn="cn=a b") together.
        const std::size_t start = i;
        bool quoted = false;
        while (i < line.size()) {
            const char c = line[i];
            if (c == '"') {
                quoted = !quoted;
            } else if (c == ' ' && !quoted) {
                break;
            }
            ++i;
        }
        const std::string word = line.substr(start, i - start);

        // The emitting thread: a bare 0x... token right after the stamp.
        if (word.size() > 8 && word[0] == '0' && word[1] == 'x') {
            add(word, rgb(0x50, 0x56, 0x64));
            continue;
        }

        // key=value, but not inside a quoted value ("(&(uid=a)(cn=b))").
        const std::size_t eq = word.find('=');
        if (eq != std::string::npos && eq > 0 && eq < 24) {
            const std::string key = word.substr(0, eq);
            const std::string value = word.substr(eq + 1);
            add(key + "=", rgb(0x6a, 0x74, 0x88));
            add(value, logValueColor(key, value));
            continue;
        }

        // Operation and lifecycle keywords.
        if (word == "BIND") {
            add(word, g_theme.accent, true);
        } else if (word == "SRCH" || word == "SEARCH" || word == "EXTENDED") {
            add(word, rgb(0x7a, 0xc8, 0xff), true);
        } else if (word == "RESULT") {
            add(word, g_theme.accent, true);
        } else if (word == "ACCEPT") {
            add(word, g_theme.ok, true);
        } else if (word == "closed" || word == "UNBIND" || word == "ABANDON") {
            add(word, rgb(0x74, 0x7c, 0x8c));
        } else if (word.size() > 1 && word.front() == '"') {
            add(word, rgb(0x94, 0xc8, 0x74));    // continuation of a quoted DN
        } else {
            add(word, base);
        }
    }
    return runs;
}

/// Draws pre-built runs, never past `width` columns.
void drawRuns(ncplane* plane, int y, int x, int width, const std::vector<LogRun>& runs) {
    if (width <= 0) {
        return;
    }
    int used = 0;
    for (const LogRun& run : runs) {
        const int remaining = width - used;
        if (remaining <= 0) {
            break;
        }
        const std::string piece = text::fit(run.text, static_cast<std::size_t>(remaining));
        if (piece.empty()) {
            break;
        }
        put(plane, y, x + used, piece, run.color, run.bold);
        used += text::width(piece);
    }
}

/// Draws one log line, run by run, never past `width` columns.  `faded` in
/// [0,1] blends every colour towards the panel background as the line ages.
void drawLogText(ncplane* plane, int y, int x, int width, const std::string& text,
                 std::uint32_t base, double faded = 0.0) {
    if (width <= 0 || text.empty()) {
        return;
    }
    drawRuns(plane, y, x, width, logRuns(text, base, faded));
}

/// One line currently on screen, with the time it appeared.
struct ShownLine {
    LogEntry entry;
};

/// Lines per second above which the log is considered to scroll fast enough
/// to need fading.  Below it the panel behaves like a plain tail: the last
/// lines stay, so the last activity is always readable.
/// Shows the most recent log lines, newest at the bottom, like a tail -f.
///
/// A line stays at full brightness for `ttlSeconds`, then fades towards the
/// background over `fadeSeconds`: at five lines per second a plain tail is
/// unreadable, the TTL keeps each line on screen long enough to be read.
void drawLogPanel(ncplane* plane, int top, int left, int height, int width,
                  const InstanceMetrics& metrics, const std::deque<ShownLine>& lines) {
    if (height <= 1 || width < 12) {
        return;
    }
    const std::uint32_t frameColor = g_theme.frame;
    const std::string rule = repeat("\u2500", static_cast<std::size_t>(std::max(0, width - 2)));
    put(plane, top, left, "\u256D" + rule, frameColor);
    put(plane, top, left + width - 1, "\u256E", frameColor);
    for (int row = 1; row < height - 1; ++row) {
        put(plane, top + row, left, "\u2502", frameColor);
        put(plane, top + row, left + width - 1, "\u2502", frameColor);
    }
    put(plane, top + height - 1, left, "\u2570" + rule, frameColor);
    put(plane, top + height - 1, left + width - 1, "\u256F", frameColor);

    const std::string title = " log " + basename(metrics.log.path) + "  " +
                              std::to_string(metrics.log.linesRead) + " lines, " +
                              std::to_string(metrics.log.errors) + " errors ";
    int x = left + 2;
    put(plane, top, x, text::fit(title, static_cast<std::size_t>(std::max(0, width - 6))), g_theme.accent,
        true);
    x += static_cast<int>(text::width(title)) + 1;
    put(plane, top, x,
        repeat("\u2500", static_cast<std::size_t>(std::max(0, width - x + left - 1))), frameColor);

    const int rows = height - 2;
    const int inner = width - 4;
    if (rows <= 0 || inner <= 0) {
        return;
    }
    const std::size_t count = lines.size();
    const std::size_t visible = static_cast<std::size_t>(std::max(0, rows));
    const std::size_t skip = count > visible ? count - visible : 0;
    // A tail is anchored at the bottom: when there are fewer lines than rows,
    // the gap stays above the text, so new lines keep appearing at the same
    // place and the panel always fills from the bottom.
    const std::size_t drawn = std::min(visible, count);
    const int firstRow = top + 1 + static_cast<int>(visible - drawn);
    // Only the oldest few lines on screen fade, and they fade by position, not
    // by age: the panel is always full, so age says nothing about what is old.
    const std::size_t fadeCount = std::clamp<std::size_t>(visible / 4, 2, 5);
    int row = firstRow;
    for (std::size_t i = skip; i < count && row < top + height - 1; ++i, ++row) {
        const ShownLine& line = lines[i];
        const std::size_t position = static_cast<std::size_t>(row - firstRow);
        double faded = 0.0;
        if (position < fadeCount) {
            faded = 1.0 - static_cast<double>(position + 1) /
                              static_cast<double>(fadeCount + 1);
        }
        drawLogText(plane, row, left + 2, inner, line.entry.text, logColor(line.entry.level),
                    faded);
    }
    if (count == 0) {
        put(plane, top + 1, left + 2,
            metrics.log.linesRead == 0 ? "no log line yet" : "no line in the window",
            g_theme.dim);
    }
}

// ---------------------------------------------------------------------------
// Screen tabs (drawn once, on top of every screen)
// ---------------------------------------------------------------------------

/// The screens, in Tab order.
enum class Screen {
    Dashboard,
    Architecture,
    Databases,
    Indexes,
    Replication,
    Io,
    Monitor,
    Connections,
    Behaviour,
    Logs
};


/// The screens offered for this fleet, in Tab order.
std::vector<Screen> screenList(const FleetSnapshot& fleet) {
    std::vector<Screen> screens{Screen::Dashboard, Screen::Architecture, Screen::Databases};
    // Always offered: when nothing is replicated — or when the CSN cannot be
    // read — the page says why.  An absent tab is an unexplained absence.
    screens.push_back(Screen::Replication);
    // Index coverage needs either a declared index or a log to compare it with.
    for (const InstanceMetrics& metrics : fleet.instances) {
        bool indexed = false;
        for (const auto& database : metrics.directory.databases) {
            if (!database.indexes.empty()) {
                indexed = true;
                break;
            }
        }
        if (indexed || metrics.log.available) {
            screens.push_back(Screen::Indexes);
            break;
        }
    }

    screens.push_back(Screen::Io);
    screens.push_back(Screen::Monitor);
    screens.push_back(Screen::Connections);
    // The behaviour tab needs an access log: a remote instance (--uri) has
    // none, and neither has a server without olcLogFile.
    for (const InstanceMetrics& metrics : fleet.instances) {
        if (metrics.log.available) {
            screens.push_back(Screen::Behaviour);
            break;
        }
    }
    screens.push_back(Screen::Logs);
    return screens;
}

const char* screenLabel(Screen screen) {
    switch (screen) {
        case Screen::Dashboard:
            return "Dashboard";
        case Screen::Architecture:
            return "Architecture";
        case Screen::Databases:
            return "Databases";
        case Screen::Replication:
            return "Replication";
        case Screen::Io:
            return "I/O";
        case Screen::Monitor:
            return "Monitor";
        case Screen::Connections:
            return "Connections";
        case Screen::Indexes:
            return "Indexes";
        case Screen::Behaviour:
            return "Behaviour";
        case Screen::Logs:
        default:
            return "Logs";
    }
}

/// Draws the one header every screen shares: the tabs stay identical and only
/// the active one is highlighted, so Tab does not redraw a different banner.
void drawScreenTabs(ncplane* plane, int dimY, int dimX, Screen screen,
                    const FleetSnapshot& fleet, int selected, bool paused) {
    put(plane, 0, 1, "slaptop", g_theme.accent, true);
    int cursor = 9;

    // Which instance every screen is about, in the accent colour right next to
    // the name of the tool: each page used to say it in a dim grey that read
    // as part of the background.
    if (selected >= 0 && selected < static_cast<int>(fleet.instances.size())) {
        const InstanceMetrics& current = fleet.instances[static_cast<std::size_t>(selected)];
        std::string label = current.instance.name;
        // A node whose slapd.d has no `slapd_<name>.d` convention is named
        // after its host already: repeating it as "@host" only adds noise.
        if (!current.instance.nodeLabel.empty() &&
            current.instance.nodeLabel != current.instance.name) {
            label += " @" + current.instance.nodeLabel;
        }
        label = " " + label + " ";
        put(plane, 0, cursor, label, g_theme.accent, true,
            rgb(0x2a, 0x22, 0x10));
        cursor += static_cast<int>(text::width(label)) + 1;
    }

    for (const Screen candidate : screenList(fleet)) {
        const char* tabLabel = screenLabel(candidate);
        const bool active = screen == candidate;
        const std::string label = std::string(active ? "[" : " ") + tabLabel +
                                  (active ? "]" : " ");
        if (cursor + static_cast<int>(label.size()) >= dimX - 24) {
            break;
        }
        put(plane, 0, cursor, label, active ? rgb(0x10, 0x18, 0x24) : g_theme.dim, active,
            active ? rgb(0x7a, 0xc8, 0xff) : 0);
        if (active) {
            // Underline the active tab on the separator row.
            put(plane, 1, cursor, repeat("\u2501", static_cast<std::size_t>(text::width(label))),
                rgb(0x7a, 0xc8, 0xff));
        }
        cursor += static_cast<int>(text::width(label)) + 1;
    }


    // Instances and clock on the right, identical on every screen.
    //
    // The clock is placed from its own width alone, never from the width of a
    // string that changes: with "refreshing from remote" the whole right side
    // moved left and back on every collection round.  The indicator now sits in
    // a fixed two-cell slot to its left, filled with an hourglass while a
    // round runs and left blank otherwise.  (⏳ is single-width in the terminal
    // but double-width in notcurses' tables: placing the clock independently
    // keeps it still whichever way it renders.)
    static const char* const hourglass[] = {"\u231B", "\u23F3"};  // ⌛ sand down, ⏳ running
    std::string indicator;
    if (g_refreshing) {
        indicator = padTo(g_theme.animate ? hourglass[(g_spinFrame / 6) % 2] : hourglass[1], 2);
    }
    ++g_spinFrame;

    const std::string now = clockNow();
    const int clockWidth = text::width(now);
    const int clockX = dimX - clockWidth - 3;
    put(plane, 0, clockX, now, paused ? g_theme.warn : g_theme.dim, paused);
    if (!indicator.empty()) {
        put(plane, 0, clockX - 3, indicator, g_theme.warn, true);
    }
    if (paused) {
        put(plane, 0, clockX - 11, "PAUSED  ", g_theme.warn, true);
    }

    // An alert outranks the key hints: it replaces the footer line when one
    // is active, because a map about to fill is not something to discover by
    // pressing a key.  Critical blinks (unless animations are off); a warning
    // stays steady.
    {
        const collector::LmdbRisk* worst = nullptr;
        std::size_t count = 0;
        for (const InstanceMetrics& instance : fleet.instances) {
            for (const collector::LmdbRisk& alert : instance.alerts) {
                ++count;
                if (worst == nullptr ||
                    static_cast<int>(alert.severity) > static_cast<int>(worst->severity)) {
                    worst = &alert;
                }
            }
        }
        if (worst != nullptr) {
            static std::uint64_t phase = 0;
            ++phase;
            const bool critical = worst->severity == collector::AlertSeverity::Critical;
            const bool lit = !g_theme.animate || ((phase / 3) % 2) == 0;
            const std::uint32_t color =
                critical ? (lit ? g_theme.error : blend(g_theme.error, 0x000000, 0.55))
                         : g_theme.warn;
            std::string line = "\u26A0 " + worst->instance + ": " + worst->message;
            if (count > 1) {
                line += "  (+" + std::to_string(count - 1) + " more)";
            }
            put(plane, dimY - 1, 1, text::fit(line, static_cast<std::size_t>(dimX - 2)),
                color, true);
        }
    }

    // Fleet status: one dot per instance, green when the server answers, red
    // when its process is gone, amber when it runs but cn=monitor does not
    // answer.  Drawn left of the clock so it is on every screen.
    if (!fleet.instances.empty()) {
        int statusWidth = 0;
        for (const InstanceMetrics& instance : fleet.instances) {
            statusWidth += 2 + text::width(instance.instance.name) + 2;
        }
        int x = clockX - statusWidth - 2 - (paused ? 11 : 0);
        if (x > cursor + 2) {
            for (const InstanceMetrics& instance : fleet.instances) {
                const bool up = instance.health == Health::Running;
                const std::uint32_t color =
                    up ? g_theme.ok
                       : (instance.health == Health::Degraded ? g_theme.warn : g_theme.error);
                put(plane, 0, x, "\u25CF", color, true);
                const std::string name = instance.instance.name;
                put(plane, 0, x + 2, text::fit(name, static_cast<std::size_t>(dimX - x - 2)),
                    up ? g_theme.dim : g_theme.error, !up);
                x += 2 + text::width(name) + 2;
            }
        }
    }
    put(plane, 1, 0, repeat("\u2500", static_cast<std::size_t>(dimX)), g_theme.frame);

    // Footer, right side: with several instances, say so and show where we are
    // in the fleet. Drawn here rather than per screen so every tab has it.
    const int instances = static_cast<int>(fleet.instances.size());
    if (instances > 1 && dimY > 0) {
        int stopped = 0;
        for (const InstanceMetrics& instance : fleet.instances) {
            if (instance.health == Health::Stopped) {
                ++stopped;
            }
        }
        char page[64];
        std::snprintf(page, sizeof(page), "%d/%d", selected + 1, instances);
        const std::string hint = "\u2190/\u2192 instance   ";
        std::string tail = hint + page;
        if (stopped > 0) {
            tail = std::to_string(stopped) + " stopped   " + tail;
        }
        const int width = text::width(tail);
        const int x = std::max(1, dimX - width - 2);
        if (stopped > 0) {
            const std::string stoppedText = std::to_string(stopped) + " stopped   ";
            put(plane, dimY - 1, x, stoppedText, g_theme.error, true);
            put(plane, dimY - 1, x + text::width(stoppedText), hint, g_theme.dim);
        } else {
            put(plane, dimY - 1, x, hint, g_theme.dim);
        }
        put(plane, dimY - 1, x + text::width(tail) - static_cast<int>(std::strlen(page)), page,
            g_theme.accent, true);
    }
}

// ---------------------------------------------------------------------------
// Framed zones
// ---------------------------------------------------------------------------

/// Geometry returned by drawBox(): where the content may be written.
struct Zone {
    int top{0};
    int left{0};
    int height{0};  ///< inner rows
    int width{0};   ///< inner columns
    bool valid{false};
};

/// Draws a rounded frame with an embedded title and returns the inner area.
Zone drawBox(ncplane* plane, int y, int x, int height, int width, const std::string& title,
             std::uint32_t color = 0) {
    Zone zone;
    if (height < 3 || width < 6) {
        return zone;
    }
    const std::uint32_t frame = color != 0 ? color : g_theme.frame;
    const std::string rule = repeat("\u2500", static_cast<std::size_t>(width - 2));
    put(plane, y, x, "\u256D" + rule, frame);
    put(plane, y, x + width - 1, "\u256E", frame);
    for (int row = 1; row < height - 1; ++row) {
        put(plane, y + row, x, "\u2502", frame);
        put(plane, y + row, x + width - 1, "\u2502", frame);
    }
    put(plane, y + height - 1, x, "\u2570" + rule, frame);
    put(plane, y + height - 1, x + width - 1, "\u256F", frame);

    if (!title.empty()) {
        int cursor = x + 2;
        put(plane, y, cursor, text::fit(title, static_cast<std::size_t>(width - 6)),
            g_theme.accent, true);
        cursor += static_cast<int>(text::width(title)) + 1;
        put(plane, y, cursor,
            repeat("\u2500", static_cast<std::size_t>(std::max(0, width - cursor + x - 1))),
            frame);
    }

    zone.top = y + 1;
    zone.left = x + 2;
    zone.height = height - 2;
    zone.width = width - 4;
    zone.valid = zone.height > 0 && zone.width > 0;
    return zone;
}

// ---------------------------------------------------------------------------
// Monitor view: the raw entries, whatever the server exposes
// ---------------------------------------------------------------------------

/// Header of a screen: the instance being read in bright white, then the
/// details in the usual dim grey.  The tab bar repeats the name in amber; here
/// it answers "whose page is this" at the exact place the eye lands first.
void drawScreenHeader(ncplane* plane, int dimX, const InstanceMetrics& metrics,
                      const std::string& details) {
    std::string name = metrics.instance.name;
    if (!metrics.instance.nodeLabel.empty() && metrics.instance.nodeLabel != name) {
        name += " @" + metrics.instance.nodeLabel;
    }
    put(plane, 2, 1, name, rgb(0xff, 0xff, 0xff), true);
    if (!details.empty()) {
        put(plane, 2, 1 + static_cast<int>(text::width(name)) + 2,
            text::fit("   " + details, static_cast<std::size_t>(std::max(0, dimX - 2))),
            g_theme.dim);
    }
}

/// Renders every collected cn=monitor entry with its attributes, grouped in
/// boxes.  Anything a derived product publishes (lload tiers, DTM backends,
/// custom overlays) shows up here without the dashboard knowing it in advance.
void drawMonitorRaw(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics,
                    int scroll, int instanceIndex, int instanceCount) {
#ifdef SLAPTOP_WITH_LDAP
    // Build the whole page first, then show a window over it: the subtree is
    // long and the screen is short, so scrolling is the only honest layout.
    struct Row {
        std::vector<LogRun> runs;
    };
    std::vector<Row> lines;
    // The page is laid out in newspaper columns first: the width of one column
    // decides how many "name value" pairs an entry packs per line, so a line
    // never has to be cut when it is finally placed.
    // One column needs room for "monitorConnectionLocalAddress IP=…", about
    // seventy columns; packing two pairs per line only pays off when each of
    // them is still wide enough to show a full attribute.
    const int pageColumns = std::clamp((dimX - 4) / 52, 1, 4);
    const int pageColumnWidth = std::max(20, (dimX - 4) / pageColumns);
    const int columns = pageColumnWidth >= 100 ? 2 : 1;
    const int columnWidth = pageColumnWidth / columns;

    for (const LdapEntry& entry : metrics.monitor.raw) {
        const std::string& dn = entry.dn;
        // Connection entries have their own screen, and the database entries
        // are fully covered by the Databases screen: showing them here only
        // buries the attributes this screen exists to expose.
        if (dn.find("cn=Connection ") != std::string::npos ||
            dn.find("cn=Connections,cn=database ") != std::string::npos ||
            (dn.find("cn=Database ") != std::string::npos &&
             dn.find("cn=Overlay") == std::string::npos)) {
            continue;
        }
        if (dn.find("cn=Operations") != std::string::npos ||
            dn.find("cn=operations") != std::string::npos) {
            continue;
        }

        // The monitoredInfo belongs in the title, not on a line of its own.
        const std::string info = entry.first("monitoredInfo");
        std::string title = "\u2500 " + dn;
        if (!info.empty()) {
            title += "  [" + info + "]";
        }
        lines.push_back(
            Row{{LogRun{text::fit(title, static_cast<std::size_t>(pageColumnWidth - 1)),
                        g_theme.accent, true}}});

        // Attributes in columns of "name value", each half piped to the same
        // column start so the eye can run down a column.
        std::vector<LogRun> cells;
        int column = 0;
        const auto flush = [&lines, &cells]() {
            if (!cells.empty()) {
                lines.push_back(Row{cells});
                cells.clear();
            }
        };
        for (const auto& [name, values] : entry.attributes) {
            if (name == "monitoredInfo" || values.empty()) {
                continue;
            }
            std::string value = values.front();
            if (values.size() > 1) {
                value += " (+" + std::to_string(values.size() - 1) + ")";
            }
            const std::string pair = name + " " + value;
            const int used = text::width(pair);
            const int room = columnWidth - 1;
            if (used > room) {
                cells.push_back(LogRun{text::fit(pair, static_cast<std::size_t>(room)),
                                       g_theme.text});
            } else {
                cells.push_back(LogRun{name + " ", g_theme.dim});
                cells.push_back(LogRun{value + std::string(static_cast<std::size_t>(
                                                   room - used),
                                               ' '),
                                       g_theme.text});
            }
            if (++column == columns) {
                flush();
                column = 0;
            }
        }
        flush();
    }

    const int total = static_cast<int>(lines.size());
    const int areaHeight = dimY - 6;  // frame borders + the header line above
    // A wide terminal shows the tree in several newspaper columns instead of
    // one long ribbon: fewer keystrokes to see everything, and no scrolling at
    // all when it fits.
    const int capacity = std::max(1, areaHeight) * pageColumns;
    const int maxScroll = std::max(0, total - capacity);
    if (scroll > maxScroll) {
        scroll = maxScroll;
    }
    char title[192];
    if (total > capacity) {
        std::snprintf(title, sizeof(title),
                      " cn=monitor   %d-%d of %d   %d columns ", scroll + 1,
                      std::min(total, scroll + capacity), total, pageColumns);
    } else {
        std::snprintf(title, sizeof(title), " cn=monitor   %d lines   %d column%s ", total,
                      pageColumns, pageColumns == 1 ? "" : "s");
    }
    Zone area = drawBox(plane, 3, 0, dimY - 4, dimX, title, g_theme.frame);
    const int left = area.valid ? area.left : 2;
    const int width = area.valid ? area.width : dimX - 4;
    const int areaColumnWidth = std::max(12, width / pageColumns);
    const int top = area.valid ? area.top : 4;
    const int height = area.valid ? area.height : areaHeight;

    // Balance the visible slice: column-major with ceil() per column, so a
    // page of 30 lines over two columns gives 15 and 15 instead of 25 and 5.
    const int visible = std::min(capacity, total - scroll);
    const int perColumn = (visible + pageColumns - 1) / pageColumns;
    for (int index = 0; index < pageColumns; ++index) {
        const int columnLeft = left + index * areaColumnWidth;
        for (int line = 0; line < perColumn && line < height; ++line) {
            const int entry = scroll + index * perColumn + line;
            if (entry >= total) {
                break;
            }
            // The last cell of each column is the separator, so text stops one
            // column short of it.
            drawRuns(plane, top + line, columnLeft, areaColumnWidth - 1,
                     lines[static_cast<std::size_t>(entry)].runs);
        }
        if (index + 1 < pageColumns) {
            for (int line = 0; line < height; ++line) {
                put(plane, top + line, columnLeft + areaColumnWidth - 1, "\u2502",
                    g_theme.frame);
            }
        }
    }
    if (total == 0) {
        put(plane, top, left, "no monitor entry collected", g_theme.dim);
    }

    char header[192];
    if (instanceCount > 1) {
        std::snprintf(header, sizeof(header), "(%d/%d)   %zu entries", instanceIndex + 1,
                      instanceCount, metrics.monitor.raw.size());
    } else {
        std::snprintf(header, sizeof(header), "%zu entries", metrics.monitor.raw.size());
    }
#else
    (void)scroll;
    (void)instanceIndex;
    (void)instanceCount;
    char header[192];
    std::snprintf(header, sizeof(header), "%s", metrics.instance.name.c_str());
    drawBox(plane, 3, 0, dimY - 4, dimX, " cn=monitor ", g_theme.frame);
    put(plane, 4, 2, "built without LDAP support", g_theme.dim);
#endif
    drawScreenHeader(plane, dimX, metrics, header);
    put(plane, dimY - 1, 1,
        text::fit("up/down scroll   left/right instance   tab next screen   esc back",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.dim);
}

// ---------------------------------------------------------------------------
// pcache hit accounting
// ---------------------------------------------------------------------------

std::string lowerCopy(const std::string& text) {
    std::string lowered = text;
    for (char& character : lowered) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return lowered;
}

/// pcache publishes one `pcacheQueryURL` per cached query, each carrying
/// `x-answerable`: how many times *that query object* was served from cache.
/// A query expires and is recreated with a new UUID, so the values cannot be
/// summed across time — they are tracked per UUID, which turns them into a
/// session hit counter.  Searches come from the frontend operation counter,
/// which counts cached answers too, so the ratio is hits / searches measured
/// over the same window.
struct PcacheTracker {
    std::string owner;  ///< instance the counters belong to
    std::uint64_t lastSearches{0};
    std::uint64_t searches{0};
    std::uint64_t hits{0};
    bool sawSearches{false};
    std::map<std::string, std::uint64_t> answerable;  ///< "db|uuid" -> last value
};

void trackPcache(PcacheTracker& tracker, const InstanceMetrics& metrics) {
    if (tracker.owner != metrics.instance.name) {
        tracker = PcacheTracker{};
        tracker.owner = metrics.instance.name;
    }
    // Operation counters are keyed by the DN leaf, which is lower-cased:
    // "cn=Search,cn=Operations" becomes "search".
    std::uint64_t searches = 0;
    for (const auto& [type, count] : metrics.monitor.opsByType) {
        if (lowerCopy(type) == "search") {
            searches = count;
            break;
        }
    }
    // The first counter read is a baseline, not a delta: without it the whole
    // search total since the server started would land in the ratio.
    if (searches > 0) {
        if (tracker.sawSearches && searches >= tracker.lastSearches) {
            tracker.searches += searches - tracker.lastSearches;
        }
        tracker.lastSearches = searches;
        tracker.sawSearches = true;
    }

    std::set<std::string> alive;
    for (const DatabaseInfo& database : metrics.monitor.databases) {
        for (const PcacheQuery& query : database.pcache) {
            const std::string key = database.label + "|" + query.uuid;
            alive.insert(key);
            const auto it = tracker.answerable.find(key);
            if (it == tracker.answerable.end()) {
                tracker.answerable.emplace(key, query.answerable);
            } else if (query.answerable >= it->second) {
                tracker.hits += query.answerable - it->second;
                it->second = query.answerable;
            } else {
                it->second = query.answerable;  // query recreated under the same uuid
            }
        }
    }
    for (auto it = tracker.answerable.begin(); it != tracker.answerable.end();) {
        it = alive.count(it->first) != 0 ? std::next(it) : tracker.answerable.erase(it);
    }
}

// ---------------------------------------------------------------------------
// Databases view: everything cn=monitor says about each database
// ---------------------------------------------------------------------------

/// Attributes worth showing, in this order; everything else is skipped.
// The MDB page counters are summarised by the "data.mdb" line and the pie, so
// they are not repeated here.
const char* const kDatabaseAttributes[] = {
    "monitoredInfo", "monitorOverlay", "readOnly", "monitorIsShadow", "namingContexts",
    "olmDbDirectory", "olmMDBEntries", "olmMDBReadersMax", "olmMDBReadersUsed",
    "olmDbOperation",
};

/// Draws a small pie: `ratio` (0..1) of the disc is the "used" sector.
///
/// A terminal cell is twice as tall as wide, so the ellipse is computed in
/// normalised coordinates and the height is half the width — otherwise the
/// "pie" looks like an egg.
/// The same pie, as a bitmap: a rune pie is a staircase of blocks, and this is
/// the one place where a round shape is expected.  Returns false when the
/// terminal cannot take a pixel blit, leaving the rune version to draw.
bool drawPixelPie(ncplane* plane, int top, int left, int width, int height, double ratio,
                  std::uint32_t fill) {
    constexpr double kPi = 3.14159265358979323846;
    if (g_nc == nullptr || g_pixelSupport == 0 || width <= 1 || height <= 1) {
        return false;
    }
    unsigned parentRows = 0;
    unsigned parentCols = 0;
    ncplane_dim_yx(plane, &parentRows, &parentCols);
    if (top < 0 || left < 0 || static_cast<unsigned>(top) >= parentRows ||
        static_cast<unsigned>(left) >= parentCols) {
        return false;
    }
    unsigned pxy = 0, pxx = 0, celldimy = 0, celldimx = 0, maxbmapy = 0, maxbmapx = 0;
    ncplane_pixel_geom(plane, &pxy, &pxx, &celldimy, &celldimx, &maxbmapy, &maxbmapx);
    if (celldimx == 0) {
        celldimx = 8;
    }
    if (celldimy == 0) {
        celldimy = 16;
    }
    const unsigned fitRows = std::min<unsigned>(static_cast<unsigned>(height),
                                                parentRows - static_cast<unsigned>(top));
    const unsigned fitCols = std::min<unsigned>(static_cast<unsigned>(width),
                                                parentCols - static_cast<unsigned>(left));
    unsigned w = fitCols * celldimx;
    unsigned h = fitRows * celldimy;
    while (static_cast<unsigned long>(w) * h > 200000 && (w > 8 || h > 8)) {
        w = std::max(8U, w / 2);
        h = std::max(8U, h / 2);
    }

    const std::uint32_t used = 0xff000000u | (fill != 0 ? fill : g_theme.accent);
    const std::uint32_t freeColor = 0xff000000u | g_theme.frame;
    // Outside the disc: fully transparent, so the terminal background (the
    // default one, like the rest of the application) shows through.  A solid
    // near-black square around a pie read as a black patch on a dark page.
    constexpr std::uint32_t kOutside = 0x00000000u;
    std::vector<std::uint32_t> pixels(static_cast<std::size_t>(w) * h, kOutside);
    // A disc, not the box: one radius for both axes, which on 8x16 cells only
    // happens if the pixel buffer is treated as square.  The previous version
    // stretched the circle to fill the cell rectangle.
    const double cx = (w - 1) / 2.0;
    const double cy = (h - 1) / 2.0;
    const double radius = std::max(1.0, (std::min(w, h) - 1) / 2.0);
    for (unsigned py = 0; py < h; ++py) {
        for (unsigned px = 0; px < w; ++px) {
            const double dx = (px - cx) / radius;
            const double dy = (py - cy) / radius;
            if (dx * dx + dy * dy > 1.0) {
                continue;
            }
            double angle = std::atan2(dx, -dy) / (2.0 * kPi);
            if (angle < 0.0) {
                angle += 1.0;
            }
            pixels[static_cast<std::size_t>(py) * w + px] = angle <= ratio ? used : freeColor;
        }
    }

    ncvisual* visual = ncvisual_from_bgra(pixels.data(), static_cast<int>(h),
                                          static_cast<int>(w * 4), static_cast<int>(w));
    if (visual == nullptr) {
        return false;
    }
    ncplane_options popts{};
    popts.y = top;
    popts.x = left;
    popts.rows = fitRows;
    popts.cols = fitCols;
    ncplane* target = ncplane_create(plane, &popts);
    if (target == nullptr) {
        ncvisual_destroy(visual);
        return false;
    }
    ncvisual_options vopts{};
    vopts.n = target;
    vopts.scaling = NCSCALE_NONE;
    vopts.blitter = NCBLIT_PIXEL;
    vopts.flags = NCVISUAL_OPTION_NODEGRADE;
    ncplane* drawn = ncvisual_blit(g_nc, visual, &vopts);
    ncvisual_destroy(visual);
    if (drawn == nullptr) {
        ncplane_destroy(target);
        return false;
    }
    g_pixelPlanes.push_back(target);
    return true;
}

void drawPie(ncplane* plane, int top, int left, int width, int height, double ratio,
             std::uint32_t fill = 0) {
    constexpr double kPi = 3.14159265358979323846;
    ratio = std::clamp(ratio, 0.0, 1.0);
    if (drawPixelPie(plane, top, left, width, height, ratio, fill)) {
        return;
    }
    const double cx = (width - 1) / 2.0;
    const double cy = (height - 1) / 2.0;
    const double rx = std::max(0.5, (width - 1) / 2.0);
    const double ry = std::max(0.5, (height - 1) / 2.0);
    for (int y = 0; y < height; ++y) {
        for (int x = 0; x < width; ++x) {
            const double dx = (x - cx) / rx;
            const double dy = (y - cy) / ry;
            if (dx * dx + dy * dy > 1.0) {
                continue;
            }
            // Angle measured from 12 o'clock, clockwise: the used sector starts
            // at the top like every other pie chart.
            double angle = std::atan2(dx, -dy) / (2.0 * kPi);
            if (angle < 0.0) {
                angle += 1.0;
            }
            const bool used = angle <= ratio;
            put(plane, top + y, left + x, used ? "\u2588" : "\u2591",
                used ? (fill != 0 ? fill : g_theme.accent) : g_theme.frame);
        }
    }
}

void drawDatabases(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics,
                   const PcacheTracker& pcache) {

#ifdef SLAPTOP_WITH_LDAP
    // One framed zone per database, laid out in one or two columns so the
    // screen reads as boxes instead of a scrolling text dump.
    struct Base {
        std::string title;
        std::vector<std::pair<std::string, std::string>> attributes;
        const DbFileUsage* file{nullptr};   ///< data.mdb sizes, when readable
        const DatabaseInfo* info{nullptr};  ///< LMDB page counters
    };
    std::vector<Base> bases;
    for (const LdapEntry& entry : metrics.monitor.raw) {
        const std::string dn = entry.dn;
        if (dn.find("cn=Database ") == std::string::npos ||
            dn.find("cn=Operations") != std::string::npos ||
            dn.find("cn=operations") != std::string::npos ||
            dn.find("cn=Overlay") != std::string::npos) {
            continue;
        }
        Base base;
        const std::string first = dn.substr(0, dn.find(','));
        const std::string backend = entry.first("monitoredInfo");
        base.title = first + (backend.empty() ? "" : " [" + backend + "]");
        for (const char* attribute : kDatabaseAttributes) {
            if (std::string(attribute) == "monitoredInfo") {
                continue;  // already in the title
            }
            std::string value = entry.first(attribute);
            if (value.empty()) {
                continue;
            }
            base.attributes.emplace_back(attribute, value);
        }
        for (const std::string& overlay : entry.all("monitorOverlay")) {
            base.attributes.emplace_back("overlay", overlay);
        }
        bases.push_back(std::move(base));
    }

    // Entry cache of the backend, read from the configuration files: what the
    // database can hold in memory.  Worth reading next to the entries count
    // below, which is the size of what it would have to hold: a cache of
    // 10 000 entries in front of a 3.4 M entry directory is a deliberate
    // choice, not an accident, and it is only visible when both are on screen.
    for (Base& base : bases) {
        // "cn=Database 1 [ldap]" -> index 1, which is how olcDatabase names it:
        // "{1}ldap".
        const std::string title = base.title;
        const std::size_t marker = title.find("Database ");
        if (marker == std::string::npos) {
            continue;
        }
        const std::size_t digits = marker + std::string("Database ").size();
        const std::size_t end = title.find_first_not_of("0123456789", digits);
        const std::string index =
            title.substr(digits, end == std::string::npos ? std::string::npos : end - digits);
        for (const auto& database : metrics.directory.databases) {
            const std::size_t brace = database.label.find('{');
            const std::size_t close = database.label.find('}', brace == std::string::npos ? 0 : brace);
            const std::string labelIndex =
                brace == std::string::npos || close == std::string::npos
                    ? std::string()
                    : database.label.substr(brace + 1, close - brace - 1);
            if (labelIndex != index) {
                continue;
            }
            char line[160];
            if (!database.pcacheSpec.empty()) {
                std::snprintf(line, sizeof(line), "pcache %s", database.pcacheSpec.c_str());
                base.attributes.emplace_back("cache", line);
            } else if (database.cacheSize != 0 || database.cacheFree != 0) {
                std::snprintf(line, sizeof(line), "%llu entries, free %llu",
                              static_cast<unsigned long long>(database.cacheSize),
                              static_cast<unsigned long long>(database.cacheFree));
                base.attributes.emplace_back("cache", line);
            }
            break;
        }
    }

    // pcache activity, attached to the database it guards.  Everything comes
    // from cn=monitor: pcacheNumQueries/NumEntries for the gauges, and the
    // x-answerable counters of the cached queries for the hits.
    for (Base& base : bases) {
        const std::string title = lowerCopy(base.title);
        const DatabaseInfo* info = nullptr;
        for (const DatabaseInfo& candidate : metrics.monitor.databases) {
            if (title.rfind("cn=" + candidate.label, 0) == 0) {
                info = &candidate;
                break;
            }
        }
        if (info == nullptr || (info->pcacheQueries == 0 && info->pcache.empty())) {
            continue;
        }
        char line[200];
        if (pcache.searches > 0) {
            const double ratio =
                100.0 * static_cast<double>(pcache.hits) / static_cast<double>(pcache.searches);
            std::snprintf(line, sizeof(line), "%.1f%%  %llu hits / %llu searches", ratio,
                          static_cast<unsigned long long>(pcache.hits),
                          static_cast<unsigned long long>(pcache.searches));
        } else {
            std::snprintf(line, sizeof(line), "--  waiting for the first searches");
        }
        base.attributes.emplace_back("pcache hit", line);
        std::snprintf(line, sizeof(line), "%llu cached queries, %llu cached entries",
                      static_cast<unsigned long long>(info->pcacheQueries),
                      static_cast<unsigned long long>(info->pcacheEntries));
        base.attributes.emplace_back("pcache now", line);

        // The most-answered queries: what the cache is actually serving.
        std::vector<const PcacheQuery*> top;
        top.reserve(info->pcache.size());
        for (const PcacheQuery& query : info->pcache) {
            if (query.answerable > 0) {
                top.push_back(&query);
            }
        }
        std::sort(top.begin(), top.end(), [](const PcacheQuery* a, const PcacheQuery* b) {
            return a->answerable > b->answerable;
        });
        std::string serving;
        for (std::size_t index = 0; index < top.size() && index < 3; ++index) {
            serving += (serving.empty() ? "" : "   ") + top[index]->filter + " x" +
                       std::to_string(top[index]->answerable);
        }
        if (serving.empty()) {
            serving = "nothing served from cache yet";
        }
        base.attributes.emplace_back("pcache top", serving);
    }

    // LMDB accounting, straight from back-mdb: the file holds `pagesUsed`
    // pages of which `pagesFree` sit in the freelist, so the data really
    // occupies pagesUsed - pagesFree.  `pagesMax` is how far the map may grow.
    for (Base& base : bases) {
        const std::string title = lowerCopy(base.title);
        for (const DatabaseInfo& candidate : metrics.monitor.databases) {
            if (title.rfind("cn=" + candidate.label, 0) != 0) {
                continue;
            }
            base.info = &candidate;
            break;
        }
        for (const DbFileUsage& usage : metrics.dbFiles) {
            if (title.rfind("cn=" + usage.label, 0) == 0) {
                base.file = &usage;
                break;
            }
        }

        const DatabaseInfo* info = base.info;
        // olmMDBPageSize is missing on some builds (it is a dSAOperation
        // attribute that older slapd versions do not register).  The file size
        // divided by the number of pages gives it back exactly, and 4096 is
        // LMDB's usual page size when the file cannot be read.
        std::uint64_t pageSize = info != nullptr ? info->pageSize : 0;
        if (pageSize == 0 && info != nullptr && info->pagesUsed > 0 && base.file != nullptr &&
            base.file->apparentBytes > 0) {
            pageSize = base.file->apparentBytes / info->pagesUsed;
        }
        if (pageSize == 0) {
            pageSize = 4096;
        }
        char line[200];
        if (info != nullptr && info->pagesUsed > 0) {
            const std::uint64_t dataPages =
                info->pagesUsed > info->pagesFree ? info->pagesUsed - info->pagesFree : 0;
            const double dataBytes = static_cast<double>(dataPages) *
                                     static_cast<double>(pageSize);
            const double mapPercent =
                info->pagesMax > 0
                    ? 100.0 * static_cast<double>(info->pagesUsed) /
                          static_cast<double>(info->pagesMax)
                    : 0.0;
            // Compact units, single spaces: the line has to survive next to
            // the pies, and the exact bytes are in --json anyway.
            const auto compact = [](double bytes) {
                char text[16];
                const double kio = 1024.0;
                if (bytes >= kio * kio * kio) {
                    std::snprintf(text, sizeof(text), "%.0fG", bytes / (kio * kio * kio));
                } else if (bytes >= kio * kio) {
                    std::snprintf(text, sizeof(text), "%.0fM", bytes / (kio * kio));
                } else if (bytes >= kio) {
                    std::snprintf(text, sizeof(text), "%.0fK", bytes / kio);
                } else {
                    std::snprintf(text, sizeof(text), "%.0fB", bytes);
                }
                return std::string(text);
            };
            std::snprintf(line, sizeof(line), "data %s  map %s", compact(dataBytes).c_str(),
                          compact(static_cast<double>(info->pagesMax) *
                                  static_cast<double>(pageSize)).c_str());
            base.attributes.emplace_back("data.mdb", line);
            if (info->readersMax > 0) {
                // slapd: read waiters should track the current connections; a
                // growing gap means read transactions that are never released.
                std::snprintf(line, sizeof(line), "%llu used / %llu max",
                              static_cast<unsigned long long>(info->readersUsed),
                              static_cast<unsigned long long>(info->readersMax));
                base.attributes.emplace_back("readers", line);
                const std::int64_t delta =
                    static_cast<std::int64_t>(info->readersUsed) -
                    static_cast<std::int64_t>(metrics.monitor.connectionsCurrent);
                if (delta > 10) {
                    std::snprintf(line, sizeof(line),
                                  "+%lld against %llu current connections: possible "
                                  "read transactions never released",
                                  static_cast<long long>(delta),
                                  static_cast<unsigned long long>(
                                      metrics.monitor.connectionsCurrent));
                    base.attributes.emplace_back("readers delta", line);
                }
            }
            // The file is sparse: what it claims and what it occupies differ,
            // and that difference is what a "sparse fill" used to try to say.
            if (base.file != nullptr && base.file->apparentBytes > 0 &&
                base.file->allocatedBytes < base.file->apparentBytes) {
                std::snprintf(line, sizeof(line), "%s on disk (%.0f%% of the file)",
                              compact(static_cast<double>(base.file->allocatedBytes)).c_str(),
                              100.0 * static_cast<double>(base.file->allocatedBytes) /
                                  static_cast<double>(base.file->apparentBytes));
                base.attributes.emplace_back("on disk", line);
            }
            (void)mapPercent;
        } else if (base.file != nullptr && base.file->apparentBytes > 0) {
            const double ratio = static_cast<double>(base.file->allocatedBytes) /
                                 static_cast<double>(base.file->apparentBytes);
            std::snprintf(line, sizeof(line), "real %s of %s (%.0f%%)",
                          humanBytes(base.file->allocatedBytes).c_str(),
                          humanBytes(base.file->apparentBytes).c_str(), ratio * 100.0);
            base.attributes.emplace_back("data.mdb", line);
            if (info->readersMax > 0) {
                // slapd: read waiters should track the current connections; a
                // growing gap means read transactions that are never released.
                std::snprintf(line, sizeof(line), "%llu used / %llu max",
                              static_cast<unsigned long long>(info->readersUsed),
                              static_cast<unsigned long long>(info->readersMax));
                base.attributes.emplace_back("readers", line);
                const std::int64_t delta =
                    static_cast<std::int64_t>(info->readersUsed) -
                    static_cast<std::int64_t>(metrics.monitor.connectionsCurrent);
                if (delta > 10) {
                    std::snprintf(line, sizeof(line),
                                  "+%lld against %llu current connections: possible "
                                  "read transactions never released",
                                  static_cast<long long>(delta),
                                  static_cast<unsigned long long>(
                                      metrics.monitor.connectionsCurrent));
                    base.attributes.emplace_back("readers delta", line);
                }
            }
        }
    }

    drawScreenHeader(plane, dimX, metrics, "databases");
    const int columns = dimX >= 96 ? 2 : 1;
    const int gap = 1;
    const int zoneWidth = (dimX - 2 - gap * (columns - 1)) / columns;
    const int top = 3;
    const int available = dimY - 1 - top;

    // --- layout first: how tall is each row of boxes, and what is left? ---
    struct RowGroup {
        std::size_t first{0};
        int count{0};
        int height{0};
        int weight{1};  ///< content lines, drives the share of the leftover
    };
    std::vector<RowGroup> groups;
    int used = 0;
    for (std::size_t index = 0; index < bases.size(); index += static_cast<std::size_t>(columns)) {
        const int count =
            std::min<int>(columns, static_cast<int>(bases.size() - index));
        // Content height, capped so one verbose database cannot push the
        // others off screen; the leftover is shared below.
        int natural = 3;
        for (int column = 0; column < count; ++column) {
            const Base& base = bases[index + static_cast<std::size_t>(column)];
            natural = std::max(
                natural, std::min(static_cast<int>(base.attributes.size()), 11) + 3);
        }
        if (used + natural > available) {
            break;  // no room left: the rest is announced at the bottom
        }
        groups.push_back(RowGroup{index, count, natural, std::max(1, natural - 3)});
        used += natural;
    }
    // Grow the boxes with whatever is left, in proportion to what each row has
    // to show: a row of verbose databases gets more of the free rows than a
    // row holding two short ones.
    {
        std::vector<int> heights;
        std::vector<int> weights;
        heights.reserve(groups.size());
        weights.reserve(groups.size());
        for (const RowGroup& group : groups) {
            heights.push_back(group.height);
            weights.push_back(group.weight);
        }
        distributeExtra(heights, weights, available - used);
        for (std::size_t index = 0; index < groups.size(); ++index) {
            groups[index].height = heights[index];
        }
    }

    // --- draw ------------------------------------------------------------
    int row = top;
    std::size_t drawn = 0;
    for (const RowGroup& group : groups) {
        for (int column = 0; column < group.count; ++column) {
            const std::size_t index = group.first + static_cast<std::size_t>(column);
            if (index >= bases.size()) {
                break;
            }
            const Base& base = bases[index];
            const int left = 1 + column * (zoneWidth + gap);
            Zone zone = drawBox(plane, row, left, group.height, zoneWidth,
                                " " + base.title + " ");
            if (!zone.valid) {
                continue;
            }
            // The pie sits at the right of the box, its legend is the
            // "data.mdb" line among the attributes: when it fits, the text
            // stops short of it.
            const bool pagesKnown = base.info != nullptr && base.info->pagesUsed > 0;
            const bool pie = (pagesKnown || base.file != nullptr) && zone.width >= 46 &&
                             zone.height >= 6;
            // The legends are words, not letters: "fragmentation" and
            // "map used" need 18 columns to stay readable.
            const int pieWidth = 18;
            const int pieHeight = 5;
            // Two pies need 37 columns; below that the sparse-file one is kept
            // because it is the one that predicts MDB_MAP_FULL.
            const bool twoPies = pie && zone.width >= 74;
            const int pieSpan = pie ? (twoPies ? 2 * pieWidth + 1 : pieWidth) : 0;
            const int attrWidth = zone.width - (pie ? pieSpan + 1 : 0);

            int line = zone.top;
            for (const auto& [name, value] : base.attributes) {
                if (line >= zone.top + zone.height) {
                    break;
                }
                char text[320];
                std::snprintf(text, sizeof(text), "%-17s %s", name.c_str(), value.c_str());
                std::uint32_t color = name == "overlay" ? g_theme.dim : g_theme.text;
                if (name == "pcache hit") {
                    color = value.rfind("--", 0) == 0
                                ? g_theme.dim
                                : (value[0] >= '7' ? g_theme.ok : g_theme.warn);
                } else if (name == "pcache now" || name == "pcache top") {
                    color = g_theme.accent;
                }
                put(plane, line++, zone.left,
                    text::fit(text, static_cast<std::size_t>(attrWidth)), color);
            }
            if (pie) {
                // Two LMDB views, because one number could not say both:
                //   fragmentation = free pages / pages in the file (freelist:
                //                   reusable, but never given back)
                //   map used      = pages in the file / pages in the map
                //                   (MDB_MAP_FULL is when this reaches 100 %)
                double fragmentation = 0.0;
                double mapFill = 0.0;
                if (pagesKnown && base.info->pagesUsed > 0) {
                    // Fragmentation = the share of the file sitting in the
                    // freelist: free pages, reusable but never given back.
                    fragmentation = static_cast<double>(base.info->pagesFree) /
                                    static_cast<double>(base.info->pagesUsed);
                    if (base.info->pagesMax > 0) {
                        // Map fill = file pages / map pages, exactly what
                        // assessLmdb() alerts on.  Using data pages instead
                        // made a 5-million-entry database read "1 %", which is
                        // true of the map and meaningless as a fill level.
                        mapFill = static_cast<double>(base.info->pagesUsed) /
                                  static_cast<double>(base.info->pagesMax);
                    }
                } else if (base.file != nullptr && base.file->apparentBytes > 0) {
                    // No monitor counters: the file tells the same story on
                    // disk, allocated against the size it claims.
                    fragmentation = base.file->apparentBytes > base.file->allocatedBytes
                                        ? 1.0 - static_cast<double>(base.file->allocatedBytes) /
                                                    static_cast<double>(
                                                        base.file->apparentBytes)
                                        : 0.0;
                    mapFill = static_cast<double>(base.file->allocatedBytes) /
                              static_cast<double>(base.file->apparentBytes);
                }
                // The sparse-file pie is the one with a threshold: amber then
                // red, the same colours the banner uses.
                const double mapPercent = mapFill * 100.0;
                const std::uint32_t mapColor =
                    mapPercent >= collector::kMapCriticalPercent
                        ? g_theme.error
                        : (mapPercent >= collector::kMapWarningPercent ? g_theme.warn
                                                                       : g_theme.accent);
                const int rightPie = zone.left + zone.width - pieWidth;
                const int leftPie = rightPie - (twoPies ? pieWidth + 1 : 0);
                char caption[32];
                if (twoPies) {
                    // Fragmentation is a maintenance signal, not an emergency:
                    // it turns amber when the freelist is large.
                    const double fragPercent = fragmentation * 100.0;
                    drawPie(plane, zone.top, leftPie, pieWidth, pieHeight, fragmentation,
                            fragPercent >= 25.0 ? g_theme.warn : g_theme.ok);
                    // Same wording as the monitor, so the two tools can
                    // be read side by side.
                    std::snprintf(caption, sizeof(caption), "fragmented %.0f%%", fragPercent);
                    put(plane, zone.top + pieHeight, leftPie,
                        text::fit(caption, static_cast<std::size_t>(pieWidth)),
                        fragPercent >= 25.0 ? g_theme.warn : g_theme.dim);
                }
                drawPie(plane, zone.top, rightPie, pieWidth, pieHeight, mapFill, mapColor);
                // One decimal below 10 %: "1 %" hides the difference between
                // 0.4 % and 1.4 % on a 19 TB map, where the figures matter.
                std::snprintf(caption, sizeof(caption),
                              mapPercent < 10.0 ? "usage %.1f%%" : "usage %.0f%%", mapPercent);
                put(plane, zone.top + pieHeight, rightPie,
                    text::fit(caption, static_cast<std::size_t>(pieWidth)),
                    mapPercent >= collector::kMapWarningPercent ? mapColor : g_theme.dim);
            }
        }
        drawn += static_cast<std::size_t>(group.count);
        row += group.height;
    }
    if (drawn < bases.size()) {
        const int remaining = static_cast<int>(bases.size() - drawn);
        char more[96];
        std::snprintf(more, sizeof(more), "  \u2026 %d more database%s (widen the window)",
                      remaining, remaining == 1 ? "" : "s");
        put(plane, dimY - 2, 1, text::fit(more, static_cast<std::size_t>(dimX - 2)),
            g_theme.warn);
    }
    if (bases.empty()) {
        put(plane, 2, 2, "cn=monitor exposes no database entry", g_theme.dim);
    }
#else
    put(plane, 2, 2, "built without LDAP support", g_theme.dim);
#endif
    put(plane, dimY - 1, 1,
        text::fit("Tab next screen   esc back", static_cast<std::size_t>(dimX - 2)), g_theme.dim);
}

// ---------------------------------------------------------------------------
// Connections view
// ---------------------------------------------------------------------------

/// True when the log line carries the "conn=<number>" field. The field must end
/// at a non-digit, otherwise conn=12 would also match conn=123.
bool mentionsConnection(const std::string& text, unsigned long number) {
    if (number == 0) {
        return false;
    }
    const std::string needle = "conn=" + std::to_string(number);
    std::size_t pos = text.find(needle);
    while (pos != std::string::npos) {
        const std::size_t after = pos + needle.size();
        if (after >= text.size() || !std::isdigit(static_cast<unsigned char>(text[after]))) {
            return true;
        }
        pos = text.find(needle, after);
    }
    return false;
}

/// Log entries belonging to one connection, oldest first, with their level so
/// the caller can keep the usual colouring.
std::vector<LogEntry> logLinesForConnection(const InstanceMetrics& metrics,
                                            unsigned long number) {
    std::vector<LogEntry> lines;
    for (const LogEntry& entry : metrics.log.recent) {
        if (mentionsConnection(entry.text, number)) {
            lines.push_back(entry);
        }
    }
    return lines;
}

/// Sort keys offered in the connection list.
enum class ConnSort { Newest, Busiest, IO, Bind };

const char* connSortLabel(ConnSort sort) {
    switch (sort) {
        case ConnSort::Newest:
            return "newest";
        case ConnSort::Busiest:
            return "busiest";
        case ConnSort::IO:
            return "io";
        case ConnSort::Bind:
        default:
            return "bind";
    }
}

/// Identity carried by a connection: what a client authenticated as, or the DN
/// the proxy asserted towards its upstream.
std::string connectionIdentity(const InstanceMetrics& metrics,
                               const ConnectionInfo& connection) {
    if (!connection.authzDn.empty()) {
        return connection.authzDn;
    }
    if (connection.isBackend && !connection.backendBoundDn.empty()) {
        return connection.backendBoundDn;
    }
    const auto it = metrics.log.binds.find(connection.number);
    return it == metrics.log.binds.end() ? std::string() : it->second;
}

/// Case-insensitive, space-trimmed DN comparison: slapd prints the same
/// identity identically, but a DN taken from a log line can carry spacing.
bool sameIdentity(const std::string& left, const std::string& right) {
    const auto normalize = [](const std::string& text) {
        std::string out;
        out.reserve(text.size());
        for (const char c : text) {
            if (c != ' ' && c != '\t') {
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
        }
        return out;
    };
    return !left.empty() && !right.empty() && normalize(left) == normalize(right);
}

/// One screen row: a client, the upstream connection it was matched with, or
/// both.  `sameIdentity` on the pair is a real match (same bind DN), never a
/// guess: slapd publishes no link between a client operation and the upstream
/// connection that serves it.
struct ConnectionRow {
    const ConnectionInfo* client{nullptr};
    const ConnectionInfo* backend{nullptr};
};

struct ConnectionTable {
    std::vector<ConnectionRow> rows;
    std::size_t clients{0};
    std::size_t backends{0};
    std::size_t matched{0};
};

/// Splits the two families, sorts each with the requested order, then pairs
/// every upstream connection with the first client of the same identity.
/// Upstream connections left alone come last, so an unmatched `[db]` line is
/// visible instead of being hidden behind a plausible neighbour.
ConnectionTable buildConnectionTable(const InstanceMetrics& metrics, ConnSort sort,
                                     bool hideUnknown) {
    std::vector<const ConnectionInfo*> clients;
    std::vector<const ConnectionInfo*> backends;
    for (const ConnectionInfo& connection : metrics.monitor.connections) {
        if (hideUnknown && connectionIdentity(metrics, connection).empty()) {
            continue;
        }
        (connection.isBackend ? backends : clients).push_back(&connection);
    }

    const auto less = [&metrics, sort](const ConnectionInfo* a, const ConnectionInfo* b) {
        switch (sort) {
            case ConnSort::Busiest:
                return a->opsCompleted > b->opsCompleted;
            case ConnSort::IO:
                return (a->ioRead + a->ioWrite) > (b->ioRead + b->ioWrite);
            case ConnSort::Bind:
                return connectionIdentity(metrics, *a) < connectionIdentity(metrics, *b);
            case ConnSort::Newest:
                break;
        }
        return a->number > b->number;
    };
    std::sort(clients.begin(), clients.end(), less);
    std::sort(backends.begin(), backends.end(), less);

    ConnectionTable table;
    table.clients = clients.size();
    table.backends = backends.size();

    std::vector<bool> taken(backends.size(), false);
    std::vector<std::size_t> pairing(clients.size(), backends.size());  // sentinel: none
    for (std::size_t b = 0; b < backends.size(); ++b) {
        const std::string identity = connectionIdentity(metrics, *backends[b]);
        for (std::size_t c = 0; c < clients.size(); ++c) {
            if (pairing[c] != backends.size()) {
                continue;
            }
            if (sameIdentity(identity, connectionIdentity(metrics, *clients[c]))) {
                pairing[c] = b;
                taken[b] = true;
                ++table.matched;
                break;
            }
        }
    }
    for (std::size_t c = 0; c < clients.size(); ++c) {
        table.rows.push_back(ConnectionRow{
            clients[c], pairing[c] < backends.size() ? backends[pairing[c]] : nullptr});
    }
    for (std::size_t b = 0; b < backends.size(); ++b) {
        if (!taken[b]) {
            table.rows.push_back(ConnectionRow{nullptr, backends[b]});
        }
    }
    return table;
}

void drawConnections(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics,
                     const ConnectionTable& table, int selected, bool detail, ConnSort sort,
                     bool hideUnknown) {
    char header[256];
    std::snprintf(header, sizeof(header),
                  "%zu client%s   %zu upstream   %zu matched by bind DN   sort %s%s",
                  table.clients, table.clients == 1 ? "" : "s", table.backends, table.matched,
                  connSortLabel(sort), hideUnknown ? "  (no-bind hidden)" : "");
    drawScreenHeader(plane, dimX, metrics, header);

#ifdef SLAPTOP_WITH_LDAP
    // --- socket headroom ---------------------------------------------------
    // Two resources cap the connections, and they fail differently: file
    // descriptors cap what the server can *accept* (inbound), ephemeral ports
    // cap what the proxy can *open* upstream (outbound).  Both are shown
    // used/limit, so exhaustion is visible before slapd logs "Too many open
    // files" or a bind fails with EADDRNOTAVAIL.
    const auto pressure = [](double ratio) -> std::uint32_t {
        if (ratio >= 0.9) {
            return g_theme.error;
        }
        return ratio >= 0.7 ? g_theme.warn : g_theme.ok;
    };
    const auto percent = [](std::uint64_t used, std::uint64_t limit) {
        char buffer[24];
        std::snprintf(buffer, sizeof(buffer), "%.1f%%",
                      limit == 0 ? 0.0 : 100.0 * static_cast<double>(used) /
                                             static_cast<double>(limit));
        return std::string(buffer);
    };
    const auto drawParts =
        [&](int row, const std::vector<std::pair<std::string, std::uint32_t>>& parts) {
            int x = 1;
            for (const auto& [text, color] : parts) {
                const int room = dimX - 1 - x;
                if (room <= 0) {
                    break;
                }
                const std::string shown =
                    text::fit(text, static_cast<std::size_t>(room));
                put(plane, row, x, shown, color);
                x += static_cast<int>(text::width(shown));
            }
        };
    if (metrics.limits.available) {
        const collector::SocketLimits& limits = metrics.limits;
        const double fdRatio = limits.fdsLimit == 0
                                   ? 0.0
                                   : static_cast<double>(limits.fdsOpen) /
                                         static_cast<double>(limits.fdsLimit);
        // Every figure carries its scope: "slapd" for what this process holds,
        // "host" for the shared pool, "system" for the machine-wide counters.
        std::vector<std::pair<std::string, std::uint32_t>> parts{
            {"  fds      ", g_theme.dim},
            {"slapd " + std::to_string(limits.fdsOpen), pressure(fdRatio)},
            {limits.fdsLimit == 0 ? " open, no soft limit   "
                                  : "/" + std::to_string(limits.fdsLimit) + " soft limit  ",
             g_theme.text},
            {percent(limits.fdsOpen, limits.fdsLimit) + " used  ", pressure(fdRatio)},
            {std::to_string(limits.fdsFree()) + " free   ", g_theme.text},
        };
        if (limits.systemFilesAllocated != 0) {
            parts.emplace_back("system " + std::to_string(limits.systemFilesAllocated) +
                                   " handles (all processes)",
                               g_theme.dim);
        }
        drawParts(3, parts);

        if (limits.portRange() > 0) {
            const double portRatio = static_cast<double>(limits.portsInUse) /
                                     static_cast<double>(limits.portRange());
            std::vector<std::pair<std::string, std::uint32_t>> portParts{
                {"  ports    ", g_theme.dim},
                {"outbound " + std::to_string(limits.portsInUse), pressure(portRatio)},
                {"/" + std::to_string(limits.portRange()) + " ephemeral  ", g_theme.text},
                {percent(limits.portsInUse, limits.portRange()) + " used  ",
                 pressure(portRatio)},
                {std::to_string(limits.portsFree()) + " free on the host   ", g_theme.text},
                {"host " + std::to_string(limits.hostPortsInUse) + " of " +
                     std::to_string(limits.portRange()) + " in use",
                 g_theme.dim},
                {"   TIME_WAIT " + std::to_string(limits.hostTimeWait) + " host / " +
                     std::to_string(limits.timeWait) + " slapd",
                 limits.timeWait > 0 ? g_theme.warn : g_theme.dim},
                {"   range " + std::to_string(limits.portFirst) + "-" +
                     std::to_string(limits.portLast),
                 g_theme.dim},
            };
            drawParts(4, portParts);
        }

        // What the descriptors above actually cap: accepted connections.  A
        // listening socket keeps its own port, so the inbound side has no port
        // pool — it is bounded by fds, which is why the two lines belong
        // together.
        std::vector<std::pair<std::string, std::uint32_t>> inParts{
            {"  inbound  ", g_theme.dim},
            {"listeners " + std::to_string(metrics.monitor.listeners.size()), g_theme.text},
        };
        // `cn=Current` and the connection list disagree on this server (the
        // list is what the screen shows, so it is what the header counts):
        // print the listed clients and the cumulative total, never a third
        // figure that contradicts both.
        inParts.emplace_back("   " + std::to_string(table.clients) + " clients listed",
                             g_theme.text);
        if (metrics.hasMonitor) {
            inParts.emplace_back("   " + std::to_string(metrics.monitor.connectionsTotal) +
                                     " connections since start",
                                 g_theme.dim);
        }
        drawParts(5, inParts);
    } else {
        drawParts(3, {{metrics.instance.pid == 0
                           ? "  inbound/outbound: no /proc on a remote LDAP target"
                           : "  inbound/outbound: /proc/<pid> not readable by this user",
                       g_theme.dim}});
    }

    const int logHeight = detail ? std::clamp(dimY / 3, 6, 12) : 0;
    // The log panel sits directly above the key line; the list takes the rest,
    // minus the two headroom rows and one blank row between the two frames.
    const int logTop = dimY - 1 - logHeight;
    const int listHeight = logHeight > 0 ? std::max(3, logTop - 7) : dimY - 7;

    // Two columns as soon as the server holds upstream connections: the whole
    // point is to read a client and the `[db]` line that serves it side by
    // side.  One column stays the rule for a provider, which has no `[db]`.
    // The frame leaves `dimX - 4` usable columns; the two halves and the one
    // separating space must add up to exactly that, or the last cell of the
    // right half is cut by the frame ("io…").
    const bool twoColumns = table.backends > 0 && dimX >= 116;
    const int leftWidth = twoColumns ? (dimX - 5) / 2 : dimX - 2;
    const int rightWidth = twoColumns ? (dimX - 4) - leftWidth - 1 : 0;
    Zone list = drawBox(plane, 6, 0, listHeight, dimX,
                        twoColumns ? " connections (client | upstream) " : " connections ",
                        g_theme.frame);
    if (!list.valid) {
        return;
    }

    // Columns of one half.  `io` costs 11 cells and is dropped first when the
    // half is too narrow: the identity and the pending count matter more.
    const auto widthsFor = [](int width) {
        struct Cell {
            int number;
            int identity;
            int ops;
            int pending;
            int io;
            int total;
        };
        Cell cell{7, 0, 6, 5, 0, 0};
        // sel(2) + number(7) + 1 + identity + ops(6) + pending(5) + spaces
        const int fixed = 2 + cell.number + 1 + 1 + cell.ops + 1 + cell.pending + 1;
        // `io r/w` costs 13 columns; kept only when the half can still show a
        // useful DN (24 columns), dropped first otherwise.
        if (width - fixed >= 24 + 13) {
            cell.io = 11;
        }
        cell.identity = std::max(10, width - fixed - (cell.io > 0 ? cell.io + 1 : 0));
        cell.total = fixed + cell.identity + (cell.io > 0 ? cell.io + 1 : 0);
        return cell;
    };

    const auto rowText = [&](const ConnectionInfo* connection, int width, bool marker) {
        const auto cell = widthsFor(width);
        std::string text = marker ? "\u25B6 " : "  ";
        if (connection == nullptr) {
            return text;
        }
        text += padLeft(std::to_string(connection->number), cell.number) + " ";
        std::string identity = connectionIdentity(metrics, *connection);
        if (identity.empty()) {
            identity = "-";
        }
        if (connection->isBackend) {
            identity = "[db] " + identity;
        }
        text += padTo(identity, cell.identity) + " " +
                padLeft(std::to_string(connection->opsCompleted), cell.ops) + " " +
                padLeft(std::to_string(connection->opsPending), cell.pending);
        if (cell.io > 0) {
            text += "  " + padLeft(std::to_string(connection->ioRead) + "/" +
                                       std::to_string(connection->ioWrite),
                                   cell.io);
        }
        return text;
    };

    // One header row covering both halves.
    // Same layout as `rowText`, cell for cell: one column too many and the
    // header alone is clipped by the frame while the values are not.
    const auto headerText = [&](int width, const char* label) {
        const auto cell = widthsFor(width);
        std::string text = std::string("  ") + padTo(label, cell.number) + " " +
                           padTo("bind (authz DN)", cell.identity) + " " +
                           padLeft("ops", cell.ops) + " " + padLeft("pend", cell.pending);
        if (cell.io > 0) {
            text += "  " + padLeft("io r/w", cell.io);
        }
        return text;
    };
    int row = list.top;
    {
        std::string line = headerText(leftWidth, "conn");
        if (twoColumns) {
            line = padTo(line, leftWidth) + " " +
                   padTo(headerText(rightWidth, "conn"), rightWidth);
        }
        put(plane, row++, list.left,
            text::fit(line, static_cast<std::size_t>(list.width)), g_theme.dim);
    }

    const int visible = std::max(0, list.height - 1);  // minus the column header
    const int count = static_cast<int>(table.rows.size());
    const int firstRow =
        count > visible ? std::clamp(selected - visible / 2, 0, count - visible) : 0;

    const ConnectionRow* current =
        selected >= 0 && selected < count ? &table.rows[static_cast<std::size_t>(selected)]
                                         : nullptr;
    for (int slot = 0; slot < visible && firstRow + slot < count; ++slot) {
        const std::size_t index = static_cast<std::size_t>(firstRow + slot);
        const bool active = static_cast<int>(index) == selected;
        const ConnectionRow& entry = table.rows[index];

        const bool blankClient =
            entry.client == nullptr || connectionIdentity(metrics, *entry.client).empty();
        const bool blankBackend =
            entry.backend == nullptr || connectionIdentity(metrics, *entry.backend).empty();
        std::string line = rowText(entry.client, leftWidth, active);
        std::uint32_t color = active ? g_theme.accent : (blankClient ? g_theme.dim : g_theme.text);
        if (twoColumns) {
            // Fit the right half before joining: an over-long DN would otherwise
            // run past the frame's right border.
            const std::string right =
                entry.backend == nullptr
                    ? std::string()
                    : text::fit(rowText(entry.backend, rightWidth, false),
                                static_cast<std::size_t>(rightWidth));
            line = padTo(line, leftWidth) + " " + right;
        }
        put(plane, row++, list.left, text::fit(line, static_cast<std::size_t>(list.width)),
            color, active);

        // The right half is colour-coded on its own so a matched upstream is
        // recognisable even when the left half is the selected (amber) row.
        if (twoColumns && entry.backend != nullptr) {
            const std::uint32_t rightColor =
                entry.client != nullptr ? g_theme.ok : (blankBackend ? g_theme.dim : g_theme.warn);
            const int x = list.left + leftWidth + 1;
            put(plane, row - 1, x,
                text::fit(rowText(entry.backend, rightWidth, false),
                          static_cast<std::size_t>(rightWidth)),
                rightColor);
        }
    }
    if (table.rows.empty()) {
        put(plane, list.top, list.left,
            text::fit("nothing to show here (f toggles the no-bind filter)",
                      static_cast<std::size_t>(list.width)),
            g_theme.dim);
    }

    if (logHeight > 0) {
        const int top = logTop;
        std::string title = " connection log ";
        std::vector<LogEntry> lines;
        // A paired row has two connections: the client carries the log lines
        // (the proxy's upstream socket logs nothing in the accesslog), and the
        // upstream connection is named beside it so the pair stays readable.
        const ConnectionInfo* focus =
            current == nullptr ? nullptr : (current->client != nullptr ? current->client
                                                                      : current->backend);
        if (focus != nullptr) {
            std::string who = connectionIdentity(metrics, *focus);
            if (who.empty()) {
                who = "anonymous";
            }
            if (focus->isBackend) {
                who = "[db] " + who;
            }
            title = " conn " + std::to_string(focus->number) + " - " + who;
            if (current->backend != nullptr && current->client != nullptr) {
                title += "  <-> [db] " + std::to_string(current->backend->number);
                if (!current->backend->backendUri.empty()) {
                    title += " " + current->backend->backendUri;
                }
            } else if (focus->isBackend && !focus->backendUri.empty()) {
                title += " -> " + focus->backendUri;
            }
            title += " ";
            lines = logLinesForConnection(metrics, focus->number);
        }
        drawBox(plane, top, 0, logHeight, dimX,
                text::fit(title, static_cast<std::size_t>(std::max(0, dimX - 6))), g_theme.frame);
        const int innerTop = top + 1;
        const int innerLeft = 2;
        const int innerWidth = dimX - 4;
        // One line of identity first: a connection that logged nothing in the
        // window still has a peer, a protocol and an activity timestamp.
        int logStart = innerTop;
        if (focus != nullptr) {
            // Labelled fields, because a bare "unknown 3" means nothing:
            // proto 3 is LDAPv3, and the peer domain is often literally
            // "unknown" when no reverse lookup ran.
            std::string facts = focus->peerAddress;
            if (!focus->peerDomain.empty() && focus->peerDomain != "unknown") {
                facts += " (" + focus->peerDomain + ")";
            }
            if (!focus->protocol.empty()) {
                facts += "  proto " + focus->protocol;
            }
            if (!focus->listener.empty()) {
                facts += "  " + focus->listener;
            }
            if (!focus->mask.empty()) {
                facts += "  mask " + focus->mask;
            }
            // monitorConnectionActivityTime is a generalizedTime; only the
            // clock part is useful next to a live tail.
            if (focus->activityTime.size() >= 14) {
                facts += "  last " + focus->activityTime.substr(8, 2) + ":" +
                         focus->activityTime.substr(10, 2) + ":" +
                         focus->activityTime.substr(12, 2);
            }
            if (focus->isBackend) {
                if (!focus->backendPeerAddress.empty()) {
                    facts += "  upstream " + focus->backendPeerAddress;
                }
                if (!focus->backendFlags.empty()) {
                    facts += " " + focus->backendFlags;
                }
            }
            put(plane, innerTop, innerLeft,
                text::fit(facts, static_cast<std::size_t>(innerWidth)), g_theme.dim);
            logStart = innerTop + 1;
        }
        const int logHeightInner = logHeight - 2 - (logStart - innerTop);
        const std::size_t first = lines.size() > static_cast<std::size_t>(logHeightInner)
                                      ? lines.size() - static_cast<std::size_t>(logHeightInner)
                                      : 0;
        if (lines.empty()) {
            put(plane, logStart, innerLeft,
                metrics.log.linesRead == 0
                    ? "the tail starts here: no line seen yet"
                    : "no line from this connection in the current window",
                g_theme.dim);
        }
        int line = logStart;
        for (std::size_t i = first; i < lines.size() && line < logStart + logHeightInner; ++i) {
            drawLogText(plane, line++, innerLeft, innerWidth, lines[i].text,
                        logColor(lines[i].level));
        }
    }
#else
    (void)selected;
    (void)detail;
    put(plane, 3, 2, "built without LDAP support", g_theme.dim);
#endif
    put(plane, dimY - 1, 1,
        text::fit("up/down select   enter log panel   s sort   f filter   tab next screen",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.dim);
}

// ---------------------------------------------------------------------------
// Startup
// ---------------------------------------------------------------------------

/// Shown until the first samples arrive.  A dashboard that stays blank while
/// six SSH connections are being opened looks frozen; this says what is
/// happening, how far it got, and what to check if it never finishes.
/// Closing, mirrored from the startup panel: the engine joins its workers and
/// closes one SSH master per node when it stops, which takes a collection round
/// on a remote fleet.  Without this the dashboard simply froze on the last
/// frame, then the terminal came back with no explanation.
void drawStopping(ncplane* plane, int dimY, int dimX,
                  const std::vector<MonitorEngine::ConfiguredTarget>& targets, bool done,
                  bool animate, std::uint64_t frame) {
    static const char* const hourglass[] = {"\u231B", "\u23F3"};  // ⌛ ⏳
    const std::string mark = animate ? hourglass[(frame / 6) % 2] : hourglass[1];

    const int width = std::min(dimX - 4, 78);
    const int room = std::max(1, dimY - 10);
    const int shown = std::min(static_cast<int>(targets.size()), room);
    const int extra = static_cast<int>(targets.size()) > shown ? 1 : 0;
    const int height = std::min(dimY - 4, shown + 3 + extra);
    const int top = std::max(2, (dimY - height) / 2);
    const int left = std::max(0, (dimX - width) / 2);
    Zone box = drawBox(plane, top, left, height, width, " stopping ", g_theme.frame);
    if (!box.valid) {
        return;
    }
    int row = box.top;
    put(plane, row++, box.left,
        text::fit(done ? "\u2713  connections closed, workers stopped"
                       : mark + "  closing connections and stopping the collection",
                  static_cast<std::size_t>(box.width)),
        done ? g_theme.ok : g_theme.accent, true);
    for (int index = 0; index < shown; ++index) {
        const auto& target = targets[static_cast<std::size_t>(index)];
        put(plane, row++, box.left,
            text::fit("   " + std::string(done ? "\u2713" : "\u2026") + " " +
                          padTo(target.label, 22) + " " + (done ? "closed" : "closing"),
                      static_cast<std::size_t>(box.width)),
            done ? g_theme.dim : g_theme.text);
    }
    if (extra > 0) {
        put(plane, row++, box.left,
            text::fit("   \u2026 " +
                          std::to_string(targets.size() - static_cast<std::size_t>(shown)) +
                          " more",
                      static_cast<std::size_t>(box.width)),
            g_theme.dim);
    }
}

/// F12: what the terminal was detected as, and what slaptop did with it.
///
/// Written for the case "pixel mode is on and I see no difference": the report
/// separates what the terminal announced, what the theme allowed, and whether
/// the blits actually produced something.
void drawPixelInfo(ncplane* plane, int dimY, int dimX, const Theme& theme) {
    const int width = std::min(dimX - 6, 96);
    const int height = 20;
    const int top = std::max(1, (dimY - height) / 2);
    const int left = std::max(0, (dimX - width) / 2);
    Zone box = drawBox(plane, top, left, height, width, " pixel support ", g_theme.frame);
    if (!box.valid) {
        return;
    }
    const char* term = std::getenv("TERM");
    const char* program = std::getenv("TERM_PROGRAM");
    const char* version = std::getenv("TERM_PROGRAM_VERSION");
    const unsigned detected =
        g_nc != nullptr ? static_cast<unsigned>(notcurses_check_pixel_support(g_nc)) : 0U;
    const char* kind = "none";
    if (detected == NCPIXEL_KITTY_STATIC) {
        kind = "kitty (static)";
    } else if (detected == NCPIXEL_KITTY_ANIMATED) {
        kind = "kitty (animated)";
    } else if (detected == NCPIXEL_SIXEL) {
        kind = "sixel";
    } else if (detected != 0) {
        kind = "other protocol";
    }
    unsigned pxy = 0, pxx = 0, celldimy = 0, celldimx = 0, maxbmapy = 0, maxbmapx = 0;
    if (g_nc != nullptr) {
        ncplane_pixel_geom(notcurses_stdplane(g_nc), &pxy, &pxx, &celldimy, &celldimx, &maxbmapy,
                           &maxbmapx);
    }

    int row = box.top;
    char line[256];
    std::snprintf(line, sizeof(line), "build %s %s   slaptop %s", __DATE__, __TIME__,
                  SLAPTOP_VERSION);
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_theme.dim);
    std::snprintf(line, sizeof(line), "TERM=%s   TERM_PROGRAM=%s %s", term ? term : "(unset)",
                  program ? program : "(unset)", version ? version : "");
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_theme.text);

    std::snprintf(line, sizeof(line), "theme pixel-graphs = %s   detected = %u (%s)   used = %s",
                  theme.pixelGraphs.c_str(), detected, kind, g_pixelSupport != 0 ? "yes" : "no");
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_pixelSupport != 0 ? g_theme.ok : g_theme.warn);

    std::snprintf(line, sizeof(line), "screen %ux%u px   cell %ux%u px   max bitmap %ux%u px",
                  pxx, pxy, celldimx, celldimy, maxbmapx, maxbmapy);
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_theme.text);

    if (!g_pixelLastError.empty()) {
        put(plane, row++, box.left,
            text::fit("last pixel failure: " + g_pixelLastError +
                          "   (visual " + std::to_string(g_pixelVisualFailed) + ", plane " +
                          std::to_string(g_pixelPlaneFailed) + ")",
                      static_cast<std::size_t>(box.width)),
            g_theme.error);
    }
    std::snprintf(line, sizeof(line), "skipped: %llu empty samples, %llu empty range, "
                                      "%llu no geometry",
                  static_cast<unsigned long long>(g_pixelNoSamples),
                  static_cast<unsigned long long>(g_pixelNoRange),
                  static_cast<unsigned long long>(g_pixelNoGeometry));
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_theme.dim);

    std::snprintf(line, sizeof(line), "blits this run: %llu ok, %llu refused   calls %llu",
                  static_cast<unsigned long long>(g_pixelBlitsOk),
                  static_cast<unsigned long long>(g_pixelBlitsFailed),
                  static_cast<unsigned long long>(g_pixelCalls));
    put(plane, row++, box.left, text::fit(line, static_cast<std::size_t>(box.width)),
        g_pixelBlitsOk > 0 ? g_theme.ok : g_theme.dim);

    row++;
    const char* verdict = "no pixel protocol detected: the terminal (or a multiplexer) does not "
                          "advertise one";
    if (g_pixelSupport != 0 && g_pixelBlitsOk > 0) {
        verdict = "pixel rendering is active: the bands are bitmaps, not runes";
    } else if (g_pixelSupport != 0 && g_pixelBlitsFailed > 0) {
        verdict = "the terminal advertises pixels but refuses the blits: runes are used instead";
    } else if (detected != 0 && g_pixelSupport == 0) {
        verdict = "supported by the terminal, disabled by pixel-graphs = off";
    } else if (detected != 0 && g_pixelSupport != 0) {
        verdict = "supported and enabled, but no graph has been drawn yet";
    }
    put(plane, row++, box.left, text::fit(verdict, static_cast<std::size_t>(box.width - 2)),
        g_theme.accent);

    row++;
    put(plane, row++, box.left,
        text::fit("a text multiplexer (tmux, screen) drops the protocol unless it allows "
                  "passthrough",
                  static_cast<std::size_t>(box.width)),
        g_theme.dim);
    // A witness, not a report: a real bitmap gradient.  If this stays a flat
    // block or shows nothing, the terminal is not rendering pixels, whatever
    // it announced; if it shows a smooth ramp, pixels work and any remaining
    // problem is in the graph scaling.
    row++;
    put(plane, row++, box.left,
        text::fit("witness bitmap below: a smooth vertical ramp, drawn as pixels",
                  static_cast<std::size_t>(box.width)),
        g_theme.dim);
    if (g_nc != nullptr && g_pixelSupport != 0 && row + 4 < box.top + box.height) {
        const unsigned w = 240;
        const unsigned h = 4 * 16;  // four text rows worth of pixels
        std::vector<std::uint32_t> ramp(static_cast<std::size_t>(w) * h);
        for (unsigned py = 0; py < h; ++py) {
            const double level = 1.0 - static_cast<double>(py) / static_cast<double>(h);
            const unsigned red = static_cast<unsigned>(255 * level);
            const unsigned green = static_cast<unsigned>(200 * (1.0 - level));
            const unsigned blue = static_cast<unsigned>(60 * (1.0 - level));
            for (unsigned px = 0; px < w; ++px) {
                ramp[static_cast<std::size_t>(py) * w + px] =
                    0xff000000u | (red << 16) | (green << 8) | blue;
            }
        }
        if (ncvisual* visual = ncvisual_from_bgra(ramp.data(), static_cast<int>(h),
                                                  static_cast<int>(w * 4), static_cast<int>(w))) {
            ncplane_options popts{};
            popts.y = row;
            popts.x = box.left + 2;
            popts.rows = 4;
            popts.cols = 30;
            ncplane* target = ncplane_create(plane, &popts);
            ncvisual_options vopts{};
            vopts.n = target;
            vopts.scaling = NCSCALE_NONE;
            vopts.blitter = NCBLIT_PIXEL;
            vopts.flags = NCVISUAL_OPTION_NODEGRADE;
            ncplane* drawn = target != nullptr ? ncvisual_blit(g_nc, visual, &vopts) : nullptr;
            if (drawn == nullptr) {
                if (target != nullptr) {
                    ncplane_destroy(target);
                }
                put(plane, row, box.left + 2,
                    text::fit("[blit refused: this terminal does not render pixels]",
                              static_cast<std::size_t>(box.width - 4)),
                    g_theme.error);
            } else {
                g_pixelPlanes.push_back(target);
            }
            ncvisual_destroy(visual);
        }
    } else if (g_pixelSupport == 0) {
        put(plane, row, box.left,
            text::fit("[no pixel protocol: nothing to draw]", static_cast<std::size_t>(box.width)),
            g_theme.warn);
    }

    put(plane, box.top + box.height - 1, box.left,
        text::fit("F12 or esc closes this panel", static_cast<std::size_t>(box.width)),
        g_theme.dim);
}

/// One configured target as the startup screen sees it.
struct StartupNode {
    std::string label;
    std::string state;
    std::uint32_t color{0};
    bool done{false};
};

/// Progress of the first round, computed from the *configured* targets: a node
/// that cannot be reached never produces an instance, so counting only the
/// fleet would declare "everything is ready" while half the hosts are still
/// connecting.
struct StartupState {
    std::vector<StartupNode> nodes;
    std::size_t readyInstances{0};
    std::size_t totalInstances{0};
    bool allSettled{false};
};

bool instanceSettled(const InstanceMetrics& metrics) {
    if (metrics.instance.pid == 0) {
        return metrics.hasMonitor;  // LDAP-only target: nothing else to wait for
    }
    // An instance whose monitor refuses is settled once we know it: Degraded
    // and Stopped are answers, not pending reads.
    return metrics.hasProc && (metrics.hasMonitor || metrics.health == Health::Degraded ||
                               metrics.health == Health::Stopped);
}

StartupState buildStartupState(
    const FleetSnapshot& fleet,
    const std::vector<MonitorEngine::ConfiguredTarget>& targets, double elapsed) {
    StartupState state;
    std::map<std::string, std::vector<const InstanceMetrics*>> byNode;
    for (const InstanceMetrics& metrics : fleet.instances) {
        byNode[metrics.instance.nodeLabel].push_back(&metrics);
        ++state.totalInstances;
        if (instanceSettled(metrics)) {
            ++state.readyInstances;
        }
    }
    const auto addNode = [&state](const std::string& label,
                                 const std::vector<const InstanceMetrics*>& found,
                                 double seconds) {
        StartupNode node;
        node.label = label;
        if (found.empty()) {
            node.state = seconds > 6.0 ? "no instance yet (ssh? see --diagnose)" : "connecting";
            node.color = seconds > 6.0 ? g_theme.warn : g_theme.dim;
            node.done = false;
            state.nodes.push_back(std::move(node));
            return;
        }
        std::size_t ok = 0;
        for (const InstanceMetrics* metrics : found) {
            if (instanceSettled(*metrics)) {
                ++ok;
            }
        }
        node.state = std::to_string(ok) + "/" + std::to_string(found.size()) +
                     (ok == found.size() ? " ready" : " answering");
        node.color = ok == found.size() ? g_theme.ok : g_theme.text;
        node.done = ok == found.size();
        state.nodes.push_back(std::move(node));
    };

    // Local discovery has no target line of its own; show it first when it
    // found something.
    if (const auto local = byNode.find(""); local != byNode.end()) {
        addNode("(local)", local->second, elapsed);
    }
    for (const MonitorEngine::ConfiguredTarget& target : targets) {
        const auto found = byNode.find(target.label);
        if (found == byNode.end() && target.sameMachine) {
            // Merged with the local discovery (same machine): there will never
            // be an instance carrying this label, and waiting for one would
            // hold the panel for twenty seconds for nothing.
            StartupNode node;
            node.label = target.label;
            node.state = "same machine as (local) -- merged";
            node.color = g_theme.dim;
            node.done = true;
            state.nodes.push_back(std::move(node));
            continue;
        }
        addNode(target.label, found == byNode.end() ? std::vector<const InstanceMetrics*>{}
                                                    : found->second,
                elapsed);
    }
    state.allSettled = !state.nodes.empty() &&
                       std::all_of(state.nodes.begin(), state.nodes.end(),
                                   [](const StartupNode& node) { return node.done; });
    return state;
}

/// Shown until every configured target has answered.  A dashboard that stays
/// blank while six SSH connections are being opened looks frozen; this says
/// what is happening, target by target.
void drawStartup(ncplane* plane, int dimY, int dimX, const StartupState& state,
                 std::size_t configuredTargets, double elapsed, bool animate,
                 std::uint64_t frame) {
    static const char* const hourglass[] = {"\u231B", "\u23F3"};  // ⌛ ⏳
    const std::string mark = animate ? hourglass[(frame / 6) % 2] : hourglass[1];

    const int width = std::min(dimX - 4, 86);
    const int room = std::max(1, dimY - 12);          // borders, header, footers
    const int shown = std::min(static_cast<int>(state.nodes.size()), room);
    const int extra = static_cast<int>(state.nodes.size()) > shown ? 1 : 0;
    const int height = std::min(dimY - 4, shown + 4 + extra);
    const int top = std::max(2, (dimY - height) / 2);
    const int left = std::max(0, (dimX - width) / 2);
    Zone box = drawBox(plane, top, left, height, width, " starting ", g_theme.frame);
    if (!box.valid) {
        return;
    }

    int row = box.top;
    put(plane, row++, box.left,
        text::fit(mark + "  establishing connections and reading the first samples",
                  static_cast<std::size_t>(box.width)),
        g_theme.accent, true);
    char progress[160];
    std::snprintf(progress, sizeof(progress), "   %zu/%zu instance(s) ready, %zu target(s), %.1f s",
                  state.readyInstances, state.totalInstances, configuredTargets, elapsed);
    put(plane, row++, box.left, text::fit(progress, static_cast<std::size_t>(box.width)),
        g_theme.text);

    for (int index = 0; index < shown; ++index) {
        const StartupNode& node = state.nodes[static_cast<std::size_t>(index)];
        put(plane, row++, box.left,
            text::fit("   " + std::string(node.done ? "\u2713" : "\u2026") + " " +
                          padTo(node.label, 18) + " " + node.state,
                      static_cast<std::size_t>(box.width)),
            node.color);
    }
    if (extra > 0) {
        put(plane, row++, box.left,
            text::fit("   \u2026 " +
                          std::to_string(state.nodes.size() - static_cast<std::size_t>(shown)) +
                          " more target(s)",
                      static_cast<std::size_t>(box.width)),
            g_theme.dim);
    }
    if (elapsed > 6.0 && row < box.top + box.height - 1) {
        put(plane, row, box.left,
            text::fit("   still waiting: `slaptop --diagnose` names what is missing",
                      static_cast<std::size_t>(box.width)),
            g_theme.warn);
    }
}

// ---------------------------------------------------------------------------
// Index coverage: the declared olcDbIndex lines against the filters seen
// ---------------------------------------------------------------------------

/// What a filter attribute needs from an index, in words that stay honest:
/// nothing here is a recommendation, only an observation over the window.
const char* indexKindLabel(const std::string& kind) {
    if (kind == "sub") {
        return "substring";
    }
    return kind == "pres" ? "presence" : "equality";
}

/// One thing the Indexes screen can talk about: a real database, a proxy that
/// has no indexes of its own, or a cache database written by an overlay.
struct IndexTarget {
    enum class Kind { Assess, Proxy, Cache };
    Kind kind{Kind::Assess};
    std::string label;
    std::string suffix;
    /// For a proxy: the upstream URI, which is what decides the indexes.
    std::string upstream;
    /// Naming of the overlay that owns a cache database ("pcache").
    std::string overlayName;
    std::uint64_t searches{0};
    std::vector<collector::FilterAttribute> uses;
    collector::IndexAssessment assessment;
    std::vector<std::string> configured;
};

std::vector<IndexTarget> indexTargets(const InstanceMetrics& metrics) {
    std::vector<IndexTarget> targets;
    for (const auto& database : metrics.directory.databases) {
        if (database.suffix.empty()) {
            continue;
        }
        IndexTarget target;
        target.label = database.label;
        target.suffix = database.suffix;
        target.upstream = database.uri;
        target.configured = database.indexes;
        // back-ldap and back-meta answer with the upstream's indexes: judging
        // the local configuration would be meaningless, and claiming "no index"
        // there is how the screen lied about a proxy.
        target.kind = (database.backend == "ldap" || database.backend == "meta")
                          ? IndexTarget::Kind::Proxy
                          : IndexTarget::Kind::Assess;
        targets.push_back(std::move(target));
    }

    // Filters, attributed to the database whose suffix contains their base.
    std::uint64_t unmatched = 0;
    for (const auto& use : metrics.behavior.attributesByBase) {
        IndexTarget* best = nullptr;
        std::size_t bestLength = 0;
        for (IndexTarget& candidate : targets) {
            if (collector::baseUnderSuffix(use.base, candidate.suffix) &&
                candidate.suffix.size() >= bestLength) {
                best = &candidate;
                bestLength = candidate.suffix.size();
            }
        }
        if (best == nullptr) {
            unmatched += use.searches;
            continue;
        }
        collector::FilterAttribute entry;
        entry.attribute = use.attribute;
        entry.kind = use.kind;
        entry.searches = use.searches;
        entry.example = use.base;
        best->uses.push_back(std::move(entry));
        best->searches += use.searches;
    }

    // Cache databases of an overlay: they do carry olcDbIndex lines, and
    // hiding them was wrong.
    for (const auto& overlay : metrics.directory.overlayDatabases) {
        if (overlay.indexes.empty()) {
            continue;
        }
        IndexTarget target;
        target.kind = IndexTarget::Kind::Cache;
        target.overlayName = overlay.overlay;
        target.label = overlay.label + " (" + overlay.overlay + " cache)";
        const std::size_t slash = overlay.directory.rfind('/');
        target.suffix = slash == std::string::npos ? overlay.directory
                                                   : overlay.directory.substr(slash + 1);
        target.configured = overlay.indexes;
        targets.push_back(std::move(target));
    }
    for (IndexTarget& target : targets) {
        if (target.kind == IndexTarget::Kind::Assess) {
            target.assessment = collector::assessAttributeUses(target.configured, target.uses);
        }
    }
    // The busiest first, whatever its kind: that is the one whose indexes
    // matter now, and the default selection lands on it.
    std::sort(targets.begin(), targets.end(), [](const IndexTarget& a, const IndexTarget& b) {
        if (a.searches != b.searches) {
            return a.searches > b.searches;
        }
        return a.label < b.label;
    });
    (void)unmatched;
    return targets;
}

void drawIndexes(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics,
                 std::size_t& selection) {
    const std::vector<IndexTarget> targets = indexTargets(metrics);
    if (targets.empty()) {
        drawScreenHeader(plane, dimX, metrics, "no database with a suffix in this instance");
        drawBox(plane, 3, 0, std::min(4, dimY - 6), dimX, " index coverage ", g_theme.frame);
        put(plane, 4, 2,
            text::fit("nothing to compare: this instance declares no suffix",
                      static_cast<std::size_t>(dimX - 4)),
            g_theme.dim);
        put(plane, dimY - 1, 1,
            text::fit("tab next screen   esc back", static_cast<std::size_t>(dimX - 2)),
            g_theme.dim);
        return;
    }
    if (selection >= targets.size()) {
        selection = 0;
    }

    // One line per database, so the reader always knows which suffix a verdict
    // belongs to; the table below details the selected one and gets all the
    // room.
    int top = 3;
    char summary[256];
    std::snprintf(summary, sizeof(summary), "%zu database(s)   up/down select   %s",
                  targets.size(),
                  targets[0].kind == IndexTarget::Kind::Proxy
                      ? "a proxy has no indexes of its own"
                      : "observation over the log window, not a verdict");
    drawScreenHeader(plane, dimX, metrics, summary);
    for (std::size_t index = 0; index < targets.size() && top < dimY - 6; ++index) {
        const IndexTarget& target = targets[index];
        const bool active = index == selection;
        std::string text = active ? "\u25B8 " : "  ";
        text += padTo(target.label, 12);
        text += " " + padTo(target.suffix, 34);
        text += padLeft(std::to_string(target.searches), 7) + " searches";
        if (target.kind == IndexTarget::Kind::Proxy) {
            text += "   proxy: indexes live on the upstream";
        } else if (target.kind == IndexTarget::Kind::Cache) {
            text += "   cache written by an overlay";
        } else {
            text += "   " + std::to_string(target.assessment.uncovered.size()) + " candidate, " +
                    std::to_string(target.assessment.mismatched.size()) + " wrong type, " +
                    std::to_string(target.assessment.unseen.size()) + " dormant";
        }
        put(plane, top++, 1, text::fit(text, static_cast<std::size_t>(dimX - 2)),
            active ? g_theme.accent : g_theme.dim, active);
    }

    const IndexTarget& target = targets[selection];
    const int boxTop = top + 1;
    const int boxHeight = std::max(4, dimY - 4 - boxTop);
    std::string title = " " + target.label + "  " + target.suffix + " ";
    Zone box = drawBox(plane, boxTop, 0, boxHeight, dimX, title, g_theme.frame);
    if (box.valid) {
        // Rows the table can hold: everything the frame offers, minus its two
        // borders and the column header.
        const int capacity = std::max(1, box.height - 2);
        int row = box.top;
        if (target.kind == IndexTarget::Kind::Proxy) {
            put(plane, row++, box.left,
                text::fit("this database is a proxy (back-ldap/back-meta): searches are answered "
                          "by the upstream server, whose index configuration decides",
                          static_cast<std::size_t>(box.width)),
                g_theme.text);
            put(plane, row++, box.left,
                text::fit(target.upstream.empty() ? "upstream: unknown (no olcDbURI)"
                                                  : "upstream: " + target.upstream,
                          static_cast<std::size_t>(box.width)),
                g_theme.dim);
            put(plane, row++, box.left,
                text::fit("no local index can help: nothing is assessed here",
                          static_cast<std::size_t>(box.width)),
                g_theme.dim);
        } else if (target.kind == IndexTarget::Kind::Cache) {
            put(plane, row++, box.left,
                text::fit("cache database written by the " + target.overlayName +
                              " overlay.  It does declare indexes:",
                          static_cast<std::size_t>(box.width)),
                g_theme.text);
            for (const std::string& line : target.configured) {
                if (row >= box.top + box.height) {
                    break;
                }
                put(plane, row++, box.left,
                    text::fit("   " + line, static_cast<std::size_t>(box.width)), g_theme.dim);
            }
            if (row < box.top + box.height) {
                put(plane, row++, box.left,
                    text::fit("pcache addresses this database by query URL, so client filters "
                              "are not looked up through these attributes — usefulness to be "
                              "verified, not assumed",
                              static_cast<std::size_t>(box.width)),
                    g_theme.warn);
            }
        } else {
            const auto& assessment = target.assessment;
            struct Row {
                std::string attribute;
                std::string index;
                std::string uses;
                std::string note;
                std::uint32_t color;
            };
            std::vector<Row> rows;
            for (const auto& use : assessment.uncovered) {
                rows.push_back({use.attribute, "-", std::to_string(use.searches),
                                std::string("no index for ") + indexKindLabel(use.kind) +
                                    " -- candidate",
                                g_theme.warn});
            }
            for (const auto& use : assessment.mismatched) {
                std::string types;
                for (const auto& configured : assessment.configured) {
                    for (const std::string& attribute : configured.attributes) {
                        if (attribute == use.attribute) {
                            types = configured.types;
                        }
                    }
                }
                rows.push_back({use.attribute, types, std::to_string(use.searches),
                                types + " cannot serve " + indexKindLabel(use.kind) +
                                    " -- candidate",
                                g_theme.warn});
            }
            for (const auto& use : assessment.byDefault) {
                rows.push_back({use.attribute, "(default) " + assessment.defaultTypes,
                                std::to_string(use.searches), "covered by the default line",
                                g_theme.dim});
            }
            std::vector<Row> used;
            for (const auto& configured : assessment.configured) {
                if (configured.attributes.size() == 1 && configured.attributes[0] == "default") {
                    continue;
                }
                std::string names;
                for (const std::string& attribute : configured.attributes) {
                    names += (names.empty() ? "" : ",") + attribute;
                }
                std::uint64_t searches = 0;
                for (const auto& use : target.uses) {
                    for (const std::string& attribute : configured.attributes) {
                        if (attribute == use.attribute) {
                            searches += use.searches;
                        }
                    }
                }
                if (searches == 0) {
                    continue;
                }
                used.push_back({names, configured.types, std::to_string(searches),
                                "used by the window", g_theme.ok});
            }
            std::sort(used.begin(), used.end(), [](const Row& a, const Row& b) {
                return std::stoull(a.uses) > std::stoull(b.uses);
            });
            rows.insert(rows.end(), used.begin(), used.end());
            // The dormant indexes fill the frame when it has room: a single
            // summary line left the rest of the box empty, and each of them is
            // worth a line (with its declared types) for whoever is about to
            // decide whether to keep it.
            std::map<std::string, std::string> typesOf;
            for (const auto& configured : assessment.configured) {
                for (const std::string& attribute : configured.attributes) {
                    typesOf[attribute] = configured.types;
                }
            }
            // Every free row lists one dormant index; only the leftover is
            // summarised.  One line for sixty-one of them left the frame
            // mostly empty.
            int room = capacity - 1 - static_cast<int>(rows.size());  // minus the header
            std::size_t shownDormant = 0;
            for (const std::string& attribute : assessment.unseen) {
                if (room <= 0) {
                    break;
                }
                const std::size_t remaining = assessment.unseen.size() - shownDormant;
                // Keep one row for the "N more" line when they will not all fit.
                if (remaining > 1 && room == 1) {
                    break;
                }
                rows.push_back({attribute, typesOf[attribute], "0",
                                "configured, no filter in this window", g_theme.dim});
                ++shownDormant;
                --room;
            }
            if (shownDormant < assessment.unseen.size()) {
                const std::size_t rest = assessment.unseen.size() - shownDormant;
                rows.push_back({std::to_string(rest) + " more attribute(s)", "-", "-",
                                "configured, no filter here -- may serve replication, tooling "
                                "or another client",
                                g_theme.dim});
            }

            const int attributeWidth = std::clamp(box.width / 5, 12, 26);
            const int indexWidth = std::clamp(box.width / 5, 10, 24);
            const int usesWidth = 7;
            const int noteWidth =
                std::max(10, box.width - attributeWidth - indexWidth - usesWidth - 6);
            put(plane, row++, box.left,
                text::fit(padTo("attribute", attributeWidth) + " " +
                              padTo("index", indexWidth) + " " + padLeft("uses", usesWidth) +
                              "  " + padTo("observation", noteWidth),
                          static_cast<std::size_t>(box.width)),
                g_theme.dim);
            // The table gets every row the frame can hold: truncating it while
            // the box has room was the visible complaint.
            int drawn = 0;
            for (const Row& item : rows) {
                if (drawn >= capacity) {
                    break;
                }
                put(plane, row++, box.left,
                    text::fit(padTo(item.attribute, attributeWidth) + " " +
                                  padTo(item.index, indexWidth) + " " +
                                  padLeft(item.uses, usesWidth) + "  " +
                                  padTo(item.note, noteWidth),
                              static_cast<std::size_t>(box.width)),
                    item.color);
                ++drawn;
            }
            if (rows.empty()) {
                put(plane, row, box.left,
                    text::fit("no filter on this suffix in the window",
                              static_cast<std::size_t>(box.width)),
                    g_theme.dim);
            } else if (drawn < static_cast<int>(rows.size())) {
                put(plane, row, box.left,
                    text::fit("  \u2026 " +
                                  std::to_string(rows.size() - static_cast<std::size_t>(drawn)) +
                                  " more (terminal too short)",
                              static_cast<std::size_t>(box.width)),
                    g_theme.dim);
            }
        }
    }

    put(plane, dimY - 3, 1,
        text::fit("observation over the log window, not a verdict: replication (entryCSN, "
                  "entryUUID, objectClass), tooling and clients absent from the window are "
                  "invisible here",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.warn);
    put(plane, dimY - 2, 1,
        text::fit("a filter is only a candidate for indexing: measure before changing, and add "
                  "one index type at a time",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.dim);
    put(plane, dimY - 1, 1,
        text::fit("up/down database   tab next screen   esc back",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.dim);
}

// ---------------------------------------------------------------------------
// Behaviour view: who spends the server's time, on which filter shape
// ---------------------------------------------------------------------------

/// Duration with the unit that keeps the number readable: an operation is
/// usually sub-millisecond, a window total is seconds.
std::string formatSeconds(double seconds) {
    char text[32];
    if (seconds >= 1.0) {
        std::snprintf(text, sizeof(text), "%.2f s", seconds);
    } else if (seconds >= 0.001) {
        std::snprintf(text, sizeof(text), "%.1f ms", seconds * 1e3);
    } else {
        std::snprintf(text, sizeof(text), "%.0f us", seconds * 1e6);
    }
    return text;
}

double etimeSecondsOf(const collector::AccessCounters& counters) {
    return static_cast<double>(counters.etimeNs) / 1e9;
}



/// One screen of behavioural analysis, fed from the access log:
///
///   - the verdict: accounts whose filter families take the largest share of
///     the window's etime — the "resource hog".  The filter shape is shown
///     beside it as a hint, never used to decide;
///   - cost by account, the raw material of the verdict;
///   - the (account, filter family) pairs, with the ones that cannot use an
///     index marked, so the shape behind the cost is visible;
///   - two sparklines over one time axis: searches and the server time they
///     cost, so a burst and its price line up vertically.
void drawBehaviour(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics) {
    const collector::BehaviorSnapshot& behaviour = metrics.behavior;
    char header[256];

    std::snprintf(header, sizeof(header),
                  "window %.0f s (%.0f s of data)   searches %llu (substr/neg %llu)   "
                  "etime %s   %zu accounts",
                  behaviour.windowSeconds, behaviour.elapsedSeconds,
                  static_cast<unsigned long long>(behaviour.searches),
                  static_cast<unsigned long long>(behaviour.slowSearches),
                  formatSeconds(etimeSecondsOf(behaviour.totals)).c_str(),
                  behaviour.accountsSeen);
    drawScreenHeader(plane, dimX, metrics, header);

    const auto footer = [&]() {
        put(plane, dimY - 1, 1,
            text::fit("tab next screen   esc back   ? help", static_cast<std::size_t>(dimX - 2)),
            g_theme.dim);
    };

    if (!behaviour.available) {
        put(plane, 4, 2, text::fit(
                "no access log for this instance: remote target, or olcLogFile is not set",
                static_cast<std::size_t>(std::max(0, dimX - 4))),
            g_theme.warn);
        footer();
        return;
    }
    if (behaviour.searches == 0) {
        // Two honest causes: the log level does not carry `stats` (no SRCH
        // line is ever written), or there has simply been no search since
        // slaptop attached — the window starts at the current end of file.
        std::string reason;
        if (collector::logLevelHasStats(behaviour.logLevel)) {
            reason = "no search since slaptop attached: the behaviour window starts at the "
                     "current end of " + (behaviour.logPath.empty() ? std::string("the log")
                                                                    : behaviour.logPath);
        } else {
            reason = "olcLogLevel must include stats (256), configured: " +
                     (behaviour.logLevel.empty() ? std::string("(unknown)") : behaviour.logLevel);
        }
        put(plane, 4, 2,
            text::fit(reason, static_cast<std::size_t>(std::max(0, dimX - 4))), g_theme.warn);
        footer();
        return;
    }

    // --- Verdict ---------------------------------------------------------
    const int hogRows = std::clamp(static_cast<int>(behaviour.hogs.size()), 1, 4);
    Zone verdict = drawBox(plane, 3, 0, hogRows + 2, dimX, " verdict ", g_theme.frame);
    if (verdict.valid) {
        int row = verdict.top;
        if (behaviour.hogs.empty()) {
            std::string message;
            if (behaviour.enoughTraffic) {
                // Measurement first: what was measured, and on what sample.
                char line[256];
                std::snprintf(line, sizeof(line),
                              "no family both above 20 %% of the window's etime and "
                              "%.0f ms per search: nothing stands out (%llu searches, "
                              "%zu families, %s of etime)",
                              1000.0 * collector::kHogMinimumAverageSeconds,
                              static_cast<unsigned long long>(behaviour.searches),
                              behaviour.familiesSeen,
                              formatSeconds(etimeSecondsOf(behaviour.totals)).c_str());
                message = line;
            } else {
                message = "no verdict yet: " + std::to_string(behaviour.searches) +
                          " searches, " + formatSeconds(etimeSecondsOf(behaviour.totals)) +
                          " of etime (need 100 searches or 500 ms)";
            }
            put(plane, row, verdict.left,
                text::fit(message, static_cast<std::size_t>(verdict.width)),
                behaviour.enoughTraffic ? g_theme.ok : g_theme.dim);
        } else {
            const int shown = std::min(hogRows, static_cast<int>(behaviour.hogs.size()));
            for (int i = 0; i < shown; ++i) {
                const auto& hog = behaviour.hogs[static_cast<std::size_t>(i)];
                char line[320];
                // Numbers first, filter family last: the pattern is often
                // longer than the screen, and a line truncated before its
                // figures is unreadable — the opposite of a verdict.
                std::snprintf(line, sizeof(line),
                              "\u25B6 %s \u2014 %.0f %% of etime, %s avg, %llu ops, %s "
                              "total%s   via ",
                              hog.account.c_str(), hog.sharePercent,
                              formatSeconds(hog.averageSeconds).c_str(),
                              static_cast<unsigned long long>(hog.counters.ops),
                              formatSeconds(hog.etimeSeconds).c_str(),
                              hog.slowShape ? " [substr/neg]" : "");
                line[sizeof(line) - 1] = '\0';
                // The family is what gets cut, never the figures above.
                std::string withFamily = line;
                const int used = static_cast<int>(text::width(withFamily));
                const int room = verdict.width - used - 1;
                if (room > 4) {
                    withFamily += text::fit(hog.family, static_cast<std::size_t>(room));
                }
                put(plane, row++, verdict.left,
                    text::fit(withFamily, static_cast<std::size_t>(verdict.width)),
                    g_theme.error);
            }
            if (static_cast<int>(behaviour.hogs.size()) > shown && verdict.height > 0) {
                char more[96];
                std::snprintf(more, sizeof(more), "  \u2026 %zu more hog(s)",
                              behaviour.hogs.size() - static_cast<std::size_t>(shown));
                put(plane, verdict.top + verdict.height - 1, verdict.left,
                    text::fit(more, static_cast<std::size_t>(verdict.width)), g_theme.warn);
            }
        }
    }

    // --- Tables and sparklines -------------------------------------------
    const int sparkHeight = 2;
    const int tablesTop = 3 + hogRows + 3;  // verdict box, then one blank row
    const int tablesBottom = dimY - 1 - (sparkHeight + 1);
    const int tablesHeight = tablesBottom - tablesTop;
    if (tablesHeight < 5) {
        footer();
        return;
    }

    // Two columns when the window is wide enough; stacked otherwise, with the
    // account ranking first because it carries the verdict.
    const bool twoColumns = dimX >= 100;
    const int leftWidth = twoColumns ? (dimX * 55) / 100 : dimX;
    const int rightWidth = twoColumns ? dimX - leftWidth - 1 : dimX;
    const int leftHeight = twoColumns ? tablesHeight : std::max(5, tablesHeight / 2);
    const int rightHeight = twoColumns ? tablesHeight : tablesHeight - leftHeight - 1;
    const int rightX = twoColumns ? leftWidth + 1 : 0;
    const int rightY = twoColumns ? tablesTop : tablesTop + leftHeight + 1;

    const auto drawAccounts = [&]() {
        Zone zone = drawBox(plane, tablesTop, 0, leftHeight, leftWidth, " cost by account ",
                            g_theme.frame);
        if (!zone.valid) {
            return;
        }
        // account | ops | total | avg | share
        const int accountWidth = std::max(16, zone.width - 34);
        int row = zone.top;
        put(plane, row++, zone.left,
            text::fit(padTo("account", accountWidth) + " " + padLeft("ops", 6) + " " +
                          padLeft("etime", 9) + " " + padLeft("avg", 9) + " " +
                          padLeft("share", 6),
                      static_cast<std::size_t>(zone.width)),
            g_theme.dim);
        const int visible = std::max(0, zone.height - 1);
        int shown = 0;
        for (const auto& account : behaviour.accounts) {
            if (shown >= visible) {
                break;
            }
            char line[400];
            std::snprintf(line, sizeof(line), "%s %6llu %9s %9s %5.1f%%",
                          padTo(account.account, accountWidth).c_str(),
                          static_cast<unsigned long long>(account.counters.ops),
                          formatSeconds(account.etimeSeconds).c_str(),
                          formatSeconds(account.averageSeconds).c_str(),
                          account.sharePercent);
            put(plane, row++, zone.left, text::fit(line, static_cast<std::size_t>(zone.width)),
                account.sharePercent >= collector::kHogSharePercent ? g_theme.warn : g_theme.text);
            ++shown;
        }
        if (behaviour.accountsSeen > behaviour.accounts.size() && row < zone.top + zone.height) {
            char more[96];
            std::snprintf(more, sizeof(more), "  \u2026 %zu more account%s",
                          behaviour.accountsSeen - behaviour.accounts.size(),
                          behaviour.accountsSeen - behaviour.accounts.size() == 1 ? "" : "s");
            put(plane, row, zone.left,
                text::fit(more, static_cast<std::size_t>(zone.width)), g_theme.dim);
        }
    };

    const auto drawFamilies = [&]() {
        Zone zone = drawBox(plane, rightY, rightX, rightHeight, rightWidth,
                            " filter families (slowest first) ", g_theme.frame);
        if (!zone.valid) {
            return;
        }
        // account | family | ops | avg | share.  A leading marker flags a
        // family that cannot use an index: that is the hog's fingerprint.
        const int accountWidth = std::min(24, std::max(12, zone.width / 4));
        const int familyWidth = std::max(10, zone.width - accountWidth - 24);
        int row = zone.top;
        put(plane, row++, zone.left,
            text::fit(padTo("account", accountWidth) + " " + padTo("family", familyWidth) +
                          " " + padLeft("ops", 5) + " " + padLeft("avg", 9) + " " +
                          padLeft("share", 6),
                      static_cast<std::size_t>(zone.width)),
            g_theme.dim);
        const int visible = std::max(0, zone.height - 1);
        int shown = 0;
        for (const auto& family : behaviour.families) {
            if (shown >= visible) {
                break;
            }
            char line[512];
            const std::string familyCell =
                padTo((family.slow ? "\u26A0 " : "  ") + family.family, familyWidth);
            std::snprintf(line, sizeof(line), "%s %s %5llu %9s %5.1f%%",
                          padTo(family.account, accountWidth).c_str(), familyCell.c_str(),
                          static_cast<unsigned long long>(family.counters.ops),
                          formatSeconds(family.averageSeconds).c_str(), family.sharePercent);
            put(plane, row++, zone.left, text::fit(line, static_cast<std::size_t>(zone.width)),
                family.slow ? g_theme.warn : g_theme.text);
            ++shown;
        }
        if (behaviour.familiesSeen > behaviour.families.size() && row < zone.top + zone.height) {
            char more[96];
            std::snprintf(more, sizeof(more), "  \u2026 %zu more families",
                          behaviour.familiesSeen - behaviour.families.size());
            put(plane, row, zone.left,
                text::fit(more, static_cast<std::size_t>(zone.width)), g_theme.dim);
        }
    };

    drawAccounts();
    drawFamilies();

    // The two sparklines share the width and the time axis.
    const int sparkTop = dimY - 1 - sparkHeight;
    if (sparkTop > tablesTop + 1) {
        const int labelWidth = 12;
        // The pattern convention, explained where it is used.  The sparklines
        // give up the room rather than the reader having to guess what "$#" is.
        const int legendWidth = dimX >= 110 ? std::min(56, dimX / 3) : 0;
        const int sparkWidth =
            std::max(0, dimX - labelWidth - 2 - (legendWidth > 0 ? legendWidth + 2 : 0));
        if (legendWidth > 0) {
            const int legendX = dimX - legendWidth - 1;
            put(plane, sparkTop, legendX,
                text::fit("$ value   # number   * wildcard   (\u2026)+ repeated clause",
                          static_cast<std::size_t>(legendWidth)),
                g_theme.dim);
            put(plane, sparkTop + 1, legendX,
                text::fit("(&(uid=$)(recordStatus=$)) = uid AND recordStatus",
                          static_cast<std::size_t>(legendWidth)),
                g_theme.dim);
        }
        put(plane, sparkTop, 1, padLeft("searches", labelWidth - 1) + " ", g_theme.dim);
        drawSpark(plane, sparkTop, 1 + labelWidth, sparkWidth, behaviour.searchTimeline,
                  std::max(1.0, behaviour.searchTimeline.empty() ? 1.0 : *std::max_element(
                                    behaviour.searchTimeline.begin(),
                                    behaviour.searchTimeline.end())),
                  kOpsPalette);
        put(plane, sparkTop + 1, 1, padLeft("etime/s", labelWidth - 1) + " ", g_theme.dim);
        drawSpark(plane, sparkTop + 1, 1 + labelWidth, sparkWidth, behaviour.etimeTimeline,
                  std::max(1e-6, behaviour.etimeTimeline.empty() ? 1e-6 : *std::max_element(
                                     behaviour.etimeTimeline.begin(),
                                     behaviour.etimeTimeline.end())),
                  kCpuPalette);
    }
    footer();
}

// ---------------------------------------------------------------------------
// Architecture view
// ---------------------------------------------------------------------------

/// One node of the path diagram: a pill with a coloured background and light
/// text, joined to the next node by an arrow.
struct PathStep {
    std::string label;
    std::uint32_t background;
    bool bold;
};

/// Text drawn inside the path pills.  Light grey rather than the near-black
/// used before: on a dark terminal the pill has to read as a label, not as a
/// hole.
constexpr std::uint32_t kPathInk = 0xf0f2f6;

/// Lines the path diagram will need: one per serving database, one per lloadd
/// tier, plus the listening sockets.
int servedDatabases(const InstanceMetrics& metrics) {
    int count = 0;
    for (const auto& database : metrics.directory.databases) {
        if (database.backend == "config" || database.backend == "monitor" ||
            database.backend == "frontend") {
            continue;
        }
        ++count;
    }
    count += static_cast<int>(metrics.monitor.lloadTiers.size());
    return std::max(1, count);
}

/// Draws the client → data path of one instance: socket, overlays in the order
/// slapd applies them, backend, storage.  A plain box per node, joined by
/// arrows, wrapped when the window is narrow.
void drawPathDiagram(ncplane* plane, int top, int height, int width,
                     const InstanceMetrics& metrics) {
    Zone zone = drawBox(plane, top, 0, height, width, " path: client \u2192 data ", g_theme.frame);
    if (!zone.valid) {
        return;
    }
    int row = zone.top;
    const auto drawChain = [&](const std::vector<PathStep>& steps, int& line) {
        int x = zone.left;
        for (std::size_t index = 0; index < steps.size(); ++index) {
            const PathStep& step = steps[index];
            const std::string pill = " " + step.label + " ";
            const int pillWidth = text::width(pill);
            if (x + pillWidth > zone.left + zone.width) {
                if (++line >= zone.top + zone.height) {
                    return;
                }
                x = zone.left;
            }
            put(plane, line, x, text::fit(pill, static_cast<std::size_t>(zone.width)),
                kPathInk, step.bold, step.background);
            x += pillWidth;
            if (index + 1 == steps.size()) {
                break;
            }
            // The arrow is always drawn: when the node does not fit, the line
            // breaks and the arrow starts the next one, so a wrapped chain
            // still reads as a chain.
            const std::string arrow = " \u2500\u25B6 ";
            if (x + static_cast<int>(text::width(arrow)) + 6 > zone.left + zone.width) {
                if (++line >= zone.top + zone.height) {
                    return;
                }
                x = zone.left;
            }
            put(plane, line, x, arrow, g_theme.dim);
            x += static_cast<int>(text::width(arrow));
        }
        ++line;
    };

    // The sockets the server accepts on, as one node: a server often has five
    // of them (clear, TLS, ldapi, and the ports of the backends it proxies),
    // and five pills would push the overlays off the line.
    std::string sockets;
    for (const ListenerInfo& listener : metrics.monitor.listeners) {
        std::string address = listener.address;
        if (address.rfind("IP=", 0) == 0) {
            address = address.substr(3);
        }
        if (address.find("ldapi") != std::string::npos || address.rfind("PATH=", 0) == 0) {
            address = "ldapi";
        } else {
            address = (listener.tls ? "ldaps " : "ldap ") + address;
        }
        sockets += (sockets.empty() ? "" : " ") + address;
    }
    const char* socketLabel = sockets.empty() ? "listener" : sockets.c_str();

    bool drew = false;

    // A load balancer has no naming context: its path is client -> lloadd ->
    // tier -> backend servers, one line per tier.
    for (const LloadTier& tier : metrics.monitor.lloadTiers) {
        std::vector<PathStep> chain;
        chain.push_back({"client", rgb(0x33, 0x3d, 0x4e), false});
        chain.push_back({socketLabel, rgb(0x28, 0x4a, 0x66), false});
        chain.push_back({"lload", rgb(0x6b, 0x53, 0x1c), true});
        const std::string tierName = tier.name.rfind("tier", 0) == 0 ? tier.name
                                                                     : "tier " + tier.name;
        chain.push_back({tierName, rgb(0x3a, 0x3e, 0x4a), false});
        for (const LloadServer& server : tier.servers) {
            chain.push_back({server.uri, rgb(0x22, 0x52, 0x35), false});
        }
        drawChain(chain, row);
        ++row;
        drew = true;
    }

    for (const auto& database : metrics.directory.databases) {
        if (database.backend == "config" || database.backend == "monitor" ||
            database.backend == "frontend") {
            continue;
        }
        std::vector<PathStep> chain;
        chain.push_back({"client", rgb(0x33, 0x3d, 0x4e), false});
        chain.push_back({socketLabel, rgb(0x28, 0x4a, 0x66), false});

        // Every overlay slapd applies, in the order it applies them.
        for (const std::string& overlay : database.overlays) {
            chain.push_back({overlay, rgb(0x6b, 0x53, 0x1c), true});
        }

        // The backend, then where the bytes actually live.
        std::string backend = database.backend;
        if (!database.suffix.empty()) {
            backend += " " + database.suffix;
        }
        chain.push_back({backend, rgb(0x22, 0x52, 0x35), true});
        if (!database.directory.empty()) {
            std::string store = database.directory;
            if (const std::size_t slash = store.rfind('/'); slash != std::string::npos) {
                store = store.substr(slash + 1);
            }
            chain.push_back({"mdb:" + store, rgb(0x3a, 0x3e, 0x4a), false});
        } else if (!database.uri.empty()) {
            chain.push_back({database.uri, rgb(0x3a, 0x3e, 0x4a), false});
        }
        drawChain(chain, row);
        ++row;  // one blank row between two databases
        drew = true;
    }
    if (!drew) {
        put(plane, zone.top, zone.left, "this instance serves no database", g_theme.dim);
    }
}

/// Role of an instance, derived from its declared databases and overlays.
std::string instanceRole(const InstanceMetrics& metrics) {
    bool proxy = false;
    bool provider = false;
    bool consumer = false;
    bool accesslog = false;
    for (const auto& database : metrics.directory.databases) {
        if (database.backend == "ldap") {
            proxy = true;
        }
        if (!database.syncreplProviders.empty()) {
            consumer = true;
        }
        for (const std::string& overlay : database.overlays) {
            if (overlay == "syncprov") {
                provider = true;
            }
            if (overlay == "accesslog") {
                accesslog = true;
            }
        }
    }
    std::string role;
    if (metrics.directory.hasLload) {
        role = "load-balancer";
    } else if (proxy) {
        role = "proxy";
    } else if (provider) {
        role = "provider";
    } else if (consumer) {
        role = "consumer";
    } else {
        role = "standalone";
    }
    if (accesslog) {
        role += " +accesslog";
    }
    return role;
}

struct TopoEdge {
    int from{0};
    int to{0};
    std::string kind;   ///< "proxy", "syncrepl"
    std::string target; ///< URI as declared
    double opsFrom{0.0};
    double opsTo{0.0};
    double lagSeconds{-1.0};
    bool resolved{false};
};

/// Builds the edges by matching each declared URI against the listeners of the
/// other instances: a proxy or a syncrepl points at host:port, and cn=monitor
/// tells which port belongs to which process.
std::vector<TopoEdge> buildTopology(const FleetSnapshot& fleet) {
    std::vector<TopoEdge> edges;
    for (std::size_t i = 0; i < fleet.instances.size(); ++i) {
        const InstanceMetrics& source = fleet.instances[i];
        std::vector<std::pair<std::string, std::string>> targets;  // kind, uri
        for (const auto& database : source.directory.databases) {
            if (!database.uri.empty()) {
                targets.emplace_back("proxy", database.uri);
            }
            for (const std::string& provider : database.syncreplProviders) {
                targets.emplace_back("syncrepl", provider);
            }
            if (!database.chainUri.empty()) {
                targets.emplace_back("chain", database.chainUri);
            }
        }
        for (const auto& [kind, uri] : targets) {
            TopoEdge edge;
            edge.from = static_cast<int>(i);
            edge.kind = kind;
            edge.target = uri;
            edge.opsFrom = i < fleet.history.size() ? fleet.history[i].opsPerSecond.last() : 0.0;
            const int to = resolveInstance(fleet, i, uri);
            if (to >= 0) {
                const std::size_t j = static_cast<std::size_t>(to);
                edge.to = to;
                edge.resolved = true;
                edge.opsTo = j < fleet.history.size() ? fleet.history[j].opsPerSecond.last() : 0.0;
                edge.lagSeconds = fleet.instances[j].replication.lagSeconds;
            }
            edges.push_back(std::move(edge));
        }
    }
    return edges;
}

/// Draws one instance as a box with its databases and a small activity bar.
/// Lines the textual part of one node needs: its databases plus its lloadd
/// backends.  Drives how much height the node deserves.
int topoNodeLines(const InstanceMetrics& metrics) {
    int lines = 0;
#ifdef SLAPTOP_WITH_LDAP
    for (const LloadTier& tier : metrics.monitor.lloadTiers) {
        lines += 1 + static_cast<int>(tier.servers.size());
    }
#endif
    for (const auto& database : metrics.directory.databases) {
        if (database.backend == "config" || database.backend == "monitor" ||
            database.backend == "frontend") {
            continue;
        }
        ++lines;
    }
    return lines;
}

void drawTopoNode(ncplane* plane, int top, int left, int height, int width,
                  const InstanceMetrics& metrics, const InstanceHistory& history, double pulse,
                  bool focused, bool relative) {
    const std::uint32_t frame = focused ? g_theme.focus : g_theme.frame;
    const std::string rule = repeat("\u2500", static_cast<std::size_t>(std::max(0, width - 2)));
    put(plane, top, left, "\u256D" + rule, frame);
    put(plane, top, left + width - 1, "\u256E", frame);
    for (int row = 1; row < height - 1; ++row) {
        put(plane, top + row, left, "\u2502", frame);
        put(plane, top + row, left + width - 1, "\u2502", frame);
    }
    put(plane, top + height - 1, left, "\u2570" + rule, frame);
    put(plane, top + height - 1, left + width - 1, "\u256F", frame);

    int x = left + 2;
    put(plane, top, x, metrics.instance.name, g_theme.accent, true);
    x += static_cast<int>(text::width(metrics.instance.name)) + 2;
    put(plane, top, x, instanceRole(metrics), g_theme.dim);
    x += static_cast<int>(text::width(instanceRole(metrics))) + 1;
    put(plane, top, x,
        repeat("\u2500", static_cast<std::size_t>(std::max(0, width - x + left - 1))), frame);

    const int inner = width - 4;
    if (height < 4 || inner < 8) {
        return;
    }
    // Everything textual is built first, so the activity graph can take all
    // the rows left over: a tall terminal gets a tall graph instead of a
    // framed void.
    struct NodeLine {
        std::string text;
        std::uint32_t color;
        bool bold;
    };
    std::vector<NodeLine> lines;
    char text[256];

#ifdef SLAPTOP_WITH_LDAP
    // lloadd tiers and backend servers: active/pending connections and the
    // operation counters each backend reports.
    for (const LloadTier& tier : metrics.monitor.lloadTiers) {
        lines.push_back({"tier " + tier.name, g_theme.accent, true});
        for (const LloadServer& server : tier.servers) {
            std::string host = server.uri;
            if (const std::size_t scheme = host.find("://"); scheme != std::string::npos) {
                host = host.substr(scheme + 3);
            }
            if (const std::size_t dot = host.find('.'); dot != std::string::npos) {
                host = host.substr(0, dot);  // short host name, the box is narrow
            }
            std::snprintf(text, sizeof(text), "  %-8.8s %-8.8s a%3llu p%3llu rx%7llu f%3llu",
                          server.name.c_str(), host.c_str(),
                          static_cast<unsigned long long>(server.activeConnections),
                          static_cast<unsigned long long>(server.pendingConnections),
                          static_cast<unsigned long long>(server.receivedOps),
                          static_cast<unsigned long long>(server.failedOps));
            lines.push_back({text, server.failedOps > 0 ? g_theme.error : g_theme.text, false});
        }
    }
#endif

    for (const auto& database : metrics.directory.databases) {
        if (database.backend == "config" || database.backend == "monitor" ||
            database.backend == "frontend") {
            continue;
        }
        std::string label = database.suffix.empty() ? database.label : database.suffix;
        if (database.backend == "ldap" && !database.uri.empty()) {
            label += " \u2192 " + database.uri;
        }
        std::string overlays;
        for (const std::string& overlay : database.overlays) {
            overlays += (overlays.empty() ? "" : ",") + overlay;
        }
        if (!overlays.empty()) {
            label += " [" + overlays + "]";
        }
        std::snprintf(text, sizeof(text), "%-10.10s %s", database.backend.c_str(),
                      label.c_str());
        lines.push_back({text, g_theme.text, false});
    }

    // The graphs take the rows the text does not need.  Cpu, memory and
    // activity sit side by side instead of one graph spanning the whole width:
    // three small multiples read better than one wide band, and they line up
    // with the dashboard card.
    struct Band {
        const char* label;
        const std::deque<double>* values;
        Palette palette;
        double minimumSpan;
        std::string value;
        double capacity;  ///< 0 = automatic scale
    };
    std::vector<Band> bands;
    {
        // Same reading as the dashboard card: raw per-core percentage against
        // the capacity of the host that runs this instance.  The series holds
        // raw values, so a capacity of 100 would pin the graph at the top as
        // soon as one core is busy.
        bands.push_back({"cpu", &history.cpuPercent.values(), kCpuPalette, 25.0,
                         cpuText(metrics), relative ? 100.0 * cpuCapacity(metrics) : 0.0});
        std::string memShown = humanBytes(metrics.proc.rssBytes);
        const double memTotal = memCapacityMiB(metrics);
        if (memTotal > 0.0) {
            memShown += " / " + humanBytes(static_cast<std::uint64_t>(memTotal * 1024.0 * 1024.0));
        }
        bands.push_back({"mem", &history.rssMiB.values(), kMemPalette, 1.0, memShown,
                         relative ? memTotal : 0.0});
        char ops[32];
        std::snprintf(ops, sizeof(ops), "%.1f/s", history.opsPerSecond.last());
        bands.push_back({"ops", &history.opsPerSecond.values(), kOpsPalette, 1.0, ops, 0.0});
    }
    const int bandGap = 2;
    const int bandWidth = (inner - bandGap * 2) / 3;
    int graphArea = height - 2 - static_cast<int>(lines.size());
    if (graphArea < 1) {
        graphArea = 1;
    }
    const int labelRow = graphArea >= 2 ? 1 : 0;
    const int graphRows = std::max(1, graphArea - labelRow);

    for (std::size_t index = 0; index < bands.size() && bandWidth >= 6; ++index) {
        const Band& band = bands[index];
        const int bandX = left + 2 + static_cast<int>(index) * (bandWidth + bandGap);

        // The scale is needed both by the caption and by the axis labels, so it
        // is computed once, outside the caption row (which is optional).
        double floor = 0.0;
        double ceiling = 1.0;
        if (band.capacity > 0.0) {
            ceiling = band.capacity;
        } else {
            const Scale scale = scaleFor(*band.values, false, band.minimumSpan, true);
            floor = scale.floor;
            ceiling = scale.ceiling;
        }
        const auto format = [&band](double value) {
            char axisText[16];
            if (std::string(band.label) == "cpu") {
                std::snprintf(axisText, sizeof(axisText), "%.0f%%", value);
            } else if (std::string(band.label) == "mem") {
                std::snprintf(axisText, sizeof(axisText), "%s",
                              humanBytes(static_cast<std::uint64_t>(value * 1024.0 * 1024.0))
                                  .c_str());
            } else {
                std::snprintf(axisText, sizeof(axisText), "%.1f/s", value);
            }
            return std::string(axisText);
        };

        if (labelRow > 0) {
            put(plane, top + 1, bandX, band.label, shade(band.palette, 0.9), true);
            const int valueWidth = static_cast<int>(band.value.size());
            if (bandWidth > valueWidth + 5) {
                put(plane, top + 1, bandX + bandWidth - valueWidth, band.value,
                    shade(band.palette, 0.85), true);
                // Block runes have no bitmap to carry the scale: the top of the
                // axis goes on the caption row, just before the value.
                if (g_pixelSupport == 0 && graphRows > 0) {
                    put(plane, top + 1, bandX + bandWidth - valueWidth - 8,
                        padLeft(format(ceiling), 7), g_theme.dim);
                }
            }
        }
        drawBandGrid(plane, top + 1 + labelRow, bandX, bandWidth, graphRows);

        // Same axis as the dashboard card: the bitmap carries the values when
        // pixel rendering is on, block runes fall back to the cell axis.
        drawGraph(plane, top + 1 + labelRow, bandX, bandWidth, graphRows, *band.values, floor,
                  ceiling, band.palette, g_theme.animate, pulse,
                  yAxisLabels(floor, ceiling, graphRows, format),
                  xAxisLabels(band.values->size(), history.sampleSeconds));
    }

    int row = top + 1 + labelRow + graphRows;
    for (const NodeLine& line : lines) {
        if (row >= top + height - 1) {
            break;
        }
        put(plane, row++, left + 2, text::fit(line.text, static_cast<std::size_t>(inner)),
            line.color, line.bold);
    }
}

/// Architecture screen: one box per instance, arrow(s) between linked boxes,
/// and a correlation panel showing both sides of each link.
void drawTopology(ncplane* plane, int dimY, int dimX, const FleetSnapshot& fleet, int selected,
                  double pulse, bool relative) {
    const int count = static_cast<int>(fleet.instances.size());
    if (count == 0) {
        put(plane, 2, 2, "no slapd instance found", g_theme.dim);
        return;
    }

    char header[160];
    std::snprintf(header, sizeof(header), "%d instance%s", count, count == 1 ? "" : "s");
    put(plane, 2, 1, header, g_theme.dim);

    const std::vector<TopoEdge> edges = buildTopology(fleet);

    const int columns = dimX >= 96 ? 2 : 1;
    const int rows = (count + columns - 1) / columns;
    // The link panel takes the rows it needs to list every link, and the boxes
    // take everything that is left: the screen is a fixed budget, so nothing
    // is left empty at the bottom.
    // Each database gets a chain line, a possible wrap, and a blank row.
    int linksHeight =
        std::max(3, 2 + servedDatabases(fleet.instances[static_cast<std::size_t>(selected)]) * 3);
    const int maxLinks = std::max(3, dimY - 5 - rows * 6);
    linksHeight = std::min(linksHeight, maxLinks);

    const int areaHeight = dimY - 5 - linksHeight;
    const int boxWidth = (dimX - (columns + 1) * 2) / columns;

    // Height of each row of nodes: what a node has to show (its databases,
    // its lloadd backends, its three graphs), and the free rows shared in
    // proportion to that content.
    std::vector<int> natural(static_cast<std::size_t>(rows), 6);
    std::vector<int> rowWeights(static_cast<std::size_t>(rows), 1);
    for (int index = 0; index < count; ++index) {
        const int row = columns == 1 ? index : index / columns;
        const int lines = topoNodeLines(fleet.instances[static_cast<std::size_t>(index)]);
        natural[static_cast<std::size_t>(row)] =
            std::max(natural[static_cast<std::size_t>(row)], std::min(lines + 5, 16));
        rowWeights[static_cast<std::size_t>(row)] =
            std::max(rowWeights[static_cast<std::size_t>(row)], lines + 1);
    }
    std::vector<int> rowHeights(static_cast<std::size_t>(rows), 0);
    int naturalTotal = 0;
    for (const int height : natural) {
        naturalTotal += height;
    }
    if (naturalTotal >= areaHeight) {
        // Short terminal: everything goes to the data, proportionally.
        distributeExtra(rowHeights, rowWeights, areaHeight);
    } else {
        rowHeights = natural;
        distributeExtra(rowHeights, rowWeights, areaHeight - naturalTotal);
    }
    std::vector<int> rowTop(static_cast<std::size_t>(rows), 3);
    for (int r = 1; r < rows; ++r) {
        rowTop[static_cast<std::size_t>(r)] =
            rowTop[static_cast<std::size_t>(r - 1)] + rowHeights[static_cast<std::size_t>(r - 1)];
    }

    for (int index = 0; index < count; ++index) {
        const int column = columns == 1 ? 0 : index % columns;
        const int row = columns == 1 ? index : index / columns;
        const int left = 2 + column * (boxWidth + 2);
        const int top = rowTop[static_cast<std::size_t>(row)];
        const int boxHeight = rowHeights[static_cast<std::size_t>(row)];
        if (boxHeight < 3) {
            break;
        }
        drawTopoNode(plane, top, left, boxHeight, boxWidth,
                     fleet.instances[static_cast<std::size_t>(index)],
                     index < static_cast<int>(fleet.history.size())
                         ? fleet.history[static_cast<std::size_t>(index)]
                         : InstanceHistory{},
                     pulse, index == selected, relative);

        // Arrow to the next box on the same row, when the link is declared.
        for (const TopoEdge& edge : edges) {
            if (edge.from != index || !edge.resolved) {
                continue;
            }
            const int targetColumn = columns == 1 ? 0 : edge.to % columns;
            const int targetRow = columns == 1 ? edge.to : edge.to / columns;
            if (targetRow != row || targetColumn != column + 1) {
                continue;
            }
            const int arrowRow = top + boxHeight / 2;
            const int arrowX = left + boxWidth;
            const std::string arrow = edge.kind == "proxy" ? "\u2500\u25B6" : "\u21C4";
            put(plane, arrowRow, arrowX, arrow, edge.kind == "proxy" ? g_theme.warn : g_theme.ok,
                true);
        }
    }

    // Path diagram: what a client actually traverses on this instance, from
    // the socket to the bytes on disk, overlays included.
    const int linkTop = dimY - 1 - linksHeight;
    if (linkTop > 3) {
        drawPathDiagram(plane, linkTop, linksHeight, dimX,
                        fleet.instances[static_cast<std::size_t>(selected)]);
    }

    put(plane, dimY - 1, 1,
        text::fit("t/esc back   tab next screen   ? help",
                  static_cast<std::size_t>(std::max(0, dimX - 2))),
        g_theme.dim);
}

// ---------------------------------------------------------------------------
// I/O view: the interfaces slapd listens on, the disks it writes to
// ---------------------------------------------------------------------------

/// "12.3M/s" from a byte-per-second rate.
std::string humanRate(double bytesPerSecond) {
    if (bytesPerSecond < 0.0) {
        return "--";
    }
    return humanBytes(static_cast<std::uint64_t>(bytesPerSecond)) + "/s";
}

void drawIo(ncplane* plane, int dimY, int dimX, const InstanceMetrics& metrics,
            const InstanceHistory& history, double pulse) {
#ifdef SLAPTOP_WITH_LDAP
    if (metrics.instance.pid == 0) {
        put(plane, 3, 2,
            "remote instance: no /proc, no /sys and no access to its database files",
            g_theme.dim);
        put(plane, dimY - 1, 1,
            text::fit("tab next screen   esc back", static_cast<std::size_t>(dimX - 2)),
            g_theme.dim);
        return;
    }
    char header[192];
    std::snprintf(header, sizeof(header), "%zu interface%s   %zu filesystem%s",
                  metrics.io.interfaces.size(),
                  metrics.io.interfaces.size() == 1 ? "" : "s", metrics.io.disks.size(),
                  metrics.io.disks.size() == 1 ? "" : "s");
    drawScreenHeader(plane, dimX, metrics, header);

    // Leave the last row for the key line (and the instance hint drawn there),
    // and one blank row between each pair of frames: `available` is therefore
    // what the three frames share, gaps excluded.  Getting this wrong pushed
    // the bottom border onto the key line.
    const int available = std::max(9, dimY - 6);
    // Three frames sharing the height in proportion to what each has to show.
    // Each interface and each disk takes one text row plus two sparklines; the
    // memory frame has two fixed lines, so it never absorbs the surplus.
    const int entryRows = 3;
    const int memoryRows = std::clamp(available / 4, 3, 5);
    std::vector<int> heights{3 + static_cast<int>(metrics.io.interfaces.size()) * entryRows,
                             3 + static_cast<int>(metrics.io.disks.size()) * entryRows,
                             memoryRows};
    const int natural = heights[0] + heights[1] + heights[2];
    if (natural <= available) {
        std::vector<int> growable{heights[0], heights[1]};
        const std::vector<int> weights{
            std::max(1, static_cast<int>(metrics.io.interfaces.size())),
            std::max(1, static_cast<int>(metrics.io.disks.size()))};
        distributeExtra(growable, weights, available - natural);
        heights[0] = growable[0];
        heights[1] = growable[1];
    } else {
        const int rest = std::max(6, available - memoryRows);
        heights[0] = std::max(3, rest / 2);
        heights[1] = std::max(3, rest - rest / 2);
    }

    // --- network ---------------------------------------------------------
    Zone net = drawBox(plane, 3, 0, heights[0], dimX, " network ", g_theme.frame);
    if (net.valid) {
        // Column widths come from the frame, not from a constant: the name
        // column takes what the numeric ones leave, so a long interface name
        // is never cut while the right edge stays empty.
        struct NetRow {
            std::string name;
            std::string rx;
            std::string tx;
            std::string rxTotal;
            std::string txTotal;
            std::string errors;
            std::string dropped;
            bool faulty;
        };
        std::vector<NetRow> rows;
        int nameWidth = 9;  // "interface"
        for (const IoInterface& interface : metrics.io.interfaces) {
            NetRow row;
            row.name = interface.name;
            row.rx = humanRate(interface.rxPerSecond);
            row.tx = humanRate(interface.txPerSecond);
            row.rxTotal = humanBytes(interface.rxBytes);
            row.txTotal = humanBytes(interface.txBytes);
            row.errors = std::to_string(interface.rxErrors + interface.txErrors);
            row.dropped = std::to_string(interface.rxDropped + interface.txDropped);
            row.faulty = interface.rxErrors + interface.txErrors > 0;
            nameWidth = std::max(nameWidth, text::width(row.name));
            rows.push_back(std::move(row));
        }
        // The name column stays readable (a NIC name is short), and every
        // column the frame still has goes to the numeric fields: they are
        // right-aligned, so the numbers end at the frame edge instead of
        // leaving a blank gutter on the right.
        nameWidth = std::clamp(nameWidth + 1, 9, 24);
        std::vector<int> widths{12, 12, 12, 12, 7, 7};
        const int used = nameWidth + widths[0] + widths[1] + widths[2] + widths[3] + widths[4] +
                         widths[5];
        if (net.width > used) {
            distributeExtra(widths, std::vector<int>(widths.size(), 1), net.width - used);
        }

        int row = net.top;
        put(plane, row++, net.left,
            text::fit(padTo("interface", nameWidth) + padLeft("rx/s", widths[0]) +
                          padLeft("tx/s", widths[1]) + padLeft("rx total", widths[2]) +
                          padLeft("tx total", widths[3]) + padLeft("err", widths[4]) +
                          padLeft("drop", widths[5]),
                      static_cast<std::size_t>(net.width)),
            g_theme.dim);
        if (rows.empty()) {
            put(plane, row, net.left, "no interface matched the listeners", g_theme.dim);
        }
        // Rows available per interface: one text row, the rest to the graphs.
        const int netTextRows = static_cast<int>(rows.size());
        const int netFree = net.height - 1 - netTextRows;  // minus the header row
        const int graphHeight =
            netTextRows == 0 ? 0 : std::max(2, netFree / netTextRows);
        for (const NetRow& entry : rows) {
            if (row + 1 + graphHeight > net.top + net.height) {
                break;
            }
            const std::string line =
                padTo(entry.name, nameWidth) + padLeft(entry.rx, widths[0]) +
                padLeft(entry.tx, widths[1]) + padLeft(entry.rxTotal, widths[2]) +
                padLeft(entry.txTotal, widths[3]) + padLeft(entry.errors, widths[4]) +
                padLeft(entry.dropped, widths[5]);
            put(plane, row++, net.left, text::fit(line, static_cast<std::size_t>(net.width)),
                entry.faulty ? g_theme.warn : g_theme.text);

            // Receive and transmit under the row, each as tall as the frame can
            // afford: one row per graph left most of the box empty, and a
            // taller graph costs nothing.
            // Block runes need their scale written beside them; the bitmap has
            // it inside.  Reserve the column only when it is used.
            const int axisCols = g_pixelSupport != 0 ? 0 : 7;
            const int graphWidth = net.width - 5 - axisCols;
            const auto rx = history.ioRx.find(entry.name);
            const auto tx = history.ioTx.find(entry.name);
            const auto runeAxis = [&](int atRow, int spanRows, const Scale& scale) {
                if (axisCols == 0) {
                    return;
                }
                const int x = net.left + 5 + graphWidth + 1;
                put(plane, atRow, x, padLeft(humanRate(scale.ceiling), axisCols), g_theme.dim);
                if (spanRows > 1) {
                    put(plane, atRow + spanRows - 1, x, padLeft("0", axisCols), g_theme.dim);
                }
            };
            if (graphWidth > 8) {
                const int rxRows = std::max(1, graphHeight - graphHeight / 2);
                const int txRows = std::max(1, graphHeight - rxRows);
                put(plane, row, net.left, "  rx ", g_theme.dim);
                const Scale rxScale =
                    rx != history.ioRx.end()
                        ? scaleFor(rx->second.values(), false, 1.0, true)
                        : Scale{};
                runeAxis(row, rxRows, rxScale);
                if (rx != history.ioRx.end()) {
                    const Scale scale = rxScale;
                    const auto rate = [](double value) { return humanRate(value); };
                    drawGraph(plane, row, net.left + 5, graphWidth, rxRows,
                              rx->second.values(), scale.floor, scale.ceiling, kMemPalette,
                              g_theme.animate, pulse,
                              yAxisLabels(scale.floor, scale.ceiling, rxRows, rate),
                              xAxisLabels(rx->second.size(), history.sampleSeconds));
                }
                row += rxRows;
                put(plane, row, net.left, "  tx ", g_theme.dim);
                const Scale txScale =
                    tx != history.ioTx.end()
                        ? scaleFor(tx->second.values(), false, 1.0, true)
                        : Scale{};
                if (tx != history.ioTx.end()) {
                    const Scale scale = txScale;
                    const auto rate = [](double value) { return humanRate(value); };
                    drawGraph(plane, row, net.left + 5, graphWidth, txRows,
                              tx->second.values(), scale.floor, scale.ceiling, kOpsPalette,
                              g_theme.animate, pulse,
                              yAxisLabels(scale.floor, scale.ceiling, txRows, rate),
                              xAxisLabels(tx->second.size(), history.sampleSeconds));
                }
                row += txRows - 1;
                ++row;
            }
        }
    }

    // --- disks -----------------------------------------------------------
    const int diskTop = 3 + heights[0] + 1;
    Zone disk = drawBox(plane, diskTop, 0, heights[1], dimX, " disk ", g_theme.frame);
    if (disk.valid) {
        struct DiskRow {
            std::string label;
            std::string rawPath;  ///< key of the history series
            std::string path;
            std::string device;
            std::string mount;
            std::string read;
            std::string write;
            std::string busy;
            std::string used;
            std::uint32_t color;
        };
        std::vector<DiskRow> rows;
        int labelWidth = 4;   // "for" + one space
        int pathWidth = 5;    // "path" + one space
        int deviceWidth = 7;  // "device" + one space
        int mountWidth = 6;   // "mount" + one space
        int usedWidth = 5;    // "used" + one space
        for (const IoDisk& entry : metrics.io.disks) {
            const double usedRatio =
                entry.totalBytes > 0
                    ? 100.0 * static_cast<double>(entry.totalBytes - entry.freeBytes) /
                          static_cast<double>(entry.totalBytes)
                    : 0.0;
            char used[64];
            if (entry.totalBytes > 0) {
                std::snprintf(used, sizeof(used), "%s / %s  %.0f%%",
                              humanBytes(entry.totalBytes - entry.freeBytes).c_str(),
                              humanBytes(entry.totalBytes).c_str(), usedRatio);
            } else {
                std::snprintf(used, sizeof(used), "--");
            }
            DiskRow row;
            row.label = entry.label.empty() ? "data" : entry.label;
            row.rawPath = entry.path;
            row.path = entry.path;
            row.device = entry.device.empty() ? "?" : entry.device;
            row.mount = entry.mountPoint.empty() ? "?" : entry.mountPoint;
            row.read = humanRate(entry.readPerSecond);
            row.write = humanRate(entry.writePerSecond);
            row.busy = std::to_string(static_cast<int>(entry.busyPercent + 0.5)) + "%";
            row.used = used;
            row.color = entry.busyPercent >= 80.0 || usedRatio >= 90.0
                            ? g_theme.error
                            : (usedRatio >= 75.0 ? g_theme.warn : g_theme.text);
            labelWidth = std::max(labelWidth, text::width(row.label) + 1);
            pathWidth = std::max(pathWidth, text::width(row.path) + 1);
            deviceWidth = std::max(deviceWidth, text::width(row.device) + 1);
            mountWidth = std::max(mountWidth, text::width(row.mount) + 1);
            usedWidth = std::max(usedWidth, text::width(row.used) + 1);
            rows.push_back(std::move(row));
        }
        // Numeric columns keep a fixed, right-aligned width; everything the
        // frame still has goes to the path, which is the column that gets cut
        // first.  Mount and device stay at their content width.
        const int readWidth = 10;
        const int writeWidth = 10;
        const int busyWidth = 6;
        usedWidth = std::max(usedWidth, 14);
        // The label names the naming context the directory holds ("log" for
        // the log directory), capped so a deep suffix cannot eat the path.
        labelWidth = std::clamp(labelWidth, 4, std::max(4, disk.width / 4));
        const int fixed = labelWidth + deviceWidth + mountWidth + readWidth + writeWidth +
                          busyWidth + usedWidth;
        pathWidth = std::max(12, disk.width - fixed);

        // Same rule as the network frame: one text row per entry, everything
        // else to the graphs.
        const int diskTextRows = static_cast<int>(rows.size());
        const int diskFree = disk.height - 1 - diskTextRows;
        const int diskGraphHeight =
            diskTextRows == 0 ? 0 : std::max(2, diskFree / diskTextRows);

        int row = disk.top;
        put(plane, row++, disk.left,
            text::fit(padTo("for", labelWidth) + padTo("path", pathWidth) +
                          padTo("device", deviceWidth) +
                          padTo("mount", mountWidth) + padLeft("read/s", readWidth) +
                          padLeft("write/s", writeWidth) + padLeft("busy", busyWidth) +
                          padLeft("used", usedWidth),
                      static_cast<std::size_t>(disk.width)),
            g_theme.dim);
        if (rows.empty()) {
            put(plane, row, disk.left, "no database directory nor log file to watch", g_theme.dim);
        }
        for (const DiskRow& entry : rows) {
            if (row + 1 + diskGraphHeight > disk.top + disk.height) {
                break;
            }
            const std::string line =
                padTo(entry.label, labelWidth) +
                padTo(shortenPath(entry.path, pathWidth - 1), pathWidth) +
                padTo(entry.device, deviceWidth) +
                padTo(entry.mount, mountWidth) + padLeft(entry.read, readWidth) +
                padLeft(entry.write, writeWidth) + padLeft(entry.busy, busyWidth) +
                padLeft(entry.used, usedWidth);
            put(plane, row++, disk.left, text::fit(line, static_cast<std::size_t>(disk.width)),
                entry.color);

            const int graphWidth = disk.width - 5;
            const auto reads = history.diskRead.find(entry.rawPath);
            const auto writes = history.diskWrite.find(entry.rawPath);
            if (graphWidth > 8) {
                const int rdRows = std::max(1, diskGraphHeight - diskGraphHeight / 2);
                const int wrRows = std::max(1, diskGraphHeight - rdRows);
                put(plane, row, disk.left, "  rd ", g_theme.dim);
                if (reads != history.diskRead.end()) {
                    const Scale scale = scaleFor(reads->second.values(), false, 1.0, true);
                    const auto rate = [](double value) { return humanRate(value); };
                    drawGraph(plane, row, disk.left + 5, graphWidth, rdRows,
                              reads->second.values(), scale.floor, scale.ceiling, kMemPalette,
                              g_theme.animate, pulse,
                              yAxisLabels(scale.floor, scale.ceiling, rdRows, rate),
                              xAxisLabels(reads->second.size(), history.sampleSeconds));
                }
                row += rdRows;
                put(plane, row, disk.left, "  wr ", g_theme.dim);
                if (writes != history.diskWrite.end()) {
                    const Scale scale = scaleFor(writes->second.values(), false, 1.0, true);
                    const auto rate = [](double value) { return humanRate(value); };
                    drawGraph(plane, row, disk.left + 5, graphWidth, wrRows,
                              writes->second.values(), scale.floor, scale.ceiling, kOpsPalette,
                              g_theme.animate, pulse,
                              yAxisLabels(scale.floor, scale.ceiling, wrRows, rate),
                              xAxisLabels(writes->second.size(), history.sampleSeconds));
                }
                row += wrRows - 1;
                ++row;
            }
        }
    }
    // --- memory ----------------------------------------------------------
    // Two questions, one frame: how much this slapd occupies, and how much of
    // the machine is gone.  `available` is the kernel's estimate of what can
    // still be handed out without swapping, so page cache is not counted as
    // used — a healthy host would otherwise read 95 %.
    const int memoryTop = diskTop + heights[1] + 1;
    Zone memory = drawBox(plane, memoryTop, 0, heights[2], dimX, " memory ", g_theme.frame);
    if (memory.valid && memory.height >= 1) {
        const double percent = systemMemoryPercent(metrics);
        const std::string rss = humanBytes(metrics.proc.rssBytes);
        const std::string total = humanBytes(metrics.proc.memTotalBytes);
        const std::string used = humanBytes(metrics.proc.memTotalBytes -
                                            metrics.proc.memAvailableBytes);
        const std::string free = humanBytes(metrics.proc.memAvailableBytes);
        int row = memory.top;
        if (percent < 0.0) {
            put(plane, row, memory.left,
                text::fit("system memory: /proc/meminfo not readable",
                          static_cast<std::size_t>(memory.width)),
                g_theme.dim);
        } else {
            // A bar made of runes, like the graphs: it reads faster than a
            // number when the frame is wide and still works when it is narrow.
            const int barWidth = std::max(0, std::min(40, memory.width - 46));
            std::string bar;
            if (barWidth > 0) {
                const int filled = static_cast<int>(
                    std::lround(percent / 100.0 * static_cast<double>(barWidth)));
                const int solid = std::clamp(filled, 0, barWidth);
                bar = repeat("\u2588", static_cast<std::size_t>(solid)) +
                      repeat("\u2591", static_cast<std::size_t>(barWidth - solid));
            }
            char line[192];
            std::snprintf(line, sizeof(line), "system  %s / %s used  %.1f%%", used.c_str(),
                          total.c_str(), percent);
            put(plane, row, memory.left, text::fit(line, static_cast<std::size_t>(memory.width)),
                g_theme.text);
            int column = memory.left + static_cast<int>(std::strlen(line)) + 2;
            if (barWidth > 0 && column + barWidth + 1 <= memory.left + memory.width) {
                put(plane, row, column, bar, memoryColor(percent));
            }
            ++row;
            std::snprintf(line, sizeof(line),
                          "         %s available   this instance %s (%.1f%% of the host)",
                          free.c_str(), rss.c_str(),
                          metrics.proc.memTotalBytes == 0
                              ? 0.0
                              : 100.0 * static_cast<double>(metrics.proc.rssBytes) /
                                    static_cast<double>(metrics.proc.memTotalBytes));
            put(plane, row++, memory.left,
                text::fit(line, static_cast<std::size_t>(memory.width)), g_theme.dim);

            // What the host would get back if slapd stopped: the monitor
            // shows this "after removing OpenLDAP" figure.  An approximation —
            // the page cache and shared mappings are counted once — but it is
            // the number that matters when deciding whether a host is
            // over-committed by the directory itself.
            if (row < memory.top + memory.height) {
                const std::uint64_t withoutSlapd =
                    metrics.proc.memAvailableBytes + metrics.proc.rssBytes;
                std::snprintf(line, sizeof(line),
                              "         %s without slapd (%s available + its %s)",
                              humanBytes(withoutSlapd).c_str(), free.c_str(), rss.c_str());
                put(plane, row, memory.left,
                    text::fit(line, static_cast<std::size_t>(memory.width)), g_theme.dim);
            }
        }
    }

#else
    put(plane, 3, 2, "built without LDAP support", g_theme.dim);
#endif
    put(plane, dimY - 1, 1,
        text::fit("tab next screen   esc back", static_cast<std::size_t>(dimX - 2)), g_theme.dim);
}

// ---------------------------------------------------------------------------
// Replication view
// ---------------------------------------------------------------------------

/// What the replication view remembers between two frames for one
/// (instance, SID) pair: when the CSN last moved, and the worst lag seen.
/// slapd-watcher keeps exactly these two numbers ("actv@", "max delta").
struct RepState {
    std::string csn;
    std::chrono::steady_clock::time_point lastChange{};
    long long maxLag{0};
    bool known{false};
    /// False until the CSN has moved at least once while we watched: an
    /// untouched SID must not pretend it changed the moment we connected.
    bool moved{false};
};

struct ReplicationTracker {
    std::map<std::pair<std::string, int>, RepState> states;
};

/// contextCSN of `sid` on one instance, nullptr when that instance does not
/// publish it.
const CsnsEntry* csnFor(const InstanceMetrics& metrics, int sid) {
    for (const CsnsEntry& entry : metrics.replication.csns) {
        if (entry.sid == sid) {
            return &entry;
        }
    }
    return nullptr;
}

/// True when every suffix this instance serves is proxied to an upstream
/// (back-ldap, back-meta): its contextCSN is then the upstream's answer, not a
/// replication state of its own.
bool isProxyInstance(const InstanceMetrics& metrics) {
    bool any = false;
    for (const auto& database : metrics.directory.databases) {
        // Pseudo backends have suffixes too (cn=Null); they say nothing about
        // whether this instance forwards to an upstream.
        if (database.suffix.empty() || database.backend == "frontend" ||
            database.backend == "config" || database.backend == "monitor" ||
            database.backend == "null") {
            continue;
        }
        any = true;
        if (database.backend != "ldap" && database.backend != "meta") {
            return false;
        }
    }
    return any;
}


/// Suffix the replication view talks about, and the database it maps to.
std::string replicatedSuffix(const InstanceMetrics& metrics) {
    for (const auto& database : metrics.directory.databases) {
        if (!database.syncreplProviders.empty() && !database.suffix.empty()) {
            return database.suffix;
        }
    }
    for (const auto& database : metrics.directory.databases) {
        if (database.suffix.empty()) {
            continue;
        }
        // Skip the bookkeeping backends: their suffix is cn=config, cn=monitor.
        if (database.backend == "config" || database.backend == "monitor" ||
            database.backend == "frontend" || database.backend == "null") {
            continue;
        }
        return database.suffix;
    }
    return std::string();
}

/// Draws the replication screen: per-SID contextCSN, the fleet matrix, and the
/// operation counters slapd-watcher prints, all rebuilt from the configuration
/// and from cn=monitor (no credentials, no extra queries).
void drawReplication(ncplane* plane, int dimY, int dimX, const FleetSnapshot& fleet, int selected,
                     ReplicationTracker& tracker) {
#ifdef SLAPTOP_WITH_LDAP
    const InstanceMetrics& metrics = fleet.instances[static_cast<std::size_t>(selected)];
    const auto now = std::chrono::steady_clock::now();

    // Every SID present in the fleet, in numeric order.
    std::vector<int> sids;
    for (const InstanceMetrics& instance : fleet.instances) {
        for (const CsnsEntry& entry : instance.replication.csns) {
            if (entry.sid >= 0 &&
                std::find(sids.begin(), sids.end(), entry.sid) == sids.end()) {
                sids.push_back(entry.sid);
            }
        }
    }
    std::sort(sids.begin(), sids.end());

    // Reference position for each SID: its owner when olcServerID names one
    // (even if that owner is the one lagging: that is the point), otherwise the
    // instance that is ahead of everybody.
    std::map<int, const CsnsEntry*> reference;
    std::map<int, std::string> referenceName;
    std::map<int, int> referenceOwner;
    for (const int sid : sids) {
        int owner = sidOwner(fleet, sid);
        if (owner < 0) {
            long long best = -1;
            for (std::size_t index = 0; index < fleet.instances.size(); ++index) {
                const CsnsEntry* entry = csnFor(fleet.instances[index], sid);
                if (entry != nullptr && entry->epoch > best) {
                    best = entry->epoch;
                    owner = static_cast<int>(index);
                }
            }
        }
        if (owner < 0) {
            continue;
        }
        if (const CsnsEntry* entry = csnFor(fleet.instances[static_cast<std::size_t>(owner)], sid);
            entry != nullptr) {
            reference[sid] = entry;
            referenceOwner[sid] = owner;
            referenceName[sid] = fleet.instances[static_cast<std::size_t>(owner)].instance.name;
        }
    }

    // Which instances an agreement links: a SID compared across two replica
    // sets that share no agreement measures a leftover, not a lag.
    const std::vector<int> replicaSet = replicaSets(fleet);
    // The screen is redrawn many times per second: report the sets when they
    // change, not at every frame.
    if (std::getenv("SLAPTOP_CSN_DEBUG") != nullptr) {
        std::string report;
        for (std::size_t index = 0; index < fleet.instances.size(); ++index) {
            report += "replica set " + fleet.instances[index].instance.name + " = " +
                      std::to_string(replicaSet[index]);
            for (const auto& database : fleet.instances[index].directory.databases) {
                for (const std::string& provider : database.syncreplProviders) {
                    report += "  [" + provider + " -> " +
                              std::to_string(resolveInstance(fleet, index, provider)) + "]";
                }
            }
            report += "\n";
        }
        static std::string lastReport;
        if (report != lastReport) {
            lastReport = report;
            std::fputs(report.c_str(), stderr);
        }
    }
    const auto sameSet = [&replicaSet](int a, int b) {
        return a >= 0 && b >= 0 && replicaSet[static_cast<std::size_t>(a)] ==
                                         replicaSet[static_cast<std::size_t>(b)];
    };

    // Feed the tracker: last change and worst lag, the two numbers a watcher
    // is actually read for.
    for (std::size_t self = 0; self < fleet.instances.size(); ++self) {
        const InstanceMetrics& instance = fleet.instances[self];
        for (const CsnsEntry& entry : instance.replication.csns) {
            if (entry.sid < 0) {
                continue;
            }
            RepState& state = tracker.states[{instance.instance.name, entry.sid}];
            if (!state.known) {
                state.csn = entry.csn;
                state.known = true;
            } else if (state.csn != entry.csn) {
                state.csn = entry.csn;
                state.lastChange = now;
                state.moved = true;
            }
            const auto referenceEntry = reference.find(entry.sid);
            const auto owner = referenceOwner.find(entry.sid);
            if (referenceEntry != reference.end() && entry.epoch >= 0 &&
                referenceEntry->second->epoch >= 0 &&
                owner != referenceOwner.end() &&
                sameSet(static_cast<int>(self), owner->second)) {
                const long long lag = std::llabs(entry.epoch - referenceEntry->second->epoch);
                if (lag > state.maxLag) {
                    state.maxLag = lag;
                }
            }
        }
    }

    // --- header: who this is, what it replicates, how big it is ----------
    std::string ids;
    for (const auto& id : metrics.directory.serverIds) {
        ids += (ids.empty() ? "" : ",") + std::to_string(id.sid);
    }
    const std::string suffix = replicatedSuffix(metrics);
    const bool proxy = isProxyInstance(metrics);
    // Largest database on that suffix rather than a sum: a proxy declares the
    // same suffix on its frontend, on the ldap backend and sometimes on a null
    // backend, and summing them would count the same entries thrice.
    std::uint64_t entries = 0;
    for (const DatabaseInfo& database : metrics.monitor.databases) {
        if (database.shadow || database.namingContexts.empty() || database.entries == 0) {
            continue;
        }
        const bool matches =
            suffix.empty() ||
            std::find(database.namingContexts.begin(), database.namingContexts.end(), suffix) !=
                database.namingContexts.end();
        if (matches) {
            entries = std::max(entries, database.entries);
        }
    }
    // Which instance is being read comes first, in the accent colour: the
    // matrix below lists every instance, so a dim title left the operator
    // unable to tell whose view this was.
    std::string title = metrics.instance.name;
    if (!metrics.instance.nodeLabel.empty()) {
        title += " @" + metrics.instance.nodeLabel;
    }
    if (proxy) {
        title += "  (proxy: CSN relayed from the upstream)";
    }
    put(plane, 2, 1, title, g_theme.accent, true);
    char header[320];
    std::snprintf(header, sizeof(header), "   %s   sid %s   %s   entries %llu   %.1f ops/s",
                  instanceRole(metrics).c_str(), ids.empty() ? "-" : ids.c_str(),
                  suffix.empty() ? "(no naming context)" : suffix.c_str(),
                  static_cast<unsigned long long>(entries),
                  selected < static_cast<int>(fleet.history.size())
                      ? fleet.history[static_cast<std::size_t>(selected)].opsPerSecond.last()
                      : 0.0);
    put(plane, 2, 1 + static_cast<int>(text::width(title)), text::fit(header, static_cast<std::size_t>(dimX - 2)), g_theme.dim);

    int row = 3;
    const int bottom = dimY - 2;  // last usable row before the key line

    // --- box 1: contextCSN of this instance, SID by SID ------------------
    // Borders (2) + column header (1) + one row per SID.
    const int sidCount = static_cast<int>(metrics.replication.csns.size());
    int box1 = std::clamp(3 + sidCount, 4, 12);
    box1 = std::min(box1, std::max(3, bottom - row - 6));
    if (!metrics.replication.available) {
        // The agreements decide, not the data: a contextCSN can be inherited
        // from an import and says nothing about replication.
        bool anyAgreement = false;
        for (const InstanceMetrics& instance : fleet.instances) {
            for (const auto& database : instance.directory.databases) {
                if (!database.syncrepl.empty()) {
                    anyAgreement = true;
                    break;
                }
            }
            if (anyAgreement) {
                break;
            }
        }
        std::string why = metrics.replication.error;
        if (!anyAgreement) {
            why = "no olcSyncRepl";
        } else if (why.empty()) {
            why = "no olcSyncRepl on this instance";
        }
        put(plane, row++, 2, text::fit(why, static_cast<std::size_t>(dimX - 4)),
            g_theme.warn);
        // The hint is for a permission problem, not for a directory that
        // simply has no agreement.
        if (!metrics.replication.error.empty() && why.find("contextCSN") == std::string::npos) {
            put(plane, row, 2,
                text::fit("ldapi:// binds EXTERNAL by default: without it the naming context is "
                          "invisible and replication cannot be read",
                          static_cast<std::size_t>(dimX - 4)),
                g_theme.dim);
        }
    } else {
        Zone zone = drawBox(plane, row, 0, box1, dimX, " contextCSN ", g_theme.frame);
        if (zone.valid) {
            int line = zone.top;
            put(plane, line++, zone.left,
                text::fit(padLeft("sid", 4) + " " + padTo("owner", 12) +
                              padTo("last write", 22) + padTo("change", 12) + "max lag",
                          static_cast<std::size_t>(zone.width)),
                g_theme.dim);
            for (const CsnsEntry& entry : metrics.replication.csns) {
                if (line >= zone.top + zone.height) {
                    break;
                }
                const auto state = tracker.states.find({metrics.instance.name, entry.sid});
                const double changeAge =
                    state == tracker.states.end() || !state->second.moved
                        ? -1.0
                        : std::chrono::duration<double>(now - state->second.lastChange).count();
                const long long maxLag =
                    state == tracker.states.end() ? 0 : state->second.maxLag;
                std::string ownerName = "-";
                if (const auto it = referenceName.find(entry.sid); it != referenceName.end()) {
                    ownerName = it->second;
                }
                // A SID whose owner sits in another replica set is a leftover of
                // this database, not a lag: no agreement can bring it up to date.
                const auto ownerIt = referenceOwner.find(entry.sid);
                const bool comparable =
                    ownerIt != referenceOwner.end() && sameSet(selected, ownerIt->second);
                std::uint32_t color = comparable ? g_theme.text : g_theme.dim;
                if (comparable) {
                    if (const auto it = reference.find(entry.sid); it != reference.end()) {
                        if (entry.epoch >= 0 && it->second->epoch > entry.epoch) {
                            color = g_theme.warn;  // behind its own SID
                        }
                    }
                }
                char lineText[320];
                std::snprintf(lineText, sizeof(lineText), "%s%s%s%s%s",
                              (padLeft(std::to_string(entry.sid), 4) + " ").c_str(),
                              padTo(ownerName, 12).c_str(),
                              padTo(formatCsn(entry.csn), 22).c_str(),
                              padTo(changeAge < 0.0 ? "-" : ("change " + humanAge(changeAge)),
                                    12)
                                  .c_str(),
                              comparable ? humanDuration(static_cast<double>(maxLag)).c_str()
                                         : "-");
                put(plane, line++, zone.left,
                    text::fit(lineText, static_cast<std::size_t>(zone.width)), color);
            }
        }
    }
    row += box1;

    // --- box 2: the fleet matrix, one column per SID ---------------------
    const int instances = static_cast<int>(fleet.instances.size());
    // Any cell outside its row's replica set?  The dash then needs a legend,
    // and the legend needs a row.
    bool anyOutside = false;
    for (std::size_t index = 0; index < fleet.instances.size() && !anyOutside; ++index) {
        for (const int sid : sids) {
            const auto owner = referenceOwner.find(sid);
            if (owner != referenceOwner.end() && !sameSet(static_cast<int>(index), owner->second)) {
                anyOutside = true;
                break;
            }
        }
    }
    int box2 = std::min(3 + instances + (anyOutside ? 1 : 0), bottom - row);
    // No SID at all: there is no matrix to draw.  Forcing one column (the old
    // std::max(1, ...) below) read sids[0] out of an empty vector and killed
    // the process as soon as the tab existed without replication agreements.
    if (box2 >= 3 && !sids.empty()) {
        Zone zone = drawBox(plane, row, 0, box2, dimX, " replication matrix ", g_theme.frame);
        if (zone.valid) {
            const int shownSids = std::max(1, std::min<int>(static_cast<int>(sids.size()),
                                                            (zone.width - 14) / 18));
            const int cell = shownSids > 0 ? (zone.width - 14) / shownSids : 0;
            int line = zone.top;
            std::string columnHeader = padTo("instance", 14);
            for (int index = 0; index < shownSids; ++index) {
                columnHeader += padTo("sid " + std::to_string(sids[static_cast<std::size_t>(index)]),
                                      cell);
            }
            put(plane, line++, zone.left,
                text::fit(columnHeader, static_cast<std::size_t>(zone.width)), g_theme.dim);

            for (std::size_t row_index = 0; row_index < fleet.instances.size(); ++row_index) {
                const InstanceMetrics& instance = fleet.instances[row_index];
                if (line >= zone.top + zone.height) {
                    break;
                }
                const bool current = static_cast<int>(row_index) == selected;
                // A row that cannot read its own CSN says so, and a proxy is
                // marked: its CSN is relayed from the upstream, so "sync'd"
                // there does not mean it replicates anything.
                std::string name = std::string(current ? "\u25B6 " : "  ") +
                                   instance.instance.name;
                if (instance.replication.csns.empty() &&
                    !instance.replication.error.empty()) {
                    name += " \u2717";
                } else if (isProxyInstance(instance) && !instance.replication.csns.empty()) {
                    name += " \u21C4";
                }
                std::string lineText = padTo(name, 14);
                std::vector<std::pair<std::string, std::uint32_t>> cells;
                for (int index = 0; index < shownSids; ++index) {
                    const int sid = sids[static_cast<std::size_t>(index)];
                    const CsnsEntry* entry = csnFor(instance, sid);
                    if (entry == nullptr || entry->epoch < 0) {
                        cells.emplace_back(padTo("-", cell), g_theme.dim);
                        continue;
                    }
                    const auto owner = referenceOwner.find(sid);
                    if (owner != referenceOwner.end() &&
                        !sameSet(static_cast<int>(row_index), owner->second)) {
                        // Another replica set: this instance never receives that
                        // SID, so the CSN it still carries is a leftover.
                        cells.emplace_back(padTo("\u2014", cell), g_theme.dim);
                        continue;
                    }
                    const auto referenceEntry = reference.find(sid);
                    if (referenceEntry == reference.end() || referenceEntry->second->epoch < 0) {
                        cells.emplace_back(padTo("unknown", cell), g_theme.dim);
                        continue;
                    }
                    const long long delta = entry->epoch - referenceEntry->second->epoch;
                    if (delta == 0) {
                        cells.emplace_back(padTo("sync'd", cell), g_theme.ok);
                    } else if (delta < 0) {
                        cells.emplace_back(
                            padTo("behind " + humanDuration(static_cast<double>(-delta)), cell),
                            g_theme.warn);
                    } else {
                        cells.emplace_back(
                            padTo("ahead " + humanDuration(static_cast<double>(delta)), cell),
                            g_theme.accent);
                    }
                }
                int x = zone.left;
                put(plane, line, x, lineText, current ? g_theme.accent : g_theme.text, current);
                x += text::width(lineText);
                for (const auto& [cellText, color] : cells) {
                    put(plane, line, x, cellText, color);
                    x += text::width(cellText);
                }
                ++line;
            }
            if (anyOutside && zone.height > 1 + instances) {
                put(plane, zone.top + zone.height - 1, zone.left,
                    text::fit(
                        "\u2014 = SID of another replica set: no olcSyncRepl links the two",
                        static_cast<std::size_t>(zone.width)),
                    g_theme.dim);
            }
        }
        row += box2;
    }

    // --- box 3: the "Num / Num/s" table of slapd-watcher -----------------
    const int box3 = bottom - row;
    if (box3 >= 3) {
        Zone zone = drawBox(plane, row, 0, box3, dimX, " operations ", g_theme.frame);
        if (zone.valid) {
            std::vector<std::pair<double, std::string>> types;
            for (const auto& [type, count] : metrics.monitor.opsByType) {
                const auto rate = metrics.monitor.opsRateByType.find(type);
                types.emplace_back(rate == metrics.monitor.opsRateByType.end() ? 0.0
                                                                              : rate->second,
                                   type);
            }
            std::sort(types.begin(), types.end(),
                      [](const auto& a, const auto& b) { return a.first > b.first; });
            int line = zone.top;
            std::string text;
            for (const auto& [rate, type] : types) {
                const auto count = metrics.monitor.opsByType.find(type);
                char cell[64];
                std::snprintf(cell, sizeof(cell), "%-8s %10llu %7.1f/s   ", type.c_str(),
                              static_cast<unsigned long long>(
                                  count == metrics.monitor.opsByType.end() ? 0 : count->second),
                              rate);
                if (text::width(text + cell) > zone.width && !text.empty()) {
                    put(plane, line++, zone.left, text::fit(text, static_cast<std::size_t>(zone.width)),
                        g_theme.text);
                    text.clear();
                    if (line >= zone.top + zone.height) {
                        break;
                    }
                }
                text += cell;
            }
            if (!text.empty() && line < zone.top + zone.height) {
                put(plane, line, zone.left, text::fit(text, static_cast<std::size_t>(zone.width)),
                    g_theme.text);
            }
        }
    }
#else
    (void)tracker;
    put(plane, 3, 2, "built without LDAP support", g_theme.dim);
#endif
    put(plane, dimY - 1, 1,
        text::fit("tab next screen   sid owner from cn=config   esc back",
                  static_cast<std::size_t>(dimX - 2)),
        g_theme.dim);
}

/// Keyboard reference, toggled with '?'.
void drawHelp(ncplane* plane, int dimY, int dimX) {
    ncplane_erase(plane);
    static const char* const lines[] = {
        "slaptop - keys",
        "",
        "  tab         next screen (shift+tab: previous screen)",
        "  enter       connections: toggle the live log panel",
        "  esc         back (closes logs, then quits)",
        "  l           toggle the log panel",
        "  s / f       connections: cycle sort key / hide entries without bind",
        "  g           graphs: automatic scale / relative to the machine",
        "  1..9        jump to an instance",
        "  arrows/j/k  move the selection",
        "  p           pause the display (collection keeps running)",
        "  + / -       collection interval",
        "  ?           this help",
        "  q           quit",
        "",
        "  Graphs: cpu (green→amber→red), memory (blue→violet), activity",
        "  (green→gold) share one time axis, so a load spike, a memory jump",
        "  and an operation burst line up vertically.",
        "",
        "  Behaviour tab: cost by account, filter families, and the resource",
        "  hog verdict (any family above 20 % of the window's etime) over",
        "  a 60 s window built from the access log as it is written.",
        "",
        "  Configuration: ~/.config/slaptop/config (docs/slaptop.conf.example)",
    };
    const int count = static_cast<int>(sizeof(lines) / sizeof(lines[0]));
    int row = 0;
    for (int i = 0; i < count && row < dimY; ++i, ++row) {
        put(plane, row, 2, text::fit(lines[i], static_cast<std::size_t>(std::max(0, dimX - 4))),
            i == 0 ? g_theme.accent : (i == count - 1 ? g_theme.dim : g_theme.text), i == 0);
    }
    // Connection: what the bind uses and which ldaprc files libldap read.
    if (!g_connectionInfo.empty() && row < dimY - 2) {
        ++row;
        put(plane, row++, 2, "connection", g_theme.accent, true);
        put(plane, row++,
            2, text::fit(g_connectionInfo, static_cast<std::size_t>(std::max(0, dimX - 4))),
            g_theme.dim);
    }
    if (dimY > 0) {
        put(plane, dimY - 1, 2,
            text::fit("any key to close", static_cast<std::size_t>(std::max(0, dimX - 4))), g_theme.dim);
    }
}

int probeSupport() {
    notcurses_options options{};
    // No alternate screen: the report must stay in the scrollback after the
    // program exits, otherwise the user sees a flash and nothing else.
    options.flags = NCOPTION_SUPPRESS_BANNERS | NCOPTION_NO_ALTERNATE_SCREEN;
    options.margin_t = 0;
    options.margin_b = 0;
    options.margin_l = 0;
    options.margin_r = 0;
    notcurses* nc = notcurses_core_init(&options, stdout);
    if (nc == nullptr) {
        // A bare exit code here looks like a crash to whoever ran it: name the
        // cause and the way out.
        const char* term = std::getenv("TERM");
        std::fprintf(stderr,
                     "slaptop: cannot start the dashboard (TERM=%s): this terminal is not "
                     "usable for a full-screen interface; use --once or --no-tui\n",
                     term == nullptr ? "unset" : term);
        return 2;
    }
    ncplane* plane = notcurses_stdplane(nc);
    const unsigned support = notcurses_check_pixel_support(nc);
    unsigned pxy = 0, pxx = 0, celldimy = 0, celldimx = 0, maxbmapy = 0, maxbmapx = 0;
    ncplane_pixel_geom(plane, &pxy, &pxx, &celldimy, &celldimx, &maxbmapy, &maxbmapx);
    const char* term = std::getenv("TERM");
    const char* program = std::getenv("TERM_PROGRAM");

    const char* kind = "none";
    if (support == NCPIXEL_KITTY_STATIC) {
        kind = "kitty (static)";
    } else if (support == NCPIXEL_KITTY_ANIMATED) {
        kind = "kitty (animated)";
    } else if (support == NCPIXEL_SIXEL) {
        kind = "sixel";
    }

    char line[256];
    std::snprintf(line, sizeof(line), "TERM=%s  TERM_PROGRAM=%s", term ? term : "(unset)",
                  program ? program : "(unset)");
    ncplane_putstr_yx(plane, 0, 1, line);
    std::snprintf(line, sizeof(line), "pixel support: %u  ->  %s", support, kind);
    ncplane_putstr_yx(plane, 1, 1, line);
    std::snprintf(line, sizeof(line),
                  "geometry: screen %ux%u px  cell %ux%u px  max bitmap %ux%u", pxy, pxx,
                  celldimx, celldimy, maxbmapx, maxbmapy);
    ncplane_putstr_yx(plane, 2, 1, line);
    ncplane_putstr_yx(plane, 3, 1, "no image is drawn: this probe only reports");

    // Draw a real rectangle whenever the terminal claims support: a report
    // saying "kitty (static)" while nothing appears is exactly the ambiguity
    // this probe exists to remove.
    if (support != 0) {
        const unsigned w = 64;
        const unsigned h = 32;
        std::vector<std::uint32_t> pixels(static_cast<std::size_t>(w) * h, 0xffcc3322u);
        if (ncvisual* visual = ncvisual_from_bgra(pixels.data(), static_cast<int>(h),
                                                  static_cast<int>(w * 4),
                                                  static_cast<int>(w))) {
            ncplane_options probePlane{};
            probePlane.y = 5;
            probePlane.x = 1;
            probePlane.rows = 8;
            probePlane.cols = 16;
            ncplane* target = ncplane_create(plane, &probePlane);
            ncvisual_options opts{};
            opts.n = target != nullptr ? target : plane;
            opts.scaling = NCSCALE_NONE;
            opts.y = 5;
            opts.x = 1;
            opts.blitter = NCBLIT_PIXEL;
            opts.flags = NCVISUAL_OPTION_NODEGRADE;
            ncvisual_blit(nc, visual, &opts);
            ncvisual_destroy(visual);
            ncplane_putstr_yx(plane, 7, 12, "solid red square above = kitty works");
        }
    }

    notcurses_render(nc);
    struct timespec pause{3, 0};
    nanosleep(&pause, nullptr);
    notcurses_stop(nc);

    // Print again on the normal screen: this is what survives in the
    // scrollback, and it is what a script can parse.
    std::printf("\nTERM=%s  TERM_PROGRAM=%s\n", term ? term : "(unset)",
                program ? program : "(unset)");
    std::printf("pixel support: %u  ->  %s\n", support, kind);
    std::printf("%s\n", support != 0 ? "pixel rendering available"
                                      : "no pixel protocol detected: block runes stay in use");
    std::printf("report written to /tmp/slaptop-probe.txt\n");
    std::fflush(stdout);

    // Keep a copy on disk: terminal replies and escape sequences cannot be
    // copied out of a terminal reliably.
    if (std::FILE* log = std::fopen("/tmp/slaptop-probe.txt", "w")) {
        std::fprintf(log, "geometry=%ux%u px cell=%ux%u px maxbitmap=%ux%u\n", pxy, pxx,
                     celldimx, celldimy, maxbmapx, maxbmapy);
        std::fprintf(log, "TERM=%s\n", term ? term : "(unset)");
        std::fprintf(log, "TERM_PROGRAM=%s\n", program ? program : "(unset)");
        std::fprintf(log, "COLORTERM=%s\n",
                     std::getenv("COLORTERM") ? std::getenv("COLORTERM") : "(unset)");
        std::fprintf(log, "TMUX=%s\n", std::getenv("TMUX") ? "set" : "(unset)");
        std::fprintf(log, "SSH_TTY=%s\n", std::getenv("SSH_TTY") ? "set" : "(unset)");
        std::fprintf(log, "pixel_support=%u\n", support);
        std::fprintf(log, "protocol=%s\n", kind);
        std::fprintf(log, "notcurses=%s\n", notcurses_version());
        std::fclose(log);
    }
    return support != 0 ? 0 : 1;
}

}  // namespace

void setConnectionInfo(const std::string& summary) {
    g_connectionInfo = summary;
}

// ---------------------------------------------------------------------------
// Dashboard
// ---------------------------------------------------------------------------

int runDashboard(MonitorEngine& engine, const Theme& theme) {
    g_theme = theme;

    // notcurses 3.0 exposes `notcurses_options` (renamed `ncopts` in later
    // releases), with -1 margins meaning "let the library decide".  Zero
    // margins give the dashboard every column.
    notcurses_options options{};
    options.flags = NCOPTION_SUPPRESS_BANNERS;
    options.margin_t = 0;
    options.margin_b = 0;
    options.margin_l = 0;
    options.margin_r = 0;

    // Core init, not the "full" init: the dashboard uses no multimedia codec,
    // and this keeps the binary linkable against libnotcurses-core only (no
    // ffmpeg/OIIO), which makes a static single-file build possible.
    notcurses* nc = notcurses_core_init(&options, stdout);
    if (nc == nullptr) {
        // A bare exit code here looks like a crash to whoever ran it: name the
        // cause and the way out.
        const char* term = std::getenv("TERM");
        std::fprintf(stderr,
                     "slaptop: cannot start the dashboard (TERM=%s): this terminal is not "
                     "usable for a full-screen interface; use --once or --no-tui\n",
                     term == nullptr ? "unset" : term);
        return 2;
    }

    ncplane* stdplane = notcurses_stdplane(nc);
    g_nc = nc;
    // auto -> use what the terminal advertises, off -> runes, on -> same as
    // auto (the detection is the truth; forcing a protocol the terminal never
    // announced draws nothing at all).
    g_pixelSupport = notcurses_check_pixel_support(nc);
    if (g_theme.pixelGraphs == "off") {
        g_pixelSupport = 0;
    }
    // Screens behave like tabs: Tab cycles, Esc goes back to the dashboard.
    Screen screen = Screen::Dashboard;
    bool running = true;
    bool paused = false;
    bool showHelp = false;
    bool showPixelInfo = false;  ///< F12 panel, closed by F12 or Esc (not by q)
    int selected = 0;
    int connectionSelected = 0;
    bool connectionDetail = false;
    ConnSort connectionSort = ConnSort::Newest;
    ReplicationTracker replicationTracker;
    PcacheTracker pcacheTracker;
    /// Graph scale: automatic (fits the data) or relative to what the machine
    /// can give (100 % of its cores, its whole RAM).  Toggled with 'g'.
    bool relativeGraphs = false;
    int monitorScroll = 0;
    bool hideUnknownBinds = false;
    double interval = engine.collectInterval();
    std::uint64_t frame = 0;
    FleetSnapshot lastFleet;
    std::size_t indexSelection = 0;  ///< which database the Indexes screen details
    // Nothing has been collected yet: say so while the connections open.
    const auto startedAt = std::chrono::steady_clock::now();

    // Log display buffer: lines are kept on screen for a TTL, then faded, so a
    // busy log stays readable instead of scrolling at collector speed.
    std::deque<ShownLine> shownLog;
    std::uint64_t lastLogSequence = 0;
    std::string shownLogOwner;
    const auto updateLogBuffer = [&](const InstanceMetrics& metrics) {
        const std::string owner =
            std::to_string(metrics.instance.pid) + ":" + metrics.instance.name;
        if (owner != shownLogOwner) {
            // New instance selected: seed with its most recent lines instead
            // of waiting for the next one to be logged.
            shownLog.clear();
            shownLogOwner = owner;
            // Seed with everything the collector kept: the panel must be full
            // the moment it opens, not fill line by line from the bottom.
            for (const LogEntry& entry : metrics.log.recent) {
                shownLog.push_back(ShownLine{entry});
            }
            lastLogSequence = metrics.log.recent.empty() ? 0 : metrics.log.recent.back().sequence;
            return;
        }
        for (const LogEntry& entry : metrics.log.recent) {
            if (entry.sequence > lastLogSequence) {
                shownLog.push_back(ShownLine{entry});
                lastLogSequence = entry.sequence;
            }
        }
        // Lines are never expired by age: the panel must always be full, so a
        // quiet server keeps showing its last activity instead of emptying
        // itself. Only the oldest lines *on screen* fade, which marks the
        // boundary without hiding anything.
        // A burst must not grow the buffer without bound.
        while (shownLog.size() > 400) {
            shownLog.pop_front();
        }
    };

    // Leave the terminal usable on Ctrl-C / kill.
    std::signal(SIGINT, onInterrupt);
    std::signal(SIGTERM, onInterrupt);

    while (running && !g_interrupted.load()) {
        ncinput input{};
        while (notcurses_get_nblock(nc, &input) != 0) {
            // Terminals speaking the kitty keyboard protocol report a press and
            // a release for one keystroke; acting on both made Tab jump two
            // screens at a time.
            if (input.evtype == NCTYPE_RELEASE) {
                continue;
            }
            switch (input.id) {
                case 'q':
                case 'Q':
                    if (showPixelInfo) {
                        break;  // F12 or Esc closes the panel, q does not
                    }
                    running = false;
                    break;
                case NCKEY_ESC:
                    // Esc never quits: it closes what is open, the panel first.
                    if (showPixelInfo) {
                        showPixelInfo = false;
                    } else if (showHelp) {
                        showHelp = false;
                    } else if (screen != Screen::Dashboard) {
                        screen = Screen::Dashboard;
                    } else {
                        running = false;
                    }
                    break;
                case NCKEY_F12:
                    showPixelInfo = !showPixelInfo;
                    break;
                case 'p':
                case 'P':
                    if (showPixelInfo) {
                        break;  // the panel is modal: keys below do not act
                    }
                    paused = !paused;
                    break;
                case 'g':
                case 'G':
                    relativeGraphs = !relativeGraphs;
                    break;
                case NCKEY_TAB: {
                    // Tab cycles through the screens actually offered (the
                    // replication tab appears only when the fleet has one);
                    // Shift+Tab walks back. Terminals send CSI Z for backtab,
                    // which notcurses reports as a TAB with shift set - there
                    // is no NCKEY_BACKTAB in 3.0.
                    showHelp = false;
                    const std::vector<Screen> screens = screenList(lastFleet);
                    const std::size_t count = screens.size();
                    std::size_t index = 0;
                    for (std::size_t i = 0; i < count; ++i) {
                        if (screens[i] == screen) {
                            index = i;
                            break;
                        }
                    }
                    screen = input.shift ? screens[(index + count - 1) % count]
                                         : screens[(index + 1) % count];
                    break;
                }
                case NCKEY_ENTER:
                    if (screen == Screen::Connections) {
                        connectionDetail = !connectionDetail;  // live log of the selected one
                    }
                    break;

                case 's':
                case 'S':
                    if (screen == Screen::Connections) {
                        switch (connectionSort) {
                            case ConnSort::Newest:
                                connectionSort = ConnSort::Busiest;
                                break;
                            case ConnSort::Busiest:
                                connectionSort = ConnSort::IO;
                                break;
                            case ConnSort::IO:
                                connectionSort = ConnSort::Bind;
                                break;
                            case ConnSort::Bind:
                            default:
                                connectionSort = ConnSort::Newest;
                                break;
                        }
                    }
                    break;
                case 'f':
                case 'F':
                    if (screen == Screen::Connections) {
                        hideUnknownBinds = !hideUnknownBinds;
                        connectionSelected = 0;
                    }
                    break;
                case 'd':
                case 'D':
                    if (screen == Screen::Indexes) {
                        ++indexSelection;
                    }
                    break;
                case 't':
                case 'T':
                    screen = screen == Screen::Architecture ? Screen::Dashboard
                                                            : Screen::Architecture;
                    showHelp = false;
                    break;
                case '?':
                    showHelp = !showHelp;
                    break;
                case '1': case '2': case '3': case '4': case '5':
                case '6': case '7': case '8': case '9':
                    if (static_cast<int>(input.id - '1') <
                        static_cast<int>(lastFleet.instances.size())) {
                        selected = static_cast<int>(input.id - '1');
                        showHelp = false;
                    }
                    break;
                case NCKEY_UP:
                case 'k':
                    if (screen == Screen::Indexes) {
                        // Same gesture as every other list: up/down walks the
                        // databases, and the table follows.
                        if (indexSelection > 0) {
                            --indexSelection;
                        }
                        break;
                    }
                    if (screen == Screen::Connections) {
                        if (connectionSelected > 0) {
                            --connectionSelected;
                        }
                        break;
                    }
                    if (screen == Screen::Monitor) {
                        if (monitorScroll > 0) {
                            --monitorScroll;
                        }
                        break;
                    }
                    if (selected > 0) {
                        --selected;
                    }
                    break;
                case NCKEY_DOWN:
                case 'j':
                    if (screen == Screen::Indexes) {
                        ++indexSelection;
                        break;
                    }
                    if (screen == Screen::Connections) {
                        ++connectionSelected;
                        break;
                    }
                    if (screen == Screen::Monitor) {
                        ++monitorScroll;
                        break;
                    }
                    ++selected;
                    break;
                case NCKEY_LEFT:
                    // One instance back: on the Monitor screen this is the
                    // only way to read another server's cn=monitor tree.
                    if (selected > 0) {
                        --selected;
                        monitorScroll = 0;
                    }
                    break;
                case NCKEY_RIGHT:
                    if (static_cast<std::size_t>(selected + 1) < lastFleet.instances.size()) {
                        ++selected;
                        monitorScroll = 0;
                    }
                    break;
                case NCKEY_PGUP:
                    selected = 0;
                    monitorScroll = 0;
                    break;
                case NCKEY_PGDOWN:
                    selected = 1 << 20;
                    monitorScroll = 0;
                    break;
                case '+':
                case '=':
                    interval = std::min(10.0, interval + 0.25);
                    engine.setCollectInterval(interval);
                    break;
                case '-':
                    interval = std::max(0.25, interval - 0.25);
                    engine.setCollectInterval(interval);
                    break;
                case NCKEY_RESIZE:
                    break;
                default:
                    break;
            }
            if (!running) {
                break;
            }
        }
        if (!running) {
            break;
        }

        // Pause freezes what is displayed; the engine keeps collecting so the
        // graphs resume with real history instead of a gap.
        if (!paused) {
            FleetSnapshot fresh = engine.snapshot();
            if (!fresh.busy) {
                lastFleet = std::move(fresh);
            }
            g_refreshing = fresh.busy || engine.busyCount() > 0;
        } else {
            g_refreshing = false;
        }
        const FleetSnapshot& fleet = lastFleet;
        const double pulse = g_theme.animate
                                 ? 0.5 + 0.5 * std::sin(static_cast<double>(frame) * 0.35)
                                 : 0.0;

        unsigned termY = 0;
        unsigned termX = 0;
        ncplane_dim_yx(stdplane, &termY, &termX);
        const int dimY = static_cast<int>(termY);
        const int dimX = static_cast<int>(termX);
        // The pixel planes of the previous frame go now: the render that
        // displayed them is done.
        for (ncplane* pixel : g_pixelPlanes) {
            ncplane_destroy(pixel);
        }
        g_pixelPlanes.clear();
        ncplane_erase(stdplane);

        if (dimY < 5 || dimX < 24) {
            put(stdplane, 0, 0, text::fit("terminal too small: need 24x5", static_cast<std::size_t>(dimX)),
                g_theme.error);
            notcurses_render(nc);
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }

        if (showPixelInfo) {
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            drawPixelInfo(stdplane, dimY, dimX, g_theme);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }

        if (showHelp) {
            drawHelp(stdplane, dimY, dimX);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }

        // Until one instance has answered, there is nothing to draw on any
        // screen: show the startup panel instead of an empty dashboard.  A run
        // without any slapd falls through after a few seconds, so the "no
        // instance found" message is not hidden behind this panel.
        {
            // "The display can be shown" means every configured target has
            // answered both sources: /proc alone sets health=Running, so that
            // alone hid this panel while the cards still had no counters.
            const double elapsed =
                std::chrono::duration<double>(std::chrono::steady_clock::now() - startedAt)
                    .count();
            const std::vector<MonitorEngine::ConfiguredTarget> targets =
                engine.configuredTargetsInfo();
            const StartupState startup = buildStartupState(fleet, targets, elapsed);
            // A run with no slapd at all falls through after four seconds; a
            // remote fleet gets twenty before the panel shows what it has.
            const bool nothingConfigured = targets.empty() && fleet.instances.empty();
            const bool waiting =
                !startup.allSettled && (nothingConfigured ? elapsed < 4.0 : elapsed < 20.0);
            if (waiting) {
                drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
                drawStartup(stdplane, dimY, dimX, startup, targets.size(), elapsed,
                            g_theme.animate, frame);
                put(stdplane, dimY - 1, 1,
                    text::fit("q quit   ? keys", static_cast<std::size_t>(dimX - 2)),
                    g_theme.dim);
                notcurses_render(nc);
                ++frame;
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
                continue;
            }
        }

        const int instanceCount = static_cast<int>(fleet.instances.size());
        if (selected >= instanceCount) {
            selected = std::max(0, instanceCount - 1);
        }
        if (instanceCount > 0) {
            updateLogBuffer(fleet.instances[static_cast<std::size_t>(selected)]);
            // pcache counters are per query UUID: keep them between frames so
            // a query that expires does not take its hits with it.
            trackPcache(pcacheTracker, fleet.instances[static_cast<std::size_t>(selected)]);
        }
        // One table per frame, shared by the cursor clamp and the drawing:
        // pairing clients with upstream connections changes the row count, so
        // both must agree or the cursor runs past the last row.
        ConnectionTable connectionTable;
        if (screen == Screen::Connections && instanceCount > 0) {
            connectionTable = buildConnectionTable(
                fleet.instances[static_cast<std::size_t>(selected)], connectionSort,
                hideUnknownBinds);
            const int count = static_cast<int>(connectionTable.rows.size());
            if (connectionSelected >= count) {
                connectionSelected = std::max(0, count - 1);
            }
        }
        if (screen == Screen::Logs && instanceCount > 0) {
            // Full-screen tail of the selected instance.
            const InstanceMetrics& metrics = fleet.instances[static_cast<std::size_t>(selected)];
            char info[192];
            const bool stopped = metrics.health == Health::Stopped;
            std::snprintf(info, sizeof(info), "%s   %llu lines   %llu errors%s",
                          metrics.instance.name.c_str(),
                          static_cast<unsigned long long>(metrics.log.linesRead),
                          static_cast<unsigned long long>(metrics.log.errors),
                          stopped ? "   stopped: showing the last lines captured" : "");
            put(stdplane, 2, 1, text::fit(info, static_cast<std::size_t>(dimX - 2)),
                stopped ? g_theme.error : g_theme.dim);
            drawBox(stdplane, 3, 0, dimY - 4, dimX,
                    metrics.health == Health::Stopped ? " tail (instance stopped) " : " tail ",
                    g_theme.frame);
            if (metrics.health == Health::Stopped) {
                // Nothing more will be written: show the capture as it is.
                std::deque<ShownLine> frozen;
                for (const LogEntry& entry : metrics.log.recent) {
                    frozen.push_back(ShownLine{entry});
                }
                drawLogPanel(stdplane, 3, 0, dimY - 4, dimX, metrics, frozen);
            } else {
                drawLogPanel(stdplane, 3, 0, dimY - 4, dimX, metrics, shownLog);
            }
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Io && instanceCount > 0) {
            drawIo(stdplane, dimY, dimX,
                   fleet.instances[static_cast<std::size_t>(selected)],
                   selected < static_cast<int>(fleet.history.size())
                       ? fleet.history[static_cast<std::size_t>(selected)]
                       : InstanceHistory{},
                   pulse);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Replication && instanceCount > 0) {
            drawReplication(stdplane, dimY, dimX, fleet, selected, replicationTracker);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Monitor && instanceCount > 0) {
            drawMonitorRaw(stdplane, dimY, dimX,
                           fleet.instances[static_cast<std::size_t>(selected)], monitorScroll,
                           selected, instanceCount);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Databases && instanceCount > 0) {
            drawDatabases(stdplane, dimY, dimX,
                          fleet.instances[static_cast<std::size_t>(selected)], pcacheTracker);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Connections && instanceCount > 0) {
            drawConnections(stdplane, dimY, dimX,
                            fleet.instances[static_cast<std::size_t>(selected)],
                            connectionTable, connectionSelected, connectionDetail,
                            connectionSort, hideUnknownBinds);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Indexes && instanceCount > 0) {
            drawIndexes(stdplane, dimY, dimX,
                        fleet.instances[static_cast<std::size_t>(selected)], indexSelection);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Behaviour && instanceCount > 0) {
            drawBehaviour(stdplane, dimY, dimX,
                          fleet.instances[static_cast<std::size_t>(selected)]);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }
        if (screen == Screen::Architecture) {
            drawTopology(stdplane, dimY, dimX, fleet, selected, pulse, relativeGraphs);
            drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
            notcurses_render(nc);
            ++frame;
            std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
            continue;
        }

        // Layout: the cards take the whole height. Cutting the log panel from
        // the dashboard was deliberate: under load it scrolled faster than it
        // could be read, so the dedicated Logs tab is the place to read it.
        const int footerRow = dimY - 1;
        const int cardArea = dimY - 3;

        if (!fleet.instances.empty()) {
            // Share the card area exactly: every row the screen offers goes to
            // the cards, one extra row to the first ones when it does not
            // divide evenly. No fixed cap, so a tall terminal grows the graphs
            // instead of leaving an empty band at the bottom.
            // Two columns when the terminal is wide enough: with a fleet of
            // several SSH nodes, one card per row leaves each of them too short
            // for its graphs and the dashboard falls back to compact lines.
            const int columns = (dimX >= 140 && instanceCount >= 3) ? 2 : 1;
            const int rows = (instanceCount + columns - 1) / columns;
            const int cardWidth = columns == 2 ? (dimX - 3) / 2 : dimX - 2;
            // One blank row between two rows of cards, subtracted before the
            // split: leaving it out made the last row one row too tall, so the
            // fit test below refused it and its instances were never drawn
            // (three instances showed two cards).
            std::vector<int> rowHeight(static_cast<std::size_t>(std::max(1, rows)), 0);
            {
                const int count = static_cast<int>(rowHeight.size());
                int remaining = std::max(0, cardArea - (count - 1));
                for (int line = 0; line < count; ++line) {
                    const int share = remaining / (count - line);
                    rowHeight[static_cast<std::size_t>(line)] = share;
                    remaining -= share;
                }
            }
            const int cardHeight = rowHeight.front();
            std::vector<int> rowTop(rowHeight.size(), 2);
            for (std::size_t line = 1; line < rowHeight.size(); ++line) {
                rowTop[line] = rowTop[line - 1] + rowHeight[line - 1] + 1;
            }

            if (cardHeight <= kCardCompact) {
                // Too little room for graphs: one line per instance.
                int row = 2;
                for (int index = 0; index < instanceCount && row < 2 + cardArea; ++index) {
                    drawCompactRow(stdplane, row++, 1, dimX - 2,
                                   fleet.instances[static_cast<std::size_t>(index)],
                                   index < static_cast<int>(fleet.history.size())
                                       ? fleet.history[static_cast<std::size_t>(index)]
                                       : InstanceHistory{},
                                   pulse);
                }
            } else {
                for (int index = 0; index < instanceCount; ++index) {
                    const int line = index / columns;
                    const int column = index % columns;
                    const int height = rowHeight[static_cast<std::size_t>(line)];
                    const int top = rowTop[static_cast<std::size_t>(line)];
                    const int left = columns == 2 ? 1 + column * (cardWidth + 1) : 1;
                    if (height < 3 || top + height > 2 + cardArea) {
                        break;
                    }
                    drawCard(stdplane, top, left, height, cardWidth,
                             fleet.instances[static_cast<std::size_t>(index)],
                             index < static_cast<int>(fleet.history.size())
                                 ? fleet.history[static_cast<std::size_t>(index)]
                                 : InstanceHistory{},
                             pulse, index == selected, relativeGraphs);
                }
            }
        } else {
            put(stdplane, 3, 3, "no slapd instance found", g_theme.dim);
        }

        // Screen keys in the accent colour: the architecture view stays
        // invisible to anyone who does not know `t` exists.
        int footerX = 1;
        const auto key = [&](const char* shortcut, const char* label) {
            put(stdplane, footerRow, footerX, shortcut, g_theme.accent, true);
            footerX += static_cast<int>(std::strlen(shortcut));
            put(stdplane, footerRow, footerX, " ", g_theme.dim);
            footerX += 1;
            const std::string text = std::string(label) + "   ";
            put(stdplane, footerRow, footerX,
                text::fit(text, static_cast<std::size_t>(std::max(0, dimX - footerX - 1))),
                g_theme.dim);
            footerX += static_cast<int>(text::width(text)) + 3;
        };
        key("t", "arch");
        key("g", relativeGraphs ? "scale: rel" : "scale: auto");
        key("Tab", "next");
        key("p", "pause");
        key("+/-", "int");
        key("?", "help");
        key("q", "quit");

        drawScreenTabs(stdplane, dimY, dimX, screen, fleet, selected, paused);
        notcurses_render(nc);
        ++frame;
        std::this_thread::sleep_for(std::chrono::milliseconds(1000 / std::max(1, g_theme.fps)));
    }

    // Say goodbye the way we said hello: the stop joins every worker and
    // closes one SSH master per node, and that wait is visible.
    {
        const std::vector<MonitorEngine::ConfiguredTarget> targets =
            engine.configuredTargetsInfo();
        unsigned termY = 0;
        unsigned termX = 0;
        ncplane_dim_yx(stdplane, &termY, &termX);
        const int height = static_cast<int>(termY);
        const int width = static_cast<int>(termX);
        drawScreenTabs(stdplane, height, width, screen, lastFleet, selected, paused);
        drawStopping(stdplane, height, width, targets, false, g_theme.animate, frame);
        notcurses_render(nc);
        engine.stop();
        // The pixel planes of the previous frame go now: the render that
        // displayed them is done.
        for (ncplane* pixel : g_pixelPlanes) {
            ncplane_destroy(pixel);
        }
        g_pixelPlanes.clear();
        ncplane_erase(stdplane);
        drawScreenTabs(stdplane, height, width, screen, lastFleet, selected, paused);
        drawStopping(stdplane, height, width, targets, true, g_theme.animate, frame);
        notcurses_render(nc);
        std::this_thread::sleep_for(std::chrono::milliseconds(350));
    }

    notcurses_stop(nc);
    return 0;
}

int probePixelSupport() {
    return probeSupport();
}

}  // namespace slaptop::ui
