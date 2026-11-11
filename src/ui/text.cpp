#include "slaptop/ui/text.hpp"

#include <unigbrk.h>
#include <unistr.h>
#include <uniwidth.h>

#include <cstdint>

namespace slaptop::ui::text {
namespace {

/// Code point ranges rendered in two columns.
///
/// RHEL 9 ships libunistring 0.9.10 (Unicode 6.1), which predates emoji: its
/// uc_width() reports 1 for every pictograph.  The terminal still draws them
/// two columns wide, so the measurement is corrected here.  Ranges follow the
/// East Asian Wide/Fullwidth plus Emoji_Presentation properties.
bool isWideCodePoint(ucs4_t cp) {
    static constexpr ucs4_t ranges[][2] = {
        {0x1100, 0x115F},   {0x2E80, 0x303E},   {0x3041, 0x33FF},   {0x3400, 0x4DBF},
        {0x4E00, 0x9FFF},   {0xA000, 0xA4CF},   {0xA960, 0xA97F},   {0xAC00, 0xD7A3},
        {0xF900, 0xFAFF},   {0xFE10, 0xFE19},   {0xFE30, 0xFE6F},   {0xFF00, 0xFF60},
        {0xFFE0, 0xFFE6},   {0x1B000, 0x1B2FF}, {0x1F000, 0x1F02F}, {0x1F0A0, 0x1F0FF},
        {0x1F100, 0x1F1FF}, {0x1F200, 0x1F2FF}, {0x1F300, 0x1F64F}, {0x1F680, 0x1F6FF},
        {0x1F900, 0x1F9FF}, {0x1FA70, 0x1FAFF}, {0x20000, 0x3FFFD},
    };
    for (const auto& range : ranges) {
        if (cp >= range[0] && cp <= range[1]) {
            return true;
        }
    }
    return false;
}

/// Width of a cluster: the first code point carries the visible width, the
/// combining marks inside the same cluster add nothing.
int clusterWidth(ucs4_t first) {
    const int measured = uc_width(first, "UTF-8");
    if (measured >= 2) {
        return measured;
    }
    if (isWideCodePoint(first)) {
        return 2;
    }
    // uc_width returns -1 for non-printable code points; the terminal still
    // consumes a cell for them, as notcurses does.
    return measured < 0 ? 1 : measured;
}

}  // namespace

std::vector<Cluster> split(const std::string& text) {
    std::vector<Cluster> clusters;
    if (text.empty()) {
        return clusters;
    }

    std::vector<ucs4_t> codepoints;
    std::vector<std::size_t> offsets;
    codepoints.reserve(text.size());
    offsets.reserve(text.size());

    std::size_t position = 0;
    while (position < text.size()) {
        ucs4_t codepoint = 0;
        const int length = u8_mbtouc(
            &codepoint, reinterpret_cast<const uint8_t*>(text.data()) + position,
            text.size() - position);
        if (length < 1) {
            break;  // invalid UTF-8: stop rather than emit garbage
        }
        offsets.push_back(position);
        codepoints.push_back(codepoint);
        position += static_cast<std::size_t>(length);
    }
    if (codepoints.empty()) {
        return clusters;
    }

    // breaks[i] != 0 means a cluster boundary sits before codepoint i.
    std::vector<char> breaks(codepoints.size(), 0);
    uc_grapheme_breaks(codepoints.data(), codepoints.size(), breaks.data());

    std::size_t start = 0;
    for (std::size_t i = 1; i <= codepoints.size(); ++i) {
        if (i != codepoints.size() && breaks[i] == 0) {
            continue;
        }
        Cluster cluster;
        cluster.offset = offsets[start];
        const std::size_t end = (i == codepoints.size()) ? text.size() : offsets[i];
        cluster.bytes = end - cluster.offset;
        cluster.width = clusterWidth(codepoints[start]);
        clusters.push_back(cluster);
        start = i;
    }
    return clusters;
}

int width(const std::string& text) {
    int total = 0;
    for (const Cluster& cluster : split(text)) {
        total += cluster.width;
    }
    return total;
}

std::string fit(const std::string& text, std::size_t maxWidth) {
    if (maxWidth == 0) {
        return {};
    }
    const std::vector<Cluster> clusters = split(text);
    int total = 0;
    for (const Cluster& cluster : clusters) {
        total += cluster.width;
    }
    if (total <= static_cast<int>(maxWidth)) {
        return text;
    }

    // Reserve one column for the ellipsis, which is one cell wide.
    const int budget = static_cast<int>(maxWidth) - 1;
    std::string out;
    int used = 0;
    for (const Cluster& cluster : clusters) {
        if (used + cluster.width > budget) {
            break;
        }
        out.append(text, cluster.offset, cluster.bytes);
        used += cluster.width;
    }
    out += "\xE2\x80\xA6";  // …
    return out;
}

}  // namespace slaptop::ui::text
