#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace slaptop::ui::text {

/// One extended grapheme cluster (UAX #29) inside a UTF-8 string.
struct Cluster {
    std::size_t offset{0};  ///< byte offset in the source string
    std::size_t bytes{0};   ///< length in bytes
    int width{0};           ///< terminal columns (0 for combining-only clusters)
};

/// Splits a UTF-8 string into grapheme clusters.
///
/// Unicode UAX #29 matters here because a naive per-codepoint split breaks
/// "e" + combining acute, emoji ZWJ sequences and flags into pieces that the
/// terminal then renders as separate glyphs, shifting every following column.
std::vector<Cluster> split(const std::string& text);

/// Number of terminal columns occupied by the string (sum of cluster widths).
int width(const std::string& text);

/// Truncates to at most `maxWidth` columns without splitting a cluster,
/// appending an ellipsis when something was cut.
std::string fit(const std::string& text, std::size_t maxWidth);

}  // namespace slaptop::ui::text
