#include <iostream>
#include <string>

#include "slaptop/ui/text.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

/// "e" followed by U+0301 COMBINING ACUTE ACCENT: one grapheme, one column.
constexpr const char* kAccentedE = "e\xCC\x81";
/// Family emoji: four people joined by ZWJ, one grapheme, two columns.
constexpr const char* kFamily = "\xF0\x9F\x91\xA8\xE2\x80\x8D\xF0\x9F\x91\xA9\xE2\x80\x8D"
                                "\xF0\x9F\x91\xA7\xE2\x80\x8D\xF0\x9F\x91\xA6";

void testPlainAscii() {
    CHECK(slaptop::ui::text::width("") == 0);
    CHECK(slaptop::ui::text::width("abc") == 3);
    CHECK(slaptop::ui::text::split("abc").size() == 3);
    CHECK(slaptop::ui::text::fit("abcdef", 10) == "abcdef");
}

void testCombiningMarks() {
    // UAX #29: base + combining mark is a single cluster of width 1.
    CHECK(slaptop::ui::text::split(kAccentedE).size() == 1);
    CHECK(slaptop::ui::text::width(kAccentedE) == 1);
    // Three separate "é" (two columns total budget + ellipsis).
    const std::string three = std::string(kAccentedE) + kAccentedE + kAccentedE;
    CHECK(slaptop::ui::text::width(three) == 3);
    const std::string cut = slaptop::ui::text::fit(three, 2);
    CHECK(cut.size() < three.size());
    // The cut must land on a cluster boundary: never in the middle of "e" + U+0301.
    CHECK(cut == std::string(kAccentedE) + "\xE2\x80\xA6");
}

void testWideCharacters() {
    // An emoji occupies two columns (the table corrects old libunistring
    // versions whose uc_width still reports 1); the family sequence stays one
    // cluster.
    CHECK(slaptop::ui::text::width("\xF0\x9F\x98\x80") == 2);
    CHECK(slaptop::ui::text::split(kFamily).size() == 1);
    CHECK(slaptop::ui::text::width(kFamily) == 2);
    // Truncating to one column cannot fit it, so only the ellipsis remains.
    CHECK(slaptop::ui::text::fit(kFamily, 1) == "\xE2\x80\xA6");
}

void testTruncationEdges() {
    CHECK(slaptop::ui::text::fit("abc", 0).empty());
    CHECK(slaptop::ui::text::fit("abc", 1) == "\xE2\x80\xA6");
    CHECK(slaptop::ui::text::fit("abc", 3) == "abc");
    CHECK(slaptop::ui::text::fit("abbc", 3) == "ab\xE2\x80\xA6");
    // Invalid UTF-8 must not crash or loop forever.
    const std::string invalid = "a\xFF\xFE" "b";
    CHECK(slaptop::ui::text::width(invalid) >= 1);
    (void)slaptop::ui::text::fit(invalid, 3);
}

}  // namespace

int main() {
    testPlainAscii();
    testCombiningMarks();
    testWideCharacters();
    testTruncationEdges();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "text checks passed\n";
    return 0;
}
