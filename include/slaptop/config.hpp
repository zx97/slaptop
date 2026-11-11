#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace slaptop {

/// Colours and animation settings for the dashboard.
///
/// Values are packed 0xRRGGBB so they can feed ncplane_set_fg_rgb directly.
struct Theme {
    std::uint32_t accent{0xffd060};  ///< Titles, header text
    std::uint32_t ok{0x60d080};      ///< Healthy state
    std::uint32_t warn{0xffc050};    ///< Paused, replication lag
    std::uint32_t error{0xff9070};   ///< Degraded state, log errors
    std::uint32_t text{0xd0d0e0};    ///< Values
    std::uint32_t dim{0x9090a0};     ///< Units, secondary text
    std::uint32_t frame{0x5a5a6a};   ///< Card borders
    std::uint32_t focus{0x9090d0};   ///< Selected card border
    /// Pulse the CPU/ops graphs and the activity dot.
    bool animate{true};
    /// How long a log line stays readable in the panel, and how long it fades
    /// out before disappearing.
    /// Fading is only used when the log scrolls fast (see kFastLogRate): a
    /// quiet server keeps its last lines on screen, a chatty one would turn
    /// into a blur.  Both are in seconds.
    /// Retired: the log panel never expires a line by age any more, and only
    /// the oldest lines on screen fade.  The keys stay parsed so an existing
    /// file does not start warning, but nothing reads them.
    double logTtlSeconds{3.0};
    double logFadeSeconds{0.3};
    /// Bitmap graphs when the terminal offers kitty/sixel graphics:
    /// "on" (enable when detected) or "off" (block runes, the default).
    ///
    /// Off by default: Konsole advertises kitty graphics but implements it
    /// partially, and the bitmap placement wiped the surrounding text.
    std::string pixelGraphs{"off"};
    /// Redraw rate.  The dashboard is a monitoring view, not a game: 5 FPS
    /// keeps it responsive while halving the rendering cost.
    int fps{5};
};

/// A named set of nodes and targets: one environment (dev, acc, test, prod).
///
///     [group acc]
///     node = user@ldap1.example.com name=ldap1
///     uri  = ldaps://lb-acc:636 insecure=yes
struct NodeGroup {
    std::string name;
    std::vector<std::string> nodes;
    std::vector<std::string> nodeFiles;
    std::vector<std::string> uris;
    std::vector<std::string> uriFiles;
};

/// User configuration, read from ~/.config/slaptop/config by default.
///
/// Format is a flat `key = value` file with a `[theme]` section:
///
///     interval = 1.0
///     ldap-interval = 2.0
///     uri-file = ~/ldap-servers.txt
///     insecure = false
///     bind = EXTERNAL
///
///     [theme]
///     accent = #ffd060
///     animate = true
///
/// Command-line options always win over the file.
struct Config {
    // --- collection -------------------------------------------------------
    double interval{1.0};
    double ldapInterval{2.0};

    // --- targets ----------------------------------------------------------
    /// One LDAP URI per line (`--uri-file`), repeatable.
    std::vector<std::string> uriFiles;
    /// Inline remote targets (`--uri`), repeatable.
    std::vector<std::string> uris;
    /// One SSH node per line (`--node-file`), repeatable.
    std::vector<std::string> nodeFiles;
    /// Inline SSH nodes (`--node`), repeatable, four at most.
    std::vector<std::string> nodes;

    // --- credentials ------------------------------------------------------
    bool insecure{false};
    std::string bindDn;
    /// File holding the bind password (first line, trailing newline stripped).
    /// A command-line password would show up in `ps`, so a file or the
    /// SLAPTOP_BIND_PW environment variable are the only two sources.
    std::string passwordFile;

    // --- run mode ---------------------------------------------------------
    /// Same meaning as the flags of the same name; the command line wins.
    bool once{false};
    double watchSeconds{0.0};
    double duration{0.0};
    bool json{false};
    bool jsonl{false};
    bool forceTui{false};
    bool forceText{false};

    // --- environments ------------------------------------------------------
    /// `[group <name>]` sections, in file order.
    std::vector<NodeGroup> groups;
    /// `group = <name>` at the top level: the group used when the command line
    /// does not say otherwise.
    std::string defaultGroup;

    Theme theme;

    /// A key written in a section that cannot hold it: `group = lab` inside
    /// [theme], `animate = false` inside [group dev].  The value is dropped,
    /// so running anyway would monitor a different environment than the file
    /// says: the caller must refuse to start and print these.
    std::vector<std::string> errors;

    /// Reads `path`; a missing file is not an error (defaults are returned).
    /// Unknown keys and malformed lines are appended to `warnings` and the
    /// offending line is skipped: a typo must not keep the dashboard from
    /// starting.  Mistakes that change *which* environment is watched go to
    /// `errors` instead.
    static Config load(const std::string& path, std::vector<std::string>* warnings = nullptr);

    /// $XDG_CONFIG_HOME/slaptop/config, or ~/.config/slaptop/config.
    static std::string defaultPath();
};

/// Parses "#rrggbb" or "rrggbb" into 0xRRGGBB.  Returns `fallback` when the
/// text is not a valid colour.
std::uint32_t parseColor(const std::string& text, std::uint32_t fallback);

}  // namespace slaptop
