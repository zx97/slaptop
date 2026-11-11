#include "slaptop/config.hpp"

#include <algorithm>
#include <cstdlib>
#include <fstream>
#include <sstream>

namespace slaptop {
namespace {

std::string trim(const std::string& text) {
    const std::size_t start = text.find_first_not_of(" \t\r\n");
    if (start == std::string::npos) {
        return {};
    }
    const std::size_t end = text.find_last_not_of(" \t\r\n");
    return text.substr(start, end - start + 1);
}

std::string lower(std::string text) {
    for (char& c : text) {
        if (c >= 'A' && c <= 'Z') {
            c = static_cast<char>(c - 'A' + 'a');
        }
    }
    return text;
}

bool toBool(const std::string& value) {
    const std::string v = lower(value);
    return v == "1" || v == "true" || v == "yes" || v == "on";
}

double toDouble(const std::string& value, double fallback) {
    try {
        return std::stod(value);
    } catch (...) {
        return fallback;
    }
}

/// Expands a leading ~ using $HOME.
std::string expandHome(const std::string& path) {
    if (path.empty() || path.front() != '~') {
        return path;
    }
    const char* home = std::getenv("HOME");
    if (home == nullptr) {
        return path;
    }
    return std::string(home) + path.substr(1);
}

/// Keys that only make sense at the top level, outside any section.  They are
/// listed so a misplaced one is reported as such instead of as an "unknown
/// theme key", which is what hid a `group = lab` written inside [theme].
bool isTopLevelKey(const std::string& key) {
    static const char* const kKeys[] = {
        "interval", "ldap-interval", "uri",       "uri-file", "node",
        "node-file", "group",        "once",      "watch",    "duration",
        "json",      "jsonl",        "tui",       "no-tui",   "insecure",
        "bind",      "password-file",
    };
    for (const char* candidate : kKeys) {
        if (key == candidate) {
            return true;
        }
    }
    return false;
}

/// Keys of the [theme] section.
bool isThemeKey(const std::string& key) {
    static const char* const kKeys[] = {
        "accent", "ok",          "warn",   "error",   "text",
        "dim",    "frame",       "focus",  "animate", "log-ttl",
        "log-fade", "pixel-graphs", "fps",
    };
    for (const char* candidate : kKeys) {
        if (key == candidate) {
            return true;
        }
    }
    return false;
}

}  // namespace

std::uint32_t parseColor(const std::string& text, std::uint32_t fallback) {
    std::string value = trim(text);
    if (!value.empty() && value.front() == '#') {
        value.erase(0, 1);
    }
    if (value.size() != 6) {
        return fallback;
    }
    std::uint32_t result = 0;
    for (const char c : value) {
        std::uint32_t digit = 0;
        if (c >= '0' && c <= '9') {
            digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else if (c >= 'A' && c <= 'F') {
            digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else {
            return fallback;
        }
        result = (result << 4U) | digit;
    }
    return result;
}

std::string Config::defaultPath() {
    if (const char* xdg = std::getenv("XDG_CONFIG_HOME"); xdg != nullptr && *xdg != '\0') {
        return std::string(xdg) + "/slaptop/config";
    }
    if (const char* home = std::getenv("HOME"); home != nullptr) {
        return std::string(home) + "/.config/slaptop/config";
    }
    return "slaptop.conf";
}

Config Config::load(const std::string& path, std::vector<std::string>* warnings) {
    Config config;
    std::ifstream in(path);
    if (!in) {
        return config;  // absent file: defaults, silently
    }

    const auto warn = [warnings, &path](const std::string& message) {
        if (warnings != nullptr) {
            warnings->push_back(path + ": " + message);
        }
    };
    const auto fail = [&path](Config& target, const std::string& message) {
        target.errors.push_back(path + ": " + message);
    };

    bool inTheme = false;
    int themeLine = 0;
    NodeGroup* group = nullptr;
    std::string line;
    int lineNumber = 0;
    while (std::getline(in, line)) {
        ++lineNumber;
        const std::string trimmed = trim(line);
        if (trimmed.empty() || trimmed.front() == '#' || trimmed.front() == ';') {
            continue;
        }
        if (trimmed.front() == '[' && trimmed.back() == ']') {
            const std::string section = trim(trimmed.substr(1, trimmed.size() - 2));
            const std::string lowered = lower(section);
            inTheme = lowered == "theme";
            themeLine = inTheme ? lineNumber : 0;
            group = nullptr;
            if (lowered.rfind("group ", 0) == 0) {
                NodeGroup fresh;
                fresh.name = trim(section.substr(6));
                if (!fresh.name.empty()) {
                    config.groups.push_back(std::move(fresh));
                    group = &config.groups.back();
                }
            }
            continue;
        }
        const std::size_t equals = trimmed.find('=');
        if (equals == std::string::npos) {
            std::ostringstream message;
            message << "line " << lineNumber << ": expected key = value";
            warn(message.str());
            continue;
        }
        const std::string key = lower(trim(trimmed.substr(0, equals)));
        const std::string value = trim(trimmed.substr(equals + 1));

        if (group != nullptr) {
            // Inside [group X]: the same target keys as the top level.
            if (key == "node") {
                group->nodes.push_back(value);
            } else if (key == "node-file") {
                group->nodeFiles.push_back(expandHome(value));
            } else if (key == "uri") {
                group->uris.push_back(value);
            } else if (key == "uri-file") {
                group->uriFiles.push_back(expandHome(value));
            } else if (isThemeKey(key) || isTopLevelKey(key)) {
                std::ostringstream message;
                message << "line " << lineNumber << ": '" << key
                        << "' cannot be set in [group " << group->name
                        << "]; move it to the top level (or to [theme])";
                fail(config, message.str());
            } else {
                warn("line " + std::to_string(lineNumber) + ": unknown key '" + key +
                     "' in group " + group->name);
            }
            continue;
        }

        if (inTheme) {
            if (key == "accent") {
                config.theme.accent = parseColor(value, config.theme.accent);
            } else if (key == "ok") {
                config.theme.ok = parseColor(value, config.theme.ok);
            } else if (key == "warn") {
                config.theme.warn = parseColor(value, config.theme.warn);
            } else if (key == "error") {
                config.theme.error = parseColor(value, config.theme.error);
            } else if (key == "text") {
                config.theme.text = parseColor(value, config.theme.text);
            } else if (key == "dim") {
                config.theme.dim = parseColor(value, config.theme.dim);
            } else if (key == "frame") {
                config.theme.frame = parseColor(value, config.theme.frame);
            } else if (key == "focus") {
                config.theme.focus = parseColor(value, config.theme.focus);
            } else if (key == "animate") {
                config.theme.animate = toBool(value);
            } else if (key == "log-ttl") {
                config.theme.logTtlSeconds = std::max(0.5, toDouble(value, 3.0));
            } else if (key == "log-fade") {
                config.theme.logFadeSeconds = std::max(0.0, toDouble(value, 1.5));
            } else if (key == "pixel-graphs") {
                config.theme.pixelGraphs = lower(value);
            } else if (key == "fps") {
                config.theme.fps = std::clamp(static_cast<int>(toDouble(value, 5.0)), 1, 30);
            } else if (isTopLevelKey(key)) {
                // The trap this guard exists for: `group = lab` pasted after
                // the last theme key is read as a theme key, dropped, and the
                // tool then silently watches the top-level targets instead of
                // the group.  Refuse to start rather than watch the wrong host.
                std::ostringstream message;
                message << "line " << lineNumber << ": '" << key
                        << "' is a top-level key, but it comes after [theme] (line " << themeLine
                        << ") and is therefore read as a theme key; move it above [theme] or "
                           "start the section that should hold it";
                fail(config, message.str());
            } else {
                warn("line " + std::to_string(lineNumber) + ": unknown theme key '" + key + "'");
            }
            continue;
        }

        if (key == "interval") {
            config.interval = toDouble(value, config.interval);
        } else if (key == "ldap-interval") {
            config.ldapInterval = toDouble(value, config.ldapInterval);
        } else if (key == "uri-file") {
            config.uriFiles.push_back(expandHome(value));
        } else if (key == "uri") {
            config.uris.push_back(value);
        } else if (key == "node-file") {
            config.nodeFiles.push_back(expandHome(value));
        } else if (key == "node") {
            config.nodes.push_back(value);
        } else if (key == "group") {
            config.defaultGroup = value;
        } else if (key == "once") {
            config.once = toBool(value);
        } else if (key == "watch") {
            config.watchSeconds = toDouble(value, config.watchSeconds);
        } else if (key == "duration") {
            config.duration = toDouble(value, config.duration);
        } else if (key == "json") {
            config.json = toBool(value);
        } else if (key == "jsonl") {
            config.jsonl = toBool(value);
        } else if (key == "tui") {
            config.forceTui = toBool(value);
        } else if (key == "no-tui") {
            config.forceText = toBool(value);
        } else if (key == "insecure") {
            config.insecure = toBool(value);
        } else if (key == "bind") {
            config.bindDn = value;
        } else if (key == "password-file") {
            config.passwordFile = expandHome(value);
        } else {
            warn("unknown key '" + key + "'");
        }
    }
    return config;
}

}  // namespace slaptop
