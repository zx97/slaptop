#include "slaptop/collector/discovery.hpp"

#include <dirent.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

namespace slaptop::collector {
namespace {

/// NUL separated argv of a process, as stored in /proc/<pid>/cmdline.
std::vector<std::string> readCmdline(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        return {};
    }
    std::string raw((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());

    std::vector<std::string> args;
    std::string current;
    for (const char c : raw) {
        if (c == '\0') {
            if (!current.empty()) {
                args.push_back(current);
                current.clear();
            }
        } else {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        args.push_back(current);
    }
    return args;
}

bool looksLikeSlapd(const std::string& argv0) {
    const std::size_t slash = argv0.rfind('/');
    const std::string binary = slash == std::string::npos ? argv0 : argv0.substr(slash + 1);
    return binary == "slapd";
}

std::string basenameOf(std::string_view path) {
    const std::size_t slash = path.rfind('/');
    return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

}  // namespace

std::string instanceNameFromConfigDir(std::string_view configDir) {
    std::string base = basenameOf(configDir);
    if (base.empty()) {
        return base;
    }

    // Expected convention: slapd_<name>.d
    constexpr std::string_view prefix = "slapd_";
    constexpr std::string_view suffix = ".d";
    if (base.size() > prefix.size() + suffix.size() && base.rfind(prefix, 0) == 0 &&
        base.compare(base.size() - suffix.size(), suffix.size(), suffix) == 0) {
        return base.substr(prefix.size(), base.size() - prefix.size() - suffix.size());
    }
    return base;
}

std::string ldapiUri(const Instance& instance) {
    for (const std::string& listener : instance.listeners) {
        if (listener.rfind("ldapi://", 0) == 0) {
            return listener;
        }
    }
    return {};
}

std::vector<Instance> discoverInstances() {
    std::vector<Instance> instances;

    DIR* proc = ::opendir("/proc");
    if (proc == nullptr) {
        return instances;
    }

    while (const dirent* entry = ::readdir(proc)) {
        if (entry->d_type != DT_DIR) {
            continue;
        }
        const std::string name = entry->d_name;
        if (name.empty() || !std::isdigit(static_cast<unsigned char>(name.front()))) {
            continue;
        }

        pid_t pid = 0;
        try {
            pid = static_cast<pid_t>(std::stol(name));
        } catch (...) {
            continue;
        }
        if (pid <= 0) {
            continue;
        }

        const std::vector<std::string> args = readCmdline("/proc/" + name + "/cmdline");
        if (args.empty() || !looksLikeSlapd(args.front())) {
            continue;
        }

        Instance instance;
        instance.pid = pid;
        for (std::size_t i = 1; i + 1 < args.size(); ++i) {
            if (args[i] == "-F") {
                instance.configDir = args[i + 1];
            } else if (args[i] == "-f") {
                instance.configFile = args[i + 1];
            } else if (args[i] == "-l") {
                instance.logArg = args[i + 1];
            } else if (args[i] == "-h") {
                std::istringstream listeners(args[i + 1]);
                std::string url;
                while (listeners >> url) {
                    instance.listeners.push_back(url);
                }
            }
        }

        instance.name = instanceNameFromConfigDir(instance.configDir);
        if (instance.name.empty() && !instance.configFile.empty()) {
            instance.name = instanceNameFromConfigDir(instance.configFile);
        }
        if (instance.name.empty()) {
            instance.name = "slapd-" + name;
        }
        instances.push_back(std::move(instance));
    }
    ::closedir(proc);

    std::sort(instances.begin(), instances.end(), [](const Instance& a, const Instance& b) {
        return a.name < b.name;
    });
    return instances;
}

}  // namespace slaptop::collector
