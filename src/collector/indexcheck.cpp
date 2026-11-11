#include "slaptop/collector/indexcheck.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <set>
#include <sstream>

namespace slaptop::collector {
namespace {

std::string lower(std::string text) {
    for (char& c : text) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return text;
}

std::vector<std::string> split(const std::string& text, char separator) {
    std::vector<std::string> parts;
    std::string current;
    for (const char c : text) {
        if (c == separator) {
            if (!current.empty()) {
                parts.push_back(current);
            }
            current.clear();
        } else if (c != ' ') {
            current.push_back(c);
        }
    }
    if (!current.empty()) {
        parts.push_back(current);
    }
    return parts;
}

}  // namespace

std::vector<IndexEntry> parseIndexLines(const std::vector<std::string>& lines) {
    std::vector<IndexEntry> entries;
    for (const std::string& line : lines) {
        std::istringstream fields(line);
        std::string attributes;
        std::string types;
        if (!(fields >> attributes >> types)) {
            continue;
        }
        IndexEntry entry;
        entry.attributes = split(attributes, ',');
        entry.types = lower(types);
        for (std::string& attribute : entry.attributes) {
            attribute = lower(attribute);
        }
        if (!entry.attributes.empty()) {
            entries.push_back(std::move(entry));
        }
    }
    // A later line for the same attribute adds to the earlier one, exactly as
    // slapd merges them.
    return entries;
}

std::vector<std::pair<std::string, std::string>> filterAttributes(const std::string& family) {
    std::vector<std::pair<std::string, std::string>> attributes;
    // Scan "(attr<op>value)": the operator decides how an index can be used.
    for (std::size_t i = 0; i < family.size(); ++i) {
        if (family[i] != '(') {
            continue;
        }
        // "(&(uid=$)..." : the first parenthesis carries the operator, the
        // attribute starts one level deeper.
        if (i + 1 < family.size() &&
            (family[i + 1] == '&' || family[i + 1] == '|' || family[i + 1] == '!')) {
            continue;
        }
        std::size_t cursor = i + 1;
        std::string attribute;
        while (cursor < family.size() && family[cursor] != '=' && family[cursor] != '<' &&
               family[cursor] != '>' && family[cursor] != '~' && family[cursor] != ')' &&
               family[cursor] != '(') {
            attribute.push_back(family[cursor]);
            ++cursor;
        }
        if (cursor >= family.size() || family[cursor] == ')') {
            continue;
        }
        // "attr=" may be "(attr=*)", a presence test with no value.
        std::string kind = "eq";
        if (family[cursor] != '=') {
            kind = "eq";  // >=, <=, ~= still compare whole values: equality-type
        }
        std::string value;
        std::size_t valueStart = cursor + 1;
        while (valueStart < family.size() && family[valueStart] != ')') {
            value.push_back(family[valueStart]);
            ++valueStart;
        }
        if (value == "*") {
            kind = "pres";
        } else if (value.find('*') != std::string::npos ||
                   value.find("$*") != std::string::npos) {
            kind = "sub";
        }
        const std::string name = lower(attribute);
        if (!name.empty()) {
            attributes.emplace_back(name, kind);
        }
        i = valueStart;
    }
    return attributes;
}

bool baseUnderSuffix(const std::string& base, const std::string& suffix) {
    if (suffix.empty()) {
        return true;
    }
    const auto normalize = [](const std::string& text) {
        std::string out;
        for (const char c : text) {
            if (c != ' ') {
                out.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            }
        }
        return out;
    };
    const std::string normalizedBase = normalize(base);
    const std::string normalizedSuffix = normalize(suffix);
    if (normalizedBase == normalizedSuffix) {
        return true;
    }
    return normalizedBase.size() > normalizedSuffix.size() &&
           normalizedBase.compare(normalizedBase.size() - normalizedSuffix.size(),
                                  normalizedSuffix.size(), normalizedSuffix) == 0 &&
           normalizedBase[normalizedBase.size() - normalizedSuffix.size() - 1] == ',';
}

IndexAssessment assessAttributeUses(const std::vector<std::string>& indexLines,
                                    const std::vector<FilterAttribute>& uses) {
    // Same assessment as the family-pattern form: rebuild the usage map from
    // the attributes the caller already extracted.
    IndexAssessment assessment = assessIndexes(indexLines, std::vector<std::pair<std::string, std::uint64_t>>{});
    std::map<std::string, FilterAttribute> usage;
    for (const FilterAttribute& use : uses) {
        FilterAttribute& entry = usage[use.attribute];
        entry.attribute = use.attribute;
        entry.searches += use.searches;
        if (entry.kind.empty()) {
            entry.kind = use.kind;
            entry.example = use.example;
        }
    }
    std::map<std::string, std::string> typesByAttribute;
    for (const IndexEntry& entry : assessment.configured) {
        for (const std::string& attribute : entry.attributes) {
            if (attribute == "default") {
                assessment.defaultTypes = entry.types;
                continue;
            }
            std::string& types = typesByAttribute[attribute];
            if (types.find(entry.types) == std::string::npos) {
                types += (types.empty() ? "" : ",") + entry.types;
            }
        }
    }
    const auto covers = [](const std::string& types, const std::string& kind) {
        return types.find(kind) != std::string::npos;
    };
    for (const auto& [attribute, entry] : usage) {
        // "(objectClass=*)" is a presence test on the entry itself: the answer
        // needs no index, and reporting it as missing one would be exactly the
        // kind of bad advice this screen must avoid.
        if (attribute == "objectclass" && entry.kind == "pres") {
            continue;
        }
        assessment.searches += entry.searches;
        const auto own = typesByAttribute.find(attribute);
        if (own != typesByAttribute.end()) {
            if (!covers(own->second, entry.kind)) {
                assessment.mismatched.push_back(entry);
            }
            continue;
        }
        if (!assessment.defaultTypes.empty() && covers(assessment.defaultTypes, entry.kind)) {
            assessment.byDefault.push_back(entry);
        } else {
            assessment.uncovered.push_back(entry);
        }
    }
    for (const auto& [attribute, types] : typesByAttribute) {
        if (usage.count(attribute) == 0) {
            assessment.unseen.push_back(attribute);
        }
    }
    const auto bySearches = [](const FilterAttribute& a, const FilterAttribute& b) {
        return a.searches > b.searches;
    };
    std::sort(assessment.uncovered.begin(), assessment.uncovered.end(), bySearches);
    std::sort(assessment.mismatched.begin(), assessment.mismatched.end(), bySearches);
    std::sort(assessment.byDefault.begin(), assessment.byDefault.end(), bySearches);
    std::sort(assessment.unseen.begin(), assessment.unseen.end());
    return assessment;
}

IndexAssessment assessIndexes(const std::vector<std::string>& indexLines,
                             const std::vector<std::pair<std::string, std::uint64_t>>& families) {
    IndexAssessment assessment;
    assessment.configured = parseIndexLines(indexLines);

    std::map<std::string, std::string> typesByAttribute;
    for (const IndexEntry& entry : assessment.configured) {
        for (const std::string& attribute : entry.attributes) {
            if (attribute == "default") {
                assessment.defaultTypes = entry.types;
                continue;
            }
            // Two lines for one attribute: the types add up.
            std::string& types = typesByAttribute[attribute];
            if (types.find(entry.types) == std::string::npos) {
                types += (types.empty() ? "" : ",") + entry.types;
            }
        }
    }

    // What the window actually filtered on.
    std::map<std::string, FilterAttribute> usage;
    for (const auto& [family, searches] : families) {
        assessment.searches += searches;
        for (const auto& [attribute, kind] : filterAttributes(family)) {
            FilterAttribute& entry = usage[attribute];
            entry.attribute = attribute;
            entry.searches += searches;
            if (entry.kind.empty()) {
                entry.kind = kind;
                entry.example = family;
            }
        }
    }

    // An index serves a filter only when its type matches the comparison:
    // `eq` for equality and ordering, `sub` for substrings, `pres` for a
    // presence test.  `sub` does not serve equality, and vice versa.
    const auto covers = [](const std::string& types, const std::string& kind) {
        return types.find(kind) != std::string::npos;
    };
    for (const auto& [attribute, entry] : usage) {
        const auto own = typesByAttribute.find(attribute);
        if (own != typesByAttribute.end()) {
            if (!covers(own->second, entry.kind)) {
                assessment.mismatched.push_back(entry);
            }
            continue;
        }
        if (!assessment.defaultTypes.empty() && covers(assessment.defaultTypes, entry.kind)) {
            assessment.byDefault.push_back(entry);
        } else {
            assessment.uncovered.push_back(entry);
        }
    }
    for (const auto& [attribute, types] : typesByAttribute) {
        if (usage.count(attribute) == 0) {
            assessment.unseen.push_back(attribute);
        }
    }
    std::sort(assessment.uncovered.begin(), assessment.uncovered.end(),
              [](const FilterAttribute& a, const FilterAttribute& b) {
                  return a.searches > b.searches;
              });
    std::sort(assessment.byDefault.begin(), assessment.byDefault.end(),
              [](const FilterAttribute& a, const FilterAttribute& b) {
                  return a.searches > b.searches;
              });
    std::sort(assessment.mismatched.begin(), assessment.mismatched.end(),
              [](const FilterAttribute& a, const FilterAttribute& b) {
                  return a.searches > b.searches;
              });
    std::sort(assessment.unseen.begin(), assessment.unseen.end());
    return assessment;
}

}  // namespace slaptop::collector
