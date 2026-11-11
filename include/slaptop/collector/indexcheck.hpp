#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace slaptop::collector {

/// One `olcDbIndex` line, split into the attributes it covers and the index
/// types it declares ("uid,cn eq,sub" -> {uid, cn} + "eq,sub").
struct IndexEntry {
    std::vector<std::string> attributes;
    std::string types;  ///< as written: eq, pres, sub, subinitial, ...
};

/// A filter attribute the access log actually used, with the number of
/// searches that carried it.
struct FilterAttribute {
    std::string attribute;
    std::uint64_t searches{0};
    /// "eq" when the filter compares whole values, "sub" when it uses a
    /// substring, "pres" for a presence test: what an index must provide to be
    /// usable for it.
    std::string kind;
    std::string example;  ///< the family pattern, for the screen
};

/// Cross-reference between the configured indexes and the filters seen.
///
/// This is an *observation over the log window*, not a verdict: an index that
/// looks unused may serve replication (entryCSN, entryUUID, objectClass), an
/// administrative tool, or a client that was quiet for the last minute.  The
/// screen says so, and so does this structure: nothing here is a command.
struct IndexAssessment {
    std::vector<IndexEntry> configured;
    /// Types of the `default` line, empty when none: it applies to every
    /// attribute without a line of its own.
    std::string defaultTypes;
    /// Attributes used by filters, with no dedicated line and no default.
    std::vector<FilterAttribute> uncovered;
    /// Attributes used by filters, covered only by `default`.
    std::vector<FilterAttribute> byDefault;
    /// Attributes with a line of their own that does not provide the type the
    /// filters need (an `eq` index in front of substring filters, or the
    /// reverse).  A substring index does not serve an equality filter: the key
    /// format differs, so this is not a detail.
    std::vector<FilterAttribute> mismatched;
    /// Configured attributes no filter in the window mentioned.
    std::vector<std::string> unseen;
    /// Total searches the window analysed.
    std::uint64_t searches{0};
};

/// Splits the raw `olcDbIndex` values of one database.
std::vector<IndexEntry> parseIndexLines(const std::vector<std::string>& lines);

/// Attributes named by a filter, with the kind of comparison each side uses.
///
/// `(&(uid=$)(objectClass=person))` names uid (eq) and objectClass (eq);
/// `(cn=$*$)` names cn (sub); `(mail=*)` names mail (pres).  The `$`
/// placeholders of a family pattern are ignored, they only mark the values.
std::vector<std::pair<std::string, std::string>> filterAttributes(const std::string& family);

/// Builds the cross-reference.  `families` holds one (pattern, searches) pair
/// per filter family, already summed over the accounts that used it.
IndexAssessment assessIndexes(const std::vector<std::string>& indexLines,
                              const std::vector<std::pair<std::string, std::uint64_t>>& families);

/// Same, from attributes already extracted (the log aggregation carries the
/// base and the comparison kind, so this is the form the screen uses).
IndexAssessment assessAttributeUses(const std::vector<std::string>& indexLines,
                                    const std::vector<FilterAttribute>& uses);

/// True when `base` is `suffix` or below it.  DN comparison: case-insensitive,
/// whitespace-insensitive, and a base belongs to the longest matching suffix.
bool baseUnderSuffix(const std::string& base, const std::string& suffix);

}  // namespace slaptop::collector
