// Index coverage: the configured olcDbIndex lines against the filters the
// access log actually used.  Pure functions, so the wording of the advice can
// be tested as well as the parsing.

#include <iostream>
#include <string>
#include <utility>
#include <vector>

#include "slaptop/collector/indexcheck.hpp"

namespace {

int g_failures = 0;

void check(bool condition, const char* expression, const char* file, int line) {
    if (!condition) {
        std::cerr << file << ':' << line << ": CHECK failed: " << expression << '\n';
        ++g_failures;
    }
}

#define CHECK(expr) check((expr), #expr, __FILE__, __LINE__)

using slaptop::collector::IndexAssessment;
using slaptop::collector::IndexEntry;
using slaptop::collector::assessIndexes;
using slaptop::collector::filterAttributes;
using slaptop::collector::parseIndexLines;

void testParseLines() {
    const auto entries = parseIndexLines({"uid,cn eq,sub", "default sub", "objectClass eq"});
    CHECK(entries.size() == 3);
    CHECK(entries[0].attributes.size() == 2);
    CHECK(entries[0].attributes[0] == "uid");
    CHECK(entries[0].attributes[1] == "cn");
    CHECK(entries[0].types == "eq,sub");
    CHECK(entries[1].attributes[0] == "default");
    CHECK(parseIndexLines({"malformed"}).empty());
}

void testFilterAttributes() {
    const auto conjunction = filterAttributes("(&(uid=$)(objectClass=person))");
    CHECK(conjunction.size() == 2);
    CHECK(conjunction[0].first == "uid");
    CHECK(conjunction[0].second == "eq");
    CHECK(conjunction[1].first == "objectclass");
    CHECK(conjunction[1].second == "eq");

    const auto substring = filterAttributes("(cn=$*$)");
    CHECK(substring.size() == 1);
    CHECK(substring[0].second == "sub");

    const auto presence = filterAttributes("(mail=*)");
    CHECK(presence.size() == 1);
    CHECK(presence[0].second == "pres");

    const auto disjunction = filterAttributes("(|(uid=$)(mail=$)(sn=$))");
    CHECK(disjunction.size() == 3);
}

void testCoverage() {
    // uid indexed, objectClass by default, recordStatus nowhere.
    const IndexAssessment assessment = assessIndexes(
        {"uid eq", "default sub"}, {{"(&(uid=$)(recordStatus=$))", 30}, {"(objectClass=*)", 5}});
    CHECK(assessment.searches == 35);
    CHECK(assessment.defaultTypes == "sub");
    // `default sub` is a substring index: it does NOT serve the equality
    // filter on recordStatus, nor the presence test on objectClass.
    CHECK(assessment.byDefault.empty());
    CHECK(assessment.uncovered.size() == 2);
    CHECK(assessment.uncovered[0].attribute == "recordstatus");
    CHECK(assessment.uncovered[0].kind == "eq");
    CHECK(assessment.uncovered[0].searches == 30);
    CHECK(assessment.unseen.empty());
}

void testNoDefault() {
    const IndexAssessment assessment =
        assessIndexes({"uid eq"}, {{"(&(uid=$)(sn=$))", 4}, {"(cn=$)", 2}});
    // Without a `default` line, sn and cn are uncovered and uid is configured.
    CHECK(assessment.defaultTypes.empty());
    CHECK(assessment.uncovered.size() == 2);
    CHECK(assessment.uncovered[0].attribute == "sn");  // sorted by searches, then name
    CHECK(assessment.unseen.empty());
}

/// An index of the wrong type is not a missing index, and the difference is
/// what keeps the advice honest.
void testMismatchedType() {
    const IndexAssessment assessment = assessIndexes({"cn eq"}, {{"(cn=$*$)", 7}});
    CHECK(assessment.uncovered.empty());
    CHECK(assessment.mismatched.size() == 1);
    CHECK(assessment.mismatched[0].attribute == "cn");
    CHECK(assessment.mismatched[0].kind == "sub");
}

/// `default` covers an attribute when the type matches.
void testDefaultCovers() {
    const IndexAssessment assessment =
        assessIndexes({"default eq,sub"}, {{"(cn=$*$)", 2}, {"(uid=$)", 1}});
    CHECK(assessment.uncovered.empty());
    CHECK(assessment.byDefault.size() == 2);
}

/// A filter is only comparable with the database whose suffix contains its
/// base: this is what the screen now does, and the reason it used to blame the
/// wrong index list.
void testBaseUnderSuffix() {
    using slaptop::collector::baseUnderSuffix;
    CHECK(baseUnderSuffix("dc=example,dc=org", "dc=example,dc=org"));
    CHECK(baseUnderSuffix("ou=people,dc=example,dc=org", "dc=example,dc=org"));
    CHECK(baseUnderSuffix("OU=People, DC=Example, DC=Org", "dc=example,dc=org"));
    CHECK(!baseUnderSuffix("dc=example,dc=com", "dc=example,dc=org"));
    // "xdc=example,dc=org" is not under "dc=example,dc=org": the comma matters.
    CHECK(!baseUnderSuffix("xdc=example,dc=org", "dc=example,dc=org"));
    CHECK(baseUnderSuffix("dc=example,dc=org", ""));
}

/// Two databases, two index sets: a filter on one suffix must not be judged
/// against the other's indexes.
void testPerDatabase() {
    using slaptop::collector::FilterAttribute;
    using slaptop::collector::assessAttributeUses;
    const std::vector<FilterAttribute> uses{{"uid", 42, "eq", "dc=example,dc=com"}};
    const auto withUid = assessAttributeUses({"uid eq"}, uses);
    CHECK(withUid.uncovered.empty());
    CHECK(withUid.searches == 42);
    const auto withoutUid = assessAttributeUses({"mail eq"}, uses);
    CHECK(withoutUid.uncovered.size() == 1);
    CHECK(withoutUid.uncovered[0].attribute == "uid");
}

void testUnseen() {
    const IndexAssessment assessment = assessIndexes({"uid eq", "cn eq"}, {{"(uid=$)", 3}});
    CHECK(assessment.unseen.size() == 1);
    CHECK(assessment.unseen[0] == "cn");
}

}  // namespace

int main() {
    testParseLines();
    testFilterAttributes();
    testCoverage();
    testNoDefault();
    testBaseUnderSuffix();
    testPerDatabase();
    testMismatchedType();
    testDefaultCovers();
    testUnseen();

    if (g_failures != 0) {
        std::cerr << g_failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "index checks passed\n";
    return 0;
}
