#include "slaptop/collector/behavior.hpp"

#include "slaptop/collector/indexcheck.hpp"

#include <algorithm>
#include <cctype>
#include <cmath>

namespace slaptop::collector {
namespace {

/// Labels used when the bind DN is not known.  A DN can never start with a
/// parenthesis, so these cannot collide with a real account.
constexpr std::string_view kAnonymous = "(anonymous)";
constexpr std::string_view kUnknown = "(unknown)";
constexpr std::string_view kOther = "(other)";

/// Ceiling on a filter we are willing to generalize: a malformed or hostile
/// line must not turn into a megabyte-sized family name.
constexpr std::size_t kMaxFilterBytes = 2048;
constexpr int kMaxFilterDepth = 64;

bool isDigit(char c) { return c >= '0' && c <= '9'; }

/// Unsigned decimal number following `key` (`conn=`, `op=`, `nentries=`).
bool unsignedAfter(std::string_view line, std::string_view key, std::uint64_t& out) {
    const std::size_t at = line.find(key);
    if (at == std::string_view::npos) {
        return false;
    }
    std::size_t pos = at + key.size();
    std::uint64_t value = 0;
    bool seen = false;
    while (pos < line.size() && isDigit(line[pos])) {
        seen = true;
        const std::uint64_t digit = static_cast<std::uint64_t>(line[pos] - '0');
        // Saturate instead of wrapping: a nonsense counter must not poison the
        // window with a huge number.
        if (value > (UINT64_MAX - digit) / 10) {
            value = UINT64_MAX;
            break;
        }
        value = value * 10 + digit;
        ++pos;
    }
    if (!seen) {
        return false;
    }
    out = value;
    return true;
}

/// Seconds following `key` (`etime=0.000156`).  Parsed by hand: the value is
/// a plain decimal, and strtod would need a NUL-terminated copy per line.
bool secondsAfter(std::string_view line, std::string_view key, double& out) {
    const std::size_t at = line.find(key);
    if (at == std::string_view::npos) {
        return false;
    }
    std::size_t pos = at + key.size();
    bool seen = false;
    double value = 0.0;
    double scale = 1.0;
    bool afterPoint = false;
    while (pos < line.size()) {
        const char c = line[pos];
        if (isDigit(c)) {
            seen = true;
            const double digit = static_cast<double>(c - '0');
            if (afterPoint) {
                scale *= 0.1;
                value += digit * scale;
            } else {
                value = value * 10.0 + digit;
            }
        } else if (c == '.' && !afterPoint) {
            afterPoint = true;
        } else {
            break;
        }
        ++pos;
    }
    if (!seen) {
        return false;
    }
    out = value;
    return true;
}

/// Quoted value following `key` (`BIND dn="…"`, `SRCH … filter="…"`).
/// LDAP escapes a literal quote inside a DN or a filter as `\22`, so the next
/// `"` is always the end of the value.
bool quotedAfter(std::string_view line, std::string_view key, std::string_view& out) {
    const std::size_t at = line.find(key);
    if (at == std::string_view::npos) {
        return false;
    }
    const std::size_t begin = at + key.size();
    const std::size_t end = line.find('"', begin);
    if (end == std::string_view::npos) {
        return false;
    }
    out = line.substr(begin, end - begin);
    return true;
}

/// Folds consecutive identical sibling clauses into one `<clause>+`, so an OR
/// of a hundred different uid values becomes a single family instead of one
/// family per arity.  Applied recursively.
void factorizeChildren(std::string_view text, std::string& out, int depth) {
    if (depth > kMaxFilterDepth) {
        out += text;
        return;
    }
    std::size_t i = 0;
    while (i < text.size()) {
        const char c = text[i];
        if (c != '(') {
            out.push_back(c);
            ++i;
            continue;
        }
        // Balanced clause [i, j).
        std::size_t j = i + 1;
        int level = 1;
        while (j < text.size() && level > 0) {
            if (text[j] == '(') {
                ++level;
            } else if (text[j] == ')') {
                --level;
            }
            ++j;
        }
        std::string clause;
        if (j - i >= 2) {
            factorizeChildren(text.substr(i + 1, j - i - 2), clause, depth + 1);
        }
        // How many identical clauses follow?
        int repetitions = 1;
        std::size_t k = j;
        while (k < text.size() && text[k] == '(') {
            std::size_t kEnd = k + 1;
            int inner = 1;
            while (kEnd < text.size() && inner > 0) {
                if (text[kEnd] == '(') {
                    ++inner;
                } else if (text[kEnd] == ')') {
                    --inner;
                }
                ++kEnd;
            }
            std::string next;
            if (kEnd - k >= 2) {
                factorizeChildren(text.substr(k + 1, kEnd - k - 2), next, depth + 1);
            }
            if (next != clause) {
                break;
            }
            ++repetitions;
            k = kEnd;
        }
        out.push_back('(');
        out += clause;
        out.push_back(')');
        if (repetitions >= 2) {
            out.push_back('+');
        }
        i = k;
    }
}

std::uint64_t toNanoseconds(double seconds) {
    if (!(seconds > 0.0)) {
        return 0;
    }
    return static_cast<std::uint64_t>(std::llround(seconds * 1e9));
}

double toSeconds(std::uint64_t nanoseconds) {
    return static_cast<double>(nanoseconds) / 1e9;
}

void addCounters(AccessCounters& into, const AccessCounters& what) {
    into.ops += what.ops;
    into.etimeNs += what.etimeNs;
    into.qtimeNs += what.qtimeNs;
    into.wtimeNs += what.wtimeNs;
    into.nentries += what.nentries;
}

void removeCounters(AccessCounters& into, const AccessCounters& what) {
    into.ops = into.ops > what.ops ? into.ops - what.ops : 0;
    into.etimeNs = into.etimeNs > what.etimeNs ? into.etimeNs - what.etimeNs : 0;
    into.qtimeNs = into.qtimeNs > what.qtimeNs ? into.qtimeNs - what.qtimeNs : 0;
    into.wtimeNs = into.wtimeNs > what.wtimeNs ? into.wtimeNs - what.wtimeNs : 0;
    into.nentries = into.nentries > what.nentries ? into.nentries - what.nentries : 0;
}

bool emptyCounters(const AccessCounters& counters) {
    return counters.ops == 0 && counters.etimeNs == 0 && counters.qtimeNs == 0 &&
           counters.wtimeNs == 0 && counters.nentries == 0;
}

double shareOf(const AccessCounters& counters, const AccessCounters& totals) {
    if (totals.etimeNs == 0) {
        return 0.0;
    }
    return 100.0 * static_cast<double>(counters.etimeNs) / static_cast<double>(totals.etimeNs);
}

double averageOf(const AccessCounters& counters) {
    if (counters.ops == 0) {
        return 0.0;
    }
    return toSeconds(counters.etimeNs) / static_cast<double>(counters.ops);
}

}  // namespace

std::string generalizeFilter(std::string_view filter) {
    const std::string_view bounded =
        filter.size() > kMaxFilterBytes ? filter.substr(0, kMaxFilterBytes) : filter;
    std::string masked;
    masked.reserve(bounded.size());
    bool inValue = false;
    for (const char c : bounded) {
        // Some SRCH lines keep the trailing quote and attributes after it: the
        // filter proper ends there.
        if (c == '"') {
            break;
        }
        if (std::isspace(static_cast<unsigned char>(c)) != 0) {
            continue;
        }
        if (c == '(' || c == ')' || c == '&' || c == '|' || c == '!') {
            masked.push_back(c);
            inValue = false;
            continue;
        }
        if (c == '=' || c == '>' || c == '<' || c == '~') {
            masked.push_back(c);
            inValue = true;
            continue;
        }
        if (!inValue) {
            masked.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
            continue;
        }
        if (c == '*') {
            masked.push_back('*');
        } else if (isDigit(c)) {
            if (masked.empty() || masked.back() != '#') {
                masked.push_back('#');
            }
        } else if (masked.empty() || masked.back() != '$') {
            masked.push_back('$');
        }
    }
    std::string out;
    out.reserve(masked.size());
    factorizeChildren(masked, out, 0);
    return out;
}

bool isSlowFilter(std::string_view family) {
    // Same rule as slaplog's is_slow_filter: a negation, or a wildcard that is
    // not a bare presence test ("(attr=*)" keeps the '*' right before ')').
    if (family.find('!') != std::string_view::npos) {
        return true;
    }
    return family.find("$*") != std::string_view::npos ||
           family.find("#*") != std::string_view::npos ||
           family.find("*$") != std::string_view::npos ||
           family.find("*#") != std::string_view::npos;
}

void BehaviorWindow::setLogLevel(std::string level) { logLevel_ = std::move(level); }

void BehaviorWindow::reset() {
    buckets_.clear();
    totals_ = AccessCounters{};
    searches_ = 0;
    slowSearches_ = 0;
    accountTotals_.clear();
    familyTotals_.clear();
    binds_.clear();
    bindOrder_.clear();
    pending_.clear();
    pendingOrder_.clear();
    accountsDropped_ = 0;
    last_ = BehaviorClock::time_point{};
}

void BehaviorWindow::advance(BehaviorClock::time_point now) {
    last_ = now;
    constexpr auto step = std::chrono::seconds(1);
    if (buckets_.empty()) {
        Bucket first;
        first.start = now;
        buckets_.push_back(std::move(first));
        return;
    }
    // A long pause (stop the process, or a gap in the loop) leaves nothing
    // inside the window: start over instead of iterating thousands of empty
    // slices.
    if (now - buckets_.back().start > step * static_cast<std::int64_t>(kBuckets) * 2) {
        reset();
        last_ = now;
        Bucket fresh;
        fresh.start = now;
        buckets_.push_back(std::move(fresh));
        return;
    }
    while (now - buckets_.back().start >= step) {
        if (buckets_.size() >= kBuckets) {
            subtractBucket(buckets_.front());
            buckets_.pop_front();
        }
        Bucket next;
        next.start = buckets_.back().start + step;
        buckets_.push_back(std::move(next));
    }
    while (buckets_.size() > kBuckets) {
        subtractBucket(buckets_.front());
        buckets_.pop_front();
    }
}

void BehaviorWindow::subtractBucket(const Bucket& bucket) {
    // The per-base figures live inside the buckets and are summed when asked
    // for: dropping a bucket drops them, nothing to subtract here.
    removeCounters(totals_, bucket.total);
    searches_ = searches_ > bucket.searches ? searches_ - bucket.searches : 0;
    slowSearches_ = slowSearches_ > bucket.slowSearches ? slowSearches_ - bucket.slowSearches : 0;
    for (const auto& [account, counters] : bucket.accounts) {
        const auto it = accountTotals_.find(account);
        if (it == accountTotals_.end()) {
            continue;
        }
        removeCounters(it->second, counters);
        if (emptyCounters(it->second)) {
            accountTotals_.erase(it);
        }
    }
    for (const auto& [key, counters] : bucket.families) {
        const auto it = familyTotals_.find(key);
        if (it == familyTotals_.end()) {
            continue;
        }
        removeCounters(it->second, counters);
        if (emptyCounters(it->second)) {
            familyTotals_.erase(it);
        }
    }
}

const std::string& BehaviorWindow::accountOf(std::uint64_t conn) {
    const auto it = binds_.find(conn);
    if (it == binds_.end()) {
        static const std::string unknown(kUnknown);
        return unknown;
    }
    return it->second;
}

void BehaviorWindow::rememberBind(std::uint64_t conn, std::string dn) {
    if (dn.empty()) {
        dn.assign(kAnonymous);
    }
    if (dn.size() > kMaxAccountLength) {
        dn.resize(kMaxAccountLength);
    }
    const auto it = binds_.find(conn);
    if (it != binds_.end()) {
        it->second = std::move(dn);
        return;
    }
    if (binds_.size() >= kMaxPending) {
        // A server with thousands of connections must not grow this map
        // without bound: forget the oldest binding, the account of that
        // connection becomes unknown rather than wrong.
        while (!bindOrder_.empty()) {
            const std::uint64_t oldest = bindOrder_.front();
            bindOrder_.pop_front();
            if (binds_.erase(oldest) != 0) {
                break;
            }
        }
    }
    binds_.emplace(conn, std::move(dn));
    bindOrder_.push_back(conn);
}

void BehaviorWindow::add(const std::string& account, const PendingSearch& search,
                         const AccessCounters& counters) {
    Bucket& bucket = buckets_.back();
    addCounters(bucket.total, counters);
    ++bucket.searches;
    if (search.slow) {
        ++bucket.slowSearches;
    }
    addCounters(totals_, counters);
    ++searches_;
    if (search.slow) {
        ++slowSearches_;
    }

    // Every distinct bind DN is kept while the window can hold it; beyond the
    // cap the newcomers fold into one row instead of evicting a real account
    // (eviction would make the ranking lie).
    std::string owner = account;
    if (accountTotals_.find(owner) == accountTotals_.end() &&
        accountTotals_.size() >= kMaxAccounts) {
        ++accountsDropped_;
        owner.assign(kOther);
    }

    addCounters(bucket.accounts[owner], counters);
    addCounters(accountTotals_[owner], counters);
    const FamilyKey familyKey{owner, search.family};
    addCounters(bucket.families[familyKey], counters);
    addCounters(familyTotals_[familyKey], counters);

    // Which base carried the filter, and on which attributes: the index
    // screen compares this with the database that owns that suffix.
    ++bucket.baseSearches[search.base];
    for (const auto& [attribute, kind] : filterAttributes(search.family)) {
        auto& use = bucket.baseAttributes[search.base][attribute];
        ++use.searches;
        if (use.kind.empty()) {
            use.kind = kind;
        }
    }
}

void BehaviorWindow::sweepPending(BehaviorClock::time_point now) {
    constexpr auto ttl = std::chrono::seconds(kPendingTtlSeconds);
    while (!pendingOrder_.empty()) {
        const PendingKey& key = pendingOrder_.front();
        const auto it = pending_.find(key);
        const bool stale = it == pending_.end() || now - it->second.at > ttl;
        if (!stale) {
            break;
        }
        if (it != pending_.end()) {
            pending_.erase(it);
        }
        pendingOrder_.pop_front();
    }
    // Completed operations leave their key behind; compact once the bookkeeping
    // outnumbers what is actually in flight.
    if (pendingOrder_.size() > 4 * kMaxPending) {
        pendingOrder_.clear();
        for (const auto& [key, search] : pending_) {
            (void)search;
            pendingOrder_.push_back(key);
        }
    }
}

void BehaviorWindow::feed(std::string_view line, BehaviorClock::time_point now) {
    advance(now);

    // Everything before the filter is the structured prefix: looking for the
    // operation keyword there keeps a filter like "(cn=BIND dn=x)" from being
    // mistaken for a bind.
    const std::size_t filterAt = line.find("filter=\"");
    const std::string_view head =
        filterAt == std::string_view::npos ? line : line.substr(0, filterAt);

    std::uint64_t conn = 0;
    std::uint64_t op = 0;
    const std::size_t connAt = head.find("conn=");
    if (connAt == std::string_view::npos) {
        return;
    }
    if (!unsignedAfter(head, "conn=", conn)) {
        return;
    }
    const std::size_t opAt = head.find(" op=", connAt);
    const bool hasOp = opAt != std::string_view::npos &&
                       unsignedAfter(head.substr(opAt + 1), "op=", op);

    // "conn=12 op=0 BIND dn=\"uid=…\" method=128"
    if (head.find(" BIND dn=\"") != std::string_view::npos) {
        std::string_view dn;
        if (quotedAfter(line, " BIND dn=\"", dn)) {
            rememberBind(conn, std::string(dn));
        }
        return;
    }

    // "conn=12 op=3 SRCH base=\"…\" scope=2 … filter=\"…\""
    if (hasOp && head.find(" SRCH ") != std::string_view::npos) {
        std::string_view filter;
        if (!quotedAfter(line, "filter=\"", filter) || filter.empty()) {
            return;
        }
        PendingSearch search;
        if (std::string_view base; quotedAfter(line, "base=\"", base)) {
            search.base = std::string(base);
        }
        search.family = generalizeFilter(filter);
        if (search.family.empty()) {
            return;
        }
        if (search.family.size() > kMaxFamilyLength) {
            search.family.resize(kMaxFamilyLength);
        }
        search.slow = isSlowFilter(search.family);
        search.at = now;
        const PendingKey key{conn, op};
        if (pending_.size() >= kMaxPending) {
            // Drop the oldest in-flight operation instead of refusing the new
            // one: the window must keep tracking what happens *now*.
            while (!pendingOrder_.empty()) {
                const PendingKey oldest = pendingOrder_.front();
                pendingOrder_.pop_front();
                if (pending_.erase(oldest) != 0) {
                    break;
                }
            }
        }
        pending_[key] = std::move(search);
        pendingOrder_.push_back(key);
        return;
    }

    // "conn=12 op=3 SEARCH RESULT tag=101 err=0 qtime=… etime=… nentries=8"
    if (!hasOp || head.find(" RESULT ") == std::string_view::npos) {
        return;
    }
    const auto it = pending_.find(PendingKey{conn, op});
    if (it == pending_.end()) {
        return;  // a result for a request the window never saw (BIND, ADD, …)
    }
    AccessCounters counters;
    counters.ops = 1;
    double value = 0.0;
    if (secondsAfter(line, "etime=", value)) {
        counters.etimeNs = toNanoseconds(value);
    }
    if (secondsAfter(line, "qtime=", value)) {
        counters.qtimeNs = toNanoseconds(value);
    }
    if (secondsAfter(line, "wtime=", value)) {
        counters.wtimeNs = toNanoseconds(value);
    }
    std::uint64_t entries = 0;
    if (unsignedAfter(line, "nentries=", entries)) {
        counters.nentries = entries;
    }
    const std::string account = accountOf(conn);
    add(account, it->second, counters);
    pending_.erase(it);
}

void BehaviorWindow::roll(BehaviorClock::time_point now) {
    advance(now);
    sweepPending(now);
}

BehaviorSnapshot BehaviorWindow::snapshot(std::size_t maxRows) const {
    BehaviorSnapshot out;
    out.logLevel = logLevel_;
    out.windowSeconds = static_cast<double>(kBuckets);
    out.totals = totals_;
    out.searches = searches_;
    out.slowSearches = slowSearches_;
    out.accountsSeen = accountTotals_.size();
    out.familiesSeen = familyTotals_.size();
    out.enoughTraffic = searches_ >= kMinSearchesForVerdict ||
                        totals_.etimeNs >= kMinEtimeForVerdictNs;
    if (!buckets_.empty()) {
        const double span =
            std::chrono::duration<double>(last_ - buckets_.front().start).count();
        out.elapsedSeconds = std::clamp(span, 0.0, static_cast<double>(kBuckets));
    }

    // Two sparklines over the same time axis: the number of searches and the
    // server time they cost, so a burst and its price line up vertically.
    const std::size_t missing = kBuckets > buckets_.size() ? kBuckets - buckets_.size() : 0;
    for (std::size_t i = 0; i < missing; ++i) {
        out.searchTimeline.push_back(0.0);
        out.etimeTimeline.push_back(0.0);
    }
    for (const Bucket& bucket : buckets_) {
        out.searchTimeline.push_back(static_cast<double>(bucket.searches));
        out.etimeTimeline.push_back(toSeconds(bucket.total.etimeNs));
    }

    std::vector<std::pair<const std::string*, const AccessCounters*>> accounts;
    accounts.reserve(accountTotals_.size());
    for (const auto& [account, counters] : accountTotals_) {
        accounts.emplace_back(&account, &counters);
    }
    std::sort(accounts.begin(), accounts.end(),
              [](const auto& a, const auto& b) {
                  if (a.second->etimeNs != b.second->etimeNs) {
                      return a.second->etimeNs > b.second->etimeNs;
                  }
                  if (a.second->ops != b.second->ops) {
                      return a.second->ops > b.second->ops;
                  }
                  return *a.first < *b.first;
              });
    const std::size_t accountRows = std::min(maxRows, accounts.size());
    out.accounts.reserve(accountRows);
    for (std::size_t i = 0; i < accountRows; ++i) {
        BehaviorAccount row;
        row.account = *accounts[i].first;
        row.counters = *accounts[i].second;
        row.etimeSeconds = toSeconds(row.counters.etimeNs);
        row.averageSeconds = averageOf(row.counters);
        row.sharePercent = shareOf(row.counters, totals_);
        out.accounts.push_back(std::move(row));
    }

    std::vector<std::pair<const FamilyKey*, const AccessCounters*>> families;
    families.reserve(familyTotals_.size());
    for (const auto& [key, counters] : familyTotals_) {
        families.emplace_back(&key, &counters);
    }
    std::sort(families.begin(), families.end(),
              [](const auto& a, const auto& b) {
                  if (a.second->etimeNs != b.second->etimeNs) {
                      return a.second->etimeNs > b.second->etimeNs;
                  }
                  if (a.first->first != b.first->first) {
                      return a.first->first < b.first->first;
                  }
                  return a.first->second < b.first->second;
              });
    const std::size_t familyRows = std::min(maxRows, families.size());
    out.families.reserve(familyRows);
    for (std::size_t i = 0; i < familyRows; ++i) {
        BehaviorFamily row;
        row.account = families[i].first->first;
        row.family = families[i].first->second;
        row.counters = *families[i].second;
        row.etimeSeconds = toSeconds(row.counters.etimeNs);
        row.averageSeconds = averageOf(row.counters);
        row.sharePercent = shareOf(row.counters, totals_);
        row.slow = isSlowFilter(row.family);
        out.families.push_back(std::move(row));
    }

    // Per-base attribute usage, summed over the buckets still in the window.
    {
        std::map<std::string, std::uint64_t> baseSearches;
        struct Use {
            std::uint64_t searches{0};
            std::string kind;
        };
        std::map<std::pair<std::string, std::string>, Use> uses;
        for (const Bucket& bucket : buckets_) {
            for (const auto& [base, count] : bucket.baseSearches) {
                baseSearches[base] += count;
            }
            for (const auto& [base, attributes] : bucket.baseAttributes) {
                for (const auto& [attribute, use] : attributes) {
                    auto& target = uses[{base, attribute}];
                    target.searches += use.searches;
                    if (target.kind.empty()) {
                        target.kind = use.kind;
                    }
                }
            }
        }
        // A directory can be queried on many bases: keep the ones that carry
        // the traffic, the long tail is noise for an index decision.
        constexpr std::size_t kMaxBases = 32;
        for (const auto& [base, count] : baseSearches) {
            out.baseTraffic.push_back(BaseTraffic{base, count});
        }
        std::sort(out.baseTraffic.begin(), out.baseTraffic.end(),
                  [](const BaseTraffic& a, const BaseTraffic& b) {
                      return a.searches != b.searches ? a.searches > b.searches : a.base < b.base;
                  });
        if (out.baseTraffic.size() > kMaxBases) {
            out.baseTraffic.resize(kMaxBases);
        }
        for (const auto& [key, use] : uses) {
            out.attributesByBase.push_back(
                BaseAttributeUse{key.first, key.second, use.kind, use.searches});
        }
        std::sort(out.attributesByBase.begin(), out.attributesByBase.end(),
                  [](const BaseAttributeUse& a, const BaseAttributeUse& b) {
                      return a.searches != b.searches ? a.searches > b.searches
                                                      : a.attribute < b.attribute;
                  });
    }

    // The verdict is a measurement, not a shape: any family that takes a large
    // share of the window's etime qualifies.  The filter shape (substring,
    // negation) is recorded on the row as a hint, but gating on it hid the
    // real hogs — an indexed substring filter can be cheap, and an equality
    // filter on a huge base can be expensive.
    std::vector<BehaviorFamily> hogs;
    if (out.enoughTraffic) {
        for (const auto& [key, counters] : familyTotals_) {
            if (counters.ops < kMinFamilyOps && counters.etimeNs < kMinFamilyEtimeNs) {
                continue;
            }
            const double share = shareOf(counters, totals_);
            if (share < kHogSharePercent) {
                continue;
            }
            // The percentage is only a pointer: the absolute figure decides.
            // A family averaging 2 ms is normal work however large its share.
            const double average = averageOf(counters);
            if (average < kHogMinimumAverageSeconds) {
                continue;
            }
            BehaviorFamily hog;
            hog.account = key.first;
            hog.family = key.second;
            hog.counters = counters;
            hog.etimeSeconds = toSeconds(counters.etimeNs);
            hog.averageSeconds = averageOf(counters);
            hog.sharePercent = share;
            hog.slow = isSlowFilter(key.second);  // hint, not a reason
            hogs.push_back(std::move(hog));
        }
        std::sort(hogs.begin(), hogs.end(), [](const BehaviorFamily& a, const BehaviorFamily& b) {
            if (a.sharePercent != b.sharePercent) {
                return a.sharePercent > b.sharePercent;
            }
            return a.account < b.account;
        });
        if (hogs.size() > maxRows) {
            hogs.resize(maxRows);
        }
    }
    out.hogs.reserve(hogs.size());
    for (const BehaviorFamily& hog : hogs) {
        BehaviorHog row;
        row.account = hog.account;
        row.family = hog.family;
        row.counters = hog.counters;
        row.etimeSeconds = hog.etimeSeconds;
        row.averageSeconds = hog.averageSeconds;
        row.sharePercent = hog.sharePercent;
        row.slowShape = hog.slow;
        out.hogs.push_back(std::move(row));
    }
    return out;
}

}  // namespace slaptop::collector
