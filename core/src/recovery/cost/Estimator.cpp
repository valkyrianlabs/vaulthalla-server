#include "recovery/cost/Estimator.hpp"

#include <boost/multiprecision/cpp_dec_float.hpp>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstdio>
#include <ctime>
#include <functional>
#include <iomanip>
#include <set>
#include <sstream>

namespace vh::recovery::cost {

namespace {

using CostDec = boost::multiprecision::cpp_dec_float_50;
using vh::recovery::CostFigure;
using vh::recovery::CostReport;
using vh::recovery::Money;

const CostDec kCostZero{"0"};
const CostDec kCostGb{"1000000000"};
const CostDec kCostHoursPerMonth{"730"};
const CostDec kCostHoursPerDay{"24"};
// 730 / 24 = 365 / 12 days.
const CostDec kCostDaysPerMonth = CostDec{"365"} / CostDec{"12"};
const CostDec kCostYearDays{"365"};

std::string costMoneyText(const CostDec& v) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(8) << (v < kCostZero ? kCostZero : v);
    auto text = out.str();
    if (text == "-0.00000000") text = "0.00000000";
    return text;
}

std::string costDecText(const CostDec& v, const int digits = 6) {
    std::ostringstream out;
    out << std::fixed << std::setprecision(digits) << v;
    auto text = out.str();
    if (text.find('.') != std::string::npos) {
        while (!text.empty() && text.back() == '0') text.pop_back();
        if (!text.empty() && text.back() == '.') text.pop_back();
    }
    if (text.empty() || text == "-0") text = "0";
    return text;
}

uint64_t costToU64(const CostDec& v) {
    if (v <= kCostZero) return 0;
    using boost::multiprecision::floor;
    const CostDec f = floor(v + CostDec{"0.5"});
    return f.convert_to<uint64_t>();
}

CostDec costJsonDec(const nlohmann::json& v) {
    try {
        if (v.is_string()) return CostDec(v.get<std::string>());
        if (v.is_number_unsigned()) return CostDec(v.get<unsigned long long>());
        if (v.is_number_integer()) return CostDec(v.get<long long>());
        if (v.is_number_float()) return CostDec(v.dump());
    } catch (const std::exception&) {
    }
    return kCostZero;
}

std::optional<std::string> costJsonString(const nlohmann::json& obj, const char* key) {
    if (!obj.is_object()) return std::nullopt;
    const auto it = obj.find(key);
    if (it == obj.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

// ---- rates from a profile -------------------------------------------------------------------------------------------

struct CostRates {
    std::string currency;
    CostDec storage_byte_month{"0"};       // per byte-month, first volume tier
    std::string storage_rate_text;         // as the profile states it, e.g. "0.023 per gb_month"
    std::optional<CostDec> egress_per_gb, retrieval_per_gb;
    std::optional<CostDec> get_request, put_request, copy_request, head_request;
    unsigned int min_days{0};
    uint64_t min_size{0};
    bool versioning_block{false};
    std::string versioning_status{"supported"};
    std::vector<std::string> exclusions;
};

const nlohmann::json* costFirstTier(const nlohmann::json& meter) {
    if (!meter.is_object() || !meter.contains("tiers") || !meter.at("tiers").is_array() || meter.at("tiers").empty())
        return nullptr;
    return &meter.at("tiers").at(0);
}

const nlohmann::json* costMeterOfType(const nlohmann::json& raw, const std::string& type) {
    if (!raw.contains("meters") || !raw.at("meters").is_object()) return nullptr;
    for (const auto& [key, meter] : raw.at("meters").items()) {
        (void)key;
        if (meter.is_object() && meter.value("meter_type", "") == type) return &meter;
    }
    return nullptr;
}

// A byte-quantity rate (gb / gib) as a price per GB (10^9 bytes).
std::optional<CostDec> costPerGb(const nlohmann::json* meter) {
    if (!meter) return std::nullopt;
    const auto* tier = costFirstTier(*meter);
    if (!tier || !tier->contains("rate")) return std::nullopt;
    const auto rate = costJsonDec(tier->at("rate"));
    const auto unit = costJsonString(*tier, "rate_unit").value_or("gb");
    if (unit == "gb") return rate;
    if (unit == "gib") return CostDec(rate * kCostGb / CostDec{"1073741824"});
    if (unit == "tb") return CostDec(rate / CostDec{"1000"});
    if (unit == "tib") return CostDec(rate * kCostGb / CostDec{"1099511627776"});
    return std::nullopt;
}

std::optional<CostDec> costRequestPrice(const nlohmann::json& raw, const std::vector<std::string>& operations) {
    if (!raw.contains("operation_map") || !raw.at("operation_map").is_object()) return std::nullopt;
    const auto& map = raw.at("operation_map");
    for (const auto& op : operations) {
        const auto it = map.find(op);
        if (it == map.end() || !it->is_object()) continue;
        const auto meterKey = costJsonString(*it, "meter_key");
        if (!meterKey || !raw.contains("meters") || !raw.at("meters").contains(*meterKey)) continue;
        const auto* tier = costFirstTier(raw.at("meters").at(*meterKey));
        if (!tier || !tier->contains("rate")) continue;
        const auto multiplier = it->contains("multiplier") ? costJsonDec(it->at("multiplier")) : CostDec{"1"};
        const auto rate = costJsonDec(tier->at("rate"));
        const auto unit = costJsonString(*tier, "rate_unit").value_or("operation");
        CostDec per{"1"};
        if (unit == "request_1000") per = CostDec{"1000"};
        else if (unit == "request_10000") per = CostDec{"10000"};
        else if (unit == "million_operations") per = CostDec{"1000000"};
        else if (unit != "operation") continue;
        return CostDec(rate * multiplier / per);
    }
    return std::nullopt;
}

// nullopt + reason when the profile can't price noncurrent storage.
std::optional<CostRates> costRatesFrom(const storage::s3::pricing::RatingProfile& profile, std::string& reason) {
    const auto& raw = profile.raw;
    CostRates r;
    r.currency = raw.contains("scope") ? costJsonString(raw.at("scope"), "currency").value_or("") : "";
    if (r.currency.empty()) {
        reason = "the price profile has no currency";
        return std::nullopt;
    }

    if (raw.contains("versioning") && raw.at("versioning").is_object()) {
        const auto& v = raw.at("versioning");
        r.versioning_block = true;
        r.versioning_status = costJsonString(v, "status").value_or("supported");
        const bool supported = v.value("supported", true);
        if (!supported || r.versioning_status == "unsupported") {
            reason = costJsonString(v, "reason").value_or("the price catalog says this provider has no object versioning");
            return std::nullopt;
        }
        if (const auto billing = costJsonString(v, "noncurrent_storage_billing"); billing && *billing != "storage_class_rate") {
            reason = "the price catalog bills noncurrent versions by a rule Vaulthalla doesn't model ('" + *billing + "')";
            return std::nullopt;
        }
        if (v.contains("minimum_storage_duration_days")) r.min_days = costToU64(costJsonDec(v.at("minimum_storage_duration_days")));
        if (v.contains("minimum_billable_object_size_bytes"))
            r.min_size = costToU64(costJsonDec(v.at("minimum_billable_object_size_bytes")));
    } else if (raw.contains("storage_rules") && raw.at("storage_rules").is_array() && !raw.at("storage_rules").empty()) {
        const auto& rule = raw.at("storage_rules").at(0);
        if (rule.contains("minimum_storage_duration_days") && !rule.at("minimum_storage_duration_days").is_null())
            r.min_days = costToU64(costJsonDec(rule.at("minimum_storage_duration_days")));
        if (rule.contains("minimum_billable_object_size_bytes") && !rule.at("minimum_billable_object_size_bytes").is_null())
            r.min_size = costToU64(costJsonDec(rule.at("minimum_billable_object_size_bytes")));
    }
    if (!r.versioning_block && profile.provider_id != "aws-s3") {
        reason = "the price catalog has no versioning rules for this provider";
        return std::nullopt;
    }

    const auto* storage = costMeterOfType(raw, "storage_byte_hours");
    const auto* tier = storage ? costFirstTier(*storage) : nullptr;
    if (!tier || !tier->contains("rate")) {
        reason = "the price profile has no storage rate";
        return std::nullopt;
    }
    const auto rate = costJsonDec(tier->at("rate"));
    const auto unit = costJsonString(*tier, "rate_unit").value_or("");
    if (unit == "gb_month") r.storage_byte_month = rate / kCostGb;
    else if (unit == "gib_month") r.storage_byte_month = rate / CostDec{"1073741824"};
    else if (unit == "tb_month") r.storage_byte_month = rate / CostDec{"1000000000000"};
    else if (unit == "tib_month") r.storage_byte_month = rate / CostDec{"1099511627776"};
    else {
        reason = "the price profile's storage rate unit '" + unit + "' is not one Vaulthalla prices";
        return std::nullopt;
    }
    r.storage_rate_text = costDecText(rate, 10) + " " + r.currency + " per " + unit;

    r.egress_per_gb = costPerGb(costMeterOfType(raw, "egress_bytes"));
    r.retrieval_per_gb = costPerGb(costMeterOfType(raw, "retrieval_bytes"));
    r.get_request = costRequestPrice(raw, {"GetObjectVersion", "GetObject"});
    r.put_request = costRequestPrice(raw, {"PutObject"});
    r.copy_request = costRequestPrice(raw, {"CopyObjectVersion", "CopyObject"});
    r.head_request = costRequestPrice(raw, {"HeadObjectVersion", "HeadObject"});

    if (raw.contains("known_exclusions") && raw.at("known_exclusions").is_array())
        for (const auto& e : raw.at("known_exclusions"))
            if (e.is_string()) r.exclusions.push_back(e.get<std::string>());
    return r;
}

// ---- the flow of new noncurrent data -------------------------------------------------------------------------------

struct CostFlow {
    CostDec bytes_per_day{"0"};       // noncurrent bytes created per day (overwrites, deletes, metadata rewrites)
    CostDec versions_per_day{"0"};
    CostDec markers_per_day{"0"};
    CostDec manifest_per_day{"0"};    // index manifest republishes
};

struct CostShape {
    CostDec manifest_bytes{"0"};
    CostDec key_bytes{"64"};
    unsigned int min_days{0};
    CostDec min_size{"0"};
};

// Bytes billed per day of new versions: each version at least the minimum billable size.
CostDec costBilledFlow(const CostFlow& f, const CostShape& s) {
    if (s.min_size > kCostZero && f.versions_per_day > kCostZero)
        return std::max(f.bytes_per_day, CostDec(f.versions_per_day * s.min_size));
    return f.bytes_per_day;
}

// Billed byte stock after `elapsedDays` with versions expiring after `retentionDays` (nullopt: kept).
CostDec costBilledStock(const CostFlow& f, const CostShape& s, const std::optional<CostDec>& retentionDays,
                        const CostDec& elapsedDays) {
    // A version deleted before the minimum storage duration still bills it.
    CostDec life = elapsedDays;
    if (retentionDays) life = std::min(elapsedDays, std::max(*retentionDays, CostDec(s.min_days)));
    const auto versions = costBilledFlow(f, s) * life;
    // Delete markers stay current (nothing of Vaulthalla's expires them): they accumulate.
    const auto markers = f.markers_per_day * elapsedDays * s.key_bytes;
    // Superseded manifests: noncurrent one day (+ a day of lifecycle lag), each at least the minimums.
    const auto manifestLife = std::min(elapsedDays, std::max(CostDec(kManifestBilledDays), CostDec(s.min_days)));
    const auto manifest = f.manifest_per_day * std::max(s.manifest_bytes, s.min_size) * manifestLife;
    return versions + markers + manifest;
}

CostDec costNoncurrentBytes(const CostFlow& f, const std::optional<CostDec>& retentionDays, const CostDec& elapsedDays) {
    const auto life = retentionDays ? std::min(elapsedDays, *retentionDays) : elapsedDays;
    return f.bytes_per_day * life;
}

struct CostRange {
    CostFlow expected, low, high;
    bool ranged{false};
    std::string basis;        // observed | illustrative
};

std::optional<Money> costMoney(const std::optional<CostRates>& rates, const CostDec& amount) {
    if (!rates) return std::nullopt;
    return Money{.amount = costMoneyText(amount), .currency = rates->currency};
}

CostFigure costFigure(const std::optional<CostRates>& rates, const CostRange& range,
                      const std::function<CostDec(const CostFlow&)>& amountOf, const std::optional<std::string>& unpriced) {
    CostFigure out;
    out.basis = range.basis;
    if (!rates) {
        out.reason = unpriced;
        return out;
    }
    out.expected = costMoney(rates, amountOf(range.expected));
    if (range.ranged) {
        out.low = costMoney(rates, amountOf(range.low));
        out.high = costMoney(rates, amountOf(range.high));
    }
    return out;
}

std::optional<CostDec> costRetentionDays(const std::optional<ProviderRetention>& retention,
                                         const std::optional<unsigned int>& foreign) {
    std::optional<CostDec> days;
    if (retention && !retention->indefinite) days = CostDec(retention->days);
    if (foreign && (!days || CostDec(*foreign) < *days)) days = CostDec(*foreign);
    return days;
}

std::string costScenarioName(const std::optional<ProviderRetention>& r) {
    if (!r) return "unset";
    return r->str();
}

}

CostReport estimate(const Inputs& in) {
    CostReport out;
    out.vault_id = in.vault_id;
    out.provider = in.provider;
    out.bucket = in.bucket;
    out.region = in.region;
    out.storage_class = in.storage_class;
    out.computed_at = in.now;
    if (in.retention) out.retention = in.retention->str();

    // ---- catalog and rates ----
    std::optional<CostRates> rates;
    std::optional<std::string> unpriced = in.unpriced_reason;
    if (in.catalog.profile) {
        const auto& p = *in.catalog.profile;
        out.catalog.version = p.catalog_version.empty() ? std::nullopt : std::make_optional(p.catalog_version);
        out.catalog.source = in.catalog.source.empty() ? std::nullopt : std::make_optional(in.catalog.source);
        out.catalog.verified = in.catalog.verified;
        out.catalog.stale = in.catalog.stale;
        if (in.catalog.age_seconds && *in.catalog.age_seconds >= 0)
            out.catalog.age_seconds = static_cast<uint64_t>(*in.catalog.age_seconds);
        out.catalog.note = in.catalog.note;
        if (!unpriced) {
            std::string why;
            rates = costRatesFrom(p, why);
            if (!rates) unpriced = why;
        }
    } else if (!unpriced) {
        unpriced = in.catalog.error.empty() ? std::string("no price profile for this provider, region and storage class")
                                            : in.catalog.error;
    }
    if (rates) {
        out.priced = true;
        out.currency = rates->currency;
    } else {
        out.priced = false;
        out.unpriced_reason = unpriced;
        rates.reset();
    }

    // ---- observation ----
    db::query::recovery::UsageCounters sum;
    std::vector<CostDec> dailyNew;
    std::optional<std::string> first, last;
    for (const auto& d : in.usage) {
        sum += d.counters;
        const auto& c = d.counters;
        dailyNew.emplace_back(CostDec(c.overwritten_bytes) + CostDec(c.deleted_bytes));
        if (!first || d.day < *first) first = d.day;
        if (!last || d.day > *last) last = d.day;
    }
    const auto days = static_cast<uint32_t>(in.usage.size());
    auto& obs = out.observation;
    obs.window_days = days;
    obs.first_day = first;
    obs.last_day = last;
    obs.sufficient = days >= kSufficientDays;
    obs.put_requests = sum.put_requests;
    obs.copy_requests = sum.copy_requests;
    obs.delete_requests = sum.delete_requests;
    obs.get_requests = sum.get_requests;
    obs.list_requests = sum.list_requests;
    obs.first_put_objects = sum.first_put_objects;
    obs.overwrite_objects = sum.overwrite_objects;
    obs.deleted_objects = sum.deleted_objects;
    obs.overwritten_bytes = sum.overwritten_bytes;
    obs.deleted_bytes = sum.deleted_bytes;
    obs.uploaded_bytes = sum.uploaded_bytes;

    // ---- current objects ----
    out.current.objects = in.current_objects;
    out.current.bytes = in.current_bytes;
    if (rates) out.current.monthly_storage = costMoney(rates, CostDec(in.current_bytes) * rates->storage_byte_month);

    // ---- history ----
    out.history.known_noncurrent_versions = in.history.versions;
    out.history.known_noncurrent_bytes = in.history.bytes;
    out.history.delete_markers = in.history.delete_markers;
    out.history.unknown_size_versions = in.history.unknown_size;
    const bool versioned = in.versioning_status == "enabled" || in.versioning_status == "suspended";
    if (!versioned && in.versioning_status != "unknown") {
        out.history.unaccounted_history = false;
    } else if (versioned && !in.enabled_by_vaulthalla) {
        out.history.unaccounted_history = true;   // versions may predate Vaulthalla's management and monitoring
    } else {
        bool predates = false;
        if (in.history.oldest_last_modified && in.first_usage_day) {
            const auto firstDay = *in.first_usage_day;
            std::tm tm{};
            const auto t = static_cast<std::time_t>(*in.history.oldest_last_modified);
            gmtime_r(&t, &tm);
            char buf[32];
            std::snprintf(buf, sizeof buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
            predates = std::string(buf) < firstDay;
        }
        out.history.unaccounted_history = in.versioning_status == "unknown" || predates;
    }

    // ---- shape and flow ----
    CostShape shape;
    shape.manifest_bytes = std::max(CostDec(kManifestMinBytes), CostDec(CostDec(in.current_objects) * CostDec(kManifestBytesPerObject)));
    shape.key_bytes = CostDec(in.average_key_bytes.value_or(kDefaultKeyBytes));
    if (rates) {
        shape.min_days = rates->min_days;
        shape.min_size = CostDec(rates->min_size);
    }
    const CostDec avgObject =
        in.current_objects > 0 ? CostDec(CostDec(in.current_bytes) / CostDec(in.current_objects)) : kCostZero;

    CostRange range;
    const CostDec daysDec(days);
    if (days > 0) {
        range.basis = "observed";
        // Metadata rewrites (CopyObject onto the same key, never a restore) each keep a full noncurrent copy.
        const auto rewrites = sum.copy_requests > sum.version_restore_requests ? sum.copy_requests - sum.version_restore_requests : 0;
        const auto objectPuts = sum.first_put_objects + sum.overwrite_objects + sum.multipart_parts + sum.multipart_uploads;
        const auto manifestPuts = sum.put_requests > objectPuts ? sum.put_requests - objectPuts : 0;
        const auto make = [&](const CostDec& newBytes) {
            CostFlow f;
            f.bytes_per_day = newBytes + CostDec(rewrites) * avgObject / daysDec;
            f.versions_per_day = (CostDec(sum.overwrite_objects) + CostDec(sum.deleted_objects) + CostDec(rewrites)) / daysDec;
            f.markers_per_day = CostDec(sum.deleted_objects) / daysDec;
            f.manifest_per_day = CostDec(manifestPuts) / daysDec;
            return f;
        };
        const CostDec total = CostDec(sum.overwritten_bytes) + CostDec(sum.deleted_bytes);
        range.expected = make(total / daysDec);
        if (days < kSufficientDays) {
            range.ranged = true;
            auto lo = *std::min_element(dailyNew.begin(), dailyNew.end());
            auto hi = *std::max_element(dailyNew.begin(), dailyNew.end());
            if (lo == hi) {
                lo = total / daysDec / CostDec{"2"};
                hi = total / daysDec * CostDec{"2"};
            }
            range.low = make(lo);
            range.high = make(hi);
        }
        out.assumptions.push_back({.kind = "observed",
                                   .text = "Measured over " + std::to_string(days) + " UTC day(s) (" + first.value_or("") +
                                           " to " + last.value_or("") + "): " +
                                           costDecText(total / daysDec, 0) + " bytes/day overwritten or deleted, " +
                                           costDecText(CostDec(rewrites) / daysDec, 2) + " metadata rewrites/day, " +
                                           costDecText(CostDec(sum.deleted_objects) / daysDec, 2) + " deletes/day, " +
                                           costDecText(CostDec(manifestPuts) / daysDec, 2) + " index manifest publishes/day."});
        if (rewrites > 0)
            out.assumptions.push_back({.kind = "observed",
                                       .text = "Each metadata rewrite keeps a full noncurrent copy, sized at the average "
                                               "current object (" + costDecText(avgObject, 0) + " bytes)."});
    } else {
        range.basis = "illustrative";
        range.ranged = true;
        const auto make = [&](const char* share) {
            CostFlow f;
            f.bytes_per_day = CostDec(in.current_bytes) * CostDec(share) / kCostDaysPerMonth;
            f.versions_per_day = CostDec(in.current_objects) * CostDec(share) / kCostDaysPerMonth;
            f.markers_per_day = kCostZero;
            f.manifest_per_day = CostDec(kIllustrativeManifestPublishesPerDay);
            return f;
        };
        range.expected = make(kIllustrativeExpected);
        range.low = make(kIllustrativeLow);
        range.high = make(kIllustrativeHigh);
        out.assumptions.push_back({.kind = "illustrative",
                                   .text = "Nothing measured yet: 1 %, 5 % and 20 % of the current " +
                                           std::to_string(in.current_bytes) +
                                           " bytes rewritten per month (low, expected, high), no deletes, and " +
                                           std::to_string(kIllustrativeManifestPublishesPerDay) +
                                           " index manifest publishes per day."});
    }
    obs.overwritten_bytes_per_day = costDecText(range.expected.bytes_per_day, 0);

    if (rates) {
        out.assumptions.push_back({.kind = "provider_rule",
                                   .text = "Noncurrent versions bill at the storage class rate (" + rates->storage_rate_text +
                                           ", first volume tier); each version is a full copy."});
        if (!rates->versioning_block)
            out.assumptions.push_back({.kind = "provider_rule",
                                       .text = "The price catalog has no versioning rules for this profile: noncurrent "
                                               "versions are priced at the storage class rate, as AWS documents."});
        if (rates->min_days > 0)
            out.assumptions.push_back({.kind = "provider_rule",
                                       .text = "Minimum storage duration " + std::to_string(rates->min_days) +
                                               " days: a version expired sooner still bills " +
                                               std::to_string(rates->min_days) + " days."});
        if (rates->min_size > 0)
            out.assumptions.push_back({.kind = "provider_rule",
                                       .text = "Minimum billable object size " + std::to_string(rates->min_size) +
                                               " bytes per version."});
        out.assumptions.push_back({.kind = "provider_rule",
                                   .text = "Delete markers bill as their key name's bytes and stay until removed: they "
                                           "accumulate."});
        out.assumptions.push_back({.kind = "observed",
                                   .text = "Average key name: " + costDecText(shape.key_bytes, 0) + " bytes."});
        out.assumptions.push_back({.kind = "provider_rule",
                                   .text = "Versioning adds no request charges for writes; lifecycle expirations and "
                                           "DELETE requests are free."});
    }
    out.assumptions.push_back({.kind = "illustrative",
                               .text = "The index manifest (.vaulthalla/index-v1.json, about " +
                                       costDecText(shape.manifest_bytes, 0) +
                                       " bytes) is republished every sync pass; Vaulthalla's lifecycle rule expires its "
                                       "old versions after 1 day (billed about 2 days each)."});
    out.assumptions.push_back({.kind = "illustrative",
                               .text = "1 month = 730 hours (365/12 days); 12 months = 365 days."});

    // ---- figures ----
    const auto chosenDays = costRetentionDays(in.retention, in.foreign_noncurrent_days);
    const bool retentionKnown = in.retention.has_value() || in.foreign_noncurrent_days.has_value() || versioned;
    const auto monthlyAt = [&](const std::optional<CostDec>& retention, const CostDec& elapsed) {
        return [&, retention, elapsed](const CostFlow& f) -> CostDec {
            if (!rates) return kCostZero;
            return CostDec(costBilledStock(f, shape, retention, elapsed) * rates->storage_byte_month);
        };
    };
    // Steady state: one retention period in (indefinite: 12 months).
    const auto steadyElapsed = [&](const std::optional<CostDec>& retention) -> CostDec {
        if (!retention) return kCostYearDays;
        return std::max({*retention, CostDec(shape.min_days), CostDec(kManifestBilledDays)});
    };

    if (retentionKnown) {
        const auto elapsed = steadyElapsed(chosenDays);
        out.pre_activation_monthly = costFigure(rates, range, monthlyAt(chosenDays, elapsed), unpriced);
        out.projected_monthly = out.pre_activation_monthly;
        if (!chosenDays) {
            const auto note = std::string("no retention: versions are kept until something deletes them (after 12 months)");
            if (!out.pre_activation_monthly.reason) out.pre_activation_monthly.reason = note;
            if (!out.projected_monthly.reason) out.projected_monthly.reason = note;
        }
    } else {
        const auto why = std::string("no retention chosen: see the scenarios");
        out.pre_activation_monthly.basis = range.basis;
        out.pre_activation_monthly.reason = rates ? why : unpriced;
        out.projected_monthly = out.pre_activation_monthly;
    }

    // Accumulation over 12 months under the chosen retention (none chosen: kept indefinitely).
    for (unsigned int month = 1; month <= 12; ++month) {
        const CostDec elapsed = kCostDaysPerMonth * CostDec(month);
        vh::recovery::AccumulationPoint point;
        point.month = month;
        point.noncurrent_bytes = costToU64(costNoncurrentBytes(range.expected, chosenDays, elapsed));
        point.monthly_cost = costFigure(rates, range, monthlyAt(chosenDays, elapsed), unpriced);
        out.accumulation.push_back(std::move(point));
    }

    // Retention scenarios.
    const std::vector<std::optional<ProviderRetention>> scenarioRetentions{
        ProviderRetention{.indefinite = false, .days = 30}, ProviderRetention{.indefinite = false, .days = 90},
        ProviderRetention{.indefinite = false, .days = 365}, ProviderRetention{.indefinite = true, .days = 0}};
    for (const auto& r : scenarioRetentions) {
        vh::recovery::RetentionScenario sc;
        sc.retention = costScenarioName(r);
        const auto scDays = costRetentionDays(r, in.foreign_noncurrent_days);
        const auto elapsed = steadyElapsed(scDays);
        sc.steady_noncurrent_bytes = costToU64(costNoncurrentBytes(range.expected, scDays, elapsed));
        sc.monthly_cost = costFigure(rates, range, monthlyAt(scDays, elapsed), unpriced);
        if (r->indefinite) sc.notes.emplace_back("keeps growing: the figures are after 12 months");
        if (in.foreign_noncurrent_days && (r->indefinite || *in.foreign_noncurrent_days < r->days))
            sc.notes.push_back("another application's lifecycle rule already expires noncurrent versions after " +
                               std::to_string(*in.foreign_noncurrent_days) + " days");
        if (rates && rates->min_days > 0 && scDays && *scDays < CostDec(rates->min_days))
            sc.notes.push_back("shorter than the storage class's " + std::to_string(rates->min_days) +
                               "-day minimum: each version still bills " + std::to_string(rates->min_days) + " days");
        if (rates && rates->min_size > 0)
            sc.notes.push_back("each version bills at least " + std::to_string(rates->min_size) + " bytes");
        out.scenarios.push_back(std::move(sc));
    }

    // ---- after activation: this calendar month ----
    if (versioned && in.month_to_date_byte_hours) {
        CostDec byteHours{"0"};
        try {
            byteHours = CostDec(*in.month_to_date_byte_hours);
        } catch (const std::exception&) {
        }
        std::tm tm{};
        gmtime_r(&in.now, &tm);
        std::tm next = tm;
        next.tm_mday = 1;
        next.tm_hour = next.tm_min = next.tm_sec = 0;
        next.tm_mon += 1;
        const auto monthEnd = timegm(&next);
        const CostDec remainingHours = CostDec(std::max<std::time_t>(0, monthEnd - in.now)) / CostDec{"3600"};
        const CostDec current = CostDec(in.history.bytes);
        const bool growing = in.versioning_status == "enabled";
        const auto mtdAmount = [&](const CostFlow&) -> CostDec {
            if (!rates) return kCostZero;
            return CostDec(byteHours / kCostHoursPerMonth * rates->storage_byte_month);
        };
        const auto projectedAmount = [&](const CostFlow& f) -> CostDec {
            if (!rates) return kCostZero;
            CostDec growth = kCostZero;
            if (growing) growth = f.bytes_per_day * remainingHours * remainingHours / (CostDec{"2"} * kCostHoursPerDay);
            return CostDec((byteHours + current * remainingHours + growth) / kCostHoursPerMonth * rates->storage_byte_month);
        };
        CostRange observedOnly = range;
        observedOnly.ranged = false;
        observedOnly.basis = "observed";
        out.current_month_to_date = costFigure(rates, observedOnly, mtdAmount, unpriced);
        out.current_month_projected = costFigure(rates, range, projectedAmount, unpriced);
        out.current_month_projected.basis = range.basis == "observed" ? "observed" : "scenario";
        if (in.history.unknown_size > 0) {
            const auto note = std::to_string(in.history.unknown_size) + " version(s) without a known size are not included";
            out.current_month_to_date.reason = note;
            out.current_month_projected.reason = note;
        }
    } else {
        const auto why = std::string("provider versioning is not active on this bucket");
        out.current_month_to_date.basis = "observed";
        out.current_month_to_date.reason = rates ? why : unpriced;
        out.current_month_projected.basis = "observed";
        out.current_month_projected.reason = rates ? why : unpriced;
    }

    // ---- recovery operations ----
    out.recovery_per_gb.basis = "scenario";
    out.recovery_per_object.basis = "scenario";
    if (rates) {
        if (rates->egress_per_gb && rates->get_request && rates->put_request) {
            CostDec perGb = *rates->egress_per_gb + *rates->get_request + *rates->put_request;
            if (rates->retrieval_per_gb) perGb += *rates->retrieval_per_gb;
            out.recovery_per_gb.expected = costMoney(rates, perGb);
            out.recovery_per_gb.reason = "restore by transfer: one GET + one PUT and 1 GB downloaded (data transfer out"
                                         + std::string(rates->retrieval_per_gb ? " + retrieval" : "") + ")";
        } else {
            out.recovery_per_gb.reason = "the price profile lacks a GET, PUT or data transfer rate";
        }
        if (rates->copy_request) {
            CostDec perObject = *rates->copy_request + rates->head_request.value_or(kCostZero);
            std::string why = "restore by provider copy: one HEAD + one CopyObject";
            if (rates->retrieval_per_gb) {
                CostDec avgVersion = avgObject;
                if (in.history.versions > 0 && in.history.bytes > 0)
                    avgVersion = CostDec(in.history.bytes) / CostDec(in.history.versions);
                perObject += *rates->retrieval_per_gb * avgVersion / kCostGb;
                why += " + retrieval of an average version (" + costDecText(avgVersion, 0) + " bytes)";
            }
            out.recovery_per_object.expected = costMoney(rates, perObject);
            out.recovery_per_object.reason = why;
        } else {
            out.recovery_per_object.reason = "the price profile lacks a CopyObject rate";
        }
    } else {
        out.recovery_per_gb.reason = unpriced;
        out.recovery_per_object.reason = unpriced;
    }

    // ---- unmodeled ----
    std::vector<std::string> unmodeled{
        "account-level free tier", "taxes", "discounts, credits and private pricing", "volume tiers beyond the first",
        "storage-class transitions and their early-deletion charges", "S3 Intelligent-Tiering monitoring and automation",
        "replication", "requests and storage of other applications using the bucket"};
    if (rates)
        for (const auto& e : rates->exclusions)
            if (std::ranges::find(unmodeled, e) == unmodeled.end()) unmodeled.push_back(e);
    out.unmodeled = std::move(unmodeled);

    // ---- confidence ----
    if (!rates) {
        out.confidence = "none";
        out.confidence_reasons.push_back(unpriced.value_or("costs can't be priced"));
    } else if (range.basis == "illustrative") {
        out.confidence = "low";
        out.confidence_reasons.emplace_back("no usage measurements yet: the figures are illustrative");
    } else if (days < kSufficientDays) {
        out.confidence = "low";
        out.confidence_reasons.push_back("only " + std::to_string(days) + " day(s) measured: a range is shown");
    } else {
        out.confidence = "high";
        if (!in.catalog.verified) {
            out.confidence = "medium";
            out.confidence_reasons.emplace_back("the price catalog's signature was not verified");
        }
        if (in.catalog.stale) {
            out.confidence = "medium";
            out.confidence_reasons.emplace_back("the price catalog is stale");
        }
        if (!rates->versioning_block || rates->versioning_status == "unverified") {
            out.confidence = "medium";
            out.confidence_reasons.emplace_back("the price catalog's versioning rules are missing or unverified");
        }
        if (out.confidence == "high") out.confidence_reasons.emplace_back("measured over " + std::to_string(days) + " days");
    }
    if (rates && in.catalog.profile && !in.catalog.verified && out.confidence != "medium")
        out.confidence_reasons.emplace_back("the price catalog's signature was not verified");

    // ---- alert ----
    if (in.alert_threshold && !in.alert_threshold->empty()) {
        out.alert.threshold = Money{.amount = *in.alert_threshold, .currency = rates ? rates->currency : std::string("USD")};
        if (rates && out.projected_monthly.expected) {
            try {
                out.alert.exceeded = CostDec(out.projected_monthly.expected->amount) > CostDec(*in.alert_threshold);
            } catch (const std::exception&) {
                out.alert.exceeded = false;
            }
        }
    }
    return out;
}

std::string pricingDigest(const CostReport& report) {
    nlohmann::json j = {{"priced", report.priced},
                        {"currency", report.currency.value_or("")},
                        {"catalog", report.catalog.version.value_or("")},
                        {"provider", report.provider.value_or("")},
                        {"region", report.region.value_or("")},
                        {"class", report.storage_class.value_or("")},
                        {"unpriced", report.unpriced_reason.value_or("")}};
    nlohmann::json rules = nlohmann::json::array();
    for (const auto& a : report.assumptions)
        if (a.kind == "provider_rule") rules.push_back(a.text);
    j["rules"] = std::move(rules);
    const auto text = j.dump();
    unsigned char hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(hash, reinterpret_cast<const unsigned char*>(text.data()), text.size());
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(sizeof hash * 2);
    for (const auto b : hash) {
        out.push_back(hex[b >> 4]);
        out.push_back(hex[b & 0x0f]);
    }
    return out;
}

}
