#include "recovery/provider/Policy.hpp"

#include "db/query/vault/APIKey.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <mutex>
#include <stdexcept>
#include <thread>

namespace vh::recovery::provider::policy {

namespace {

namespace lifecycle = storage::upstream::lifecycle;

std::atomic<unsigned int> policyReadBackReads{6};
std::atomic<int64_t> policyReadBackDelayMs{250};

const std::array<unsigned char, crypto_auth_hmacsha256_KEYBYTES>& policyTokenKey() {
    static const auto key = [] {
        std::array<unsigned char, crypto_auth_hmacsha256_KEYBYTES> k{};
        if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
        randombytes_buf(k.data(), k.size());
        return k;
    }();
    return key;
}

std::string policyHex(const unsigned char* data, const size_t n) {
    static constexpr char digits[] = "0123456789abcdef";
    std::string out;
    out.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        out.push_back(digits[data[i] >> 4]);
        out.push_back(digits[data[i] & 0x0f]);
    }
    return out;
}

std::string policyTokenMessage(const TokenBinding& b, const std::time_t expiresAt) {
    // Length-prefixed fields: no value can be crafted to read as another.
    std::string m = "vaulthalla.recovery.disclosure.v1";
    const auto add = [&](const std::string& v) { m += "|" + std::to_string(v.size()) + ":" + v; };
    add(std::to_string(b.vault_id));
    add(b.bucket.provider);
    add(b.bucket.account_ref.value_or(""));
    add(b.bucket.bucket);
    add(b.retention);
    add(std::to_string(b.actor_id));
    add(b.estimate_digest);
    add(std::to_string(static_cast<int64_t>(expiresAt)));
    return m;
}

std::string policyMac(const TokenBinding& b, const std::time_t expiresAt) {
    const auto message = policyTokenMessage(b, expiresAt);
    unsigned char mac[crypto_auth_hmacsha256_BYTES];
    crypto_auth_hmacsha256(mac, reinterpret_cast<const unsigned char*>(message.data()), message.size(),
                           policyTokenKey().data());
    return policyHex(mac, sizeof mac);
}

std::vector<std::string> policyForeignIds(const std::vector<padmin::LifecycleRule>& rules) {
    std::vector<std::string> out;
    for (const auto& r : rules)
        if (!lifecycle::isVaulthallaRule(r.id)) out.push_back(r.id);
    std::ranges::sort(out);
    return out;
}

}

std::string to_string(const padmin::Versioning v) {
    switch (v) {
    case padmin::Versioning::Unversioned: return "unversioned";
    case padmin::Versioning::Enabled: return "enabled";
    case padmin::Versioning::Suspended: return "suspended";
    case padmin::Versioning::Unknown: break;
    }
    return "unknown";
}

bool VaultBucket::isProtected() const {
    return (row && row->is_protected) || storage::upstream::guard::isProtected(identity);
}

std::string VaultBucket::state() const {
    if (isProtected()) return "protected";
    if (!row) return "unmanaged";
    switch (row->ownership) {
    case storage::upstream::model::Ownership::Managed: return "managed";
    case storage::upstream::model::Ownership::Adopted: return "adopted";
    case storage::upstream::model::Ownership::Unmanaged: break;
    }
    return "unmanaged";
}

std::optional<VaultBucket> bucketForVault(const uint32_t vaultId) {
    const auto& deps = runtime::Deps::get();
    if (!deps.storageManager) return std::nullopt;
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(deps.storageManager->getVault(vaultId));
    if (!s3) return std::nullopt;
    VaultBucket out;
    out.vault_id = vaultId;
    out.bucket = s3->bucket;
    out.api_key_id = s3->api_key_id;
    out.key = db::query::vault::APIKey::getAPIKey(s3->api_key_id);
    if (!out.key) return out;
    out.identity = storage::upstream::identityFor(*out.key, s3->bucket);
    if (out.identity.account_ref)
        out.row = db::query::upstream::Bucket::getByIdentity(out.identity.provider, *out.identity.account_ref, s3->bucket);
    if (out.row) out.versioning = db::query::upstream::Bucket::getVersioning(out.row->id);
    return out;
}

// ---- versioning ----------------------------------------------------------------------------------------------------

ReadBack putAndConfirm(padmin::AdminClient& admin, const std::string& bucket, const padmin::Versioning target) {
    admin.putVersioning(bucket, target);
    ReadBack out;
    const auto reads = std::max(1u, policyReadBackReads.load());
    auto delay = std::chrono::milliseconds(policyReadBackDelayMs.load());
    for (unsigned int i = 0; i < reads; ++i) {
        if (i > 0 && delay.count() > 0) {
            std::this_thread::sleep_for(delay);
            delay = std::min(delay * 2, std::chrono::milliseconds(4000));
        }
        try {
            out.state = admin.versioning(bucket);
            ++out.reads;
        } catch (const padmin::ProviderError& e) {
            ++out.reads;
            if (e.accessDenied()) break;   // the credential can't read it back: report unconfirmed
            continue;
        }
        if (out.state.status == target) {
            out.confirmed = true;
            break;
        }
    }
    return out;
}

void setReadBackForTesting(const unsigned int reads, const std::chrono::milliseconds delay) {
    policyReadBackReads = reads;
    policyReadBackDelayMs = delay.count();
}

// ---- retention -----------------------------------------------------------------------------------------------------

RetentionResult describeRetention(const std::vector<padmin::LifecycleRule>& rules) {
    RetentionResult out;
    out.effective_days = lifecycle::effectiveNoncurrentDays(rules, "");
    for (const auto& e : lifecycle::noncurrentExpirations(rules)) {
        if (lifecycle::isVaulthallaRule(e.rule_id)) continue;
        const auto cover = lifecycle::coverage(e, "");
        if (cover == lifecycle::Coverage::None) continue;
        out.foreign_rules.push_back(e.rule_id + ": " + std::to_string(e.days.value_or(0)) + " days" +
                                    (cover == lifecycle::Coverage::Partial ? " (partial)" : "") +
                                    (e.newer_noncurrent_versions
                                         ? " (keeps the newest " + std::to_string(*e.newer_noncurrent_versions) + ")"
                                         : ""));
        if (cover == lifecycle::Coverage::Whole && (!out.foreign_whole_days || *e.days < *out.foreign_whole_days))
            out.foreign_whole_days = e.days;
    }
    for (const auto& r : rules)
        if (r.id == lifecycle::kOwnedRuleId && !r.prefix.empty() && r.expire_noncurrent_days)
            out.warnings.push_back("Vaulthalla's lifecycle rule applies under the prefix '" + r.prefix +
                                   "' only: noncurrent versions outside it are kept");
    return out;
}

RetentionResult applyRetention(padmin::AdminClient& admin, const std::string& bucket, const ProviderRetention& retention,
                               const bool allowNoncurrent) {
    if (!allowNoncurrent)
        throw std::invalid_argument("this provider has no object versions: noncurrent-version expiration is not supported");
    const auto config = admin.inspect(bucket);
    if (!config.lifecycle_readable)
        throw std::invalid_argument("the lifecycle configuration of bucket '" + bucket +
                                    "' can't be read with this credential, so Vaulthalla can't set the retention");

    const lifecycle::OwnedRuleChange change{
        .abort_incomplete_multipart_days = std::nullopt,
        .expire_current_days = std::nullopt,
        .expire_noncurrent_days = retention.indefinite ? 0u : retention.days,
        .prefix = std::nullopt,
        .clear = false};
    const auto owned = lifecycle::mergeOwnedRule(config.lifecycle, change, allowNoncurrent);
    const auto withManifest = lifecycle::mergeManifestRule(owned.rules, true, allowNoncurrent);

    RetentionResult out;
    out.written = owned.changed || withManifest.changed;
    auto after = config.lifecycle;
    if (out.written) {
        admin.putLifecycle(bucket, withManifest.rules);
        const auto reread = admin.inspect(bucket);
        if (reread.lifecycle_readable) {
            if (policyForeignIds(reread.lifecycle) != policyForeignIds(config.lifecycle))
                throw std::runtime_error("the lifecycle configuration of bucket '" + bucket + "' no longer holds the other "
                                         "rules it had before Vaulthalla's write; check it with the provider");
            after = reread.lifecycle;
        } else {
            after = withManifest.rules;
        }
    }
    auto described = describeRetention(after);
    described.written = out.written;
    // Ours must say what was asked (a provider that silently dropped the element would leave history unbounded).
    std::optional<unsigned int> ours;
    for (const auto& e : lifecycle::noncurrentExpirations(after))
        if (e.rule_id == lifecycle::kOwnedRuleId && e.enabled) ours = e.days;
    if (retention.indefinite ? ours.has_value() : ours != std::optional<unsigned int>(retention.days))
        throw std::runtime_error("the provider did not keep Vaulthalla's noncurrent retention on bucket '" + bucket + "'");
    return described;
}

// ---- disclosure token ----------------------------------------------------------------------------------------------

std::string issueToken(const TokenBinding& binding, const std::time_t expiresAt) {
    return "v1." + std::to_string(static_cast<int64_t>(expiresAt)) + "." + policyMac(binding, expiresAt);
}

bool verifyToken(const std::string& token, const TokenBinding& binding, const std::time_t now) {
    if (!token.starts_with("v1.")) return false;
    const auto dot = token.find('.', 3);
    if (dot == std::string::npos) return false;
    const auto expiresText = token.substr(3, dot - 3);
    if (expiresText.empty() || expiresText.size() > 18 ||
        !std::ranges::all_of(expiresText, [](const char c) { return c >= '0' && c <= '9'; }))
        return false;
    const auto expiresAt = static_cast<std::time_t>(std::stoll(expiresText));
    if (expiresAt <= now) return false;
    const auto expected = policyMac(binding, expiresAt);
    const auto given = token.substr(dot + 1);
    if (given.size() != expected.size()) return false;
    return sodium_memcmp(given.data(), expected.data(), expected.size()) == 0;
}

}
