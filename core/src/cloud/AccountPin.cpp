#include "cloud/AccountPin.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "log/Registry.hpp"
#include <paths.h>

#include <vl/keykit/recovery_policy.hpp>
#include <vl/keykit/secret.hpp>

#include <sodium.h>

#include <algorithm>
#include <mutex>

namespace vh::cloud::pin {

// Named, not anonymous: the unity build joins this file with others.
namespace pin_detail {

constexpr std::size_t kKeySize = 32;
constexpr std::string_view kMacLabel = "vh.cloud-account-key-row.v1";

std::string slot() { return paths::testMode ? "test_cloud_account_pin" : "cloud_account_pin"; }

std::mutex keyMutex;
std::optional<vl::keykit::SecretBytes> cached;

// The unsealed key, sealing a fresh one when `create` and there is none. Throws KeyLost.
const vl::keykit::SecretBytes& key(const bool create) {
    if (cached) return *cached;
    crypto::secrets::KeyProvider provider(slot());
    if (!provider.sealedExists()) {
        if (!create) throw KeyLost("no account key pin is sealed on this host");
        auto fresh = vl::keykit::SecretBytes::random(kKeySize);
        provider.updateMasterKey(fresh.bytes());
        cached.emplace(std::move(fresh));
        return *cached;
    }
    try {
        provider.init();
    } catch (const std::exception& e) {
        throw KeyLost(std::string("the account key pin no longer unseals on this host (") + e.what() + ")");
    }
    if (provider.getMasterKey().size() != kKeySize) throw KeyLost("the sealed account key pin has the wrong size");
    cached.emplace(provider.getMasterKey());
    return *cached;
}

// The MAC's input: a label, then every column, each as a 4-byte big-endian length and its bytes (0xffffffff for a
// null). Integers and times are decimal text.
class Input {
public:
    Input() { add(kMacLabel); }
    void add(const std::string_view s) {
        length(static_cast<uint32_t>(s.size()));
        bytes_.insert(bytes_.end(), s.begin(), s.end());
    }
    template <std::size_t N>
    void add(const std::array<uint8_t, N>& a) {
        length(static_cast<uint32_t>(N));
        bytes_.insert(bytes_.end(), a.begin(), a.end());
    }
    template <typename T>
    void addOpt(const std::optional<T>& v) {
        if (v) add(*v);
        else length(0xffffffffu);
    }
    void addNumber(const int64_t n) { add(std::to_string(n)); }
    [[nodiscard]] const std::vector<uint8_t>& bytes() const { return bytes_; }

private:
    void length(const uint32_t n) {
        for (int shift = 24; shift >= 0; shift -= 8) bytes_.push_back(static_cast<uint8_t>(n >> shift));
    }
    std::vector<uint8_t> bytes_;
};

Mac compute(const db::query::cloud::AccountKeyRow& r, const vl::keykit::SecretBytes& k) {
    Input in;
    in.add(r.account_public_id);
    in.addNumber(r.generation);
    in.add(r.fingerprint);
    in.add(r.x25519_public);
    in.add(r.ed25519_public);
    in.add(r.statement);
    in.add(r.signature);
    in.addOpt(r.previous_signature);
    in.add(r.link);
    in.add(r.state);
    in.addOpt(r.confirmed_by);
    if (r.confirmed_at) in.addNumber(static_cast<int64_t>(*r.confirmed_at));
    else in.addOpt(std::optional<std::string>{});
    in.addNumber(r.policy_sequence);
    in.addOpt(r.policy_sha256);
    in.addOpt(r.policy);
    in.addOpt(r.policy_signature);
    in.addNumber(static_cast<int64_t>(r.stored_at));
    Mac out{};
    crypto_auth_hmacsha256_state st;
    crypto_auth_hmacsha256_init(&st, k.bytes().data(), k.bytes().size());
    crypto_auth_hmacsha256_update(&st, in.bytes().data(), in.bytes().size());
    crypto_auth_hmacsha256_final(&st, out.data());
    sodium_memzero(&st, sizeof(st));
    return out;
}

Checked check(std::vector<db::query::cloud::AccountKeyRow> rows) {
    Checked out;
    for (auto& r : rows) {
        bool ok = false;
        try {
            std::scoped_lock lock(keyMutex);
            const auto m = compute(r, key(false));
            ok = sodium_memcmp(m.data(), r.mac.data(), m.size()) == 0;
        } catch (const KeyLost&) {
            out.key_lost = true;
        }
        if (ok) out.rows.push_back(std::move(r));
        else out.tampered.push_back(r.generation);
    }
    if (!out.tampered.empty())
        log::Registry::crypto()->error("[cloud::pin] {} account recovery key row(s) fail their MAC{}: nothing is wrapped "
                                       "to that account's key until `vh cloud key forget` and a new confirmation",
                                       out.tampered.size(), out.key_lost ? " (the pin key is lost)" : "");
    return out;
}

}

Mac macOf(const db::query::cloud::AccountKeyRow& row, const bool create) {
    std::scoped_lock lock(pin_detail::keyMutex);
    return pin_detail::compute(row, pin_detail::key(create));
}

bool verifies(const db::query::cloud::AccountKeyRow& row) noexcept {
    try {
        const auto m = macOf(row);
        return sodium_memcmp(m.data(), row.mac.data(), m.size()) == 0;
    } catch (...) {
        return false;
    }
}

bool exists() {
    crypto::secrets::KeyProvider provider(pin_detail::slot());
    return provider.sealedExists();
}

void destroy() {
    std::scoped_lock lock(pin_detail::keyMutex);
    pin_detail::cached.reset();
    crypto::secrets::KeyProvider provider(pin_detail::slot());
    if (provider.sealedExists()) provider.destroySealed();
}

const db::query::cloud::AccountKeyRow* Checked::pinned() const {
    const auto it = std::ranges::find(rows, std::string("pinned"), &db::query::cloud::AccountKeyRow::state);
    return it == rows.end() ? nullptr : &*it;
}

const db::query::cloud::AccountKeyRow* Checked::waiting() const {
    const db::query::cloud::AccountKeyRow* out = nullptr;
    for (const auto& r : rows)
        if ((r.state == "pending" || r.state == "refused") && (!out || r.generation > out->generation)) out = &r;
    return out;
}

Checked load(const std::string& accountPublicId) {
    return pin_detail::check(db::query::cloud::AccountKeys::list(accountPublicId));
}

Checked loadAll() { return pin_detail::check(db::query::cloud::AccountKeys::list("")); }

bool isPinnedKey(const uint32_t generation, const std::span<const uint8_t> x25519) {
    if (x25519.size() != 32) return false;
    const auto all = loadAll();
    return std::ranges::any_of(all.rows, [&](const db::query::cloud::AccountKeyRow& r) {
        return r.state == "pinned" && r.generation == generation && std::ranges::equal(r.x25519_public, x25519);
    });
}

bool isPolicyRecipient(const std::span<const uint8_t> x25519) {
    if (x25519.size() != 32) return false;
    namespace account = vl::keykit::account;
    for (const auto& r : loadAll().rows) {
        if (r.state != "pinned" || !r.policy || !r.policy_sha256) continue;
        try {
            if (account::policyHash(*r.policy) != *r.policy_sha256) continue;
            const auto policy = account::parsePolicy(*r.policy);
            if (std::ranges::any_of(policy.recipients, [&](const account::PolicyRecipient& p) {
                    return std::ranges::equal(p.x25519_public, x25519);
                }))
                return true;
        } catch (const account::Error&) {
        }
    }
    return false;
}

}
