#include "db/query/cloud/AccountKey.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <stdexcept>

namespace vh::db::query::cloud {

namespace account_key_detail {

constexpr const char* kColumns =
    "account_public_id, generation, fingerprint, x25519_public, ed25519_public, statement, signature, "
    "previous_signature, link, state, confirmed_by, EXTRACT(EPOCH FROM confirmed_at)::BIGINT, policy_sequence, "
    "policy_sha256, policy, policy_signature, EXTRACT(EPOCH FROM stored_at)::BIGINT, mac";

template <std::size_t N>
std::array<uint8_t, N> fixed(const pqxx::field_ref f, const char* what) {
    const auto bytes = encoding::from_hex_bytea(f.as<std::string>());
    if (bytes.size() != N) throw std::runtime_error(std::string("cloud_account_key.") + what + " has the wrong size");
    std::array<uint8_t, N> out{};
    std::ranges::copy(bytes, out.begin());
    return out;
}

template <std::size_t N>
std::optional<std::array<uint8_t, N>> fixedOpt(const pqxx::field_ref f, const char* what) {
    if (f.is_null()) return std::nullopt;
    return fixed<N>(f, what);
}

template <std::size_t N>
std::string hex(const std::array<uint8_t, N>& a) {
    return encoding::to_hex_bytea({a.begin(), a.end()});
}

template <std::size_t N>
std::optional<std::string> hexOpt(const std::optional<std::array<uint8_t, N>>& a) {
    if (!a) return std::nullopt;
    return hex(*a);
}

AccountKeyRow rowFrom(const pqxx::row_ref r) {
    AccountKeyRow row;
    row.account_public_id = r[0].as<std::string>();
    row.generation = r[1].as<uint32_t>();
    row.fingerprint = r[2].as<std::string>();
    row.x25519_public = fixed<32>(r[3], "x25519_public");
    row.ed25519_public = fixed<32>(r[4], "ed25519_public");
    row.statement = r[5].as<std::string>();
    row.signature = fixed<64>(r[6], "signature");
    row.previous_signature = fixedOpt<64>(r[7], "previous_signature");
    row.link = r[8].as<std::string>();
    row.state = r[9].as<std::string>();
    if (!r[10].is_null()) row.confirmed_by = r[10].as<std::string>();
    if (!r[11].is_null()) row.confirmed_at = static_cast<std::time_t>(r[11].as<int64_t>());
    row.policy_sequence = r[12].as<uint32_t>();
    row.policy_sha256 = fixedOpt<32>(r[13], "policy_sha256");
    if (!r[14].is_null()) row.policy = r[14].as<std::string>();
    row.policy_signature = fixedOpt<64>(r[15], "policy_signature");
    row.stored_at = static_cast<std::time_t>(r[16].as<int64_t>());
    row.mac = fixed<32>(r[17], "mac");
    return row;
}

}

std::vector<AccountKeyRow> AccountKeys::list(const std::string& accountPublicId) {
    using namespace account_key_detail;
    return Transactions::exec("cloud::AccountKeys::list", [&](pqxx::work& txn) {
        std::vector<AccountKeyRow> out;
        const auto res = accountPublicId.empty()
                             ? txn.exec(std::string("SELECT ") + kColumns +
                                        " FROM cloud_account_key ORDER BY account_public_id, generation")
                             : txn.exec(std::string("SELECT ") + kColumns +
                                            " FROM cloud_account_key WHERE account_public_id = $1 ORDER BY generation",
                                        pqxx::params{accountPublicId});
        for (const auto r : res) out.push_back(rowFrom(r));
        return out;
    });
}

void AccountKeys::put(const std::vector<AccountKeyRow>& rows, const std::vector<uint32_t>& drop) {
    using namespace account_key_detail;
    if (rows.empty() && drop.empty()) return;
    Transactions::exec("cloud::AccountKeys::put", [&](pqxx::work& txn) {
        if (!drop.empty() && !rows.empty())
            for (const auto g : drop)
                txn.exec("DELETE FROM cloud_account_key WHERE account_public_id = $1 AND generation = $2",
                         pqxx::params{rows.front().account_public_id, g});
        // Demotions first, so the one-pin index holds at every statement.
        auto ordered = rows;
        std::ranges::stable_sort(ordered, {}, [](const AccountKeyRow& r) { return r.state == "pinned" ? 1 : 0; });
        for (const auto& r : ordered) {
            txn.exec("DELETE FROM cloud_account_key WHERE account_public_id = $1 AND generation = $2",
                     pqxx::params{r.account_public_id, r.generation});
            txn.exec("INSERT INTO cloud_account_key (account_public_id, generation, fingerprint, x25519_public, "
                     "ed25519_public, statement, signature, previous_signature, link, state, confirmed_by, confirmed_at, "
                     "policy_sequence, policy_sha256, policy, policy_signature, stored_at, mac) VALUES ($1, $2, $3, "
                     "$4::bytea, $5::bytea, $6, $7::bytea, $8::bytea, $9, $10, $11, to_timestamp($12::bigint), $13, "
                     "$14::bytea, $15, $16::bytea, to_timestamp($17::bigint), $18::bytea)",
                     pqxx::params{r.account_public_id, r.generation, r.fingerprint, hex(r.x25519_public),
                                  hex(r.ed25519_public), r.statement, hex(r.signature), hexOpt(r.previous_signature),
                                  r.link, r.state, r.confirmed_by,
                                  r.confirmed_at ? std::optional<int64_t>(static_cast<int64_t>(*r.confirmed_at))
                                                 : std::optional<int64_t>{},
                                  r.policy_sequence, hexOpt(r.policy_sha256), r.policy, hexOpt(r.policy_signature),
                                  static_cast<int64_t>(r.stored_at), hex(r.mac)});
        }
    });
}

void AccountKeys::clear() {
    Transactions::exec("cloud::AccountKeys::clear", [&](pqxx::work& txn) { txn.exec("DELETE FROM cloud_account_key"); });
}

std::vector<PolicyVaultRow> PolicyVaults::list() {
    return Transactions::exec("cloud::PolicyVaults::list", [&](pqxx::work& txn) {
        std::vector<PolicyVaultRow> out;
        for (const auto r : txn.exec("SELECT vault_id, account_public_id, sequence, "
                                     "EXTRACT(EPOCH FROM applied_at)::BIGINT FROM cloud_account_policy_vault "
                                     "ORDER BY vault_id"))
            out.push_back({.vault_id = r[0].as<uint32_t>(), .account_public_id = r[1].as<std::string>(),
                           .sequence = r[2].as<uint32_t>(), .applied_at = static_cast<std::time_t>(r[3].as<int64_t>())});
        return out;
    });
}

void PolicyVaults::applied(const uint32_t vaultId, const std::string& accountPublicId, const uint32_t sequence) {
    Transactions::exec("cloud::PolicyVaults::applied", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO cloud_account_policy_vault (vault_id, account_public_id, sequence) VALUES ($1, $2, $3) "
                 "ON CONFLICT (vault_id) DO UPDATE SET account_public_id = EXCLUDED.account_public_id, "
                 "sequence = EXCLUDED.sequence, applied_at = CURRENT_TIMESTAMP",
                 pqxx::params{vaultId, accountPublicId, sequence});
    });
}

}
