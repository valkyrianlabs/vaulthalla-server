#include "db/query/vault/RemoteAccess.hpp"

#include "db/Transactions.hpp"

#include <pqxx/result>

namespace vh::db::query::vault {

namespace {

namespace rac = ::vh::storage::remote_access;

RemoteAccess::State racStateFrom(const pqxx::row_ref r) {
    RemoteAccess::State s;
    s.vault_id = r["vault_id"].as<uint32_t>();
    s.mode = rac::modeFromString(r["access"].as<std::string>()).value_or(rac::Mode::None);   // unknown: the strictest
    if (!r["reason"].is_null()) s.reason = r["reason"].as<std::string>();
    s.set_by = r["set_by"].as<std::string>();
    s.set_at = static_cast<std::time_t>(r["set_at"].as<int64_t>());
    return s;
}

constexpr const char* racKColumns =
    "a.vault_id, a.access, a.reason, a.set_by, extract(epoch from a.set_at)::BIGINT AS set_at";

}

std::optional<RemoteAccess::State> RemoteAccess::get(const uint32_t vaultId) {
    return Transactions::read("RemoteAccess::get", [&](pqxx::transaction_base& txn) -> std::optional<State> {
        const auto res = txn.exec(std::string("SELECT ") + racKColumns + " FROM vault_remote_access a WHERE a.vault_id = $1",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return racStateFrom(res[0]);
    });
}

std::optional<RemoteAccess::State> RemoteAccess::set(const uint32_t vaultId, const Mode mode,
                                                     const std::optional<std::string>& reason, const std::string& setBy) {
    return Transactions::exec("RemoteAccess::set", [&](pqxx::work& txn) -> std::optional<State> {
        const auto vault = txn.exec("SELECT 1 FROM vault WHERE id = $1 AND type = 's3' AND deleted_at IS NULL FOR UPDATE",
                                    pqxx::params{vaultId});
        if (vault.empty()) return std::nullopt;
        txn.exec("INSERT INTO vault_remote_access (vault_id, access, reason, set_by, set_at) "
                 "VALUES ($1, $2, $3, $4, now()) ON CONFLICT (vault_id) DO UPDATE SET access = EXCLUDED.access, "
                 "  reason = EXCLUDED.reason, set_by = EXCLUDED.set_by, set_at = EXCLUDED.set_at",
                 pqxx::params{vaultId, std::string(rac::to_string(mode)), reason, setBy});
        const auto res = txn.exec(std::string("SELECT ") + racKColumns + " FROM vault_remote_access a WHERE a.vault_id = $1",
                                  pqxx::params{vaultId});
        return racStateFrom(res[0]);
    });
}

std::vector<RemoteAccess::Restricted> RemoteAccess::restricted() {
    return Transactions::read("RemoteAccess::restricted", [&](pqxx::transaction_base& txn) {
        std::vector<Restricted> out;
        for (const auto r : txn.exec(std::string("SELECT ") + racKColumns + ", v.name FROM vault_remote_access a "
                                     "JOIN vault v ON v.id = a.vault_id WHERE v.deleted_at IS NULL AND v.type = 's3' "
                                     "AND a.access <> 'full' ORDER BY a.vault_id"))
            out.push_back({.state = racStateFrom(r), .vault_name = r["name"].as<std::string>()});
        return out;
    });
}

}
