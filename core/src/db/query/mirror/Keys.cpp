#include "db/query/mirror/Keys.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "ops/Error.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <cstdint>
#include <optional>
#include <string>

namespace vh::db::query::mirror {

namespace mirror_keys_detail {

using vh::db::encoding::to_hex_bytea;

std::optional<uint32_t> currentIn(pqxx::work& txn, const uint32_t vaultId, const bool lock) {
    const auto r = txn.exec(std::string("SELECT version FROM vault_keys WHERE vault_id = $1") + (lock ? " FOR UPDATE" : ""),
                            pqxx::params{vaultId});
    if (r.empty()) return std::nullopt;
    return r[0][0].as<uint32_t>();
}

std::optional<std::string> originCheckIn(pqxx::work& txn, const uint32_t vaultId, const uint32_t version) {
    const auto r = txn.exec("SELECT origin_key_check FROM vault_key_origin WHERE vault_id = $1 AND version = $2",
                            pqxx::params{vaultId, static_cast<int64_t>(version)});
    if (r.empty()) return std::nullopt;
    return r[0][0].as<std::string>();
}

bool heldRetired(pqxx::work& txn, const uint32_t vaultId, const uint32_t version) {
    return !txn.exec("SELECT 1 FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2",
                     pqxx::params{vaultId, static_cast<int64_t>(version)})
                .empty();
}

void writeOrigin(pqxx::work& txn, const uint32_t vaultId, const MirrorKeyRow& k) {
    txn.exec("INSERT INTO vault_key_origin (vault_id, version, origin_node_id, origin_vault_id, origin_key_check, "
             "  attestation_key_id, attestation_public_key, attestation, anchor) "
             "VALUES ($1, $2, $3, $4, $5, $6, $7::bytea, $8::bytea, 'peer') "
             "ON CONFLICT (vault_id, version) DO UPDATE SET origin_node_id = EXCLUDED.origin_node_id, "
             "  origin_vault_id = EXCLUDED.origin_vault_id, origin_key_check = EXCLUDED.origin_key_check, "
             "  attestation_key_id = EXCLUDED.attestation_key_id, "
             "  attestation_public_key = EXCLUDED.attestation_public_key, attestation = EXCLUDED.attestation, "
             "  anchor = 'peer', recovered_at = NOW()",
             pqxx::params{vaultId, static_cast<int64_t>(k.version), k.origin_node_id,
                          static_cast<int64_t>(k.origin_vault_id), k.origin_key_check, k.attestation_key_id,
                          to_hex_bytea(k.attestation_public_key), to_hex_bytea(k.attestation)});
}

}

std::optional<uint64_t> MirrorKeys::originVaultOf(const uint32_t vaultId, const std::string& node) {
    return Transactions::exec("mirror::MirrorKeys::originVaultOf", [&](pqxx::work& txn) -> std::optional<uint64_t> {
        const auto r = txn.exec("SELECT origin_vault_id FROM vault_key_origin WHERE vault_id = $1 AND origin_node_id = $2 "
                                "ORDER BY version DESC LIMIT 1",
                                pqxx::params{vaultId, node});
        if (r.empty()) return std::nullopt;
        return r[0][0].as<uint64_t>();
    });
}

std::optional<uint32_t> MirrorKeys::currentVersion(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorKeys::currentVersion", [&](pqxx::work& txn) {
        return mirror_keys_detail::currentIn(txn, vaultId, false);
    });
}

KeyInstall MirrorKeys::install(const uint32_t vaultId, const MirrorKeyRow& k) {
    using namespace mirror_keys_detail;
    return Transactions::exec("mirror::MirrorKeys::install", [&](pqxx::work& txn) {
        txn.exec("SELECT pg_advisory_xact_lock($1::bigint)", pqxx::params{vaultId});
        const auto current = currentIn(txn, vaultId, true);
        if (!current) throw ops::Conflict("this server holds no key for that vault");
        const auto held = originCheckIn(txn, vaultId, k.version);
        if (k.version <= *current) {
            // A version that is current here, or retired: only the very same key (a delivery repeated after the
            // rotation committed) is answered; another key under a version in use is never taken.
            if (held && *held == k.origin_key_check &&
                (k.version == *current || heldRetired(txn, vaultId, k.version)))
                return KeyInstall::AlreadyHeld;
            return KeyInstall::Conflict;
        }
        const auto& p = k.provenance;
        const std::optional<std::string> sig =
            p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
        if (heldRetired(txn, vaultId, k.version)) {
            if (held && *held == k.origin_key_check) return KeyInstall::AlreadyHeld;
            // Delivered before for a rotation the core never committed: nothing here references a version above the
            // current one (it becomes current only when the core's log names it), so the new delivery replaces it.
            txn.exec("UPDATE vault_keys_trashed SET encrypted_key = $3, iv = $4, master_version = $5, key_check = $6, "
                     "  attestation_key_id = $7, attestation = $8::bytea, created_at = NOW(), trashed_at = NOW(), "
                     "  rotation_completed_at = NOW(), encrypted_key_next = NULL, iv_next = NULL, "
                     "  master_version_next = NULL, encrypted_key_prev = NULL, iv_prev = NULL, master_version_prev = NULL "
                     "WHERE vault_id = $1 AND version = $2",
                     pqxx::params{vaultId, static_cast<int64_t>(k.version), to_hex_bytea(k.encrypted_key),
                                  to_hex_bytea(k.iv), k.master_version, p.key_check, p.attestation_key_id, sig});
        } else {
            // Held retired with its rotation complete: this server never re-seals under it on its own.
            txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, trashed_at, "
                     "  rotation_completed_at, key_check, attestation_key_id, attestation, master_version) "
                     "VALUES ($1, $2, $3, $4, NOW(), NOW(), NOW(), $5, $6, $7::bytea, $8)",
                     pqxx::params{vaultId, static_cast<int64_t>(k.version), to_hex_bytea(k.encrypted_key),
                                  to_hex_bytea(k.iv), p.key_check, p.attestation_key_id, sig, k.master_version});
        }
        writeOrigin(txn, vaultId, k);
        return KeyInstall::Installed;
    });
}

bool MirrorKeys::promote(pqxx::work& txn, const uint32_t vaultId, const uint32_t version,
                         const std::optional<std::string>& originKeyCheck) {
    using namespace mirror_keys_detail;
    const auto current = currentIn(txn, vaultId, true);
    if (!current) return false;
    const auto held = originCheckIn(txn, vaultId, version);
    // The log's key check is the core's over its vault id, as this server recorded it for every key it was given.
    if (originKeyCheck && held && *originKeyCheck != *held)
        throw ops::Conflict(fmt::format("the core's key version {} is not the key it gave this server", version));
    if (version <= *current || !held || !heldRetired(txn, vaultId, version)) return false;
    // The outgoing current version stays held, retired (files sealed under it arrive re-sealed later); the delivered
    // one takes the current row with everything it was stored with.
    txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, trashed_at, "
             "  rotation_completed_at, key_check, attestation_key_id, attestation, master_version, encrypted_key_next, "
             "  iv_next, master_version_next, encrypted_key_prev, iv_prev, master_version_prev) "
             "SELECT vault_id, version, encrypted_key, iv, created_at, NOW(), NOW(), key_check, attestation_key_id, "
             "  attestation, master_version, encrypted_key_next, iv_next, master_version_next, encrypted_key_prev, "
             "  iv_prev, master_version_prev FROM vault_keys WHERE vault_id = $1 "
             "ON CONFLICT (vault_id, version) DO NOTHING",
             pqxx::params{vaultId});
    txn.exec("UPDATE vault_keys k SET encrypted_key = t.encrypted_key, iv = t.iv, version = t.version, "
             "  created_at = t.created_at, updated_at = CURRENT_TIMESTAMP, key_check = t.key_check, "
             "  attestation_key_id = t.attestation_key_id, attestation = t.attestation, master_version = t.master_version, "
             "  encrypted_key_next = t.encrypted_key_next, iv_next = t.iv_next, master_version_next = t.master_version_next, "
             "  encrypted_key_prev = t.encrypted_key_prev, iv_prev = t.iv_prev, master_version_prev = t.master_version_prev, "
             "  exported_at = NULL, exported_version = NULL "
             "FROM vault_keys_trashed t WHERE k.vault_id = $1 AND t.vault_id = $1 AND t.version = $2",
             pqxx::params{vaultId, static_cast<int64_t>(version)});
    txn.exec("DELETE FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2",
             pqxx::params{vaultId, static_cast<int64_t>(version)});
    return true;
}

}
