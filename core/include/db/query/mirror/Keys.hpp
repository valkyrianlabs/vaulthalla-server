#pragma once

#include "db/query/mirror/Start.hpp"

#include <pqxx/transaction>

#include <cstdint>
#include <optional>
#include <string>

// A key version delivered over the link for a rotation of a mirrored vault (design/peers/mirror.md "Key rotation";
// mirror/rotate/Rotate.hpp). On the mirror, a delivered version is held (vault_keys_trashed, with where it came from in
// vault_key_origin) and becomes the current one only when the core's log names it (the applier's `key` row): until then
// the core may not have committed its rotation, and nothing here seals under it. No key material is ever logged.
namespace vh::db::query::mirror {

enum class KeyInstall {
    Installed,    // held now (a version above the current one; a delivery of it that never became current is replaced)
    AlreadyHeld,  // the same key, by the core's key check, was held already (a repeated delivery)
    Conflict,     // this server holds that version as current or older with another key: refused
};

class MirrorKeys {
public:
    // The vault id the vault's keys came from on `node` (vault_key_origin), nullopt when none of its keys did.
    [[nodiscard]] static std::optional<uint64_t> originVaultOf(uint32_t vaultId, const std::string& node);
    // The vault's current key version here, nullopt without a key row.
    [[nodiscard]] static std::optional<uint32_t> currentVersion(uint32_t vaultId);
    // A delivered key version (row.current is ignored): held, never current (see the top).
    static KeyInstall install(uint32_t vaultId, const MirrorKeyRow& row);

    // In the applier's transaction: the core's log names `version` with its key check (`originKeyCheck`, nullopt when
    // the row carries none yet). A version above the current one that is held from the core with that check becomes
    // the current one (the outgoing current version stays held, retired). True when it moved; false when there was
    // nothing to do (the version is current or older and held); ops::Conflict when the check is another key's.
    static bool promote(pqxx::work& txn, uint32_t vaultId, uint32_t version,
                        const std::optional<std::string>& originKeyCheck);
};

}
