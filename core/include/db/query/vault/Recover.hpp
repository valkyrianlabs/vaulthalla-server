#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "db/query/vault/Key.hpp"
#include "sync/manifest/Content.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <set>
#include <string>
#include <vector>

// The database side of `vh vault recover` (#371, design/encryption/03-metadata-recovery.md §6.2 step 5): one
// transaction that creates the restored vault (a new numeric id, the bucket's vault uid, storage_layout opaque_v1, the
// cache strategy) and rebuilds what the manifest says: the tree (fs_entry, directories, files, symlinks, with the
// manifest's uids), the trash, the remote object index, the provider versions, the snapshot records, the recovered key
// versions (sealed under this host's vault master, re-attested by this node, their origin recorded in
// vault_key_origin), the recovery grants and envelope rows, the file-recovery preference and the manifest chain
// position. Nothing is written unless all of it is: a failure rolls the whole restore back.
namespace vh::db::query::vault {

struct RecoverKeyRow {
    uint32_t version{};
    bool current{false};
    std::vector<uint8_t> encrypted_key{}, iv{};
    unsigned int master_version{1};
    Key::Provenance provenance{};               // this node's: key check over the new vault id, this node's attestation
    std::optional<std::string> created_at{}, retired_at{};  // ISO 8601 (the root's)
    bool rotation_pending{false};               // retired, and live files are still sealed under it
    struct Origin {
        std::string node_id;
        uint64_t vault_id{};
        std::string key_check;
        unsigned int attestation_key_id{};
        std::vector<uint8_t> attestation_public_key, attestation;
        std::string anchor;                      // kit | export
    };
    std::optional<Origin> origin{};             // recovered versions; absent for a fresh salvage key
};

struct RecoverGrant {
    std::string grant_id, recipient_id;
    std::vector<uint8_t> public_key;
    uint16_t suite{1};
    std::optional<std::string> label, added_at, authorized_by, revoked_at;
};

struct RecoverEnvelope {
    std::string grant_id;   // the grant's id in the manifest (renamed with the grant when that id is taken here)
    uint32_t version{};
    std::string kid;
};

struct RecoverInput {
    uint32_t vault_id{};                        // reserveVaultId()
    crypto::id::ObjectUid vault_uid{};
    std::string name, description;
    unsigned int owner_id{};
    unsigned int api_key_id{};
    std::string bucket;
    std::optional<std::string> storage_tier{};
    uint64_t quota{};
    std::string mount_point;
    int64_t sync_interval_seconds{300};
    std::string conflict_policy{"keep_local"};
    const vh::sync::manifest::Content* content{};   // the plan's (not owned)
    std::string root_uid;
    std::set<std::string> skip_uids{};          // files left out (sealed under a version nothing holds)
    std::vector<RecoverKeyRow> keys{};
    std::vector<RecoverGrant> grants{};
    std::vector<RecoverEnvelope> envelopes{};
    struct Salvage {
        std::vector<uint32_t> versions;
        uint32_t new_version{};
        std::optional<unsigned int> started_by;
    };
    std::optional<Salvage> salvage{};
    std::optional<uint64_t> epoch{};
    std::optional<std::string> root_sha256{}, root_etag{};
    std::optional<std::string> root_version_id{};   // version_log buckets (migration 137)
    std::vector<std::string> root_sids{};
    std::optional<unsigned int> created_by{};
    // An inode for each restored entry (root excluded: reinstateVault gives it one), from the FS cache, as creating
    // the entry would have: (the vault's FUSE name, the entry's vault path) → inode. Unset: assigned on first lookup.
    std::function<std::optional<uint64_t>(const std::string& fuseName, const std::string& vaultPath)> inode_for{};
};

struct RecoverResult {
    uint32_t vault_id{};
    unsigned int files{}, dirs{}, symlinks{}, trashed{}, index_rows{}, provider_versions{}, snapshots{},
        snapshot_members{}, skipped{};
    std::vector<std::string> notes;             // what was adjusted (an invalid symlink target, a renamed grant id)
};

class Recover {
public:
    // A vault id from the sequence: the key check and this node's attestation bind it, and both are computed before
    // the restore's transaction (signing reads the database).
    [[nodiscard]] static uint32_t reserveVaultId();
    [[nodiscard]] static RecoverResult apply(const RecoverInput& input);
};

}
