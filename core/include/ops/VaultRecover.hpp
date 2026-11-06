#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <functional>
#include <memory>
#include <optional>
#include <string>

// `vh vault recover` and ws `vault.recover` (#371, design/encryption/03-metadata-recovery.md §6): rebuild a vault on
// this instance from its bucket plus the customer's recovery material (a recovery kit and/or a key export), after the
// original server, database and TPM are gone. vault::recover plans it (no writes); this layer authorizes, confirms,
// writes it (db::query::vault::Recover), starts the vault in the cache strategy (nothing is downloaded until a file is
// read), runs a salvage when one was confirmed, and publishes a new manifest root (epoch + 1), so the old node, should
// it come back, sees a fork and stops.
//
// Who: the encryption-key Export permission (super admins), vault Create for the owner, Consume on the API key.
// Where (D4): the local CLI or a paired device (recover_requires_device for browser sessions; agents denied and
// excluded from MCP). A paired device also needs the keys step-up (a device approval or a console approval, #361);
// the host CLI is exempt by design.
//
// Recovery only (key-backup.md, revision 3, carried to a new node by D1): a key version becomes canonical only when
// its original node's attestation verifies against a key pinned in the customer's material; it is then re-sealed
// under this host's vault master and re-attested by this node, its origin recorded. Nothing else is ever stored as a
// version: a restore that needs an unproven (or missing) version stops with `salvage_required`; `salvage` (confirmed
// by typing the vault's name, NeedsConfirmation "vault_recover_salvage") then re-encrypts what the supplied key
// decrypts under a fresh key this node creates, above every version the bucket names, and never stores the supplied
// key. `dry_run` writes nothing and makes no request but reads. No key material goes anywhere but the bucket.
namespace vh::ops::vault_recover {

inline constexpr const char* RECOVER_SALVAGE = "vault_recover_salvage";

struct Request {
    unsigned int api_key_id{};
    std::string bucket{};
    nlohmann::json const* kit{};         // a recovery kit (vh-recovery kit create), not owned
    nlohmann::json const* exported{};    // a key export (vh vault keys export), not owned
    std::optional<std::string> into{};   // the new vault's name (default: the manifest's)
    std::optional<std::string> vault_uid{};  // which vault of the bucket (base32; default: the kit's or the hint)
    std::optional<unsigned int> owner_id{};
    bool accept_rollback{false};
    bool dry_run{false};
    bool salvage{false};
    std::optional<std::string> confirm_name{};
};

struct Result {
    nlohmann::json report{};             // vault::recover::toJson(plan) plus what was written
    bool dry_run{false};
    bool written{false};
    std::optional<unsigned int> vault_id{};
    std::string vault_name{};
    std::string mode{};                  // canonical | salvage
    bool key_available{false};           // the vault's engine runs
    std::optional<uint64_t> published_epoch{};
    std::optional<vault_keys::SalvageReport> salvage{};
    std::optional<std::string> note{};
};

[[nodiscard]] Result recover(const Actor& actor, const Request& request, vault_keys::Channel channel);
[[nodiscard]] nlohmann::json toJson(const Result& result);

// Test seams. The bucket a restore reads (default: an S3Store over the API key's controller, opaque_v1 rules), and a
// hook called with the new vault's engine before anything is published or salvaged (tests install a fake bucket).
using StoreFactory = std::function<std::shared_ptr<sync::manifest::ObjectStore>(unsigned int apiKeyId,
                                                                               const std::string& bucket)>;
void setStoreFactoryForTesting(StoreFactory factory);
using EngineHook = std::function<void(const std::shared_ptr<storage::Engine>& engine)>;
void setEngineHookForTesting(EngineHook hook);

}
