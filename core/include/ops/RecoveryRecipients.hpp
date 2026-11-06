#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// Recovery recipients (design/encryption/03-metadata-recovery.md §5; #370): customer-held X25519 public keys enrolled
// on a vault, to which the daemon wraps every key version (KEV1 envelopes in the vault's bucket). Shared by
// `vh vault keys recipient list|add|revoke` and the ws vault.keys.recipients.* commands.
//
// Custody (amendment on #344): recovery is customer-controlled. Only class "customer" grants exist; the server only
// ever receives a public key (the seed is generated on the customer's device: Desktop or `vh-recovery kit create`),
// and envelopes go to the vault's own bucket and nowhere else. Nothing here is reachable from an account, payment,
// subscription or upgrade flow: a recipient is enrolled only by a person through these commands.
//
// Who: list needs the encryption-key View permission; add and revoke the Export permission (super admins hold both),
// on the local CLI or a paired device (D4; a browser session gets recipient_requires_device, an agent is denied).
// Both also need a step-up of family keys bound to the vault (#359, auth::stepup::require) right before they write: the
// host CLI is exempt by design; a paired device is refused until device approvals (#361) can answer it.
namespace vh::ops::recovery_recipients {

struct Recipient {
    std::string grant_id{};
    std::string recipient_id{};     // hex SHA-256 of the public key
    std::string public_key{};       // base64, 32 bytes (X25519)
    unsigned int suite{1};
    std::string recipient_class{};  // "customer"
    std::optional<std::string> label{};
    std::time_t added_at{};
    std::string authorized_by{};
    std::optional<std::time_t> revoked_at{};
    std::optional<std::string> revoked_by{};
    std::vector<unsigned int> envelope_versions{};  // key versions with an envelope for this grant
};

using Material = vault_keys::RecoveryMaterial;

struct RecipientList {
    unsigned int vault_id{};
    std::string vault_name{};
    std::string vault_uid{};  // base32: what a recovery kit names the vault by
    std::vector<Recipient> recipients{};
    Material recovery{};
};

[[nodiscard]] RecipientList list(const Actor& actor, unsigned int vaultId);

struct AddRequest {
    unsigned int vault_id{};
    std::string public_key{};  // X25519: base64 (44 characters) or hex (64 digits)
    std::optional<std::string> label{};
};

struct AddResult {
    Recipient recipient{};
    unsigned int envelopes_written{};
    std::vector<unsigned int> versions{};  // the key versions wrapped to it
    std::optional<std::string> note{};     // e.g. the bucket was unreachable: the sync pass writes them
    Material recovery{};
};

[[nodiscard]] AddResult add(const Actor& actor, const AddRequest& request, vault_keys::Channel channel);

struct RevokeResult {
    Recipient recipient{};
    Material recovery{};
};

// Stops new envelopes for the grant. Access it already has is not revoked: an envelope it received keeps unwrapping the
// versions it covers, so status says a rotation is needed (rotation_needed) to cut it off from new data.
[[nodiscard]] RevokeResult revoke(const Actor& actor, unsigned int vaultId, const std::string& grantId,
                                  vault_keys::Channel channel);

[[nodiscard]] nlohmann::json toJson(const Recipient& r);
[[nodiscard]] nlohmann::json toJson(const RecipientList& l);
[[nodiscard]] nlohmann::json toJson(const AddResult& r);
[[nodiscard]] nlohmann::json toJson(const RevokeResult& r);

}
