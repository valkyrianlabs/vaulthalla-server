#pragma once

#include "ops/Actor.hpp"
#include "db/query/vault/ReadGrants.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// Vault read grants (migration 155), shared by `vh vault read-grant …`. A read grant gives a backup orchestrator
// (Sentinel) everything a disaster-recovery tool needs to read one vault from two places: through Vaulthalla's S3
// gateway, and straight from the vault's upstream bucket if this server is lost. One operation creates
//   - an S3 gateway credential that can only read the vault (vault-allowlist, the built-in reader role, the vault
//     selected; its principal is the issuer, so it never reaches further than the issuer does), and
//   - a read-only provider key restricted to the vault's upstream bucket, minted with the upstream account key the
//     vault already uses (Backblaze B2: b2_create_key, bucketIds = [the bucket], listBuckets + listFiles + readFiles;
//     AWS S3 and Cloudflare R2: not supported yet),
// puts both, with everything a client needs to use them, in one JSON document, and returns that document only as an
// OpenPGP message (ASCII armor) encrypted to one or two pinned recipients (crypto/openpgp/Gpg.hpp). The plaintext
// secrets are never stored, logged, audited or returned: the grant row keeps ids only (and the armored message).
//
// Who:
//   - pinning and removing a recipient (an OpenPGP public key pinned by its full fingerprint): super admins only, with
//     a step-up of family secrets right before the write, like every other secret-handling operation. An agent
//     (vh mcp, /mcp) is refused by the step-up; the host CLI is exempt by design (peer credentials), as everywhere.
//     Listing recipients: any signed-in account (public keys only).
//   - issuing, listing, showing and revoking grants: the vault permission vault.sync.action.read_grants on that vault
//     (super admins hold every permission), no step-up: the output is useless to anyone but the recipient. The issuer
//     must also be able to list and read the vault itself.
//
// Refusals (ops::Refused codes): recipient_not_pinned, recipient_unusable (revoked, expired, no encryption subkey),
// local_vault (no upstream bucket: needs gateway_only), upstream_encrypted (objects upstream are unreadable without
// this server's keys: the upstream half would be useless; gateway_only issues the gateway half alone),
// upstream_unsupported (provider without read keys, or a key not enabled for provider administration),
// no_gateway_bucket (the vault isn't exposed by the S3 gateway), read_grant_limit (vaults.read_grants.max_per_vault
// grants that are not revoked yet), revocation_incomplete.
//
// Never half a grant: if the upstream key can't be created (or the document can't be encrypted), the gateway
// credential (and the upstream key) are deleted again and nothing is recorded. Revoking deletes the gateway credential,
// then the upstream key (B2 b2_delete_key); if the provider refuses or fails, the grant stays revocation_incomplete,
// the call fails, and running revoke again retries.
namespace vh::ops::read_grants {

using Recipient = db::query::vault::ReadGrantRecipient;
using Grant = db::query::vault::ReadGrant;

inline constexpr const char* kDocumentType = "vaulthalla.vault-read-grant";
inline constexpr int kDocumentVersion = 1;

// ---- recipients

struct PinRequest {
    std::string fingerprint{};                 // the full 40-hex fingerprint the key must have
    std::optional<std::string> public_key{};   // armored (or binary) public key, read by the client
    std::optional<std::string> keyserver{};    // https URL: a keyserver base (…/vks/v1/by-fingerprint/<FPR> is added)
                                               // or a URL that already names the fingerprint
    std::optional<std::string> label{};
};

[[nodiscard]] std::vector<Recipient> listRecipients(const Actor& actor, bool includeRemoved = false);
[[nodiscard]] Recipient pinRecipient(const Actor& actor, const PinRequest& request);
struct RemovedRecipient {
    Recipient recipient{};
    uint32_t live_grants{};   // grants already encrypted to it that are not revoked (removal doesn't revoke them)
};
[[nodiscard]] RemovedRecipient removeRecipient(const Actor& actor, const std::string& fingerprint);

// ---- grants

struct IssueRequest {
    uint32_t vault_id{};
    std::vector<std::string> recipients{};   // one or two pinned fingerprints
    bool gateway_only{false};                // the gateway half alone (a local vault, or one that encrypts upstream)
};

struct Issued {
    Grant grant{};
    std::string ciphertext{};                // the ASCII-armored OpenPGP message (the only copy of the secrets)
};

[[nodiscard]] Issued issue(const Actor& actor, const IssueRequest& request);
// Grants of one vault, or of every vault the actor may manage grants of.
[[nodiscard]] std::vector<Grant> list(const Actor& actor, std::optional<uint32_t> vaultId, bool includeRevoked = false);
[[nodiscard]] Grant get(const Actor& actor, const std::string& grantId);
// Deletes both halves; throws Refused("revocation_incomplete") when the upstream key could not be deleted.
[[nodiscard]] Grant revoke(const Actor& actor, const std::string& grantId);

// ---- JSON (never a secret; the ciphertext only where asked for)

[[nodiscard]] nlohmann::json toJson(const Recipient& r);
[[nodiscard]] nlohmann::json toJson(const Grant& g, bool withCiphertext = false);

}
