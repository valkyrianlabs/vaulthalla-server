#pragma once

#include "recovery/Model.hpp"
#include "vault/Fwd.hpp"

#include <optional>
#include <string>

// The provider-versioning capability contract, per provider (.claude/context/recovery.md, "Provider versioning"):
// what ops::recovery may offer, what status reports, and what a restore may rely on. Pure: no request, no database.
namespace vh::recovery::provider {

// Why each refusal happens (also in the contract's `unsupported` lines).
inline constexpr const char* kB2SuspendUnsupported =
    "Backblaze B2 buckets always keep object versions: versioning can't be suspended. To stop keeping old versions, "
    "set the vault's recovery mode to off (vh vault recovery set <vault> --mode off): only the latest version is kept, "
    "older ones are deleted a day after they are replaced";
inline constexpr const char* kB2CopyFromVersionUnsupported =
    "Backblaze B2 doesn't document CopyObject from a version id, so a version is restored by transfer (GET ?versionId, "
    "re-seal, PUT) instead";

// aws-s3 | backblaze-b2 | cloudflare-r2 | s3:<other> (storage::upstream::providerIdentity).
[[nodiscard]] ProviderCapabilities capabilitiesOf(const std::string& providerIdentity);
// Provider versioning can be used at all ("" = yes; else the reason, without a request).
[[nodiscard]] std::string unsupportedReason(const std::string& providerIdentity);

// Where Vaulthalla's history rules apply in a vault's bucket.
//   prefix: the owned rule's key prefix (nullopt: leave it as it is, AWS); manifest_rule: whether the
//   vaulthalla-manifest-versions rule (.vaulthalla/, old versions after 1 day) is written.
// Backblaze B2 rules select by prefix only (no exclusions), and an opaque_v1 vault on a bucket without conditional
// writes (every B2 bucket) publishes its manifest root as versions of .vaulthalla/root and keeps the older ones
// itself (vl-vaultfmt version_log): no rule may delete versions under .vaulthalla/. Its file contents are all under
// o/ (vl::vaultfmt::keys::kContentPrefix), so its rule is scoped to "o/" and it gets no manifest rule. transparent and
// path_v0 vaults name objects after their paths (anything can start a key), write their index
// (.vaulthalla/index-v1.json) as a plain PUT and read only its current version, and their recovery envelopes
// (.vaulthalla/key/<kid>) are named by their own hash: a whole-bucket rule ("") is safe for them, plus the manifest
// rule.
struct RuleScope {
    std::optional<std::string> prefix{};
    bool manifest_rule{true};
};
[[nodiscard]] RuleScope ruleScopeFor(const std::string& providerIdentity, vault::model::StorageLayout layout);
// The key prefix the vault's data lives under, for coverage checks ("" = the whole bucket).
[[nodiscard]] std::string dataPrefixFor(vault::model::StorageLayout layout);

}
