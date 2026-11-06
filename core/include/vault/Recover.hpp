#pragma once

#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/recovery/Kit.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/KeyAttestation.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// `vh vault recover`: rebuilding a vault on any instance from its bucket and the customer's recovery material
// (design/encryption/03-metadata-recovery.md §6.2, decision D1 of #344). This is the bucket side, with no database
// writes: read the customer material, unwrap the vault's KEV1 envelopes, load the manifest (or rebuild blind), prove
// every key version against the customer's pinned attestation keys, reconcile the manifest with the objects, and say
// what a restore would write. ops::vault_recover writes it (db::query::vault::Recover) and starts the vault.
//
// The trust anchor (D1): a key version becomes canonical in the new vault only when an attestation of the version by
// the node that minted it verifies against an attestation public key the customer pinned (the kit's
// attestation_public_keys, or an export's attestation.public_key), over that node's id and the vault id it had there,
// with the key check recomputed from the key's bytes. The bucket is untrusted: anyone who can write to it can wrap a
// key of their own to the recipient's public key, so an envelope only supplies bytes, never provenance. The restoring
// node's own attestation keys are never an anchor (they prove nothing about where a key came from). Everything else is
// salvage: decrypt what authenticates, re-encrypt it under a fresh key this node creates, never store the supplied key.
namespace vh::vault::recover {

using Uid = crypto::id::ObjectUid;

// ---- customer material ---------------------------------------------------------------------------------------------

// One key version from a key export (`vh vault keys export`, Desktop's 1Password item).
struct ExportedVersion {
    uint32_t version{};
    crypto::SecretKeyPtr key;
    std::optional<std::string> key_check;                       // the export's own (consistency only)
    std::optional<attestation::Attestation> attestation;
    std::optional<std::vector<uint8_t>> attestation_public_key;  // customer-held: an anchor (spec 03 §5.4)
};

// One vault of an export. vault_id is the id it had on the node that exported it; node_id and vault_uid are present in
// exports since #371.
struct ExportedVault {
    std::optional<uint64_t> vault_id;
    std::optional<std::string> node_id;
    std::optional<Uid> vault_uid;
    std::vector<ExportedVersion> versions;
};

// Parses an export document (one vault object or the `all` array). Throws std::invalid_argument naming the problem.
// Key bytes are held only in crypto::SecretKey.
[[nodiscard]] std::vector<ExportedVault> parseExport(const nlohmann::json& doc);

struct Material {
    std::optional<crypto::recovery::Kit> kit;
    std::vector<ExportedVault> exports;
};

// ---- trust anchors (D1) ----------------------------------------------------------------------------------------------

enum class Anchor {
    Verified,          // canonical
    NoAnchor,          // no customer material that pins attestation keys: salvage only
    EmptyAnchor,       // the kit's entry for the vault pins no keys: salvage only
    Unattested,        // neither the bucket nor the material carries an attestation of the version: salvage only
    Unverified,        // no pinned key verifies the attestation (another node's key, a forged key, an attestation over
                       // another vault id, node id or version): salvage only
    WrongNode,         // a pinned key verifies it, but over another node than the kit's pinned origin: salvage only
    WrongVault,        // a pinned key verifies it, but over another vault id than the kit's pinned origin: salvage only
    SelfAttested,      // only the restoring node's own key verifies it: never proof of origin, salvage only
    KeyCheckMismatch,  // the key check recomputed from the bytes differs from the recorded one: refused (damaged or
                       // another vault's key), not even salvaged
};
[[nodiscard]] std::string_view to_string(Anchor anchor);

struct PinnedKey {
    unsigned key_id{};
    std::vector<uint8_t> public_key;  // Ed25519, 32 bytes
    std::string source;               // kit | export
    [[nodiscard]] bool operator==(const PinnedKey&) const = default;
};

// What the customer's material pins for one vault.
struct Pins {
    bool supplied{false};              // a kit entry for the vault, or an export carrying attestation public keys
    std::vector<PinnedKey> keys;
    std::optional<std::string> node_id;  // the kit's origin
    std::optional<uint64_t> vault_id;
};
[[nodiscard]] Pins pinsFor(const Material& material, const Uid& vaultUid);

// One claim about where a version was minted: the root's key record (the producer's node and vault id), its recorded
// origin (a version an earlier restore recovered), or an export.
struct Evidence {
    std::string source;                // root | origin | export
    std::string node_id;               // empty: unknown (an export without one and no root)
    uint64_t vault_id{};
    std::optional<std::string> key_check;
    std::optional<attestation::Attestation> attestation;
    [[nodiscard]] bool operator==(const Evidence&) const = default;
};

struct Proof {
    uint32_t version{};
    Anchor verdict{Anchor::Unattested};
    std::string detail;
    std::optional<PinnedKey> anchor;   // Verified: the pinned key that verified it
    std::optional<Evidence> evidence;  // Verified: the claim it verified
    [[nodiscard]] bool canonical() const { return verdict == Anchor::Verified; }
    [[nodiscard]] bool refused() const { return verdict == Anchor::KeyCheckMismatch; }
};

// The D1 rule for one version's key. selfKeys: the restoring node's attestation public keys (every one it has had).
// Pure: no database, no bucket.
[[nodiscard]] Proof prove(uint32_t version, std::span<const uint8_t> key, const std::vector<Evidence>& evidence,
                          const Pins& pins, const std::vector<std::vector<uint8_t>>& selfKeys);

// ---- the plan ------------------------------------------------------------------------------------------------------

// Refusals a restore makes before writing anything; code() is the report's / the ws error's data.code.
class Refusal : public std::runtime_error {
public:
    Refusal(std::string code, const std::string& message) : std::runtime_error(message), code_(std::move(code)) {}
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

struct Options {
    std::optional<Uid> vault_uid;                 // which vault in the bucket (default: the kit's, else the bucket's hint)
    bool accept_rollback{false};
    std::vector<std::vector<uint8_t>> self_keys;  // this node's attestation public keys
};

// Bytes fetched while planning, by what they were: the restore's download budget (spec 03 §7: nothing beyond
// headers, manifest and envelopes until a file is read).
struct Downloads {
    uint64_t manifest_bytes{}, envelope_bytes{}, header_bytes{}, content_bytes{}, other_bytes{};
    unsigned gets{}, ranged_gets{}, lists{}, version_lists{};
};

struct EnvelopeStats {
    unsigned listed{}, unwrapped{}, skipped{}, rejected{};
};

// One key version as the restore sees it.
struct VersionPlan {
    uint32_t version{};
    crypto::SecretKeyPtr key;                      // null: no material holds it (missing)
    std::string key_source;                        // envelope | export | envelope+export
    Proof proof;
    bool current{false};
    bool needed{false};                            // live files are sealed under it
    std::optional<std::string> created_at, retired_at;
    std::vector<std::string> kids;                 // the root's envelope ids for the version
};

struct Plan {
    Uid vault_uid{};
    std::string origin_node_id;                    // the root's producer (or the material's), may be empty
    std::optional<uint64_t> origin_vault_id;
    std::optional<std::string> vault_name;         // the root's
    bool blind{false};                             // no usable root: names and the tree are lost (§4.3)
    std::optional<uint64_t> epoch;
    std::optional<std::string> root_sha256;
    std::optional<std::string> root_etag;
    sync::manifest::Freshness freshness{sync::manifest::Freshness::Unverified};
    std::string freshness_report;
    std::vector<std::string> issues;               // manifest fallbacks (segments from versions, older roots, blind)
    sync::manifest::Content content;               // what the restore writes (orphans placed under /Recovered)
    std::string root_uid;                          // the vault root directory's uid in content
    std::vector<VersionPlan> versions;             // ascending
    uint32_t current_version{};
    uint32_t highest_seen{};                       // the highest key version anything in the bucket names
    std::vector<std::string> orphans;              // uids placed under /Recovered
    std::vector<std::string> missing_objects;      // entries (uids) whose object the bucket doesn't hold
    std::vector<std::string> rejected;             // o/ objects that did not authenticate ("o/<uid>: reason")
    std::map<std::string, std::pair<std::string, uint32_t>> envelope_index;  // kid → (recipient id hex, version)
    EnvelopeStats envelopes;
    Downloads downloads;
    Pins pins;
    std::optional<sync::manifest::RecoveryPolicy> recovery_policy;

    [[nodiscard]] const VersionPlan* version(uint32_t v) const;
    // Versions whose key is held and proven (D1).
    [[nodiscard]] std::vector<uint32_t> canonical() const;
    // Versions live files need that can't be restored canonically: held but unproven (salvage), refused, or missing.
    [[nodiscard]] std::vector<uint32_t> blocking() const;
    // Of those, the ones salvage can re-key (held, unproven, not refused).
    [[nodiscard]] std::vector<uint32_t> salvageable() const;
};

// Reads the bucket and the material and decides everything a restore needs. Throws Refusal (no key material, a kit for
// another vault, a wrong seed, a rollback without accept_rollback, a fork), or the store's errors.
[[nodiscard]] Plan plan(sync::manifest::ObjectStore& store, const Material& material, const Options& options);

// The report a dry run returns (and a restore extends): never key material.
[[nodiscard]] nlohmann::json toJson(const Plan& plan);
[[nodiscard]] nlohmann::json toJson(const Proof& proof);
[[nodiscard]] nlohmann::json toJson(const Downloads& downloads);

// ---- the store a restore reads through --------------------------------------------------------------------------------

// Counts what is fetched, by key class (Downloads). Writes and deletes pass through.
class MeteredStore final : public sync::manifest::ObjectStore {
public:
    explicit MeteredStore(std::shared_ptr<sync::manifest::ObjectStore> inner) : inner_(std::move(inner)) {}
    [[nodiscard]] const Downloads& downloads() const { return downloads_; }

    [[nodiscard]] std::optional<sync::manifest::StoredObject> get(const std::string& key,
                                                                 const std::optional<std::string>& versionId) override;
    [[nodiscard]] std::optional<std::vector<uint8_t>> getRange(const std::string& key, uint64_t offset,
                                                              uint64_t length) override;
    [[nodiscard]] std::optional<std::string> headEtag(const std::string& key) override { return inner_->headEtag(key); }
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override {
        return inner_->putIfAbsent(key, bytes);
    }
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override {
        return inner_->putIfMatch(key, bytes, etag);
    }
    [[nodiscard]] std::vector<sync::manifest::ListedObject> list(const std::string& prefix) override;
    [[nodiscard]] std::vector<sync::manifest::StoredVersion> versions(const std::string& key) override;
    void remove(const std::string& key) override { inner_->remove(key); }

private:
    void count(const std::string& key, uint64_t bytes, bool ranged);

    std::shared_ptr<sync::manifest::ObjectStore> inner_;
    Downloads downloads_;
};

}
