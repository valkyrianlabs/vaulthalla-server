#pragma once

#include "crypto/id/ObjectUid.hpp"

#include <nlohmann/json.hpp>

#include <compare>
#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// Manifest v2 documents (design/encryption/03-metadata-recovery.md §3): the plaintext of the encrypted root (VHF1 kind
// 3) and segments (VHF1 kind 2) that let a fresh installation rebuild an opaque_v1 vault from its bucket.
//
// Documents are UTF-8 JSON. The AEAD authenticates bytes, so no canonical form is required; writers here emit the
// vectors' form (sorted keys, no whitespace: canonicalJson) so a document re-encodes to the bytes it was parsed from.
// Encoding rules that keep that true: an absent optional member is omitted, except the members the spec spells as
// null (an entry's `parent`, an object's `version_id`, a key's `key_check`/`attestation`/`retired_at`, the root's
// `prev`), which are always written.
//
// Readers ignore members they don't know, so a newer writer can add members without a format version bump; a member
// they know with the wrong type or value is FormatError. Timestamps are UTC ISO 8601 strings ("2026-11-05T12:00:00Z"),
// kept as text: the documents compare and round-trip exactly.
//
// Uids are 16 raw bytes written as 26 lower-case Crockford base32 symbols (crypto::id::toBase32); sids name segments.
// Hex digests are lower case.
namespace vh::sync::manifest {

using Uid = crypto::id::ObjectUid;
using Json = nlohmann::json;

inline constexpr std::string_view kRootType = "vh.manifest.root";
inline constexpr std::string_view kSegmentType = "vh.manifest.segment";
inline constexpr std::string_view kSnapshotType = "vh.manifest.snapshot";
inline constexpr unsigned kDocumentVersion = 1;
inline constexpr std::string_view kLayoutOpaqueV1 = "OpaqueV1";
inline constexpr unsigned kRecoveryPolicyVersion = 1;
// The recipient class every grant this design writes carries (KEV1 recipient_class 0, spec 03 §5.2). Any other class
// is a separately authorized recipient type a later spec defines: parsed and kept, never used to decrypt (§5.7).
inline constexpr std::string_view kCustomerClass = "customer";
// Prior locations kept per file (spec 03 §3.3).
inline constexpr std::size_t kMaxPriorNames = 32;

// A document that is not a manifest document of the expected type, or breaks a structural rule. code() is the spec's
// reader error ("bad_root", "bad_segment", "bad_snapshot").
class FormatError : public std::runtime_error {
public:
    FormatError(std::string code, const std::string& detail);
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

// [lo, hi], inclusive bounds on the first byte of an entry's uid.
struct Range {
    uint8_t lo{0x00};
    uint8_t hi{0xff};

    [[nodiscard]] bool contains(const Uid& uid) const { return uid[0] >= lo && uid[0] <= hi; }
    [[nodiscard]] auto operator<=>(const Range&) const = default;
};

[[nodiscard]] std::string uidText(const Uid& uid);
// Strict base32 (crypto::id::fromBase32); throws FormatError(code) naming `what` otherwise.
[[nodiscard]] Uid parseUid(std::string_view text, const std::string& code, std::string_view what);

// ---- segment entries (§3.3) -----------------------------------------------------------------------------------------

enum class EntryKind { Dir, File, Symlink, Tombstone };
[[nodiscard]] std::string_view to_string(EntryKind kind);

struct Owner {
    int64_t uid{};
    int64_t gid{};
    [[nodiscard]] bool operator==(const Owner&) const = default;
};

// The current object of a file (o/<uid>) as the provider reported it when it was written.
struct ObjectRef {
    std::optional<std::string> etag;            // quoted, as sent
    uint64_t size{};                            // sealed bytes
    std::optional<std::string> version_id;      // always written (null on an unversioned bucket)
    std::optional<std::string> storage_class;
    [[nodiscard]] bool operator==(const ObjectRef&) const = default;
};

// One provider version of the file's object (upstream_object_version).
struct FileVersion {
    std::string version_id;
    std::optional<std::string> generation;      // hex salt, when known
    std::optional<uint32_t> key_version;
    std::optional<uint64_t> size;
    std::optional<std::string> etag;
    std::optional<std::string> last_modified;
    std::optional<std::string> noncurrent_at;
    bool delete_marker{false};
    std::optional<std::string> origin_last_modified;
    [[nodiscard]] bool operator==(const FileVersion&) const = default;
};

// Where a file was until `until` (renames and moves; bounded by the retention window and kMaxPriorNames).
struct PriorName {
    std::string until;
    std::optional<std::string> parent;          // uid text
    std::string name;
    [[nodiscard]] bool operator==(const PriorName&) const = default;
};

// A file in the vault trash (files_trashed). `path` is where it was when it was trashed (its parent may be gone).
struct Trashed {
    std::string at;
    std::optional<std::string> by;
    std::optional<std::string> path;
    [[nodiscard]] bool operator==(const Trashed&) const = default;
};

struct Entry {
    std::string uid;                            // base32
    EntryKind kind{EntryKind::File};
    std::optional<std::string> parent;          // uid text; null for the vault root (always written)
    std::string name;                           // "" for the vault root
    std::optional<uint32_t> mode;
    std::optional<Owner> owner;
    std::optional<std::string> mtime;
    std::optional<std::string> ctime;

    // files (and tombstones: versions, names)
    std::optional<uint64_t> size;               // plaintext bytes
    std::optional<std::string> mime;
    std::optional<uint32_t> format;             // 1 = VHF1 (spec 02)
    std::optional<uint32_t> key_version;
    std::optional<std::string> generation;      // hex salt of the current object
    std::optional<std::string> content_hash;    // the sealed bytes' hash, never a plaintext digest (§3.3)
    std::optional<ObjectRef> object;
    std::vector<FileVersion> versions;
    std::vector<PriorName> names;
    std::optional<Trashed> trashed;

    // symlinks
    std::optional<std::string> target;

    [[nodiscard]] bool operator==(const Entry&) const = default;
};

[[nodiscard]] Json toJson(const Entry& entry);
[[nodiscard]] Entry entryFromJson(const Json& j);  // FormatError("bad_segment")

struct SegmentDocument {
    std::string vault_uid;
    Range range;
    std::vector<Entry> entries;                 // ascending by uid
    [[nodiscard]] bool operator==(const SegmentDocument&) const = default;
};

[[nodiscard]] Json toJson(const SegmentDocument& doc);
// Checks the type, version, vault uid (expectedVaultUid), range, and that every entry's uid falls in the range and
// appears once. FormatError("bad_segment").
[[nodiscard]] SegmentDocument segmentFromJson(const Json& j, const Uid& expectedVaultUid);

// ---- snapshot segments (§3.3): one immutable segment per snapshot -----------------------------------------------------

struct SnapshotMember {
    std::optional<std::string> uid;             // the file's uid, when it is still known
    std::string path_at_capture;
    std::optional<std::string> generation;
    std::optional<uint32_t> key_version;
    std::optional<std::string> provider_version_id;
    // Whether the bucket holds this generation (a provider version or the current object): local snapshot blobs live
    // on the host only, so after a catastrophe a member is restorable only from the bucket. Nothing claims more.
    bool restorable_from_bucket{false};
    [[nodiscard]] bool operator==(const SnapshotMember&) const = default;
};

struct SnapshotRecord {
    uint64_t id{};
    std::optional<std::string> name;
    std::string created_at;
    std::string root_path;
    std::vector<SnapshotMember> members;        // ascending by path_at_capture
    [[nodiscard]] bool operator==(const SnapshotRecord&) const = default;
};

struct SnapshotDocument {
    std::string vault_uid;
    SnapshotRecord snapshot;
    [[nodiscard]] bool operator==(const SnapshotDocument&) const = default;
};

[[nodiscard]] Json toJson(const SnapshotDocument& doc);
[[nodiscard]] SnapshotDocument snapshotFromJson(const Json& j, const Uid& expectedVaultUid);  // FormatError("bad_snapshot")

// ---- root (§3.2) ------------------------------------------------------------------------------------------------------

struct Producer {
    std::string node_id;
    std::optional<uint64_t> vault_id;
    std::string software;
    [[nodiscard]] bool operator==(const Producer&) const = default;
};

// The vault's file-recovery policy (vault_recovery_policy), not to be confused with the root's recovery_policy.
struct FileRecovery {
    std::string mode;                           // off | local_snapshots | provider_versioning
    std::optional<uint32_t> retention_days;
    [[nodiscard]] bool operator==(const FileRecovery&) const = default;
};

struct VaultInfo {
    std::string name;
    std::optional<std::string> created_at;
    std::optional<uint64_t> quota_bytes;        // null = unlimited
    std::optional<std::string> sync_strategy;
    std::optional<FileRecovery> recovery_policy;
    [[nodiscard]] bool operator==(const VaultInfo&) const = default;
};

struct KeyAttestation {
    unsigned key_id{};
    std::optional<std::string> public_key;      // base64, 32 bytes (Ed25519)
    std::string signature;                      // base64, 64 bytes
    [[nodiscard]] bool operator==(const KeyAttestation&) const = default;
};

// One key version of the vault's complete key history (§3.2), with the version's key check and this node's
// attestation (migration 113). `envelopes` names KEV1 envelopes (`.vaulthalla/key/<kid>`) for this version: absent
// until recovery recipients exist (#370).
struct KeyRecord {
    uint32_t version{};
    std::optional<std::string> key_check;
    std::optional<KeyAttestation> attestation;
    std::optional<std::string> created_at;
    std::optional<std::string> retired_at;
    std::optional<std::vector<std::string>> envelopes;
    [[nodiscard]] bool operator==(const KeyRecord&) const = default;
};

// recovery_policy (§3.2, §5.7): a versioned list of independently revocable grants. Every grant this server writes is
// class "customer"; a reader keeps grants of other classes but never uses them to decrypt, and ignores a policy of a
// version it doesn't know (`understood` false) instead of failing. `threshold` is reserved: null.
struct Grant {
    std::string grant_id;
    std::string recipient_id;                   // hex SHA-256 of the recipient public key
    std::string recipient_class;                // the JSON member "class"
    uint32_t suite{};
    std::optional<std::string> label;
    std::optional<std::string> added_at;
    std::optional<std::string> authorized_by;
    std::optional<std::string> revoked_at;
    [[nodiscard]] bool operator==(const Grant&) const = default;
    // Customer class, not revoked: the only grants a reader may unwrap envelopes for.
    [[nodiscard]] bool usableForDecryption() const;
};

struct RecoveryPolicy {
    uint32_t v{kRecoveryPolicyVersion};
    bool understood{true};                      // false: a version this reader doesn't know (grants left empty)
    std::vector<Grant> grants;
    [[nodiscard]] bool operator==(const RecoveryPolicy&) const = default;
};

struct SegmentRef {
    std::string sid;                            // base32
    Range range;
    uint64_t count{};
    std::string object_sha256;
    uint64_t size{};
    [[nodiscard]] bool operator==(const SegmentRef&) const = default;
};

struct SnapshotRef {
    std::string sid;
    std::string object_sha256;
    uint64_t size{};
    [[nodiscard]] bool operator==(const SnapshotRef&) const = default;
};

struct Stats {
    uint64_t files{};
    uint64_t dirs{};
    uint64_t bytes{};
    [[nodiscard]] bool operator==(const Stats&) const = default;
};

struct RootDocument {
    std::string vault_uid;
    std::string layout{kLayoutOpaqueV1};
    uint64_t epoch{};
    std::optional<std::string> prev;            // hex SHA-256 of the previous root object; null for epoch 1
    std::string published_at;
    Producer producer;
    std::optional<VaultInfo> vault;
    std::vector<KeyRecord> keys;                // ascending by version
    std::optional<RecoveryPolicy> recovery_policy;
    std::vector<SegmentRef> segments;           // ascending by range, covering 00..ff exactly
    std::vector<SnapshotRef> snapshots;
    Stats stats;
    [[nodiscard]] bool operator==(const RootDocument&) const = default;
};

[[nodiscard]] Json toJson(const RootDocument& root);
// Checks the type, version, vault uid, epoch/prev (epoch >= 1; prev null exactly at epoch 1), layout, and the
// segment list (valid sids, unique, ranges in order covering 00..ff without gaps or overlap). FormatError("bad_root").
[[nodiscard]] RootDocument rootFromJson(const Json& j, const Uid& expectedVaultUid);

// The vectors' serialization: UTF-8, keys sorted, no insignificant whitespace (Python json.dumps(sort_keys=True,
// separators=(",", ":"), ensure_ascii=False)). Invalid UTF-8 in a string throws.
[[nodiscard]] std::string canonicalJson(const Json& j);

// "2026-11-05T12:00:00Z" for a Unix time.
[[nodiscard]] std::string isoTime(std::time_t t);

}
