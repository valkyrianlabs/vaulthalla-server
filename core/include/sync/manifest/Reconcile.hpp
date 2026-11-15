#pragma once

#include "sync/manifest/Content.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The applier's merge (design/sync/manifest-applier.md, work item 2): what a writer's database must become to take in
// another writer's root. reconcile(base, theirs, ours) is pure: three Content values in (base = the content of the
// recorded root, the local base copy; theirs = the head; ours = Manifest::collect now), the resulting tree, an
// ordered plan and the conflicts out. No database, no I/O, nothing of the server, so the shared format library and
// the Desktop engine can run the same rules.
//
// Per entry (matched by uid only) the groups are compared three-way: placement (parent, name), content (generation,
// key_version, size, content_hash, object, mime, format; mtime follows it), attributes (mode, owner, symlink target)
// and state (live, trashed, gone). A group changed on one side takes that side, changed on both to the same value is in
// sync, changed on both differently is a conflict:
//   content edit / edit          ours stays in the tree, an open conflict carries theirs (the planner decides it)
//   placement, attributes        the head wins, reported
//   edit / delete, edit / trash  the edit wins in both directions ("edit" = content changed since base, or a restore)
//   trash / purge, delete / delete, trash / trash   converged (purge over trash: both deleted, nothing edited)
// then the tree rules, in order: a folder deleted on one side keeps living while the result puts a live entry in it
// (from the side that kept it); a move that would close a directory cycle is not applied (the entry keeps our
// placement); an entry whose folder is gone everywhere, or a cycle the head alone made, goes under /Recovered (a
// directory with a uid derived from the vault root's, so every writer makes the same one); of live names that clash in
// one folder every entry but the least uid becomes `name (<uid[0..8]>)`. Names compare byte for byte. History
// (provider versions, prior names, tombstones) is a union, never a conflict.
//
// Vault settings are merged per field (the head wins a conflict); recovery grants are never merged (the account's
// signed policy is handed on, design/cloud/key-manager.md); key records are only checked: a version this writer
// doesn't hold, or one whose key check differs, stops everything (stopped(), nothing in the plan). Snapshot records
// merge by uid (created where theirs added one, deleted where theirs deleted one we hadn't changed); records without a
// uid (written before uids) are left alone.
//
// reconcile(base, theirs, result) is result with an empty plan (applying the same head twice changes nothing), and so
// is reconcile(theirs, theirs, result) once the root is recorded (ManifestReconcileProperty.*).
namespace vh::sync::manifest {

// The plan's order (the design's "What it applies, in order"; step 11, the record, is the executor's).
enum class Step : uint8_t {
    VaultSettings = 1,
    Envelopes = 2,
    CreateDirs = 4,
    Moves = 5,
    Creates = 6,
    Content = 7,
    Deletes = 8,
    History = 9,
    Snapshots = 10,
};

enum class OpKind : uint8_t {
    SetVault,         // 1: result.vault (a name another vault of this server holds is the executor's to refuse)
    AddEnvelopes,     // 2: envelope kids of one key version
    CreateDir,        // 4: parents first
    Move,             // 5: placement (directories first, then files and symlinks)
    Create,           // 6: a file or symlink (remote-only, bound to o/<uid>), or a trash row
    Restore,          // 6: a trashed file back to a live place
    ReplaceContent,   // 7: the new generation and object
    SetAttributes,    // 7: mode, owner, symlink target
    Trash,            // 8: live into trash, or trash metadata
    Delete,           // 8: a live entry gone (children first)
    Purge,            // 8: a trashed file gone
    AddHistory,       // 9: provider versions, prior names, tombstones (insert only)
    CreateSnapshot,   // 10
    DeleteSnapshot,   // 10
};
[[nodiscard]] std::string_view to_string(OpKind kind);
[[nodiscard]] Step stepOf(OpKind kind);

// One change to the database. For entry operations `ours` is the entry as ours held it (what the executor's
// compare-and-set checks: a row a local write changed since collect is skipped) and `target` the entry as the result
// has it (nullopt: gone). Several operations may name one uid (a move and a content replacement); each carries the
// whole target.
struct Op {
    OpKind kind{};
    std::string uid;                              // entry uid, snapshot uid; empty for SetVault
    std::optional<Entry> ours;
    std::optional<Entry> target;
    std::optional<SnapshotRecord> snapshot;       // CreateSnapshot, DeleteSnapshot
    std::optional<VaultInfo> vault;               // SetVault
    uint32_t key_version{};                       // AddEnvelopes
    std::vector<std::string> envelopes;           // AddEnvelopes: the kids to add
    [[nodiscard]] bool operator==(const Op&) const = default;
};

enum class ConflictKind : uint8_t {
    ContentEditEdit,   // open: the planner's conflict path decides it under the vault's policy
    Placement,         // decided: the head's placement
    Attributes,        // decided: the head's attributes
    VaultSetting,      // decided: the head's value (uid = the field's name)
    EditBeatsDelete,   // decided: the edited side's entry lives on (ours kept, or theirs re-created)
    EditBeatsTrash,    // decided: the edited side's entry stays live (or is restored from our trash)
    FolderKept,        // decided: a deleted folder kept for the live entries the result puts in it
    CycleNotApplied,   // decided: the head's move would close a directory cycle; ours kept
    Repaired,          // decided: an entry whose folder is gone everywhere, or a cycle in the head, under /Recovered
    NameClash,         // decided: renamed `name (<uid[0..8]>)`
};
[[nodiscard]] std::string_view to_string(ConflictKind kind);

struct Conflict {
    ConflictKind kind{};
    std::string uid;
    bool open{false};
    std::optional<Entry> theirs;
    std::optional<Entry> ours;
    std::string detail;
    [[nodiscard]] bool operator==(const Conflict&) const = default;
};

// manifest_key_missing: theirs names a key version this writer doesn't hold; manifest_key_mismatch: one it holds with
// another key check.
struct KeyProblem {
    uint32_t version{};
    std::string code;
    [[nodiscard]] bool operator==(const KeyProblem&) const = default;
};

struct Reconciliation {
    Content result;                       // what the database holds once the plan is applied
    std::vector<Op> plan;                 // ordered by step
    std::vector<Conflict> conflicts;
    std::vector<KeyProblem> key_problems; // non-empty: stopped, the plan is empty and result is ours
    // theirs carries an account recovery policy other than ours: the executor verifies it (pin, sequence) and hands it
    // to the cloud service; it is never applied here.
    std::optional<AccountPolicyBytes> incoming_account_policy;

    [[nodiscard]] bool stopped() const { return !key_problems.empty(); }
};

[[nodiscard]] Reconciliation reconcile(const Content& base, const Content& theirs, const Content& ours);

// The plan applied to `ours` as a model (no compare-and-set: nothing changes in between): result. The reference the DB
// executor is tested against, and the Desktop engine's model.
[[nodiscard]] Content applyPlan(const Content& ours, const std::vector<Op>& plan);

// What makes a tree broken, one line each: a live entry whose parent is not a live directory, a directory cycle, two
// live entries with one name in one folder, no root or more than one. Empty for a sound tree.
[[nodiscard]] std::vector<std::string> treeProblems(const Content& content);

// The /Recovered directory reconcile creates under the vault root `rootUid` (the same uid on every writer).
[[nodiscard]] std::string recoveredDirUid(const std::string& rootUid);
inline constexpr std::string_view kRecoveredName = "Recovered";

}
