#pragma once

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

// The sealed bytes of a change made on the mirror (design/peers/mirror.md "A change made on the mirror" step 2, "As
// built: a change made on the mirror"):
//
//   * On the mirror, the pending store: when a person's write is applied here, its sealed bytes are linked (a second
//     name for the same inode, or a copy where linking is not possible) to .vh-mirror-pending/<vault id>/<row id>
//     under the backing root, so nothing that later replaces the file here (the core's state coming back) can take
//     them before the core has them. The link goes when the change is confirmed; a held change keeps it
//     (.vh-mirror-held/<vault id>/<held id>) until the person discards it.
//   * On the core, the staging area: the bytes a mirror PUT on the sealed lane, verified (size, BLAKE2b, every chunk
//     authenticated with the vault's key as that generation), kept under .vh-mirror-staged/<vault id>/<object uid>.
//     <generation> until the change that names them commits them (ops::fs::commitSealed) or a day passes.
namespace vh::mirror::submit::contents {

struct Facts {
    std::string generation{};     // files.encryption_iv form
    uint32_t key_version{};
    uint64_t size{};              // plaintext
    std::string content_hash{};   // BLAKE2b of the sealed bytes (files.content_hash)
};

// ---- the mirror

[[nodiscard]] std::filesystem::path pendingBlob(uint32_t vaultId, uint64_t rowId);
[[nodiscard]] std::filesystem::path heldBlob(uint32_t vaultId, uint64_t heldId);
// A second name for `from` at `to` (a hard link; a copy when the link fails). Throws when neither works.
void keep(const std::filesystem::path& from, const std::filesystem::path& to);
// Moves a blob (pending to held), removes one; both quietly when it is not there.
void moveBlob(const std::filesystem::path& from, const std::filesystem::path& to);
void dropBlob(const std::filesystem::path& blob) noexcept;

// ---- the core

[[nodiscard]] std::filesystem::path stagedPath(uint32_t vaultId, const std::string& objectUuid,
                                               const std::string& generation);

struct Staging {
    bool ok{false};
    unsigned http_status{0};
    std::string code{};
    std::string error{};
};

// The sealed bytes a linked server PUT for vault `vaultId` (this server its core, that server its mirror), received in
// `received` (a file of this server's that this call takes over): verified, then kept at stagedPath. Refusals:
// 422 invalid_contents (a size, hash or authentication that does not match), 404 not_found, 409 key_version_missing.
[[nodiscard]] Staging stage(uint32_t vaultId, const std::string& objectUuid, const Facts& facts,
                            const std::filesystem::path& received);
// stage()'s last step, for bytes already verified against `facts`: the facts kept beside them, the bytes moved into
// place. (In one database two vaults never hold each other's keys, so the unit tests' sealed lane delivers with this.)
[[nodiscard]] Staging keepVerified(uint32_t vaultId, const std::string& objectUuid, const Facts& facts,
                                   const std::filesystem::path& received);
// Where a PUT's body is written while it arrives (a private name in the vault's staging directory).
[[nodiscard]] std::filesystem::path receivingPath(uint32_t vaultId);
// Staged bytes and the facts they were verified against (kept beside them, written before the bytes are in place: the
// commit describes the file with these, never with what a submit claims).
struct StagedBytes {
    std::filesystem::path path{};
    Facts facts{};
};
// The staged bytes for a change, when they are there with their verified facts.
[[nodiscard]] std::optional<StagedBytes> staged(uint32_t vaultId, const std::string& objectUuid,
                                                const std::string& generation);
// Staged bytes and their facts go (committed, or no longer wanted).
void dropStaged(const StagedBytes& staged) noexcept;
// Staged bytes (and partial receptions) older than `age`, never committed, go. Returns how many.
std::size_t sweep(std::chrono::hours age);

}
