#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>

// The per-vault remote access gate (design/cloud/managed-remotes.md, "Entitlement states and the access gate"): what an
// S3 vault may still do with its bucket.
//
//   full       everything (no row: full)
//   read_only  reads and hydrates work; no PUT, COPY, DELETE or manifest publish. Local writes and deletes are kept
//              and go up on the first pass after access is full again; a key rotation waits.
//   none       no request to the bucket at all; local copies keep working, a remote-only file fails with
//              remote_unavailable.
//
// Set by an internal setter (set(): the managed-storage service, or an operator through `vh vault remote access`),
// stored in vault_remote_access (migration 140) and held in memory, so the checks below never touch the database:
// they are safe on FUSE, HTTP and ws threads. The gate prevents failures instead of retrying them: a sync pass of a
// restricted vault is skipped and records why (sync_event stalled, "skipped: remote read-only"), hydrate refuses
// before any request, and every metered request of a controller tagged with the vault (s3::Controller::recordRequest,
// beside the protection guard) is refused as a last line, so no path can write by accident.
namespace vh::storage::remote_access {

enum class Mode { Full, ReadOnly, None };
[[nodiscard]] std::string_view to_string(Mode mode);
[[nodiscard]] std::optional<Mode> modeFromString(std::string_view text);   // full | read_only | none

struct State {
    uint32_t vault_id{};
    Mode mode{Mode::Full};
    std::optional<std::string> reason;
    std::optional<std::string> set_by;   // "user:<name>" | "system:<service>"; nullopt: never set (full)
    std::optional<std::time_t> set_at;
};

// What is held in memory for the vault (Full when nothing is): never blocks on the database.
[[nodiscard]] Mode mode(uint32_t vaultId) noexcept;
[[nodiscard]] State state(uint32_t vaultId);

// Reads the vault's row into memory (a CloudEngine does this when it is built: at start, on reload and after an
// attach's cutover). A database failure keeps what memory held.
void refresh(uint32_t vaultId);
// Forgets the vault (its row is gone: the vault was detached or deleted).
void forget(uint32_t vaultId) noexcept;

// The internal setter: writes the row, then memory, and records the audit event `vault.remote.access` (with the
// cause). Only an S3 vault has remote access to gate (std::invalid_argument otherwise). Back to full from a restriction,
// it starts the vault's sync pass, which uploads what waited. Returns the new state.
State set(uint32_t vaultId, Mode mode, const std::optional<std::string>& reason, const std::string& setBy);

// The gate refused a request: the vault's access does not allow it. Not a provider error, never retried.
class Restricted final : public std::runtime_error {
public:
    Restricted(uint32_t vaultId, Mode mode, std::string_view operation);
    [[nodiscard]] uint32_t vaultId() const noexcept { return vaultId_; }
    [[nodiscard]] Mode mode() const noexcept { return mode_; }
    // remote_read_only | remote_unavailable
    [[nodiscard]] std::string_view code() const noexcept;

private:
    uint32_t vaultId_;
    Mode mode_;
};

// Writes (PUT, COPY, DELETE, manifest publish) need full access; reads (LIST, HEAD, GET) need anything but none.
[[nodiscard]] constexpr bool allowsWrites(const Mode m) noexcept { return m == Mode::Full; }
[[nodiscard]] constexpr bool allowsReads(const Mode m) noexcept { return m != Mode::None; }
// Throws Restricted when the vault's access doesn't allow the operation (named in the message).
void requireWrite(uint32_t vaultId, std::string_view operation);
void requireRead(uint32_t vaultId, std::string_view operation);

// Drops everything held in memory: storage::Manager::initStorageEngines starts over with it, and the engines it builds
// read their rows again (a test's schema reset reuses vault ids).
void clear() noexcept;

}
