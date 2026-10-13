#pragma once

#include "vault/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::storage::s3 { class Controller; }

// Safe vault deletion with retention (#162). Trusted primitives below ops::vaults (callers authorize):
//
//   schedule ──► Pending ──(restore)──► live again, exactly as it was
//                   │ purge_after passes (at once for "delete now")
//                   ▼
//                Purging: upstream objects (only when chosen) → local backing + cache directories → vault row
//                   │     (resumes after a restart; failures retry with backoff)
//                   ▼
//                Purged: tombstone + sealed key copies until key_retain_until → key copies dropped, tombstone stays
//
// A deleted vault leaves FUSE, listings, sync, shares and the S3 gateway at once. Its name, slug, FUSE name and bucket
// binding stay reserved until the purge. The key retention window always runs in full from the deletion.
namespace vh::vault::retention {

using Clock = std::chrono::system_clock;
using DeletionPtr = std::shared_ptr<model::Deletion>;

// The windows in force for a vault type (config vaults.*).
struct Windows {
    std::chrono::seconds retention_window{};
    std::chrono::seconds key_retention_window{};
};
[[nodiscard]] Windows windowsFor(model::VaultType type);

// A directory a purge would remove is not a plain directory directly under its root.
struct PathGuardError : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Removes root/alias recursively, only when alias is one well-formed name ([A-Za-z0-9_-]) and root/alias is a real
// directory (never a symlink) whose resolved path is directly under the resolved root. Returns false when there is
// nothing to remove. Throws PathGuardError on anything else.
bool removeVaultDirectory(const std::filesystem::path& root, const std::string& alias);
// The vault's backing directory and its cache directory, both through removeVaultDirectory.
void removeBackingData(const std::string& alias);

// Marks the vault deleted and takes it off every live surface. `now` purges on the next pass instead of after the
// retention window; the key retention window is unchanged.
DeletionPtr schedule(unsigned int vaultId, std::optional<unsigned int> deletedBy, bool now, bool deleteUpstream);
// A pending deletion is undone and the vault is live again; null when it is no longer restorable.
std::shared_ptr<model::Vault> restore(unsigned int vaultId);
// A pending (or purging) deletion purges on the next pass; delete_upstream changes when given. False when purged.
bool expedite(unsigned int vaultId, std::optional<bool> deleteUpstream);

struct PassResult {
    unsigned int purged{}, failed{}, deferred{}, keys_expired{};
};
// One retention pass at `now`: purges the due deletions (resuming interrupted ones) and drops expired key copies.
// Never runs inside a DB transaction or on a FUSE thread; S3 work is bounded per pass.
PassResult runPass(Clock::time_point now, const std::function<bool()>& stopRequested = {});

// "Delete now" asks the retention service for a pass without waiting for its interval.
void requestPass();
[[nodiscard]] bool takePassRequest();

// Per-pass upstream purge caps (one LIST page is 1000 keys).
inline constexpr unsigned int kUpstreamListsPerPass = 10;
inline constexpr unsigned int kUpstreamDeletesPerPass = 10'000;

// Test seam: the S3 controller an upstream purge uses (default: the vault's API key and bucket).
using ControllerFactory = std::function<std::shared_ptr<storage::s3::Controller>(const model::S3Vault&)>;
void setControllerFactoryForTesting(ControllerFactory factory);

// A deleted vault's retained key (current version), unsealed with the TPM master key, for `vh vault keys export`.
struct RetainedKey {
    std::vector<uint8_t> key;
    std::shared_ptr<model::Key> record;
};
[[nodiscard]] RetainedKey retainedKey(unsigned int vaultId);

}
