#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/mirror/Copy.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <vector>

// Detach a copy (server mirror phase 2, wave 5, piece C; design/peers/mirror.md "Detach a copy", "As built: detach a
// copy"; migration 169).
//
// On the server holding a vault as another server's copy (role mirror in any state, or orphaned), a new, separate local
// vault is written from it: the normal vault creation (storage::Manager::addVault: a new vault uid and its own new key),
// a chosen owner with the owner's ordinary access, new entry uids, every live folder, file and symlink with its name,
// place, mode and modification time. Trash, versions, shares and access rules are not copied. Each file is decrypted
// from the held vault and written through the new vault's ordinary write path (fs::Filesystem::createFile with a
// streamed source: never a whole file in memory). Files whose contents were not here when the copy started (the detach
// preview's list) are left out and listed exactly; so is any file removed, or whose bytes fail authentication, while
// the copy runs. The held vault is untouched: it stays a mirror (following, or read-only) or an orphaned copy. Nothing
// is asked of the core; the link may be down.
//
// A background job (Service, "MirrorCopies") with progress (entries and bytes done of the totals counted at the start).
// While it runs, the new vault is read-only to everything but the copy (mirror::access kCopyWriting). It ends with a
// complete new vault or none: a failure or a cancel removes the partial vault (storage::Manager::removeVault). A
// daemon stop leaves the job running and its partial vault gated; the next start removes that vault and starts the
// copy over (attempts counts how often).
//
// Refused up front: a vault not held here (mirror_not_held), a copy of it already running, a name the owner has, and a
// copy that the volume's free space (with a margin) or the quota the new vault takes (the held vault's) cannot hold
// (mirror_copy_no_space). ops::mirrors authorizes (requireDetacher) and resolves the owner.
namespace vh::mirror::copy {

using json = nlohmann::json;
using Job = vh::db::query::mirror::CopyJob;

struct Plan {
    uint32_t source_vault_id{};
    std::string source_name{};
    std::vector<vh::db::query::mirror::CopyEntry> entries{};   // what is copied (the root first)
    uint64_t files{}, bytes{};          // files to copy and their plaintext bytes
    uint64_t sealed_bytes{};            // what they take on disk once sealed
    std::vector<vh::db::query::mirror::CopySkipped> skipped{};
    uint64_t quota{};                   // the held vault's, which the new vault takes (0: none)
};

// What a copy of the held vault would write now. ops::Refused mirror_not_held for a vault not held here.
[[nodiscard]] Plan plan(uint32_t sourceVaultId);

struct Request {
    uint32_t source_vault_id{};
    std::optional<std::string> name{};   // default: "<held vault's name> copy" (then "copy 2", ...)
    uint32_t owner_id{};                 // a local, active account (ops::mirrors checks)
};

// Plans, checks and queues the copy (audited mirror.detach.copy); the service writes it.
[[nodiscard]] Job start(const Request& request, std::optional<uint32_t> actorId, const std::string& actorName);
// The newest copy of the held vault, nullopt when it has none.
[[nodiscard]] std::optional<Job> latest(uint32_t sourceVaultId);
// Asks the running copy of the held vault to stop; it removes its partial vault and ends cancelled (audited
// mirror.detach.copy.cancel). ops::Refused mirror_copy_not_running when none runs.
[[nodiscard]] Job cancel(uint32_t sourceVaultId, std::optional<uint32_t> actorId, const std::string& actorName);

// Writes the copy to its end (the service's thread; tests): finished, failed or cancelled, audited. `stop` is asked
// between chunks; when it answers true the copy leaves off where it is and stays running (the next run starts it over).
// A job that is not running is returned as it is.
Job run(uint64_t jobId, const std::function<bool()>& stop = {});

[[nodiscard]] json toJson(const Job& job);

class Service final : public concurrency::AsyncService {
public:
    static constexpr std::chrono::seconds kInterval{5};

    Service();
    static const std::shared_ptr<Service>& instance();

    // Runs every running copy to its end, one after another (the loop; tests). How many it ran.
    std::size_t tick();
    void wake();

protected:
    void runLoop() override;
    void onStop() override;

private:
    std::mutex wakeMutex_;
    std::condition_variable wakeCv_;
    bool woken_{false};
};

// Tests: cancel requests this process holds in memory.
void resetForTesting();

}
