#pragma once

#include "db/query/mirror/Pending.hpp"
#include "fs/Fwd.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// A person's change to a vault this server mirrors, applied here at once as pending (design/peers/mirror.md "A change
// made on the mirror" step 1, "As built: a change made on the mirror"). ops::fs builds one right after the gate's line
// (mirror::access::requireWritable) and runs its mutation through it:
//
//   * inert (the mutation runs as it always has) unless the vault is held here as a mirror that is Live and accepts
//     local changes;
//   * otherwise, under the vault's local-change lock (also held by the applier: a change here and a group from the core
//     never interleave), it records the pending change first (mirror_pending, state local) with every entry it touches
//     as the tables hold it now (mirror_dirty: what the core last confirmed, unless the entry is already dirty), a
//     created entry under a uid chosen now (db::query::fs::AssignedUid, so the core creates it under the same one);
//     then it runs the mutation with the backstop's switch and the request id set in every transaction it begins
//     (db::SessionSettings, from db::query::mirror::Pending::localSettings), and marks the change ready to submit and wakes the
//     follower, which submits it (mirror::submit::submitPending). A mutation that fails having changed nothing leaves
//     nothing; one that changed something is submitted all the same (the core decides, and the confirmation or the
//     refusal settles every entry it touched).
//
// The journal fires from the table writes as for any local change, so this server's clients see the change at once.
// The entry hashes (mirror_entry_hash) and the digest stay what the core confirmed: a pending change never moves them.
namespace vh::mirror::submit {

// The local-change lock of a vault this server mirrors: held by a change made here for as long as it runs, and by the
// applier around each page or group it applies (and by the settling of a refused change). Recursive: the follower,
// holding it, settles through the applier.
[[nodiscard]] std::recursive_mutex& vaultMutex(uint32_t vaultId);

// A new request id (32 lower-case hex digits).
[[nodiscard]] std::string newRequestId();

// "name (conflict <8 hex of the uid>).ext" (the extension of a file kept last; none for a folder or a dot-file).
[[nodiscard]] std::string conflictName(const std::string& name, const std::string& uid, bool directory);


class Local {
public:
    enum class Mode {
        Change,   // a person's change: taken only while the vault is Live
        // A seal of a file that was open for writing (design/peers/mirror.md "What strict mode cannot refuse"): taken
        // while Live and also while the link is down (sealed and kept as pending, submitted when the link returns).
        Seal,
    };

    // `op`: mkdir | move | rename | remove | copy | write | setattr (the mirror_pending ops). Inert as well when a Local
    // of the same vault is already running on this thread (the outer one describes the change: ops::fs over
    // vh::fs::Filesystem), or under a Suppress.
    Local(const vh::ops::Actor& actor, uint32_t vaultId, std::string op, Mode mode = Mode::Change);
    ~Local();
    Local(const Local&) = delete;
    Local& operator=(const Local&) = delete;

    // Whether the change is pending here (false: an ordinary local change).
    [[nodiscard]] bool active() const noexcept { return active_; }

    // The operation is on the entry at `vaultPath`; it and (`subtree`) everything under it change. The first call names
    // the change's entry. NotFound when nothing is there.
    void on(const std::filesystem::path& vaultPath, bool subtree);
    // The operation creates the entry at `vaultPath` (a folder): its uid is chosen now; the first call names the
    // change's entry. Returns the uid.
    std::string creates(const std::filesystem::path& vaultPath);
    // The operation's destination (`vaultPath`'s folder and name), as the core is told it: args parent_uid and name.
    void into(const std::filesystem::path& vaultPath);

    // Submitted without being applied here (copy: its new entries come back from the core with the core's uids).
    void submitOnly();

    // A replacement of contents: the generation it was based on (the core commits it only over that one).
    void base(const std::string& generation);
    // The contents the change wrote (after the mutation, inside run): their facts go to the core with it, and the sealed
    // bytes are kept in the pending store (mirror::submit::contents) until the core has confirmed or refused it.
    void content(const vh::fs::model::File& file);
    // Any other argument the core needs (setattr's mode and time).
    void arg(const std::string& key, nlohmann::json value);

    // While alive, no Local of `vaultId` starts on this thread: this server's own bringing-into-line of a change it
    // already describes (a conflict copy made from the pending store).
    class Suppress {
    public:
        explicit Suppress(uint32_t vaultId);
        ~Suppress();
        Suppress(const Suppress&) = delete;
        Suppress& operator=(const Suppress&) = delete;

    private:
        uint32_t vault_;
    };

    // Runs `apply` (the mutation) as a pending change; when inert, just runs it.
    template <class F>
    void run(F&& apply) {
        if (!active_) {
            apply();
            return;
        }
        begin();
        try {
            if (!submitOnly_) {
                const auto settings = scope();
                apply();
            }
        } catch (...) {
            failed();
            throw;
        }
        succeeded();
    }

    // The pending change's request id (empty when inert).
    [[nodiscard]] const std::string& requestId() const noexcept { return requestId_; }

private:
    struct Scope;
    [[nodiscard]] std::shared_ptr<Scope> scope();
    void begin();
    void failed();
    void succeeded();

    vh::ops::Actor actor_;
    uint32_t vaultId_{};
    std::string op_;
    bool active_{false};
    bool pushed_{false};
    bool submitOnly_{false};
    std::optional<std::string> base_;
    std::optional<std::string> newGeneration_;
    std::optional<std::filesystem::path> contentBacking_;
    std::unique_lock<std::recursive_mutex> lock_;
    std::string requestId_;
    std::string entryUid_;
    nlohmann::json args_ = nlohmann::json::object();
    std::vector<vh::db::query::mirror::DirtyEntry> captured_;
    std::vector<std::string> created_;
    std::optional<std::filesystem::path> createdPath_;
    std::optional<uint64_t> row_;
};

}
