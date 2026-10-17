#include "recovery/local/Restore.hpp"
#include "recovery/local/Versions.hpp"

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <filesystem>
#include <system_error>

namespace vh::recovery::local {

namespace {

namespace rq = db::query::recovery;
namespace sfs = std::filesystem;

constexpr unsigned int kPlanMemberPage = 500;

sfs::path cleanVaultPath(const std::string& p) {
    if (p.empty() || p.front() != '/') throw ops::Invalid("a vault path starts with '/': '" + p + "'");
    auto s = sfs::path(p).lexically_normal().string();   // absolute: no leading ".." survives
    while (s.size() > 1 && s.back() == '/') s.pop_back();
    return s;
}

bool pathAtOrUnder(const sfs::path& path, const sfs::path& root) {
    if (root == "/" || path == root) return true;
    const auto rel = path.lexically_relative(root);
    return !rel.empty() && rel.native() != "." && rel.native() != ".." && !rel.native().starts_with("../");
}

std::shared_ptr<storage::Engine> engineOf(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->vault) throw ops::NotFound("vault " + std::to_string(vaultId) + " is not available");
    return engine;
}

std::shared_ptr<fs::model::Entry> entryAt(const storage::Engine& engine, const sfs::path& vaultPath) {
    return runtime::Deps::get().fsCache->getEntry(engine.vaultPathToFusePath(vaultPath));
}

// The first existing ancestor of `path` that is not a directory (a file or symlink in the way), if any.
std::optional<sfs::path> blockingAncestor(const storage::Engine& engine, const sfs::path& path) {
    for (auto p = path.parent_path(); ; p = p.parent_path()) {
        if (const auto e = entryAt(engine, p)) {
            if (e->isDirectory()) return std::nullopt;
            return p;
        }
        if (p == p.parent_path()) return std::nullopt;
    }
}

std::vector<sfs::path> missingAncestors(const storage::Engine& engine, const sfs::path& path) {
    std::vector<sfs::path> missing;
    for (auto p = path.parent_path(); ; p = p.parent_path()) {
        if (entryAt(engine, p)) break;
        missing.push_back(p);
        if (p == p.parent_path()) break;
    }
    std::ranges::reverse(missing);
    return missing;
}

std::string lvId(const int64_t id) {
    return RecoveryId{.type = RecoveryId::Type::LocalGeneration, .id = static_cast<uint64_t>(id)}.str();
}

std::string snapId(const int64_t id) {
    return RecoveryId{.type = RecoveryId::Type::Snapshot, .id = static_cast<uint64_t>(id)}.str();
}

bool isDirectoryItem(const PlanItem& item) {
    return item.source_id.starts_with("snap-") && std::ranges::find(item.notes, std::string(kDirectoryNote)) != item.notes.end();
}

// Where a retained path goes: itself, or under the alternate root (see Restore.hpp).
struct DestinationMap {
    std::optional<sfs::path> root;
    sfs::path base;   // parent of the chosen point

    [[nodiscard]] sfs::path operator()(const sfs::path& retained) const {
        if (!root) return retained;
        const auto rel = retained.lexically_relative(base);
        if (rel.empty() || rel.native() == ".") return *root;
        return (*root / rel).lexically_normal();
    }
};

// Why a generation's body can't be restored, if it can't.
std::optional<std::string> unavailableReason(const rq::GenerationRow& row, const storage::Engine& engine,
                                             const store::VaultRef& ref) {
    if (!row.blob_id)
        return row.upstream_state == rq::UpstreamState::Sent
                   ? std::string("the body is held only by the provider (sent upstream)")
                   : std::string("no retained body");
    const auto handle = store::open(ref, *row.blob_id);
    if (!handle || !handle->present) return std::string("blob missing");
    if (!handle->row.encryption_iv.empty() && !engine.encryptionManager->hasKeyVersion(handle->row.key_version))
        return "key version " + std::to_string(handle->row.key_version) + " is no longer held by the vault";
    if (handle->row.encryption_iv.empty() && handle->row.cipher_bytes != 0)
        return std::string("the retained generation is not sealed");
    return std::nullopt;
}

PlanItem fileItem(const rq::GenerationRow& row, const storage::Engine& engine, const store::VaultRef& ref,
                  const sfs::path& destination) {
    PlanItem item;
    item.source_id = lvId(row.id);
    item.source_path = row.path;
    item.destination_path = destination.string();
    item.size_bytes = row.size_bytes;

    const auto iv = row.encryption_iv.value_or("");
    const auto keyVersion = row.key_version.value_or(0);
    const bool empty = iv.empty();
    item.method = empty || keyVersion == engine.encryptionManager->get_key_version() ? "local_copy" : "local_reseal";
    if (item.method == "local_reseal")
        item.notes.push_back("sealed under key version " + std::to_string(keyVersion) +
                             ": re-sealed under the current key");

    if (const auto dest = entryAt(engine, destination)) {
        if (dest->isDirectory()) {
            item.action = ItemAction::Conflict;
            item.notes.emplace_back("a directory is at the destination");
            return item;
        }
        if (dest->isSymlink()) {
            item.action = ItemAction::Conflict;
            item.notes.emplace_back("a symlink is at the destination");
            return item;
        }
        const auto file = std::static_pointer_cast<fs::model::File>(dest);
        const bool same = empty ? file->encryption_iv.empty() && file->size_bytes == 0 && row.size_bytes == 0
                                : file->encryption_iv == iv && file->encrypted_with_key_version == keyVersion;
        if (same && row.blob_id) {
            item.action = ItemAction::Skip;
            item.method = "none";
            item.notes.emplace_back("the destination already holds this generation");
            return item;
        }
        item.action = ItemAction::Overwrite;
        item.destination_source_id = storage::generationOf(*file).sourceId();
    } else if (const auto blocker = blockingAncestor(engine, destination)) {
        item.action = ItemAction::Conflict;
        item.notes.push_back("a file is in the way at " + blocker->string());
        return item;
    } else {
        item.action = ItemAction::Create;
    }

    if (const auto reason = unavailableReason(row, engine, ref)) {
        item.action = ItemAction::Unavailable;
        item.method = "none";
        item.destination_source_id.reset();
        item.notes.push_back(*reason);
    }
    return item;
}

PlanItem directoryItem(const int64_t snapshotId, const storage::Engine& engine, const sfs::path& retained,
                       const sfs::path& destination) {
    PlanItem item;
    item.source_id = snapId(snapshotId);
    item.source_path = retained.string();
    item.destination_path = destination.string();
    item.method = "none";
    item.notes.emplace_back(kDirectoryNote);
    if (const auto dest = entryAt(engine, destination)) {
        if (dest->isDirectory()) {
            item.action = ItemAction::Skip;
            item.notes.emplace_back("the directory exists");
        } else {
            item.action = ItemAction::Conflict;
            item.notes.emplace_back("a file is at the destination");
        }
    } else if (const auto blocker = blockingAncestor(engine, destination)) {
        item.action = ItemAction::Conflict;
        item.notes.push_back("a file is in the way at " + blocker->string());
    } else {
        item.action = ItemAction::Create;
    }
    return item;
}

void tally(LocalPlan& plan) {
    for (const auto& item : plan.items) {
        switch (item.action) {
        case ItemAction::Create: ++plan.creates; break;
        case ItemAction::Overwrite: ++plan.overwrites; break;
        case ItemAction::Skip: ++plan.skips; break;
        case ItemAction::Conflict: ++plan.conflicts; break;
        case ItemAction::Unavailable: ++plan.unavailable; break;
        case ItemAction::Remove: break;
        }
    }
}

void addWarningsAndBlockers(LocalPlan& plan, const storage::Engine& engine) {
    uint64_t reseals = 0, bytes = 0;
    for (const auto& item : plan.items) {
        if (item.action != ItemAction::Create && item.action != ItemAction::Overwrite) continue;
        if (item.method == "local_reseal") ++reseals;
        if (item.size_bytes && *item.size_bytes > 0) bytes += *item.size_bytes + crypto::util::AES_TAG_SIZE;
    }
    if (reseals > 0)
        plan.warnings.push_back(std::to_string(reseals) +
                                " file(s) were sealed under an older vault key and are re-sealed under the current one");
    if (plan.unavailable > 0)
        plan.warnings.push_back(std::to_string(plan.unavailable) + " file(s) can't be restored (see each item's notes)");
    if (plan.conflicts > 0)
        plan.warnings.push_back(std::to_string(plan.conflicts) + " destination(s) conflict and will not be written");
    if (engine.type() == storage::StorageType::Cloud && plan.creates + plan.overwrites > 0)
        plan.warnings.emplace_back("restored files are local writes: the next sync uploads each once");
    if (bytes > 0) {
        if (const auto free = engine.freeSpace(); bytes > free)
            plan.blockers.push_back("the restore writes " + std::to_string(bytes) + " bytes but the vault has " +
                                    std::to_string(free) + " left in its quota");
    }
}

}

LocalPlan planFor(const RecoveryId& source, const std::optional<std::string>& subPath,
                  const std::optional<std::string>& destination) {
    if (source.type == RecoveryId::Type::ProviderVersion)
        throw std::invalid_argument(source.str() + " is not a local recovery point");

    LocalPlan plan;
    const std::optional<sfs::path> destRoot =
        destination ? std::optional<sfs::path>(cleanVaultPath(*destination)) : std::nullopt;

    if (source.type == RecoveryId::Type::LocalGeneration) {
        if (subPath) throw ops::Invalid("a sub-path applies to snapshots only");
        const auto row = rq::Generation::get(static_cast<int64_t>(source.id));
        if (!row || !row->vault_id) throw ops::NotFound("no local recovery point " + source.str());
        const auto engine = engineOf(*row->vault_id);
        const auto ref = store::vaultRef(*engine->vault);
        const DestinationMap map{.root = destRoot, .base = sfs::path(row->path).parent_path()};
        plan.vault_id = *row->vault_id;
        plan.source_label = source.str();
        plan.atomic = false;
        plan.consistency_note = "one retained generation of one file";
        plan.items.push_back(fileItem(*row, *engine, ref, map(row->path)));
        tally(plan);
        addWarningsAndBlockers(plan, *engine);
        return plan;
    }

    const auto snapshotId = static_cast<int64_t>(source.id);
    const auto snap = rq::Snapshot::get(snapshotId);
    if (!snap) throw ops::NotFound("no snapshot " + source.str());
    if (snap->state != "ready") throw ops::Conflict(source.str() + " is " + snap->state + ", not ready");
    const auto engine = engineOf(snap->vault_id);
    const auto ref = store::vaultRef(*engine->vault);

    const sfs::path point = subPath ? cleanVaultPath(*subPath) : sfs::path(snap->root_path);
    if (!pathAtOrUnder(point, snap->root_path))
        throw ops::NotFound(point.string() + " is not in " + source.str() + " (taken of " + snap->root_path + ")");
    const DestinationMap map{.root = destRoot, .base = point.parent_path()};

    plan.vault_id = snap->vault_id;
    plan.source_label = subPath ? source.str() + ":" + point.string() : source.str();
    plan.atomic = true;
    plan.consistency_note =
        "taken in one pass: every file is the generation it had when the snapshot read it under its content lock "
        "(the last sealed one for files open through the mount); files changed during the pass are as of that moment";

    std::string after;
    for (;;) {
        const auto page = rq::Generation::listSnapshotMembers(snapshotId, after, kPlanMemberPage);
        for (const auto& member : page) {
            if (!pathAtOrUnder(member.path, point)) continue;
            plan.items.push_back(fileItem(member, *engine, ref, map(member.path)));
        }
        if (page.size() < kPlanMemberPage) break;
        after = page.back().rel_path.value_or("");
    }
    for (const auto& dir : snap->empty_directories)
        if (pathAtOrUnder(dir, point)) plan.items.push_back(directoryItem(snapshotId, *engine, dir, map(dir)));

    if (plan.items.empty() && subPath && point != sfs::path(snap->root_path))
        throw ops::NotFound(point.string() + " is not in " + source.str());

    tally(plan);
    addWarningsAndBlockers(plan, *engine);
    return plan;
}

std::vector<std::string> missingParents(const storage::Engine& engine, const PlanItem& item) {
    std::vector<std::string> out;
    for (const auto& p : missingAncestors(engine, cleanVaultPath(item.destination_path))) out.push_back(p.string());
    return out;
}

ItemOutcome restore(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<identities::User>& actor,
                    const PlanItem& item) {
    ItemOutcome out{.destination_path = item.destination_path, .outcome = "failed", .error = std::nullopt};
    const auto notes = [&item] {
        std::string s;
        for (const auto& n : item.notes) s += (s.empty() ? "" : "; ") + n;
        return s.empty() ? std::optional<std::string>() : std::optional<std::string>(s);
    };
    switch (item.action) {
    case ItemAction::Skip: out.outcome = "skipped"; out.error = notes(); return out;
    case ItemAction::Conflict: out.outcome = "conflict"; out.error = notes(); return out;
    case ItemAction::Unavailable: out.outcome = "unavailable"; out.error = notes(); return out;
    case ItemAction::Remove: out.error = "not a local restore action"; return out;
    case ItemAction::Create:
    case ItemAction::Overwrite: break;
    }

    try {
        if (!engine || !engine->vault || !actor) throw std::invalid_argument("restore needs the vault's engine and an actor");
        const auto destination = cleanVaultPath(item.destination_path);
        const auto fusePath = engine->vaultPathToFusePath(destination);
        const auto existing = runtime::Deps::get().fsCache->getEntry(fusePath);

        if (isDirectoryItem(item)) {
            if (existing) {
                out.outcome = existing->isDirectory() ? "skipped" : "conflict";
                out.error = existing->isDirectory() ? "the directory exists" : "a file is at the destination";
                return out;
            }
            if (const auto blocker = blockingAncestor(*engine, destination)) {
                out.outcome = "conflict";
                out.error = "a file is in the way at " + blocker->string();
                return out;
            }
            engine->mkdir(destination, actor);
            out.outcome = "restored";
            return out;
        }

        const auto id = RecoveryId::parse(item.source_id);
        if (id.type != RecoveryId::Type::LocalGeneration) throw std::invalid_argument("not a local generation: " + item.source_id);
        const auto row = rq::Generation::get(static_cast<int64_t>(id.id));
        if (!row) {
            out.outcome = "unavailable";
            out.error = item.source_id + " no longer exists";
            return out;
        }
        if (!row->vault_id || *row->vault_id != engine->vault->id)
            throw std::invalid_argument(item.source_id + " belongs to another vault");
        const auto ref = store::vaultRef(*engine->vault);
        if (const auto reason = unavailableReason(*row, *engine, ref)) {
            out.outcome = "unavailable";
            out.error = *reason;
            return out;
        }
        const auto handle = store::open(ref, *row->blob_id);
        if (!handle || !handle->present) {
            out.outcome = "unavailable";
            out.error = "blob missing";
            return out;
        }

        // The destination as planned (the CAS in createFile settles the rest under the content lock).
        if (item.action == ItemAction::Create && existing) {
            out.outcome = "conflict";
            out.error = "the destination was created after the plan";
            return out;
        }
        if (item.action == ItemAction::Overwrite && (!existing || !item.destination_source_id)) {
            out.outcome = "conflict";
            out.error = "the destination was removed after the plan";
            return out;
        }
        if (existing && (existing->isDirectory() || existing->isSymlink())) {
            out.outcome = "conflict";
            out.error = "the destination is no longer a file";
            return out;
        }
        if (const auto blocker = blockingAncestor(*engine, destination)) {
            out.outcome = "conflict";
            out.error = "a file is in the way at " + blocker->string();
            return out;
        }
        if (!existing && !missingAncestors(*engine, destination).empty()) engine->mkdir(destination.parent_path(), actor);

        const auto blob = handle->row;
        const auto blobPath = handle->path;
        const auto em = engine->encryptionManager;
        const auto mime = row->mime_type;
        const fs::SealedWriter writer = [&](const sfs::path& dst) -> fs::SealedContent {
            if (blob.encryption_iv.empty()) {
                // Every empty file is stored as nothing, unencrypted (no IV, key version 0).
                const int fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
                if (fd < 0) throw std::system_error(errno, std::generic_category(), "create " + dst.string());
                ::close(fd);
                return {.encryption_iv = "", .key_version = 0, .plaintext_size = 0, .mime_type = mime};
            }
            if (blob.key_version == em->currentKey().version) {
                // Same key: the sealed bytes are reused (same IV, same plaintext, as copy does), once they authenticate.
                if (blob.cipher_bytes < crypto::util::AES_TAG_SIZE ||
                    blob.cipher_bytes - crypto::util::AES_TAG_SIZE != blob.plaintext_bytes)
                    throw storage::IntegrityError("the retained generation's size does not match its record");
                const auto key = em->historicalKeySnapshot(blob.key_version);
                const auto iv = crypto::util::b64_decode(blob.encryption_iv);
                if (iv.size() != crypto::util::AES_IV_SIZE) throw storage::IntegrityError("the retained generation has a bad IV");
                const int fd = ::open(blobPath.c_str(), O_RDONLY | O_CLOEXEC);
                if (fd < 0) throw std::system_error(errno, std::generic_category(), "open " + blobPath.string());
                bool ok = false;
                try {
                    ok = crypto::util::gcmVerifyFd(fd, 0, blob.plaintext_bytes, key->bytes(),
                                                   crypto::util::GcmIv(iv.data(), crypto::util::AES_IV_SIZE));
                } catch (...) {
                    ::close(fd);
                    throw;
                }
                ::close(fd);
                if (!ok) throw storage::IntegrityError("the retained generation failed authentication");
                sfs::copy_file(blobPath, dst, sfs::copy_options::none);
                return {.encryption_iv = blob.encryption_iv, .key_version = blob.key_version,
                        .plaintext_size = blob.plaintext_bytes, .mime_type = mime};
            }
            // An older key: streaming re-seal under the current key with a fresh IV (old tag verified first).
            const auto sealed = std::make_shared<fs::model::File>();
            em->resealFileToCurrent(blobPath, blob.encryption_iv, blob.key_version, dst, sealed);
            return {.encryption_iv = sealed->encryption_iv, .key_version = sealed->encrypted_with_key_version,
                    .plaintext_size = blob.plaintext_bytes, .mime_type = mime};
        };

        fs::NewFileContext ctx{
            .path = destination,
            .fuse_path = fusePath,
            .engine = engine,
            .user = actor,
            .mode = row->mode ? static_cast<mode_t>(*row->mode) : static_cast<mode_t>(0644),
            .overwrite = true,
            // "" matches no generation: a Create must not find a file there (ContentConflict).
            .expected_source_id = item.action == ItemAction::Create ? std::string() : *item.destination_source_id,
            .version_reason = Reason::Restore,
            .sealed = writer,
        };
        static_cast<void>(fs::Filesystem::createFile(ctx));
        out.outcome = "restored";
        out.error.reset();
        log::Registry::audit()->info("[recovery] {} restored {} to {} in vault {}", actor->name(), item.source_id,
                                     destination.string(), engine->vault->id);
    } catch (const fs::ContentConflict& e) {
        out.outcome = "conflict";
        out.error = e.what();
    } catch (const vault::KeyVersionUnavailable& e) {
        out.outcome = "unavailable";
        out.error = e.what();
    } catch (const storage::IntegrityError& e) {
        out.outcome = "failed";
        out.error = std::string("the retained generation failed authentication: ") + e.what();
    } catch (const std::exception& e) {
        out.outcome = "failed";
        out.error = e.what();
    }
    if (out.outcome == "failed")
        log::Registry::storage()->error("[recovery::restore] {} → {} failed: {}", item.source_id, item.destination_path,
                                        out.error.value_or("unknown"));
    return out;
}

}
