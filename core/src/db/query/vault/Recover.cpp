#include "db/query/vault/Recover.hpp"

#include "crypto/id/Generator.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/fs/Entry.hpp"
#include "fs/model/Entry.hpp"
#include "sync/manifest/Objects.hpp"
#include "vault/Content.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <functional>
#include <map>
#include <stdexcept>
#include <unordered_map>

namespace vh::db::query::vault {

namespace recover_query_detail {

namespace mf = vh::sync::manifest;
using encoding::to_hex_bytea;

std::optional<std::string> generationB64(const std::optional<std::string>& hex) {
    if (!hex || hex->size() != 2 * vh::crypto::vhf1::kSaltSize) return std::nullopt;
    std::vector<uint8_t> bytes(vh::crypto::vhf1::kSaltSize);
    std::size_t len = 0;
    if (sodium_hex2bin(bytes.data(), bytes.size(), hex->data(), hex->size(), nullptr, &len, nullptr) != 0 ||
        len != bytes.size())
        return std::nullopt;
    return vh::crypto::util::b64_encode(bytes);
}

std::string alias(const std::string& token) {
    return vh::crypto::id::Generator({.namespace_token = token}).generate();
}

std::string joinPath(const std::string& parent, const std::string& name) {
    return parent == "/" ? "/" + name : parent + "/" + name;
}

// The plaintext size a provider version holds, when its generation is known.
std::optional<uint64_t> plaintextOf(const mf::FileVersion& v) {
    if (!v.size) return std::nullopt;
    const auto gen = generationB64(v.generation);
    if (!gen) return std::nullopt;
    return vh::vault::content::plaintextSizeOfGeneration(*v.size, *gen);
}

std::string versionsLiteral(const std::vector<uint32_t>& versions) {
    std::string out = "{";
    for (const auto v : versions) out += (out.size() > 1 ? "," : "") + std::to_string(v);
    return out + "}";
}

}

uint32_t Recover::reserveVaultId() {
    return Transactions::exec("Recover::reserveVaultId", [&](pqxx::work& txn) {
        return txn.exec("SELECT nextval('vault_id_seq')").one_field_ref().as<uint32_t>();
    });
}

RecoverResult Recover::apply(const RecoverInput& in) {
    using namespace recover_query_detail;
    if (!in.content) throw std::invalid_argument("a restore needs the manifest content");
    if (in.vault_id == 0) throw std::invalid_argument("a restore needs a reserved vault id");
    const auto fsRoot = query::fs::Entry::getRootEntry();
    if (!fsRoot) throw std::runtime_error("the filesystem root entry is missing");

    return Transactions::exec("Recover::apply", [&](pqxx::work& txn) {
        RecoverResult r;
        r.vault_id = in.vault_id;
        const auto vid = in.vault_id;

        // ---- the vault: S3, opaque_v1, cache strategy (nothing is downloaded until a file is read)
        txn.exec("INSERT INTO vault (id, name, type, description, owner_id, mount_point, quota, is_active, slug, "
                 "fuse_name, uid) VALUES ($1, $2, $3, $4, $5, $6, $7, true, NULL, NULL, $8)",
                 pqxx::params{vid, in.name, vh::vault::model::to_string(vh::vault::model::VaultType::S3), in.description,
                              in.owner_id, in.mount_point, static_cast<int64_t>(in.quota),
                              vh::crypto::id::toUuid(in.vault_uid)});
        const auto syncId = txn.exec("INSERT INTO sync (vault_id, interval) VALUES ($1, $2) RETURNING id",
                                     pqxx::params{vid, in.sync_interval_seconds})
                                .one_field_ref()
                                .as<unsigned int>();
        txn.exec("INSERT INTO rsync (sync_id, conflict_policy, strategy) VALUES ($1, $2, 'cache')",
                 pqxx::params{syncId, in.conflict_policy});
        txn.exec("INSERT INTO s3 (vault_id, api_key_id, bucket, encrypt_upstream, storage_tier_id, storage_layout) "
                 "VALUES ($1, $2, $3, true, $4, 'opaque_v1')",
                 pqxx::params{vid, in.api_key_id, in.bucket, in.storage_tier});
        const auto rootName = txn.exec("SELECT COALESCE(fuse_name, slug) FROM vault WHERE id = $1", pqxx::params{vid})
                                  .one_field_ref()
                                  .as<std::string>();

        // ---- the tree, parents first
        std::unordered_map<std::string, const mf::Entry*> byUid;
        std::unordered_map<std::string, std::vector<const mf::Entry*>> children;
        for (const auto& e : in.content->entries) {
            if (e.trashed || e.kind == mf::EntryKind::Tombstone || in.skip_uids.contains(e.uid)) continue;
            byUid[e.uid] = &e;
            if (e.parent) children[*e.parent].push_back(&e);
        }
        const auto rootIt = byUid.find(in.root_uid);
        if (rootIt == byUid.end()) throw std::runtime_error("the restore's tree has no root");

        // Subtree totals (directories.file_count / subdirectory_count / size_bytes count every descendant).
        struct Totals {
            int64_t files{}, dirs{}, bytes{};
        };
        std::unordered_map<std::string, Totals> totals;
        std::function<Totals(const std::string&)> sum = [&](const std::string& uid) {
            Totals t;
            for (const auto* c : children[uid]) {
                if (c->kind == mf::EntryKind::File) {
                    ++t.files;
                    t.bytes += static_cast<int64_t>(c->size.value_or(0));
                } else if (c->kind == mf::EntryKind::Dir) {
                    const auto sub = sum(c->uid);
                    ++t.dirs;
                    t.files += sub.files;
                    t.dirs += sub.dirs;
                    t.bytes += sub.bytes;
                }
            }
            totals[uid] = t;
            return t;
        };
        (void)sum(in.root_uid);

        std::unordered_map<std::string, std::pair<unsigned int, std::string>> placed;  // uid → (entry id, path)
        const auto insertEntry = [&](const mf::Entry& e, const std::optional<unsigned int> parentId,
                                     const std::string& name, const std::string& path) {
            const auto mode = e.mode.value_or(e.kind == mf::EntryKind::Dir ? 0755u : 0644u);
            std::optional<int64_t> inode;
            if (e.parent && in.inode_for)
                if (const auto i = in.inode_for(rootName, path)) inode = static_cast<int64_t>(*i);
            return txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, created_at, "
                            "updated_at, last_modified_by, path, mode, owner_uid, group_gid, is_hidden, is_system, inode) "
                            "VALUES ($1, $2, $3, $4, $5, COALESCE($6::timestamptz, NOW()), "
                            "COALESCE($7::timestamptz, NOW()), $5, $8, $9, $10, $11, false, false, $12) RETURNING id",
                            pqxx::params{vid, parentId, name, e.parent ? alias(name) : in.mount_point, in.created_by,
                                         e.ctime, e.mtime, path, static_cast<int>(mode),
                                         e.owner ? std::optional<int64_t>(e.owner->uid) : std::nullopt,
                                         e.owner ? std::optional<int64_t>(e.owner->gid) : std::nullopt, inode})
                .one_field_ref()
                .as<unsigned int>();
        };

        const auto& root = *rootIt->second;
        const auto rootId = insertEntry(root, fsRoot->id, rootName, "/");
        {
            const auto& t = totals[root.uid];
            txn.exec("INSERT INTO directories (fs_entry_id, file_count, subdirectory_count, size_bytes, uid) "
                     "VALUES ($1, $2, $3, $4, $5)",
                     pqxx::params{rootId, t.files, t.dirs, t.bytes,
                                  vh::crypto::id::toUuid(mf::parseUid(root.uid, "bad_segment", "root uid"))});
        }
        placed[root.uid] = {rootId, "/"};
        ++r.dirs;

        std::vector<std::string> queue{root.uid};
        for (std::size_t qi = 0; qi < queue.size(); ++qi) {
            const auto parentUid = queue[qi];
            const auto [parentId, parentPath] = placed.at(parentUid);
            for (const auto* c : children[parentUid]) {
                if (placed.contains(c->uid)) continue;
                const auto path = joinPath(parentPath, c->name);
                const auto uuid = vh::crypto::id::toUuid(mf::parseUid(c->uid, "bad_segment", "entry uid"));
                if (c->kind == mf::EntryKind::Symlink &&
                    (!c->target || c->target->empty() || c->target->starts_with("/"))) {
                    r.notes.push_back("symlink " + c->uid + " has no relative target; left out");
                    continue;
                }
                const auto id = insertEntry(*c, parentId, c->name, path);
                placed[c->uid] = {id, path};
                if (c->kind == mf::EntryKind::Dir) {
                    const auto& t = totals[c->uid];
                    txn.exec("INSERT INTO directories (fs_entry_id, file_count, subdirectory_count, size_bytes, uid) "
                             "VALUES ($1, $2, $3, $4, $5)",
                             pqxx::params{id, t.files, t.dirs, t.bytes, uuid});
                    queue.push_back(c->uid);
                    ++r.dirs;
                } else if (c->kind == mf::EntryKind::File) {
                    const auto gen = generationB64(c->generation);
                    txn.exec("INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv, "
                             "encrypted_with_key_version, object_uid) VALUES ($1, $2, $3, $4, $5, $6, $7)",
                             pqxx::params{id, static_cast<int64_t>(c->size.value_or(0)), c->mime, c->content_hash,
                                          gen.value_or(""), static_cast<int>(gen ? c->key_version.value_or(0) : 0),
                                          uuid});
                    ++r.files;
                } else {
                    txn.exec("INSERT INTO symlinks (fs_entry_id, target, uid) VALUES ($1, $2, $3)",
                             pqxx::params{id, *c->target, uuid});
                    ++r.symlinks;
                }
            }
        }

        // ---- trash, the remote object index, provider versions (by uid, every entry kind)
        std::unordered_map<std::string, std::string> pathOf;  // uid → path (trash and snapshot lookups)
        for (const auto& [uid, p] : placed) pathOf[uid] = p.second;
        for (const auto& e : in.content->entries) {
            if (in.skip_uids.contains(e.uid)) {
                ++r.skipped;
                continue;
            }
            const auto uuid = vh::crypto::id::toUuid(mf::parseUid(e.uid, "bad_segment", "entry uid"));
            const auto key = std::string(mf::kObjectPrefix) + e.uid;
            if (e.trashed && e.kind == mf::EntryKind::File) {
                std::string path = e.trashed->path.value_or("");
                if (path.empty()) {
                    const auto parent = e.parent ? placed.find(*e.parent) : placed.end();
                    path = joinPath(parent == placed.end() ? "/" : parent->second.second, e.name);
                }
                txn.exec("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias, size_bytes, trashed_at, "
                         "trashed_by, object_uid) VALUES ($1, $2, '', $3, $4, COALESCE(NULLIF($5, '')::timestamptz, "
                         "NOW()), $6, $7)",
                         pqxx::params{vid, path, alias(path + ":" + e.uid), static_cast<int64_t>(e.size.value_or(0)),
                                      e.trashed->at, in.created_by, uuid});
                pathOf[e.uid] = path;
                ++r.trashed;
            }
            const bool restoredFile = e.kind == mf::EntryKind::File && (e.trashed || placed.contains(e.uid));
            const auto gen = generationB64(e.generation);
            if (restoredFile && e.object) {
                const auto size = gen ? e.size.value_or(0) : e.object->size;
                txn.exec("INSERT INTO remote_object_index (vault_id, object_key, size_bytes, last_modified, etag, "
                         "storage_class, version_id, source, content_hash, encrypted, encryption_iv, "
                         "encrypted_with_key_version) VALUES ($1, $2, $3, $4::timestamptz, $5, $6, $7, 'manifest', $8, "
                         "true, $9, $10)",
                         pqxx::params{vid, key, static_cast<int64_t>(size), e.mtime, e.object->etag, e.object->storage_class,
                                      e.object->version_id, e.content_hash, gen,
                                      gen ? std::optional<int>(static_cast<int>(e.key_version.value_or(0))) : std::nullopt});
                ++r.index_rows;
            }
            for (std::size_t i = 0; i < e.versions.size(); ++i) {
                const auto& v = e.versions[i];
                const auto vgen = generationB64(v.generation);
                const bool latest = e.object ? (e.object->version_id && *e.object->version_id == v.version_id) : i == 0;
                const auto plain = plaintextOf(v);
                txn.exec("INSERT INTO upstream_object_version (vault_id, object_key, version_id, is_delete_marker, "
                         "is_latest, etag, size_bytes, last_modified, origin, encrypted, encryption_iv, key_version, "
                         "plaintext_bytes, became_noncurrent_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz, "
                         "'observed', $9, $10, $11, $12, $13::timestamptz) "
                         "ON CONFLICT (vault_id, object_key, version_id) DO NOTHING",
                         pqxx::params{vid, key, v.version_id, v.delete_marker, latest, v.etag,
                                      v.size ? std::optional<int64_t>(static_cast<int64_t>(*v.size)) : std::nullopt,
                                      v.last_modified, !v.delete_marker, vgen,
                                      v.key_version ? std::optional<int>(static_cast<int>(*v.key_version)) : std::nullopt,
                                      plain ? std::optional<int64_t>(static_cast<int64_t>(*plain)) : std::nullopt,
                                      v.noncurrent_at});
                ++r.provider_versions;
            }
        }

        // ---- snapshot records (members restorable only from the bucket: no local blobs survived)
        for (const auto& s : in.content->snapshots) {
            const auto rootEntry = std::ranges::find_if(placed, [&](const auto& kv) { return kv.second.second == s.root_path; });
            const auto rootType = rootEntry != placed.end() && byUid.contains(rootEntry->first) &&
                                          byUid.at(rootEntry->first)->kind == mf::EntryKind::Dir
                                      ? "directory"
                                      : "file";
            uint64_t bytes = 0;
            const auto sid = txn.exec("INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, root_entry_id, "
                                      "state, file_count, directory_count, plaintext_bytes, created_at, completed_at) "
                                      "VALUES ($1, $2, $3, $4, $5, 'ready', $6, 0, 0, "
                                      "COALESCE(NULLIF($7, '')::timestamptz, NOW()), COALESCE(NULLIF($7, '')::timestamptz, "
                                      "NOW())) RETURNING id",
                                      pqxx::params{vid, s.name, s.root_path.empty() ? "/" : s.root_path, rootType,
                                                   rootEntry != placed.end()
                                                       ? std::optional<unsigned int>(rootEntry->second.first)
                                                       : std::nullopt,
                                                   static_cast<int64_t>(s.members.size()), s.created_at})
                                 .one_field_ref()
                                 .as<int64_t>();
            std::map<unsigned int, int> numbers;
            for (const auto& m : s.members) {
                std::optional<unsigned int> fileId;
                if (m.uid)
                    if (const auto it = placed.find(*m.uid); it != placed.end() && byUid.contains(*m.uid) &&
                                                             byUid.at(*m.uid)->kind == mf::EntryKind::File)
                        fileId = it->second.first;
                uint64_t size = 0;
                if (m.uid)
                    if (const auto e = std::ranges::find(in.content->entries, *m.uid, &mf::Entry::uid);
                        e != in.content->entries.end()) {
                        size = e->size.value_or(0);
                        for (const auto& v : e->versions)
                            if (m.provider_version_id && v.version_id == *m.provider_version_id)
                                if (const auto p = plaintextOf(v)) size = *p;
                    }
                bytes += size;
                const int number = fileId ? ++numbers[*fileId] : 1;
                std::string rel = m.path_at_capture;
                if (const auto& rp = s.root_path; !rp.empty() && rp != "/" && rel.starts_with(rp + "/"))
                    rel = rel.substr(rp.size() + 1);
                else if (rel.starts_with("/"))
                    rel = rel.substr(1);
                const bool fromBucket = m.restorable_from_bucket && m.uid.has_value();
                txn.exec("INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, "
                         "content_hash, size_bytes, path, rel_path, created_at, origin, upstream_state, upstream_key, "
                         "upstream_version_id) VALUES ($1, $2, $3, NULL, $4, NULL, $5, $6, $7, "
                         "COALESCE(NULLIF($8, '')::timestamptz, NOW()), 'snapshot', $9, $10, $11)",
                         pqxx::params{vid, fileId, sid, number, static_cast<int64_t>(size), m.path_at_capture, rel,
                                      s.created_at, fromBucket ? "sent" : "none",
                                      fromBucket ? std::optional<std::string>(std::string(mf::kObjectPrefix) + *m.uid)
                                                 : std::nullopt,
                                      fromBucket ? m.provider_version_id : std::nullopt});
                ++r.snapshot_members;
            }
            txn.exec("UPDATE recovery_snapshot SET plaintext_bytes = $2 WHERE id = $1",
                     pqxx::params{sid, static_cast<int64_t>(bytes)});
            ++r.snapshots;
        }

        // ---- keys: sealed under this host's vault master, this node's provenance, the origin they were proven by
        for (const auto& k : in.keys) {
            const auto& p = k.provenance;
            const std::optional<std::string> sig =
                p.attestation.empty() ? std::nullopt : std::make_optional(to_hex_bytea(p.attestation));
            if (k.current)
                txn.exec("INSERT INTO vault_keys (vault_id, encrypted_key, iv, version, key_check, attestation_key_id, "
                         "attestation, master_version, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7::bytea, $8, "
                         "COALESCE($9::timestamptz, NOW()))",
                         pqxx::params{vid, to_hex_bytea(k.encrypted_key), to_hex_bytea(k.iv), k.version, p.key_check,
                                      p.attestation_key_id, sig, k.master_version, k.created_at});
            else
                txn.exec("INSERT INTO vault_keys_trashed (vault_id, version, encrypted_key, iv, created_at, trashed_at, "
                         "rotation_completed_at, key_check, attestation_key_id, attestation, master_version) VALUES ($1, "
                         "$2, $3, $4, COALESCE($5::timestamptz, NOW()), COALESCE($6::timestamptz, NOW()), CASE WHEN $7 "
                         "THEN NULL ELSE NOW() END, $8, $9, $10::bytea, $11)",
                         pqxx::params{vid, k.version, to_hex_bytea(k.encrypted_key), to_hex_bytea(k.iv), k.created_at,
                                      k.retired_at, k.rotation_pending, p.key_check, p.attestation_key_id, sig,
                                      k.master_version});
            if (const auto& o = k.origin)
                txn.exec("INSERT INTO vault_key_origin (vault_id, version, origin_node_id, origin_vault_id, "
                         "origin_key_check, attestation_key_id, attestation_public_key, attestation, anchor) VALUES ($1, "
                         "$2, $3, $4, $5, $6, $7::bytea, $8::bytea, $9)",
                         pqxx::params{vid, k.version, o->node_id, static_cast<int64_t>(o->vault_id), o->key_check,
                                      o->attestation_key_id, to_hex_bytea(o->attestation_public_key),
                                      to_hex_bytea(o->attestation), o->anchor});
        }

        // ---- recovery grants (customer class only, re-enrolled with their public keys) and their envelope rows
        std::map<std::string, std::string> grantIds;
        for (const auto& g : in.grants) {
            auto id = g.grant_id;
            if (!txn.exec("SELECT 1 FROM vault_recovery_grant WHERE grant_id = $1", pqxx::params{id}).empty()) {
                id = mf::uidText(vh::crypto::id::newObjectUid());
                r.notes.push_back("grant " + g.grant_id + " is restored as " + id + " (its id is taken on this node)");
            }
            grantIds[g.grant_id] = id;
            txn.exec("INSERT INTO vault_recovery_grant (vault_id, grant_id, recipient_id, public_key, suite, class, label, "
                     "added_at, authorized_by, revoked_at, revoked_by) VALUES ($1, $2, $3, $4::bytea, $5, 'customer', $6, "
                     "COALESCE($7::timestamptz, NOW()), $8, $9::timestamptz, CASE WHEN $9 IS NULL THEN NULL ELSE "
                     "'restored' END)",
                     pqxx::params{vid, id, g.recipient_id, to_hex_bytea(g.public_key), static_cast<int>(g.suite), g.label,
                                  g.added_at, g.authorized_by.value_or("restored"), g.revoked_at});
        }
        for (const auto& e : in.envelopes) {
            const auto g = grantIds.find(e.grant_id);
            if (g == grantIds.end()) continue;
            txn.exec("INSERT INTO vault_key_envelope (vault_id, grant_id, key_version, kid) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT DO NOTHING",
                     pqxx::params{vid, g->second, e.version, e.kid});
        }

        // ---- a salvage the restore hands over (its rows name the versions it re-keys)
        if (in.salvage)
            txn.exec("INSERT INTO vault_key_salvage (vault_id, versions, started_by, new_version) VALUES ($1, $2::int[], "
                     "$3, $4)",
                     pqxx::params{vid, versionsLiteral(in.salvage->versions), in.salvage->started_by,
                                  in.salvage->new_version});

        // ---- the file-recovery preference and the chain position (the next publish builds on the loaded root)
        if (in.content->vault && in.content->vault->recovery_policy)
            txn.exec("INSERT INTO vault_recovery_policy (vault_id, mode, version_max_age_days) VALUES ($1, $2, $3) "
                     "ON CONFLICT (vault_id) DO NOTHING",
                     pqxx::params{vid, in.content->vault->recovery_policy->mode,
                                  in.content->vault->recovery_policy->retention_days
                                      ? std::optional<int>(static_cast<int>(*in.content->vault->recovery_policy->retention_days))
                                      : std::nullopt});
        if (in.epoch && in.root_sha256) {
            txn.exec("INSERT INTO remote_manifest_state (vault_id, manifest_key, etag, epoch, root_sha256, updated_at) "
                     "VALUES ($1, '.vaulthalla/root', $2, $3, $4, CURRENT_TIMESTAMP)",
                     pqxx::params{vid, in.root_etag, static_cast<int64_t>(*in.epoch), *in.root_sha256});
            std::string sids = "{";
            for (const auto& s : in.root_sids) sids += (sids.size() > 1 ? "," : "") + s;
            sids += "}";
            txn.exec("INSERT INTO remote_manifest_root (vault_id, epoch, root_sha256, sids) VALUES ($1, $2, $3, $4::text[])",
                     pqxx::params{vid, static_cast<int64_t>(*in.epoch), *in.root_sha256, sids});
        }

        return r;
    });
}

}
