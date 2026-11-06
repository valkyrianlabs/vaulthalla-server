#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "recovery/Fwd.hpp"
#include "recovery/Hooks.hpp"
#include "storage/Engine.hpp"
#include "storage/RemoteFetch.hpp"
#include "sync/model/Action.hpp"
#include "storage/s3/provider/Provider.hpp"
#include "fs/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <atomic>
#include <functional>
#include <future>
#include <mutex>
#include <span>
#include <chrono>
#include <exception>
#include <unordered_map>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::storage {
    namespace s3 {
        class Controller;
        struct RequestOptions;
        struct S3RequestBudget;
        struct S3RequestMetrics;
        struct ObjectVersionPage;
        struct ObjectVersionHead;
        struct GetObjectResult;
        struct CopyResult;
    }

    class CloudEngine final : public Engine {
    public:
        struct RemoteEncryptionResolveOptions {
            bool trust_file_encryption_metadata{false};
            bool allow_local_db_recovery{false};

            constexpr RemoteEncryptionResolveOptions() = default;
            constexpr RemoteEncryptionResolveOptions(
                bool trustFileEncryptionMetadata,
                bool allowLocalDbRecovery)
                : trust_file_encryption_metadata(trustFileEncryptionMetadata),
                  allow_local_db_recovery(allowLocalDbRecovery) {}
        };

        CloudEngine() = default;

        ~CloudEngine() override = default;

        explicit CloudEngine(const std::shared_ptr<vault::model::S3Vault> &vault);
        explicit CloudEngine(const std::shared_ptr<vault::model::S3Vault> &vault,
                             std::shared_ptr<s3::Controller> s3Provider);

        [[nodiscard]] StorageType type() const override { return StorageType::Cloud; }

        // ---- storage layout (design/encryption/01-provider-blind-storage.md §4; storage/ObjectKeys.hpp) ------------
        // opaque_v1: objects are o/<file uid> and .vaulthalla/…, requests carry no x-amz-meta-* and no names (the
        // controller enforces §4.3), sync is keyed by file uid, and a rename or move is a manifest-only change.
        [[nodiscard]] bool opaqueLayout() const;
        // The object key of a file's content: o/<object uid> under opaque_v1 (std::runtime_error when the row has no
        // uid), the vault path without its leading slash otherwise.
        [[nodiscard]] std::string objectKeyOf(const vh::fs::model::File &f) const;
        [[nodiscard]] std::string objectKeyOf(const vh::fs::model::file::Trashed &f) const;
        // The object key of the file at rel_path. opaque_v1 resolves the path through the database (the live file,
        // else the newest trashed file that was there): ObjectNotFound-free callers get std::runtime_error when
        // nothing is there. path_v0 / transparent: the path without its leading slash, as before.
        [[nodiscard]] std::string objectKeyForPath(const std::filesystem::path &rel_path) const;

        // opaque_v1: one full listing of the bucket (no prefix: no name in the query), classified (spec 01 §4.4).
        // objects: the o/<uid> content objects as remote rows (path "/o/<uid>", object_uid set, sealed size, ETag,
        // storage class); foreign: every key that is neither content nor .vaulthalla/ metadata.
        struct OpaqueListing {
            std::vector<std::shared_ptr<vh::fs::model::File>> objects;
            std::vector<std::string> foreign;
        };
        [[nodiscard]] OpaqueListing listOpaqueBucket() const;
        // opaque_v1, foreign_objects = import (spec 01 §4.4): reads the foreign object at `key` as plaintext (one
        // GET, the only request of an opaque_v1 vault that names a foreign key) and seals it into a new file at
        // /Imported/<key> (a new uid; the next pass uploads it as o/<uid>). The original is left untouched. nullptr
        // when /Imported/<key> exists already (live or in the trash): an object is imported once.
        std::shared_ptr<vh::fs::model::File> importForeignObject(const std::string &key);

        void purge(const std::filesystem::path &rel_path) const;

        void purge(const std::shared_ptr<vh::fs::model::file::Trashed> &f) const;

        void removeRemotely(const std::filesystem::path &rel_path) const;

        void removeRemotely(const std::shared_ptr<vh::fs::model::file::Trashed> &f) const;

        // DELETE of one object as Vaulthalla's own write; rel_path names the file whose derived artifacts go with it.
        void removeRemoteKey(const std::string &key, const std::filesystem::path &rel_path) const;

        void upload(const std::shared_ptr<vh::fs::model::File> &f) const;

        void upload(const std::shared_ptr<vh::fs::model::File> &f, const std::vector<uint8_t> &buffer,
                    bool isCiphertext = true) const;

        std::shared_ptr<vh::fs::model::File> uploadBufferObject(
            const std::filesystem::path &rel_path,
            const std::vector<uint8_t> &plaintext,
            std::optional<std::string> contentHash = std::nullopt) const;

        std::shared_ptr<vh::fs::model::File> downloadFile(const std::filesystem::path &rel_path);
        std::shared_ptr<vh::fs::model::File> downloadFile(const std::shared_ptr<vh::fs::model::File> &remoteFile);

        std::vector<uint8_t> downloadToBuffer(const std::filesystem::path &rel_path) const;
        [[nodiscard]] std::vector<uint8_t> decryptRemotePayload(
            const std::filesystem::path &rel_path,
            const std::vector<uint8_t> &payload,
            const std::shared_ptr<vh::fs::model::File> &remoteFile = nullptr) const;

        [[nodiscard]] std::vector<uint8_t> decryptRemotePayload(
            const std::filesystem::path &rel_path,
            const std::vector<uint8_t> &payload,
            const std::shared_ptr<vh::fs::model::File> &remoteFile,
            RemoteEncryptionResolveOptions options) const;

        // Records a remote object as a local row without a local copy; returns the row as written.
        std::shared_ptr<vh::fs::model::File> indexAndDeleteFile(const std::shared_ptr<vh::fs::model::File> &remoteFile);

        [[nodiscard]] std::string getRemoteContentHash(const std::filesystem::path &rel_path) const;

        [[nodiscard]] std::unordered_map<std::u8string, std::shared_ptr<vh::fs::model::File> > getGroupedFilesFromS3(
            const std::filesystem::path &prefix = {}) const;

        [[nodiscard]] bool refreshRemoteIndexFromManifestIfChanged() const;
        void publishRemoteIndexManifest(const std::optional<std::string>& expectedETag = std::nullopt) const;
        void publishRemoteIndexManifestWithRetry() const;
        // The index was just rebuilt from a full LIST (Cloud::initBins): the pass's applyRemoteIndexMutation publishes
        // it together with the plan's changes, so a pass publishes the manifest once (#248). Any successful publish
        // or a reload from the manifest clears it.
        void markRemoteIndexRebuilt() const;
        [[nodiscard]] bool remoteIndexPublishPending() const;
        // Recovery recipients (#370): an opaque_v1 vault's next pass republishes its manifest root (grants, envelopes).
        void requestManifestPublish() const;
        // Writes the KEV1 envelopes still missing for the key versions this engine holds (vault/RecoveryEnvelopes.hpp;
        // no request when the vault has no usable recovery recipient) and, when it wrote any, requests a manifest
        // publish. Returns how many it wrote; throws on a failed PUT. Run at the start of every sync pass.
        unsigned ensureRecoveryEnvelopes() const;
        // Publishes a rebuilt index that applyRemoteIndexMutation did not (failed operations, an error after the
        // LIST). No-op when nothing is pending; logs instead of throwing.
        void publishPendingRemoteIndexManifest() const noexcept;
        // Records the plan's uploads/remote deletes in the index and publishes the manifest when it changed. After a
        // rebuild (markRemoteIndexRebuilt) the index is the bucket's truth: it publishes even without changes and a
        // conflict refreshes the ETag (as the post-LIST publish did) instead of reloading the index from the manifest.
        void applyRemoteIndexMutation(const std::vector<sync::model::Action>& plan) const;
        [[nodiscard]] bool selectedDownloadRequiresRestore(const std::shared_ptr<vh::fs::model::File>& remoteFile) const;

        std::vector<std::shared_ptr<vh::fs::model::Directory> > extractDirectories(
            const std::vector<std::shared_ptr<vh::fs::model::File> > &files) const;

        [[nodiscard]] bool remoteFileIsEncrypted(const std::filesystem::path &rel_path) const;

        std::optional<std::pair<std::string, unsigned int> > getRemoteIVBase64AndVersion(
            const std::filesystem::path &rel_path) const;

        std::shared_ptr<sync::model::RemotePolicy> remote_policy() const;

        void configureS3RequestBudget(const s3::S3RequestBudget& budget) const;
        void clearS3RequestBudget() const;
        void resetS3RequestMetrics() const;
        [[nodiscard]] s3::S3RequestMetrics s3RequestMetrics() const;
        [[nodiscard]] std::shared_ptr<vault::model::APIKey> s3ApiKey() const { return key_; }
        [[nodiscard]] s3::provider::ProfilePtr s3ProviderProfile() const { return s3Profile_; }
        [[nodiscard]] std::optional<s3::provider::StorageTier> resolvedStorageTier() const { return storageTier_; }

        void setS3ControllerForTesting(std::shared_ptr<s3::Controller> s3Provider);
        void setS3ProviderProfileForTesting(s3::provider::ProfilePtr profile);

        // Fetches a remote-only file's object once and keeps it as the local *ciphertext* copy at f->backing_path
        // (never plaintext on disk). Price-preflighted (RemoteFetchGate) before any body is fetched, metered and
        // capped (one HEAD, one GET, exactly the object's bytes), bound to the HEAD's ETag with If-Match, and
        // authenticated (whole GCM message) before the copy becomes visible. An object stored in plaintext
        // (encrypt_upstream off) is sealed on the fly under a fresh IV, recorded in the files row by
        // compare-and-set before the copy is linked in. Concurrent callers for one file share a single fetch.
        // Returns the file as it now reads locally (IV and key version of the stored copy). Throws ContentUnavailable
        // (refused by a budget, archived, missing or changed remotely, or the row changed meanwhile), IntegrityError
        // (the object failed authentication: nothing is kept), or std::runtime_error/std::system_error.
        // The copy stays local afterwards: the Cache strategy has no eviction yet.
        std::shared_ptr<vh::fs::model::File> hydrate(const std::shared_ptr<vh::fs::model::File> &f) const;

        // Key salvage (ops::vault_keys): the whole sealed object at `objectKey` (sealed under `keyVersion`, `ivB64`),
        // in memory, through the metered remote-read path: price preflight (`operation`, one HEAD + one GET + the
        // object's bytes), a usage capture with those caps, the HEAD (which must still name that key version and IV),
        // then one GET with If-Match on its ETag. Nothing is written anywhere. Throws ContentUnavailable when the read
        // was refused (price budget or request caps) or the object is missing, archived or changed.
        [[nodiscard]] std::vector<uint8_t> fetchSealedObject(const std::string &objectKey, uint64_t storedBytes,
                                                             const std::string &ivB64, unsigned int keyVersion,
                                                             const std::string &operation) const;

        // What one HEAD says about a remote object.
        struct RemoteObjectHead {
            std::string etag;
            std::optional<uint64_t> content_length;
            bool encrypted{};
            std::string iv_b64;           // empty when the object carries none (or is plaintext)
            unsigned int key_version{};
            bool requires_restore{};      // archive tier without a completed restore
            std::optional<std::string> content_hash;  // Vaulthalla's content-hash metadata, when present
        };

        // One metered HEAD of the file at rel_path (objectKeyForPath); nullopt when the object does not exist.
        [[nodiscard]] std::optional<RemoteObjectHead> headRemoteObject(const std::filesystem::path &rel_path) const;
        // Like headRemoteObject, but nullopt only for a confirmed absence (404): a refused or failed HEAD throws, so
        // an outage can never read as a deletion.
        [[nodiscard]] std::optional<RemoteObjectHead> headRemoteObjectStrict(const std::filesystem::path &rel_path) const;
        // The same by object key (a leading '/' ignored): event keys, backlog keys, key salvage. Under opaque_v1 an
        // o/<uid> object always counts as sealed (it carries no metadata; its header names the generation).
        [[nodiscard]] std::optional<RemoteObjectHead> headObjectKey(const std::string &key) const;
        [[nodiscard]] std::optional<RemoteObjectHead> headObjectKeyStrict(const std::string &key) const;

        // Sync conflict resolution and previews (#187). One metered GET of the object (If-Match `ifMatch` when
        // given: ConditionalRequestFailed when it changed), aborted past `maxBytes`, decrypted (authenticated) with
        // the object's own encryption metadata exactly like a sync download. Returns the plaintext.
        [[nodiscard]] std::vector<uint8_t> fetchRemotePlaintext(const std::shared_ptr<vh::fs::model::File> &remoteFile,
                                                                const std::optional<std::string> &ifMatch,
                                                                std::optional<uint64_t> maxBytes) const;
        // Writes a downloaded object's plaintext as the file's content, as a sync download does, but only while the
        // local copy is still generation `expectedSourceId` (fs::ContentConflict otherwise).
        std::shared_ptr<vh::fs::model::File> replaceLocalContent(const std::filesystem::path &rel_path,
                                                                 const std::vector<uint8_t> &plaintext,
                                                                 const std::string &expectedSourceId);

        // Local versioning's upstream backlog (storage/CloudEngineBacklog.cpp): PUTs one retained generation at `key`
        // with that generation's OWN metadata (vh-iv, vh-key-version, content-hash, vh-encrypted), never the file's
        // current one. `blob` holds its sealed bytes; a vault that doesn't encrypt upstream gets the plaintext,
        // decrypted in memory with the generation's (possibly retired) key. Goes through noteOwnWrite/done(), so the
        // recovery hook records the version. Returns the provider's version id (nullopt: the bucket kept none).
        // Throws ContentUnavailable (blob or key version gone) or IntegrityError (blob fails authentication) for
        // local problems, anything else for the request.
        std::optional<std::string> uploadGeneration(const std::filesystem::path &key, const std::filesystem::path &blob,
                                                    const db::query::recovery::GenerationRow &generation) const;

        // Price preflight for remote reads (default: priceBudgetRemoteFetchGate).
        void setRemoteFetchGate(RemoteFetchGate gate);
        // Per-reader request caps for the opt-in ranged reader.
        void setRangedReadLimits(const RangedReadLimits &limits);
        [[nodiscard]] const RangedReadLimits &rangedReadLimits() const { return rangedLimits_; }
        // Test seam for the files-row compare-and-set a hydrate needs when the stored IV changes.
        void setHydrateCatalogCommitForTesting(HydrateCatalogCommit commit);

        // ---- file recovery: provider object versions (CloudEngineRestore.cpp; .claude/context/recovery.md) ------------
        // Metered like every other request (engine budget, protection guard, every usage capture on the thread). The
        // orchestration (pass lease, CAS, reconciliation) lives in recovery::provider.

        // One ListObjectVersions page under prefix (metadata only, never a body).
        [[nodiscard]] s3::ObjectVersionPage listObjectVersionsPage(const std::string &prefix, const std::string &keyMarker,
                                                                   const std::string &versionIdMarker,
                                                                   unsigned int maxKeys) const;
        // HEAD ?versionId=: nullopt only for 404; a delete marker answers delete_marker=true; outages throw.
        [[nodiscard]] std::optional<s3::ObjectVersionHead> headObjectVersion(const std::string &key,
                                                                             const std::string &versionId) const;
        // One streamed GET of key@versionId (If-Match ifMatch, aborted past maxBytes) into sink.
        s3::GetObjectResult streamObjectVersion(const std::string &key, const std::string &versionId,
                                                const std::optional<std::string> &ifMatch,
                                                std::optional<uint64_t> maxBytes,
                                                const std::function<void(std::span<const uint8_t>)> &sink) const;
        // CopyObject of sourceKey@versionId onto destKey (directive COPY, the vault's storage class,
        // x-amz-copy-source-if-match sourceEtag) as Vaulthalla's own write: a write intent with the object's size while
        // an event subscription is active, and recovery::hooks::afterUpstreamWrite with `generation` (the restored
        // generation's IV, key version, hash and plaintext size) once it succeeded. Throws what copyObjectVersion
        // throws (ObjectTooLargeForCopy before anything is sent).
        s3::CopyResult copyObjectVersionAsOwnWrite(const std::string &sourceKey, const std::string &versionId,
                                                   const std::string &destKey, uint64_t objectSize,
                                                   const std::string &sourceEtag,
                                                   const std::shared_ptr<vh::fs::model::File> &generation) const;
        // The storage class this vault writes new objects with (wire value); nullopt = the provider's default.
        [[nodiscard]] std::optional<std::string> writeStorageClass() const { return configuredStorageClass(); }

    protected:
        // Remote-only file: preview.media.remote (ReaderOptions::remote) hydrate (default) | ranged | off.
        [[nodiscard]] std::unique_ptr<PlaintextReader> openMissingReader(
            const std::shared_ptr<vh::fs::model::File> &f, const ReaderOptions &options) const override;

    private:
        [[nodiscard]] std::shared_ptr<vh::fs::model::File> hydrateNow(const std::shared_ptr<vh::fs::model::File> &f) const;
        [[nodiscard]] std::unique_ptr<PlaintextReader> openRangedReader(
            const std::shared_ptr<vh::fs::model::File> &f) const;
        [[nodiscard]] std::unique_ptr<RemoteFetchReservation> reserveRemoteFetch(const RemoteFetchRequest &request) const;

        struct RemoteEncryptionContext {
            bool encrypted{};
            std::optional<std::pair<std::string, unsigned int>> payload;
        };

        std::shared_ptr<vault::model::APIKey> key_;
        std::shared_ptr<s3::Controller> s3Provider_;
        s3::provider::ProfilePtr s3Profile_;
        std::optional<s3::provider::StorageTier> storageTier_;

        RemoteFetchGate fetchGate_;
        HydrateCatalogCommit catalogCommit_;
        RangedReadLimits rangedLimits_;
        // One in-flight hydrate per backing path; waiters share its outcome.
        mutable std::mutex hydrateMutex_;
        mutable std::unordered_map<std::string, std::shared_future<std::shared_ptr<vh::fs::model::File>>> hydrating_;
        // Recent failures (by backing path + row IV): a tampered, mismatched or refused object is not fetched again
        // on every request; it is retried after kHydrateFailureBackoff or as soon as the row changes.
        struct HydrateFailure {
            std::chrono::steady_clock::time_point at;
            std::exception_ptr error;
        };
        mutable std::unordered_map<std::string, HydrateFailure> hydrateFailures_;
        // markRemoteIndexRebuilt: the index holds a full LIST the manifest doesn't have yet.
        mutable std::atomic<bool> remoteIndexPublishPending_{false};
        // opaque_v1 vaults: the encrypted manifest v2 (#368, spec 03) replaces index-v1.json. Created on first use.
        mutable std::mutex manifestV2Mutex_;
        mutable std::shared_ptr<sync::manifest::Service> manifestV2_;
        [[nodiscard]] bool usesManifestV2() const;
        [[nodiscard]] std::shared_ptr<sync::manifest::Service> manifestV2() const;
        // Publishes the vault's manifest v2 (and collects superseded segments once a day). A refused root (rollback,
        // fork) or repeated conflicts stall the pass (SyncStalled): nothing is written over a root the chain rules
        // refuse. onlyIfChanged: nothing is written when the vault's content equals what the last publish produced.
        void publishManifestV2(bool onlyIfChanged = false) const;

        std::shared_ptr<vault::model::S3Vault> s3Vault() const;
        void resolveS3ProviderConfiguration();
        // Event-driven sync (#96): before Vaulthalla's own PUT/DELETE of an object, while the vault has an active
        // event subscription, record a write intent so the notification it causes is recognised as ours. Best
        // effort: a failure only costs a redundant transfer later.
        // Vaulthalla's own PUT/DELETE of `key`, recorded only while the vault has an active event subscription so the
        // notification it causes is recognised as ours. done() after the request succeeded; destroyed without it
        // (the request threw), the intent is removed so it can never claim someone else's event.
        // One upstream PUT/DELETE in flight: the event write intent (when a subscription is active) and what recovery
        // learns once it succeeded (recovery::hooks::afterUpstreamWrite, fired by done()).
        class OwnWrite {
        public:
            OwnWrite() = default;
            OwnWrite(std::optional<int64_t> id, std::optional<recovery::hooks::UpstreamWrite> write)
                : id_(id), write_(std::move(write)) {}
            OwnWrite(OwnWrite&& other) noexcept
                : id_(std::exchange(other.id_, std::nullopt)), write_(std::exchange(other.write_, std::nullopt)) {}
            OwnWrite& operator=(OwnWrite&&) = delete;
            OwnWrite(const OwnWrite&) = delete;
            ~OwnWrite();
            void done();
        private:
            std::optional<int64_t> id_;
            std::optional<recovery::hooks::UpstreamWrite> write_;
        };
        [[nodiscard]] OwnWrite noteOwnWrite(const std::filesystem::path &key, bool isDelete,
                                            std::optional<uint64_t> objectSize,
                                            const std::shared_ptr<vh::fs::model::File> &file = nullptr) const;
        [[nodiscard]] s3::RequestOptions requestOptionsFor(s3::provider::RequestOperation operation) const;
        // What an upload of a content object sends: the provider's mutation and, except under opaque_v1, the file's
        // x-amz-meta-* (opaque_v1 sends none, spec 01 §4.3).
        [[nodiscard]] s3::RequestOptions uploadOptionsFor(s3::provider::RequestOperation operation,
                                                          const std::shared_ptr<vh::fs::model::File> &f) const;
        // One content object PUT (single request below the multipart threshold, else multipart with the adaptive
        // part size, storage/ObjectKeys.hpp partSizeFor). opaque_v1 records the PUT's ETag and version id on f, for
        // the index row and the manifest's object reference.
        void putContent(const std::string &key, const std::shared_ptr<vh::fs::model::File> &f,
                        const std::filesystem::path &source, uint64_t size) const;
        void putContent(const std::string &key, const std::shared_ptr<vh::fs::model::File> &f,
                        const std::vector<uint8_t> &bytes) const;
        // Sets the controller's opaque_v1 request policy from the vault's layout (constructors, test seams).
        void applyLayoutPolicy() const;

        // opaque_v1 reads (spec 01 §4.4, 03 §4.4): the sealed bytes of the file's object opened against this vault and
        // the file's uid (mandatory), and the generation and key version the row records when it records one; a row
        // without one (indexed from a listing) learns them from the authenticated header.
        [[nodiscard]] std::vector<uint8_t> openOpaqueObject(const std::vector<uint8_t> &sealed,
                                                            const std::shared_ptr<vh::fs::model::File> &f) const;
        // opaque_v1: the generation and key version an o/<uid> object's header names (one ranged GET of the 120-byte
        // header, authenticated against this vault and the uid). Throws IntegrityError when it doesn't authenticate.
        [[nodiscard]] std::pair<std::string, unsigned int> opaqueObjectGeneration(const crypto::id::ObjectUid &uid) const;
        // opaque_v1: what goes up as o/<uid> must be readable as o/<uid>: its header (the first 120 bytes) must
        // authenticate as this vault's, this generation's and this file's (storage::IntegrityError otherwise, before
        // any request).
        void requireOpaqueHeader(std::span<const uint8_t> sealed, const vh::fs::model::File &f) const;
        [[nodiscard]] std::optional<std::string> configuredStorageClass() const;

        std::unordered_map<std::string, std::string> getMetaMapFromFile(
            const std::shared_ptr<vh::fs::model::File> &f) const;

        std::shared_ptr<vh::fs::model::File> downloadFileWithRemoteMetadata(
            const std::filesystem::path &rel_path,
            const std::shared_ptr<vh::fs::model::File> &remoteFile);

        [[nodiscard]] RemoteEncryptionContext resolveRemoteEncryptionContext(
            const std::filesystem::path &rel_path,
            const std::shared_ptr<vh::fs::model::File> &remoteFile,
            RemoteEncryptionResolveOptions options) const;
    };
} // namespace vh::storage
