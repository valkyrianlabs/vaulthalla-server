#pragma once

// An in-memory versioned bucket and the manifest ObjectStore over it: what the manifest's own tests need from a
// provider, with no HTTP, no XML and nothing of the server (it includes the Store seam, OpenSSL for MD5 ETags and the
// standard library; tools/contracts/test_format_library_contract.py). It answers as the versioned fake bucket
// (versioned_bucket.hpp) does behind storage::s3::ManifestStore, so a suite can run on either:
//
//   - versions per key, listed newest first; a DELETE adds a delete marker, a DELETE by version id removes exactly
//     that version (never adds a marker); a GET of a marker by id, or of a key whose newest version is one, finds
//     nothing;
//   - ETags are the quoted MD5 of the body, as S3 answers a single PUT;
//   - conditional PUTs are evaluated (412: PreconditionFailed), refused unevaluated as Backblaze B2 does
//     (ConditionsUnsupported, nothing written) or ignored;
//   - the bucket's clock is the test's: every write stamps `now` and, with autoTick, advances it by a second;
//   - the provider assumptions of design/encryption/06-publish-without-preconditions.md §4 can be broken on purpose:
//     listingLag (A3) and orderBy(Start) with holdPut (A4).
//
// MemoryBucket is the provider's state (thread-safe); MemoryStore is one client of it with its bucket mode.

#include "sync/manifest/Store.hpp"

#include <openssl/evp.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <ctime>
#include <format>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace vh::test_support::manifest_store {

class MemoryBucket {
public:
    struct Version {
        std::string version_id;
        std::vector<uint8_t> body;
        std::string etag;   // quoted; empty for a delete marker
        std::time_t last_modified{};
        bool delete_marker{};
    };

    enum class ConditionalPuts { Supported, Reject, Ignore };
    enum class Order { Commit, Start };

    // false: an unversioned bucket (one version "null" per key, a DELETE removes the key).
    explicit MemoryBucket(const bool versioned = true) : versioned_(versioned) {}

    // ---- the provider's behaviour --------------------------------------------------------------------------------------

    void conditionalPuts(const ConditionalPuts how) {
        std::scoped_lock lock(mutex_);
        conditional_ = how;
    }
    void autoTick(const bool on) {
        std::scoped_lock lock(mutex_);
        autoTick_ = on;
    }
    void setNow(const std::time_t now) {
        std::scoped_lock lock(mutex_);
        now_ = now;
    }
    void advance(const std::time_t seconds) {
        std::scoped_lock lock(mutex_);
        now_ += seconds;
    }
    [[nodiscard]] std::time_t now() const {
        std::scoped_lock lock(mutex_);
        return now_;
    }
    // Version listings omit versions written less than `seconds` ago (bucket clock): breaks A3.
    void listingLag(const std::time_t seconds) {
        std::scoped_lock lock(mutex_);
        listingLag_ = seconds;
    }
    // orderBy(Start) + holdPut(key): the next PUT of `key` from this thread is ordered as if it had started now
    // although it commits later: its version is inserted below every version of that key written in between (by
    // other threads). Breaks A4.
    void orderBy(const Order order) {
        std::scoped_lock lock(mutex_);
        order_ = order;
    }
    void holdPut(const std::string& key) {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        heldAt_[{key, std::this_thread::get_id()}] = it == objects_.end() ? 0 : it->second.size();
    }

    // ---- seeding and inspection ------------------------------------------------------------------------------------------

    // Writes a version as a PUT would. Returns its version id.
    std::string seed(const std::string& key, std::vector<uint8_t> body) {
        std::scoped_lock lock(mutex_);
        return writeLocked(key, std::move(body)).version_id;
    }
    // Newest first; empty when the key has no versions.
    [[nodiscard]] std::vector<Version> history(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return {};
        return {it->second.rbegin(), it->second.rend()};
    }
    // The newest version unless it is a delete marker.
    [[nodiscard]] std::optional<Version> current(const std::string& key) const {
        std::scoped_lock lock(mutex_);
        const auto* v = latestLocked(key);
        if (!v || v->delete_marker) return std::nullopt;
        return *v;
    }

    // ---- requests (MemoryStore) ------------------------------------------------------------------------------------------

    [[nodiscard]] std::optional<Version> read(const std::string& key, const std::optional<std::string>& versionId) const {
        std::scoped_lock lock(mutex_);
        const Version* v = nullptr;
        if (versionId) {
            const auto it = objects_.find(key);
            if (it != objects_.end())
                for (const auto& x : it->second)
                    if (x.version_id == *versionId) v = &x;
        } else {
            v = latestLocked(key);
        }
        if (!v || v->delete_marker) return std::nullopt;
        return *v;
    }

    // A PUT with its conditions. Throws PreconditionFailed / ConditionsUnsupported as the bucket answers them.
    sync::manifest::PutResult write(const std::string& key, const std::vector<uint8_t>& body,
                                    const std::optional<std::string>& ifMatch, const bool ifNoneMatch) {
        std::scoped_lock lock(mutex_);
        const auto* latest = latestLocked(key);
        const bool exists = latest && !latest->delete_marker;
        if ((ifMatch || ifNoneMatch) && conditional_ == ConditionalPuts::Reject)
            throw sync::manifest::ConditionsUnsupported("the bucket does not support conditional writes (501 "
                                                        "NotImplemented, test)");
        if (conditional_ == ConditionalPuts::Supported) {
            if (ifMatch && (!exists || latest->etag != *ifMatch))
                throw sync::manifest::PreconditionFailed("conditional PUT failed (412, test)");
            if (ifNoneMatch && exists) throw sync::manifest::PreconditionFailed("conditional PUT failed (412, test)");
        }
        const auto& written = writeLocked(key, body);
        return {written.etag, versioned_ ? std::make_optional(written.version_id) : std::nullopt};
    }

    [[nodiscard]] std::vector<sync::manifest::ListedObject> list(const std::string& prefix) const {
        std::scoped_lock lock(mutex_);
        std::vector<sync::manifest::ListedObject> out;
        for (const auto& [key, stack] : objects_) {
            if (!key.starts_with(prefix) || stack.back().delete_marker) continue;
            const auto& v = stack.back();
            out.push_back({key, v.body.size(), v.last_modified, v.etag});
        }
        return out;
    }

    // Every version and delete marker of every key under `prefix` (of exactly `key` when exact), keys ascending, each
    // key's newest first, without those the listing lag hides.
    [[nodiscard]] std::vector<sync::manifest::StoredVersion> versions(const std::string& prefix, const bool exact) const {
        std::scoped_lock lock(mutex_);
        std::vector<sync::manifest::StoredVersion> out;
        for (const auto& [key, stack] : objects_) {
            if (exact ? key != prefix : !key.starts_with(prefix)) continue;
            for (auto v = stack.rbegin(); v != stack.rend(); ++v) {
                if (listingLag_ && now_ - v->last_modified < listingLag_) continue;   // A3 broken on purpose
                out.push_back({key, v->version_id, v->delete_marker ? 0 : v->body.size(), v->last_modified,
                               v->delete_marker, v->etag, v == stack.rbegin()});
            }
        }
        return out;
    }

    // DELETE: a delete marker on a versioned bucket, the key's removal on an unversioned one.
    void remove(const std::string& key) {
        std::scoped_lock lock(mutex_);
        if (!versioned_) {
            objects_.erase(key);
            return;
        }
        Version marker;
        marker.version_id = newVersionIdLocked();
        marker.delete_marker = true;
        marker.last_modified = stampLocked();
        objects_[key].push_back(std::move(marker));
    }

    // DELETE ?versionId=: exactly that version or marker; one that is gone is not an error.
    void removeVersion(const std::string& key, const std::string& versionId) {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return;
        std::erase_if(it->second, [&](const Version& v) { return v.version_id == versionId; });
        if (it->second.empty()) objects_.erase(it);
    }

private:
    [[nodiscard]] static std::string md5Etag(const std::vector<uint8_t>& body) {
        std::array<unsigned char, 16> digest{};
        unsigned int n = 0;
        if (EVP_Digest(body.data(), body.size(), digest.data(), &n, EVP_md5(), nullptr) != 1 || n != digest.size())
            throw std::runtime_error("MD5 failed (test)");
        std::string out = "\"";
        for (const auto b : digest) out += std::format("{:02x}", b);
        return out + "\"";
    }

    [[nodiscard]] const Version* latestLocked(const std::string& key) const {
        const auto it = objects_.find(key);
        if (it == objects_.end() || it->second.empty()) return nullptr;
        return &it->second.back();
    }

    std::string newVersionIdLocked() { return std::format("mem-{:06}", ++versionSeq_); }

    std::time_t stampLocked() {
        const auto t = now_;
        if (autoTick_) ++now_;
        return t;
    }

    const Version& writeLocked(const std::string& key, std::vector<uint8_t> body) {
        auto& stack = objects_[key];
        Version v;
        v.etag = md5Etag(body);
        v.body = std::move(body);
        v.last_modified = stampLocked();
        if (!versioned_) {
            stack.clear();
            v.version_id = "null";
        } else {
            v.version_id = newVersionIdLocked();
        }
        if (order_ == Order::Start)
            if (const auto held = heldAt_.find({key, std::this_thread::get_id()}); held != heldAt_.end()) {
                const auto at = std::min(held->second, stack.size());
                heldAt_.erase(held);
                return *stack.insert(stack.begin() + static_cast<std::ptrdiff_t>(at), std::move(v));
            }
        stack.push_back(std::move(v));
        return stack.back();
    }

    mutable std::mutex mutex_;
    bool versioned_;
    ConditionalPuts conditional_{ConditionalPuts::Supported};
    bool autoTick_{true};
    std::time_t now_{1'700'000'000};
    std::time_t listingLag_{0};
    Order order_{Order::Commit};
    std::map<std::pair<std::string, std::thread::id>, std::size_t> heldAt_;
    std::map<std::string, std::vector<Version>> objects_;   // oldest first
    uint64_t versionSeq_{0};
};

class MemoryStore final : public sync::manifest::ObjectStore {
public:
    explicit MemoryStore(std::shared_ptr<MemoryBucket> bucket,
                         const sync::manifest::WriteCapability mode = sync::manifest::WriteCapability::Unknown)
        : bucket_(std::move(bucket)), mode_(mode) {
        if (!bucket_) throw std::invalid_argument("MemoryStore needs a bucket");
    }

    std::optional<sync::manifest::StoredObject> get(const std::string& key,
                                                    const std::optional<std::string>& versionId) override {
        auto v = bucket_->read(key, versionId);
        if (!v) return std::nullopt;
        if (v->body.size() > sync::manifest::kMaxManifestObjectBytes)
            throw std::runtime_error("the object is larger than a manifest object may be (test)");
        // As storage::s3::ManifestStore answers: the version id asked for, none for the current object.
        return sync::manifest::StoredObject{std::move(v->body), std::move(v->etag), versionId};
    }
    std::optional<std::vector<uint8_t>> getRange(const std::string& key, const uint64_t offset,
                                                 const uint64_t length) override {
        if (length == 0) return std::vector<uint8_t>{};
        const auto v = bucket_->read(key, std::nullopt);
        if (!v) return std::nullopt;
        if (offset >= v->body.size()) throw std::runtime_error("range not satisfiable (416, test)");
        const auto end = std::min<uint64_t>(v->body.size(), offset + length);
        return std::vector<uint8_t>(v->body.begin() + static_cast<std::ptrdiff_t>(offset),
                                    v->body.begin() + static_cast<std::ptrdiff_t>(end));
    }
    std::optional<std::string> headEtag(const std::string& key) override {
        const auto v = bucket_->read(key, std::nullopt);
        if (!v) return std::nullopt;
        return v->etag;
    }
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override {
        return bucket_->write(key, bytes, std::nullopt, true).etag;
    }
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override {
        return bucket_->write(key, bytes, etag, false).etag;
    }
    sync::manifest::PutResult put(const std::string& key, const std::vector<uint8_t>& bytes) override {
        return bucket_->write(key, bytes, std::nullopt, false);
    }
    std::vector<sync::manifest::ListedObject> list(const std::string& prefix) override { return bucket_->list(prefix); }
    std::vector<sync::manifest::StoredVersion> versions(const std::string& key) override {
        return bucket_->versions(key, true);
    }
    std::vector<sync::manifest::StoredVersion> versionsUnder(const std::string& prefix) override {
        return bucket_->versions(prefix, false);
    }
    void remove(const std::string& key) override { bucket_->remove(key); }
    void removeVersion(const std::string& key, const std::string& versionId) override {
        bucket_->removeVersion(key, versionId);
    }
    [[nodiscard]] sync::manifest::WriteCapability mode() const override { return mode_; }

private:
    std::shared_ptr<MemoryBucket> bucket_;
    sync::manifest::WriteCapability mode_;
};

}
