#pragma once

// A manifest ObjectStore that forwards every call to another and runs hooks around each one: the test seam for
// "something happens between two requests of a publish" (design/encryption/06-publish-without-preconditions.md §8.2).
// `before` runs before the request is sent and `after` once it returned (or threw: then with `failed` set); both get
// the operation, the key (the prefix of a listing) and the version id of a GET or DELETE by id (else empty). test_manifest.cpp lands versions in the middle of a publish with it, and
// test_manifest_interleavings.cpp parks writers and readers at their scheduling points.

#include "sync/manifest/Store.hpp"

#include <functional>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_support::manifest_store {

enum class StoreOp { Get, GetRange, Head, PutIfAbsent, PutIfMatch, Put, List, Versions, VersionsUnder, Remove, RemoveVersion };

class HookedStore final : public sync::manifest::ObjectStore {
public:
    using Hook = std::function<void(StoreOp op, const std::string& key, const std::string& versionId, bool failed)>;

    explicit HookedStore(std::shared_ptr<sync::manifest::ObjectStore> inner) : inner_(std::move(inner)) {}

    Hook before;
    Hook after;

private:
    template <typename F>
    auto around(const StoreOp op, const std::string& key, F&& call, const std::string& versionId = {}) {
        if (before) before(op, key, versionId, false);
        try {
            auto out = call();
            if (after) after(op, key, versionId, false);
            return out;
        } catch (...) {
            if (after) after(op, key, versionId, true);
            throw;
        }
    }

public:
    std::optional<sync::manifest::StoredObject> get(const std::string& key,
                                                    const std::optional<std::string>& versionId) override {
        return around(StoreOp::Get, key, [&] { return inner_->get(key, versionId); }, versionId.value_or(""));
    }
    std::optional<std::vector<uint8_t>> getRange(const std::string& key, const uint64_t offset,
                                                 const uint64_t length) override {
        return around(StoreOp::GetRange, key, [&] { return inner_->getRange(key, offset, length); });
    }
    std::optional<std::string> headEtag(const std::string& key) override {
        return around(StoreOp::Head, key, [&] { return inner_->headEtag(key); });
    }
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override {
        return around(StoreOp::PutIfAbsent, key, [&] { return inner_->putIfAbsent(key, bytes); });
    }
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string& etag) override {
        return around(StoreOp::PutIfMatch, key, [&] { return inner_->putIfMatch(key, bytes, etag); });
    }
    sync::manifest::PutResult put(const std::string& key, const std::vector<uint8_t>& bytes) override {
        return around(StoreOp::Put, key, [&] { return inner_->put(key, bytes); });
    }
    std::vector<sync::manifest::ListedObject> list(const std::string& prefix) override {
        return around(StoreOp::List, prefix, [&] { return inner_->list(prefix); });
    }
    std::vector<sync::manifest::StoredVersion> versions(const std::string& key) override {
        return around(StoreOp::Versions, key, [&] { return inner_->versions(key); });
    }
    std::vector<sync::manifest::StoredVersion> versionsSince(const std::string& key,
                                                             const std::optional<std::string>& stopAt) override {
        return around(StoreOp::Versions, key, [&] { return inner_->versionsSince(key, stopAt); });
    }
    std::vector<sync::manifest::StoredVersion> versionsUnder(const std::string& prefix) override {
        return around(StoreOp::VersionsUnder, prefix, [&] { return inner_->versionsUnder(prefix); });
    }
    void remove(const std::string& key) override {
        around(StoreOp::Remove, key, [&] {
            inner_->remove(key);
            return 0;
        });
    }
    void removeVersion(const std::string& key, const std::string& versionId) override {
        around(
            StoreOp::RemoveVersion, key,
            [&] {
                inner_->removeVersion(key, versionId);
                return 0;
            },
            versionId);
    }
    storage::s3::WriteCapability mode() const override { return inner_->mode(); }

private:
    std::shared_ptr<sync::manifest::ObjectStore> inner_;
};

}
