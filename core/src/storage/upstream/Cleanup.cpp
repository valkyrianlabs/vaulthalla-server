#include "storage/upstream/Cleanup.hpp"

#include "storage/upstream/Provisioner.hpp"

#include <mutex>
#include <unordered_map>

namespace vh::storage::upstream::cleanup {

namespace {

namespace padmin = s3::provider::admin;

struct TokenRecord {
    std::string identity;
    uint32_t actor = 0;
    Count seen;
    std::chrono::steady_clock::time_point expires;
};

std::mutex& tokenMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, TokenRecord>& tokens() {
    static std::unordered_map<std::string, TokenRecord> t;
    return t;
}

void dropExpired(std::unordered_map<std::string, TokenRecord>& t, const std::chrono::steady_clock::time_point now) {
    std::erase_if(t, [&](const auto& entry) { return entry.second.expires <= now; });
}

std::string identityKey(const BucketIdentity& id) { return id.provider + '\n' + id.account_ref.value_or("") + '\n' + id.bucket; }

}

Count count(padmin::AdminClient& admin, const std::string& bucket, const uint64_t limit) {
    Count out;
    std::string token;
    uint64_t seen = 0;
    do {
        const auto page = admin.listObjectVersions(bucket, token, 1000);
        for (const auto& o : page.objects) {
            if (seen >= limit) {
                out.truncated = true;
                return out;
            }
            ++seen;
            if (o.delete_marker) ++out.delete_markers;
            else if (o.latest) ++out.objects;
            else ++out.versions;
            if (!o.delete_marker) out.bytes += o.size;
            if (out.sample_keys.size() < 10 && !o.delete_marker && o.latest) out.sample_keys.push_back(o.key);
        }
        token = page.next_token;
    } while (!token.empty());
    return out;
}

Run execute(padmin::AdminClient& admin, const std::string& bucket, const bool deleteBucket, const Limits& limits,
            const std::function<bool()>& stillOurs) {
    Run run;
    std::unordered_map<std::string, std::string> failedKeys;   // a key that keeps failing counts once
    const auto deadline = std::chrono::steady_clock::now() + limits.deadline;
    const auto leaseHeld = [&] {
        if (!stillOurs || stillOurs()) return true;
        run.lease_lost = true;
        run.error = "the cleanup's hold on the bucket was lost (locked, bound or taken over meanwhile); stopped";
        return false;
    };
    try {
        while (std::chrono::steady_clock::now() < deadline && run.deleted < limits.max_objects) {
            if (!leaseHeld()) return run;
            const auto page = admin.listObjectVersions(bucket, {}, 1000);
            if (page.objects.empty()) {
                run.emptied = true;
                break;
            }
            const auto failures = admin.deleteObjects(bucket, page.objects);
            run.deleted += page.objects.size() - std::min(page.objects.size(), failures.size());
            for (const auto& [key, code] : failures)
                if (failedKeys.emplace(key, code).second && run.errors.size() < 20) run.errors.push_back(key + ": " + code);
            run.failed = failedKeys.size();
            // A page that deleted nothing would be listed again forever (locked objects): stop and report.
            if (failures.size() >= page.objects.size()) break;
        }
    } catch (const std::exception& e) {
        run.interrupted = true;
        run.error = e.what();
        return run;
    }

    if (run.emptied && deleteBucket) {
        if (!leaseHeld()) return run;
        try {
            admin.deleteBucket(bucket);
            bool exists = true;
            try {
                exists = admin.headBucket(bucket).has_value();
            } catch (const padmin::ProviderError& e) {
                exists = true;
                run.errors.push_back(std::string("bucket deletion not confirmed: ") + e.what());
            }
            run.bucket_deleted = !exists;
            if (exists && run.errors.empty()) run.errors.push_back("the bucket still exists after deletion");
        } catch (const std::exception& e) {
            run.errors.push_back(std::string("bucket deletion failed: ") + e.what());
        }
    }
    return run;
}

Issued issueToken(const BucketIdentity& id, const Count& seen, const uint32_t actorId) {
    const auto now = std::chrono::steady_clock::now();
    Issued issued{.token = provision::newOperationToken(),
                  .expires_at = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(kTokenLifetime).count()};
    std::scoped_lock lock(tokenMutex());
    dropExpired(tokens(), now);
    tokens()[issued.token] = {.identity = identityKey(id), .actor = actorId, .seen = seen,
                             .expires = now + kTokenLifetime};
    return issued;
}

std::optional<Count> consumeToken(const std::string& token, const BucketIdentity& id, const uint32_t actorId) {
    if (token.empty()) return std::nullopt;
    std::scoped_lock lock(tokenMutex());
    dropExpired(tokens(), std::chrono::steady_clock::now());
    const auto it = tokens().find(token);
    if (it == tokens().end()) return std::nullopt;
    if (it->second.identity != identityKey(id) || it->second.actor != actorId) return std::nullopt;
    auto seen = it->second.seen;
    tokens().erase(it);
    return seen;
}

bool sameAs(const Count& seen, const Count& now) {
    return seen.objects == now.objects && seen.versions == now.versions && seen.delete_markers == now.delete_markers &&
           seen.bytes == now.bytes && seen.truncated == now.truncated;
}

}
