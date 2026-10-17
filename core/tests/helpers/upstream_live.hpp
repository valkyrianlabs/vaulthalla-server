#pragma once

// Shared by the live provider tests (test_upstream_live.cpp, test_recovery_live.cpp). Never part of CI: every live test
// skips unless VH_LIVE_UPSTREAM=1. They create ONLY buckets/queues named vaulthalla-test-<unix time>-<random> and remove
// them again (every version), even on failure. Nothing else in the accounts is read at object level, changed or deleted.
//
//   AWS:  VH_AWS_ADMIN_API_KEY, VH_AWS_ADMIN_SECRET_KEY            (buckets in us-east-2)
//   R2:   VH_R2_ADMIN_ACCESS_KEY, VH_R2_ADMIN_SECRET_KEY, VH_R2_ADMIN_ENDPOINT, optional VH_CF_API_TOKEN (events)

#include "storage/s3/provider/admin/Adapters.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <functional>
#include <iostream>
#include <memory>
#include <random>
#include <stdexcept>
#include <string>
#include <thread>

namespace vh::test_support::live {

inline std::string liveEnv(const char* name) {
    const auto* v = std::getenv(name);
    return v ? std::string(v) : std::string{};
}

inline bool liveEnabled() { return liveEnv("VH_LIVE_UPSTREAM") == "1"; }

inline std::string liveTestName(const std::string& suffix = {}) {
    std::mt19937_64 rng(std::random_device{}());
    char rand[9];
    std::snprintf(rand, sizeof(rand), "%08x", static_cast<unsigned int>(rng()));
    return "vaulthalla-test-" + std::to_string(std::time(nullptr)) + "-" + rand + suffix;
}

struct LiveCleanup {
    std::function<void()> fn;
    ~LiveCleanup() {
        try {
            if (fn) fn();
        } catch (const std::exception& e) {
            std::cerr << "[live cleanup] " << e.what() << std::endl;
            ADD_FAILURE() << "cleanup failed: " << e.what();
        }
    }
};

// Empties and deletes a test bucket (all versions and delete markers). Refuses any name that isn't ours. A provider
// that still reports the bucket non-empty right after the last batch delete is asked again (bounded).
inline void liveDestroyTestBucket(storage::s3::provider::admin::AdminClient& client, const std::string& bucket) {
    if (!bucket.starts_with("vaulthalla-test-")) throw std::logic_error("refusing to delete a non-test bucket");
    if (!client.headBucket(bucket)) return;
    for (int attempt = 1;; ++attempt) {
        uint64_t removed = 0;
        for (int round = 0; round < 20; ++round) {
            const auto page = client.listObjectVersions(bucket, {}, 1000);
            if (page.objects.empty()) break;
            const auto failed = client.deleteObjects(bucket, page.objects);
            if (!failed.empty())
                throw std::runtime_error("could not delete " + std::to_string(failed.size()) + " test object(s)");
            removed += page.objects.size();
        }
        try {
            client.deleteBucket(bucket);
            std::cout << "[live] deleted " << bucket << " (" << removed << " version(s)/marker(s) removed)" << std::endl;
            return;
        } catch (const std::exception& e) {
            if (attempt >= 5) throw;
            std::cerr << "[live cleanup] delete " << bucket << " attempt " << attempt << ": " << e.what()
                      << "; retrying" << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds{2 * attempt});
        }
    }
}

inline std::shared_ptr<vault::model::APIKey> liveAwsKey(const unsigned int ownerId = 0) {
    return std::make_shared<vault::model::APIKey>(ownerId, "live-aws", vault::model::S3Provider::AWS,
                                                  liveEnv("VH_AWS_ADMIN_API_KEY"), liveEnv("VH_AWS_ADMIN_SECRET_KEY"),
                                                  "us-east-2", "https://s3.us-east-2.amazonaws.com");
}

inline std::shared_ptr<vault::model::APIKey> liveR2Key(const unsigned int ownerId = 0) {
    auto key = std::make_shared<vault::model::APIKey>(ownerId, "live-r2", vault::model::S3Provider::CloudflareR2,
                                                      liveEnv("VH_R2_ADMIN_ACCESS_KEY"), liveEnv("VH_R2_ADMIN_SECRET_KEY"),
                                                      "auto", liveEnv("VH_R2_ADMIN_ENDPOINT"));
    key->provider_token = liveEnv("VH_CF_API_TOKEN");
    return key;
}

}
