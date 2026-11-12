#pragma once

// The staged master-secret rewrap suites (test_vault_master_rewrap, test_master_secret_rotation): a DB suite with the
// `secret` CLI, every rotation ended before each test, crash hooks, and the audit/CLI helpers both use.

#include "../helpers/db_suite.hpp"
#include "../helpers/temp_dir.hpp"

#include "audit/Trail.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Rewrap.hpp"
#include "crypto/secrets/Versioned.hpp"
#include "db/Transactions.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Users.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/types.hpp"
#include "runtime/Deps.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace vh::test::rewrap {

struct SimulatedCrash : std::runtime_error {
    SimulatedCrash() : std::runtime_error("simulated crash") {}
};

// A crash hook that throws at the n-th time `point` is reached (1-based).
inline vh::crypto::secrets::rewrap::CrashHook crashAt(const std::string& point, const int n = 1) {
    auto seen = std::make_shared<int>(0);
    return [point, n, seen](const std::string_view p) {
        if (p == point && ++*seen == n) throw SimulatedCrash();
    };
}

inline bool slotOnHost(const vh::crypto::secrets::versioned::Slot slot, const unsigned int version) {
    return vh::crypto::secrets::KeyProvider(vh::crypto::secrets::versioned::slotName(slot, version)).sealedExists();
}

class Fixture : public db::Suite {
protected:
    inline static std::string skipWhy = "Skipping db tests due to missing environment variables.";
    inline static std::shared_ptr<vh::protocols::shell::Router> router;

    // The DB suite and the `secret` CLI. With `probeSealing`, the suite skips when sealing
    // doesn't round-trip on this host (CI's container TPM): real sealing is the point of these tests.
    static bool setUpRewrapSuite(const std::string& name, const bool probeSealing) {
        skipWhy = "Skipping db tests due to missing environment variables.";
        if (!setUpDbSuite(name)) return false;
        if (probeSealing) {
            try {
                std::vector<uint8_t> first;
                {
                    vh::crypto::secrets::KeyProvider probe("test_rotation_probe");
                    probe.init();
                    first.assign(probe.getMasterKey().begin(), probe.getMasterKey().end());
                }
                vh::crypto::secrets::KeyProvider again("test_rotation_probe");
                again.init();
                if (!std::ranges::equal(again.getMasterKey(), first)) throw std::runtime_error("a different secret");
            } catch (const std::exception& e) {
                skipTests = true;
                skipWhy = std::string("sealing doesn't round-trip on this host: ") + e.what();
                std::error_code ec;
                std::filesystem::remove_all(root, ec);
                return false;
            }
        }
        vh::crypto::secrets::versioned::resetForTesting();
        if (!vh::runtime::Deps::get().shellUsageManager)
            vh::runtime::Deps::get().shellUsageManager = std::make_shared<vh::protocols::shell::UsageManager>();
        router = std::make_shared<vh::protocols::shell::Router>();
        vh::protocols::shell::commands::registerSecretsCommands(router);
        return true;
    }

    static void tearDownRewrapSuite() {
        if (skipTests) return;
        vh::crypto::secrets::rewrap::setCrashHookForTesting(nullptr);
        vh::crypto::secrets::versioned::resetForTesting();
        tearDownDbSuite();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << skipWhy;
        namespace rw = vh::crypto::secrets::rewrap;
        rw::setCrashHookForTesting(nullptr);
        // Every test starts with no rotation in progress on any slot (a previous one may have left a window open).
        for (const auto slot : vh::crypto::secrets::versioned::kSlots) {
            const auto st = rw::state(slot);
            if (st.previous_version) (void)rw::finalize(slot);
            else if (st.staging_version) (void)rw::rollback(slot);
        }
    }

    void TearDown() override { vh::crypto::secrets::rewrap::setCrashHookForTesting(nullptr); }

    static std::shared_ptr<vh::identities::User> createUser(const std::string& prefix, const std::string& role) {
        const auto created = vh::ops::users::create(superUser, {.name = prefix + "_" + uniqueTag('r'), .role = role,
                                                            .password = std::string("Secret-Rotation-Pass-123")});
        return vh::identities::manager().user(created.user->id);
    }

    static vh::protocols::shell::CommandResult cli(const std::string& line,
                                                   const std::shared_ptr<vh::identities::User>& user) {
        return router->executeLine(line, user, nullptr);
    }

    static long long auditCount(const std::string& action, const std::string& outcome,
                                const std::optional<std::string>& slot = std::nullopt) {
        (void)vh::audit::Trail::instance()->flushNow();
        return vh::db::Transactions::exec("rotationTest::audit", [&](pqxx::work& txn) {
            if (slot)
                return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND outcome = $2 AND "
                                "details::jsonb->>'slot' = $3",
                                pqxx::params{action, outcome, *slot})
                    .one_field_ref()
                    .as<long long>();
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND outcome = $2",
                            pqxx::params{action, outcome})
                .one_field_ref()
                .as<long long>();
        });
    }
};

}
