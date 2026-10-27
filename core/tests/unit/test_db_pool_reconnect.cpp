// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Regression guard for P0-1 (production-hardening.md): after a PostgreSQL restart the pool leaked a slot for
// every dead connection that reached pqxx::work's constructor and then parked every DB caller on a condvar
// forever. These tests kill the pool's server sessions with pg_terminate_backend (a PostgreSQL restart as the
// client sees it, without touching the shared server) and assert that the pool heals, never loses a slot,
// and never blocks without bound.

#include "db/DBPool.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "seed/include/init_db_tables.hpp"

#include <paths.h>
#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

constexpr std::size_t kPoolSize = 4;

bool hasDbEnv() {
    return std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
           std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME");
}

std::string testConnectionString() {
    return std::string("user=") + std::getenv("VH_TEST_DB_USER") + " password=" + std::getenv("VH_TEST_DB_PASS") +
           " host=" + std::getenv("VH_TEST_DB_HOST") + " port=" + std::getenv("VH_TEST_DB_PORT") +
           " dbname=" + std::getenv("VH_TEST_DB_NAME");
}

}

class DBPoolReconnectTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    std::shared_ptr<vh::db::DBPool> pool;
    // Out-of-pool session used to kill pool backends and toggle the connection limit. Opened before any
    // limit change, so it can always restore it.
    std::unique_ptr<pqxx::connection> admin;

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_db_pool_reconnect] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        vh::paths::enableTestMode();
        vh::db::Transactions::init();
        vh::db::seed::init_tables_if_not_exists();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";

        pool = std::make_shared<vh::db::DBPool>(kPoolSize, std::chrono::milliseconds(2000));
        pool->initPreparedStatements();
        vh::db::Transactions::dbPool_ = pool;
        admin = std::make_unique<pqxx::connection>(testConnectionString());
    }

    void TearDown() override {
        if (skipTests) return;
        try { setConnectionLimit(-1); } catch (...) {}
        vh::db::Transactions::dbPool_.reset();
        pool.reset();
        admin.reset();
    }

    // Leases every slot at once so each backend is seen exactly once.
    std::vector<int> poolBackendPids() const {
        std::vector<vh::db::DBPool::Lease> leases;
        std::vector<int> pids;
        for (std::size_t i = 0; i < kPoolSize; ++i) {
            leases.push_back(pool->acquire());
            pids.push_back(leases.back()->get().backendpid());
        }
        return pids;
    }

    void terminateBackends(const std::vector<int>& pids) const {
        pqxx::nontransaction tx(*admin);
        for (const auto pid : pids)
            EXPECT_TRUE(tx.exec("SELECT pg_terminate_backend($1, 5000)", pqxx::params{pid}).one_field_ref().as<bool>());
    }

    void setConnectionLimit(const int limit) const {
        pqxx::nontransaction tx(*admin);
        tx.exec("ALTER DATABASE " + admin->quote_name(admin->dbname()) + " CONNECTION LIMIT " + std::to_string(limit));
    }

    void expectPoolWhole() const {
        const auto stats = pool->stats();
        EXPECT_EQ(stats.size, kPoolSize);
        EXPECT_EQ(stats.idle, kPoolSize) << "a pool slot leaked";
        EXPECT_EQ(stats.inUse, 0u);
    }

    static bool runQuery() {
        // Goes through Transactions::exec and a prepared statement, like every real caller.
        return vh::db::query::identities::User::userExists("db_pool_reconnect_nobody");
    }
};

TEST_F(DBPoolReconnectTest, RecoversAfterEveryBackendIsTerminatedRepeatedly) {
    ASSERT_FALSE(runQuery());

    for (int cycle = 0; cycle < 3; ++cycle) {
        const auto before = poolBackendPids();
        terminateBackends(before);

        // More operations than slots: before the fix the 5th call blocked forever.
        for (std::size_t i = 0; i < kPoolSize * 3; ++i)
            ASSERT_NO_THROW(EXPECT_FALSE(runQuery())) << "cycle " << cycle << " op " << i;

        expectPoolWhole();
        const auto after = poolBackendPids();
        for (const auto pid : after)
            EXPECT_EQ(std::ranges::count(before, pid), 0) << "a terminated backend is still in the pool";
    }

    const auto stats = pool->stats();
    EXPECT_EQ(stats.reconnects, kPoolSize * 3);
    EXPECT_EQ(stats.brokenIdle, 0u);
    EXPECT_EQ(stats.consecutiveReconnectFailures, 0u);
}

TEST_F(DBPoolReconnectTest, ConcurrentCallersRecoverAfterTermination) {
    terminateBackends(poolBackendPids());

    std::atomic<int> ok{0};
    std::atomic<int> failed{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&] {
            for (int i = 0; i < 10; ++i) {
                try {
                    runQuery();
                    ++ok;
                } catch (...) {
                    ++failed;
                }
            }
        });
    }
    for (auto& t : threads) t.join();

    EXPECT_EQ(failed.load(), 0);
    EXPECT_EQ(ok.load(), 80);
    expectPoolWhole();
    EXPECT_EQ(pool->stats().brokenIdle, 0u);
}

TEST_F(DBPoolReconnectTest, ConnectionLostMidTransactionSurfacesErrorWithoutRetryOrLeak) {
    int calls = 0;
    EXPECT_ANY_THROW(vh::db::Transactions::exec("DBPoolReconnectTest::selfTerminate", [&](pqxx::work& txn) {
        ++calls;
        txn.exec("SELECT pg_terminate_backend(pg_backend_pid())");
    }));
    EXPECT_EQ(calls, 1) << "work that had already started must not be replayed";

    expectPoolWhole();
    EXPECT_EQ(pool->stats().brokenIdle, 1u);
    for (std::size_t i = 0; i < kPoolSize; ++i) EXPECT_FALSE(runQuery()); // FIFO reaches the dead one
    EXPECT_EQ(pool->stats().brokenIdle, 0u);
    EXPECT_EQ(pool->stats().reconnects, 1u);
}

TEST_F(DBPoolReconnectTest, ExceptionsInsideTransactionsNeverLeakSlots) {
    for (std::size_t i = 0; i < kPoolSize * 2; ++i) {
        EXPECT_THROW(vh::db::Transactions::exec("DBPoolReconnectTest::throws", [](pqxx::work& txn) {
            txn.exec("SELECT 1/0");
        }), pqxx::sql_error);
    }
    expectPoolWhole();
    EXPECT_FALSE(runQuery());
    EXPECT_EQ(pool->stats().reconnects, 0u) << "an SQL error must not poison its connection";
}

// libpqxx 8 flags errors after which a session can't be trusted although its socket still looks open
// (pqxx::failure::poisons_connection(): an unknown COMMIT outcome, a protocol violation). Such a connection is
// replaced instead of being handed to the next caller; the plain SQL errors above never cost a reconnect.
TEST_F(DBPoolReconnectTest, PoisonedConnectionsAreReplacedOnTheNextAcquire) {
    int poisonedBackend = 0;
    EXPECT_THROW(vh::db::Transactions::exec("DBPoolReconnectTest::poisoned", [&](pqxx::work& txn) {
        poisonedBackend = txn.conn().backendpid();
        throw pqxx::in_doubt_error{"simulated: COMMIT outcome unknown"};
    }), pqxx::in_doubt_error);

    expectPoolWhole();
    EXPECT_EQ(pool->stats().brokenIdle, 1u);
    EXPECT_EQ(pool->stats().reconnects, 0u);
    for (std::size_t i = 0; i < kPoolSize; ++i) EXPECT_FALSE(runQuery()); // FIFO reaches the poisoned one
    EXPECT_EQ(pool->stats().brokenIdle, 0u);
    EXPECT_EQ(pool->stats().reconnects, 1u);
    for (const auto pid : poolBackendPids()) EXPECT_NE(pid, poisonedBackend);
}

TEST_F(DBPoolReconnectTest, AcquireTimesOutInsteadOfBlockingWhenExhausted) {
    std::vector<vh::db::DBPool::Lease> held;
    for (std::size_t i = 0; i < kPoolSize; ++i) held.push_back(pool->acquire());

    const auto start = std::chrono::steady_clock::now();
    EXPECT_THROW((void)pool->acquire(std::chrono::milliseconds(250)), vh::db::PoolAcquireTimeout);
    EXPECT_THROW(runQuery(), vh::db::PoolAcquireTimeout); // default pool timeout (2s here)
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_GE(elapsed, std::chrono::milliseconds(2200));
    EXPECT_LT(elapsed, std::chrono::seconds(10));
    EXPECT_EQ(pool->stats().acquireTimeouts, 2u);

    // A waiter wakes as soon as a slot comes back.
    std::thread releaser([&] {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
        held.pop_back();
    });
    EXPECT_NO_THROW((void)pool->acquire(std::chrono::seconds(5)));
    releaser.join();

    held.clear();
    expectPoolWhole();
}

TEST_F(DBPoolReconnectTest, UnreachableDatabaseFailsFastKeepsSlotsAndRecovers) {
    try {
        setConnectionLimit(0);
    } catch (const std::exception& e) {
        GTEST_SKIP() << "test role cannot change its database's connection limit: " << e.what();
    }

    terminateBackends(poolBackendPids());

    // New sessions are refused: the first caller hits a reconnect failure, later callers inside the backoff
    // window fail fast. Nobody blocks, and no slot is lost.
    const auto start = std::chrono::steady_clock::now();
    for (std::size_t i = 0; i < kPoolSize * 3; ++i)
        EXPECT_THROW(runQuery(), vh::db::DatabaseUnavailable);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(10));

    auto stats = pool->stats();
    EXPECT_GE(stats.reconnectFailures, 1u);
    EXPECT_GE(stats.consecutiveReconnectFailures, 1u);
    EXPECT_EQ(stats.idle, kPoolSize) << "a pool slot leaked while the database was unreachable";

    setConnectionLimit(-1);

    // Recovers once the backoff window (max 5s) passes.
    bool recovered = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
    while (!recovered && std::chrono::steady_clock::now() < deadline) {
        try {
            EXPECT_FALSE(runQuery());
            recovered = true;
        } catch (const vh::db::DatabaseUnavailable&) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    ASSERT_TRUE(recovered);

    for (std::size_t i = 0; i < kPoolSize * 2; ++i) EXPECT_FALSE(runQuery());
    stats = pool->stats();
    EXPECT_EQ(stats.consecutiveReconnectFailures, 0u);
    EXPECT_EQ(stats.brokenIdle, 0u);
    expectPoolWhole();
}
