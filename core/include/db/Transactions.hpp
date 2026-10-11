#pragma once

#include "DBPool.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"

#include <memory>
#include <optional>
#include <pqxx/pqxx>
#include <stdexcept>
#include <string>
#include <type_traits>
#include <utility>

namespace vh::db {

    class Transactions {
        static void markIfPoisoned(Connection& conn, const std::exception& e) noexcept {
            if (const auto* failure = dynamic_cast<const pqxx::failure*>(&e); failure && failure->poisons_connection())
                conn.markPoisoned();
        }

    public:
        static inline std::shared_ptr<DBPool> dbPool_;

        static void init() { dbPool_ = std::make_shared<DBPool>(); }

        template <typename Func>
        static decltype(auto) exec(const std::string& ctx, Func&& func) {
            using Fn = std::remove_reference_t<Func>;
            using ReturnT = std::invoke_result_t<Fn&, pqxx::work&>;

            // Local copy keeps the pool alive for as long as this call holds a lease on it.
            const auto pool = dbPool_;
            if (!pool) throw std::runtime_error("Transactions not initialized!");

            log::Registry::db()->trace("[Transactions::exec] Starting transaction: {}", ctx);

            // Declared before `txn` so the transaction is torn down (rolled back) before the lease hands the
            // connection back to the pool, on every path.
            auto conn = pool->acquire();
            std::optional<pqxx::work> txn;

            try {
                txn.emplace(conn->get());
            } catch (const std::exception& e) {
                // A session the server dropped while idle (PostgreSQL restart, pg_terminate_backend) only shows
                // up when BEGIN is sent. Nothing of `func` has run yet, so replacing the connection and beginning
                // once more is always safe. Failures after `func` starts are surfaced, never retried.
                markIfPoisoned(*conn, e);
                if (conn->healthy()) {
                    log::Registry::db()->error(
                        "[Transactions::exec] Failed to begin transaction '{}': {}", ctx, e.what());
                    throw;
                }
                log::Registry::db()->warn(
                    "[Transactions::exec] Connection lost before transaction '{}' began ({}); reconnecting",
                    ctx, e.what());
                pool->repair(conn);
                txn.emplace(conn->get());
            }

            try {
                if constexpr (std::is_void_v<ReturnT>) {
                    func(*txn);
                    txn->commit();
                    log::Registry::db()->trace("[Transactions::exec] Transaction committed: {}", ctx);
                    return;
                } else {
                    ReturnT result = func(*txn);
                    txn->commit();
                    log::Registry::db()->trace("[Transactions::exec] Transaction committed: {}", ctx);
                    return result;
                }
            } catch (const ops::Error& e) {
                // A typed refusal (ops::Denied, NotFound, Invalid, ...) thrown inside the transaction on purpose
                // is the caller's answer, not a database fault: roll back quietly and let it propagate.
                log::Registry::db()->debug(
                    "[Transactions::exec] Refusal in transaction context '{}', rolling back: {}", ctx, e.what());
                throw;
            } catch (const std::exception& e) {
                // libpqxx flags errors after which the session can't be trusted even if the socket looks open
                // (unknown COMMIT outcome, protocol violation); the pool replaces it on the next acquire().
                markIfPoisoned(*conn, e);
                log::Registry::db()->error(
                    "[Transactions::exec] Exception in transaction context '{}', rolling back: {}", ctx, e.what());
                throw;
            } catch (...) {
                log::Registry::db()->error(
                    "[Transactions::exec] Exception in transaction context '{}', rolling back",
                    ctx
                );
                throw;
            }
        }

        // A read that needs no transaction (one statement, or statements that need not agree): runs outside
        // BEGIN/COMMIT, so a single-statement read is one round trip instead of three. `func` takes a
        // pqxx::transaction_base&. A session the server dropped while idle is replaced and the read retried once
        // (reads are idempotent); any other failure is surfaced.
        template <typename Func>
        static decltype(auto) read(const std::string& ctx, Func&& func) {
            const auto pool = dbPool_;
            if (!pool) throw std::runtime_error("Transactions not initialized!");

            auto conn = pool->acquire();
            for (int attempt = 0;; ++attempt) {
                try {
                    pqxx::nontransaction ntx(conn->get());
                    return func(static_cast<pqxx::transaction_base&>(ntx));
                } catch (const pqxx::broken_connection& e) {
                    markIfPoisoned(*conn, e);
                    if (attempt > 0 || conn->healthy()) throw;
                    log::Registry::db()->warn("[Transactions::read] Connection lost before read '{}' ({}); reconnecting",
                                              ctx, e.what());
                    pool->repair(conn);
                } catch (const std::exception& e) {
                    markIfPoisoned(*conn, e);
                    log::Registry::db()->error("[Transactions::read] Read '{}' failed: {}", ctx, e.what());
                    throw;
                }
            }
        }
    };

}
