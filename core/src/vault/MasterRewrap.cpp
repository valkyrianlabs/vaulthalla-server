#include "vault/MasterRewrap.hpp"

#include "audit/Trail.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "log/Registry.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/Master.hpp"
#include "vault/model/Key.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <shared_mutex>
#include <sstream>

namespace vh::vault::master::rewrap {

namespace {

using Provider = std::shared_ptr<const crypto::secrets::KeyProvider>;
using db::encoding::from_hex_bytea;
using db::encoding::to_hex_bytea;

constexpr std::array<const char*, 3> kTables{"vault_keys", "vault_keys_trashed", "vault_deletion_key"};
constexpr const char* kCols =
    "vault_id, version, encrypted_key, iv, master_version, key_check, encrypted_key_next, iv_next, master_version_next, "
    "encrypted_key_prev, iv_prev, master_version_prev";
constexpr const char* kLockTables = "LOCK TABLE vault_keys, vault_keys_trashed, vault_deletion_key IN EXCLUSIVE MODE";
constexpr std::size_t kListed = 10;  // rows named in a refusal

std::mutex opMutex;  // one rewrap operation at a time in this process
std::mutex hookMutex;
CrashHook crashHook;

void crashPoint(const std::string_view point) {
    CrashHook hook;
    {
        std::scoped_lock lock(hookMutex);
        hook = crashHook;
    }
    if (hook) hook(point);
}

struct Wrap {
    std::vector<uint8_t> key, iv;
    unsigned int master{};
};

struct Row {
    std::string table;
    unsigned int vault_id{}, version{};
    Wrap cur;
    std::optional<std::string> key_check;
    std::optional<Wrap> next, prev;

    [[nodiscard]] std::string name() const { return fmt::format("{} vault {} version {}", table, vault_id, version); }
};

std::optional<Wrap> wrapAt(const pqxx::row_ref row, const int k, const int iv, const int v) {
    if (row[k].is_null() || row[iv].is_null() || row[v].is_null()) return std::nullopt;
    return Wrap{from_hex_bytea(row[k].as<std::string>()), from_hex_bytea(row[iv].as<std::string>()),
                row[v].as<unsigned int>()};
}

std::vector<Row> rowsOf(const pqxx::result& res, const std::string& table) {
    std::vector<Row> out;
    for (const auto& r : res) {
        Row row{.table = table, .vault_id = r[0].as<unsigned int>(), .version = r[1].as<unsigned int>(),
                .cur = *wrapAt(r, 2, 3, 4)};
        if (!r[5].is_null()) row.key_check = r[5].as<std::string>();
        row.next = wrapAt(r, 6, 7, 8);
        row.prev = wrapAt(r, 9, 10, 11);
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<Row> loadAll(pqxx::work& txn) {
    std::vector<Row> out;
    for (const auto* t : kTables) {
        auto rows = rowsOf(txn.exec(fmt::format("SELECT {} FROM {} ORDER BY vault_id, version", kCols, t)), t);
        std::ranges::move(rows, std::back_inserter(out));
    }
    return out;
}

std::vector<Row> loadAll() {
    return db::Transactions::exec("rewrap::loadAll", [](pqxx::work& txn) { return loadAll(txn); });
}

// The key `w` wraps under `master`, in locked memory (null when it doesn't authenticate or isn't a 32-byte key, or
// there is no master).
crypto::SecretKeyPtr unwrapWith(const Provider& master, const Wrap& w) {
    if (!master) return nullptr;
    try {
        const crypto::WipedKeyCopy raw(crypto::util::decrypt_aes256_gcm(w.key, master->getMasterKey(), w.iv));
        if (raw.bytes.size() != crypto::util::AES_KEY_SIZE) return nullptr;
        return std::make_shared<const crypto::SecretKey>(raw.bytes);
    } catch (const std::exception&) {
        return nullptr;
    }
}

// The bytes are the row's key: its recorded key check (migration 113) matches, when there is one.
bool matchesRecord(const Row& row, const std::span<const uint8_t> key) {
    if (!row.key_check) return true;
    return keyCheckEquals(keyCheck(key, row.vault_id, row.version), *row.key_check);
}

Wrap wrapUnder(const Provider& master, const std::span<const uint8_t> key, const unsigned int version) {
    Wrap w{.master = version};
    w.key = crypto::util::encrypt_aes256_gcm(key, master->getMasterKey(), w.iv);
    return w;
}

// A wrap that came straight back from encryption is checked once more before it is stored.
bool roundTrips(const Provider& master, const Wrap& w, const std::span<const uint8_t> key) {
    const auto back = unwrapWith(master, w);
    return back && std::ranges::equal(back->bytes(), key);
}

void writeNext(pqxx::work& txn, const Row& row, const Wrap& w) {
    txn.exec(fmt::format("UPDATE {} SET encrypted_key_next = $3, iv_next = $4, master_version_next = $5 "
                         "WHERE vault_id = $1 AND version = $2",
                         row.table),
             pqxx::params{row.vault_id, row.version, to_hex_bytea(w.key), to_hex_bytea(w.iv), w.master});
}

std::string listed(const std::vector<std::string>& names) {
    std::string out;
    for (std::size_t i = 0; i < names.size() && i < kListed; ++i) out += (i ? "; " : "") + names[i];
    if (names.size() > kListed) out += fmt::format("; and {} more", names.size() - kListed);
    return out;
}

unsigned int countMasterOtherThan(pqxx::work& txn, const unsigned int version) {
    unsigned int n = 0;
    for (const auto* t : kTables)
        n += txn.exec(fmt::format("SELECT COUNT(*) FROM {} WHERE master_version <> $1", t), pqxx::params{version})
                 .one_field_ref()
                 .as<unsigned int>();
    return n;
}

void beginRewrapTxn(pqxx::work& txn) {
    txn.exec("SET LOCAL vh.vault_master_rewrap = 'on'");
    txn.exec(kLockTables);
}

State readState(pqxx::work& txn, const bool forUpdate) {
    const auto r = txn.exec(std::string(
                                "SELECT version, highest_version, staging_version, "
                                "EXTRACT(EPOCH FROM staging_started_at)::bigint, previous_version, "
                                "EXTRACT(EPOCH FROM switched_at)::bigint, EXTRACT(EPOCH FROM window_until)::bigint, "
                                "array_to_string(discard_versions, ',') FROM vault_master_state WHERE id") +
                            (forUpdate ? " FOR UPDATE" : ""))
                       .one_row();
    State s{.version = r[0].as<unsigned int>(), .highest_version = r[1].as<unsigned int>()};
    if (!r[2].is_null()) s.staging_version = r[2].as<unsigned int>();
    if (!r[3].is_null()) s.staging_started_at = r[3].as<std::time_t>();
    if (!r[4].is_null()) s.previous_version = r[4].as<unsigned int>();
    if (!r[5].is_null()) s.switched_at = r[5].as<std::time_t>();
    if (!r[6].is_null()) s.window_until = r[6].as<std::time_t>();
    std::stringstream csv(r[7].is_null() ? std::string{} : r[7].as<std::string>());
    for (std::string item; std::getline(csv, item, ',');)
        if (!item.empty()) s.discard_versions.push_back(static_cast<unsigned int>(std::stoul(item)));
    return s;
}

bool slotSealed(const unsigned int version) {
    return crypto::secrets::KeyProvider(slotName(version)).sealedExists();
}

// Deletes the sealed slots listed in discard_versions, never one a row or the state still names.
std::vector<unsigned int> discardPending() {
    std::vector<unsigned int> deleted;
    const auto st = db::Transactions::exec("rewrap::discard.state", [](pqxx::work& txn) { return readState(txn, false); });
    for (const auto v : st.discard_versions) {
        const bool inUse = v == st.version || v == st.staging_version || v == st.previous_version ||
                           db::Transactions::exec("rewrap::discard.inUse", [&](pqxx::work& txn) {
                               for (const auto* t : kTables)
                                   if (!txn.exec(fmt::format("SELECT 1 FROM {} WHERE master_version = $1 OR "
                                                             "master_version_next = $1 OR master_version_prev = $1 "
                                                             "LIMIT 1", t),
                                                 pqxx::params{v})
                                            .empty())
                                       return true;
                               return false;
                           });
        if (inUse) {
            log::Registry::crypto()->error("[VaultMasterRewrap] Not deleting vault master version {}: it is still in "
                                           "use", v);
        } else {
            forget(v);
            crypto::secrets::KeyProvider(slotName(v)).destroySealed();
            deleted.push_back(v);
            log::Registry::crypto()->info("[VaultMasterRewrap] Deleted the sealed vault master version {} ('{}')", v,
                                          slotName(v));
        }
        db::Transactions::exec("rewrap::discard.done", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_master_state SET discard_versions = array_remove(discard_versions, $1) WHERE id",
                     pqxx::params{v});
        });
    }
    return deleted;
}

// The staged master `target`: unsealed when it is sealed and usable, else (absent, or it no longer unseals) generated
// afresh. Replacing it is safe: nothing is switched to it while it is staging; its staged wraps are dropped first.
Provider sealTarget(const unsigned int target) {
    forget(target);
    if (slotSealed(target)) {
        try {
            return provider(target);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[VaultMasterRewrap] The staged vault master version {} no longer unseals "
                                          "({}); staging restarts under a new one", target, e.what());
        }
    }
    db::Transactions::exec("rewrap::dropStaged", [&](pqxx::work& txn) {
        for (const auto* t : kTables)
            txn.exec(fmt::format("UPDATE {} SET encrypted_key_next = NULL, iv_next = NULL, master_version_next = NULL "
                                 "WHERE master_version_next = $1", t),
                     pqxx::params{target});
    });
    crypto::secrets::KeyProvider slot(slotName(target));
    slot.destroySealed();
    slot.init();  // generates and seals a fresh secret (libsodium CSPRNG)
    forget(target);
    return provider(target);
}

}

void setCrashHookForTesting(CrashHook hook) {
    std::scoped_lock lock(hookMutex);
    crashHook = std::move(hook);
}

State state() {
    return db::Transactions::exec("rewrap::state", [](pqxx::work& txn) { return readState(txn, false); });
}

Status status() {
    Status out;
    out.state = state();
    for (const auto& row : loadAll()) {
        ++out.rows;
        ++out.by_master[row.cur.master];
        if (out.state.staging_version && row.next && row.next->master == *out.state.staging_version) ++out.staged;
        if (out.state.previous_version && row.prev && row.prev->master == *out.state.previous_version) ++out.retained;
    }
    out.current_sealed = slotSealed(out.state.version);
    if (out.state.staging_version) out.staging_sealed = slotSealed(*out.state.staging_version);
    if (out.state.previous_version) out.previous_sealed = slotSealed(*out.state.previous_version);
    return out;
}

RotateResult rotate(const Options& options) {
    if (options.batch == 0) throw ops::Invalid("the rewrap batch size must be at least 1");
    if (options.window < std::chrono::seconds(0)) throw ops::Invalid("the recovery window can't be negative");
    std::scoped_lock op(opMutex);
    auto st = state();
    if (st.previous_version)
        throw Refused("window_open",
                      fmt::format("the recovery window of the last vault master rotation (version {} to {}) is still "
                                  "open: finalize it (vh secret master finalize) or roll it back first",
                                  *st.previous_version, st.version));

    RotateResult result{.from = st.version};
    const auto current = provider(st.version);  // MasterSecretLost propagates: nothing can be rewrapped without it

    // Preflight, before anything is sealed: every row unwraps under the current master and is its recorded key.
    {
        std::vector<std::string> unreadable;
        for (const auto& row : loadAll()) {
            if (row.cur.master != st.version) {
                unreadable.push_back(row.name() + fmt::format(" (wrapped under version {})", row.cur.master));
                continue;
            }
            const auto raw = unwrapWith(current, row.cur);
            if (!raw || !matchesRecord(row, raw->bytes())) unreadable.push_back(row.name());
        }
        if (!unreadable.empty())
            throw Refused("unreadable_rows",
                          fmt::format("{} vault key row(s) don't unwrap under the current vault master (version {}) "
                                      "or don't match their key check, so they can't be rewrapped: {}. Restore those "
                                      "vaults' keys first (vh vault keys import). Nothing was changed.",
                                      unreadable.size(), st.version, listed(unreadable)));
    }

    unsigned int target = 0;
    if (st.staging_version) {
        target = *st.staging_version;
        result.resumed = true;
    } else {
        target = db::Transactions::exec("rewrap::beginStaging", [](pqxx::work& txn) {
            return txn.exec("UPDATE vault_master_state SET staging_version = highest_version + 1, "
                            "highest_version = highest_version + 1, staging_started_at = NOW() "
                            "WHERE id AND staging_version IS NULL AND previous_version IS NULL "
                            "RETURNING staging_version")
                .one_field_ref()
                .as<unsigned int>();
        });
        crashPoint("staging_recorded");
    }
    result.to = target;
    const auto next = sealTarget(target);
    crashPoint("sealed");

    // Stage, in batches. A row whose bytes change meanwhile loses its staged wrap (trigger) and is picked up again.
    for (const auto* table : kTables) {
        for (unsigned int stalled = 0;;) {
            const auto rows = db::Transactions::exec("rewrap::stage.select", [&](pqxx::work& txn) {
                return rowsOf(txn.exec(fmt::format("SELECT {} FROM {} WHERE master_version_next IS DISTINCT FROM $1 "
                                                   "OR encrypted_key_next IS NULL OR iv_next IS NULL "
                                                   "ORDER BY vault_id, version LIMIT $2",
                                                   kCols, table),
                                       pqxx::params{target, options.batch}),
                              table);
            });
            if (rows.empty()) break;
            std::vector<std::pair<const Row*, Wrap>> staged;
            for (const auto& row : rows) {
                const auto raw = row.cur.master == st.version ? unwrapWith(current, row.cur) : nullptr;
                if (!raw || !matchesRecord(row, raw->bytes()))
                    throw Refused("unreadable_rows", row.name() + " no longer unwraps under the current vault master "
                                                     "(it changed during staging); nothing switched, run the rotation "
                                                     "again");
                if (!row.key_check) {
                    // Rows from before migration 113 that never unsealed since: record the key check now, so the
                    // verification and the finalize can compare against it.
                    vault::model::Key rec;
                    rec.vaultId = row.vault_id;
                    rec.version = row.version;
                    rec.encrypted_key = row.cur.key;
                    rec.iv = row.cur.iv;
                    rec.master_version = row.cur.master;
                    attestation::backfill(rec, raw->bytes());
                }
                auto w = wrapUnder(next, raw->bytes(), target);
                if (!roundTrips(next, w, raw->bytes()))
                    throw std::runtime_error("a new wrap under vault master version " + std::to_string(target) +
                                             " did not unwrap to the same key");
                staged.emplace_back(&row, std::move(w));
            }
            const auto written = db::Transactions::exec("rewrap::stage.batch", [&](pqxx::work& txn) {
                unsigned int n = 0;
                for (const auto& [row, w] : staged)
                    n += static_cast<unsigned int>(
                        txn.exec(fmt::format("UPDATE {} SET encrypted_key_next = $3, iv_next = $4, "
                                             "master_version_next = $5 WHERE vault_id = $1 AND version = $2 AND "
                                             "encrypted_key = $6 AND iv = $7 AND master_version = $8",
                                             row->table),
                                 pqxx::params{row->vault_id, row->version, to_hex_bytea(w.key), to_hex_bytea(w.iv),
                                              w.master, to_hex_bytea(row->cur.key), to_hex_bytea(row->cur.iv),
                                              row->cur.master})
                            .affected_rows());
                return n;
            });
            ++result.batches;
            result.staged_now += written;
            crashPoint("batch");
            if (written == 0 && ++stalled >= 3)
                throw std::runtime_error(fmt::format("staging {} makes no progress: its rows keep changing", table));
            if (written) stalled = 0;
        }
    }

    // Verify, before taking any lock: every staged wrap is the row's key under the new master.
    {
        std::vector<std::string> bad;
        std::vector<const Row*> drop;
        const auto rows = loadAll();
        for (const auto& row : rows) {
            if (!row.next || row.next->master != target) continue;  // changed since staging: the switch stages it
            const auto oldRaw = unwrapWith(current, row.cur);
            const auto newRaw = unwrapWith(next, *row.next);
            if (!oldRaw || !newRaw || !std::ranges::equal(oldRaw->bytes(), newRaw->bytes) ||
                !matchesRecord(row, newRaw->bytes())) {
                bad.push_back(row.name());
                drop.push_back(&row);
            }
        }
        if (!bad.empty()) {
            db::Transactions::exec("rewrap::verify.drop", [&](pqxx::work& txn) {
                for (const auto* row : drop)
                    txn.exec(fmt::format("UPDATE {} SET encrypted_key_next = NULL, iv_next = NULL, "
                                         "master_version_next = NULL WHERE vault_id = $1 AND version = $2",
                                         row->table),
                             pqxx::params{row->vault_id, row->version});
            });
            throw Refused("mismatch",
                          fmt::format("{} staged wrap(s) under vault master version {} are not the row's key: {}. "
                                      "Nothing was switched; the bad wraps were dropped and the next rotation "
                                      "stages them again.",
                                      bad.size(), target, listed(bad)));
        }
    }
    crashPoint("verified");

    // Switch: one transaction with the key tables locked against writes, every in-process wrapper waiting.
    {
        std::unique_lock gate(master::gate());
        const auto window = static_cast<double>(options.window.count());
        db::Transactions::exec("rewrap::switch", [&](pqxx::work& txn) {
            beginRewrapTxn(txn);
            const auto s = readState(txn, true);
            if (s.version != result.from || s.staging_version != target || s.previous_version)
                throw std::runtime_error("the vault master state changed during the rotation");
            std::vector<std::string> bad;
            unsigned int caughtUp = 0, rows = 0;
            for (const auto& row : loadAll(txn)) {
                ++rows;
                const auto raw = row.cur.master == result.from ? unwrapWith(current, row.cur) : nullptr;
                if (!raw || !matchesRecord(row, raw->bytes())) {
                    bad.push_back(row.name());
                    continue;
                }
                Wrap w;
                if (row.next && row.next->master == target) {
                    w = *row.next;
                } else {
                    // Written or changed after staging: staged here, under the lock.
                    w = wrapUnder(next, raw->bytes(), target);
                    writeNext(txn, row, w);
                    ++caughtUp;
                }
                const auto back = unwrapWith(next, w);
                if (!back || !std::ranges::equal(back->bytes(), raw->bytes())) bad.push_back(row.name());
            }
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} vault key row(s) failed verification at the switch: {}. Nothing was "
                                          "switched.", bad.size(), listed(bad)));
            for (const auto* t : kTables)
                txn.exec(fmt::format("UPDATE {} SET encrypted_key_prev = encrypted_key, iv_prev = iv, "
                                     "master_version_prev = master_version, encrypted_key = encrypted_key_next, "
                                     "iv = iv_next, master_version = master_version_next, encrypted_key_next = NULL, "
                                     "iv_next = NULL, master_version_next = NULL WHERE master_version_next = $1",
                                     t),
                         pqxx::params{target});
            if (const auto left = countMasterOtherThan(txn, target); left != 0)
                throw std::runtime_error(fmt::format("{} vault key row(s) were not switched", left));
            result.window_until =
                txn.exec("UPDATE vault_master_state SET version = $1, previous_version = $2, switched_at = NOW(), "
                         "window_until = NOW() + make_interval(secs => $3), staging_version = NULL, "
                         "staging_started_at = NULL WHERE id RETURNING EXTRACT(EPOCH FROM window_until)::bigint",
                         pqxx::params{target, result.from, window})
                    .one_field_ref()
                    .as<std::time_t>();
            result.rows = rows;
            result.caught_up = caughtUp;
        });
    }
    log::Registry::crypto()->info("[VaultMasterRewrap] Switched {} vault key row(s) from vault master version {} to {}; "
                                  "the previous master stays until {}", result.rows, result.from, result.to,
                                  result.window_until);
    crashPoint("switched");
    return result;
}

RollbackResult rollback() {
    std::scoped_lock op(opMutex);
    const auto st = state();

    if (st.staging_version && !st.previous_version) {
        const auto target = *st.staging_version;
        db::Transactions::exec("rewrap::abandon", [&](pqxx::work& txn) {
            for (const auto* t : kTables)
                txn.exec(fmt::format("UPDATE {} SET encrypted_key_next = NULL, iv_next = NULL, "
                                     "master_version_next = NULL WHERE master_version_next IS NOT NULL", t));
            txn.exec("UPDATE vault_master_state SET staging_version = NULL, staging_started_at = NULL, "
                     "discard_versions = array_append(array_remove(discard_versions, $1), $1) WHERE id",
                     pqxx::params{target});
        });
        crashPoint("rollback_committed");
        forget(target);
        (void)discardPending();
        return {.kind = RollbackResult::Kind::AbandonedStaging, .from = target, .to = st.version};
    }
    if (!st.previous_version)
        throw Refused("no_window", "there is no vault master rotation to roll back: nothing is staged and no recovery "
                                   "window is open");

    const auto prev = *st.previous_version, cur = st.version;
    Provider previous, current;
    try {
        previous = provider(prev);
    } catch (const std::exception& e) {
        throw Refused("previous_unavailable",
                      fmt::format("the previous vault master (version {}) no longer unseals here ({}), so there is "
                                  "nothing to roll back to. The current master (version {}) stays.",
                                  prev, e.what(), cur));
    }
    try {
        current = provider(cur);
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[VaultMasterRewrap] The current vault master (version {}) doesn't unseal ({}); "
                                      "rolling back from the retained wraps", cur, e.what());
    }

    RollbackResult result{.kind = RollbackResult::Kind::Reverted, .from = cur, .to = prev};
    {
        std::unique_lock gate(master::gate());
        db::Transactions::exec("rewrap::rollback", [&](pqxx::work& txn) {
            beginRewrapTxn(txn);
            const auto s = readState(txn, true);
            if (s.version != cur || s.previous_version != prev)
                throw std::runtime_error("the vault master state changed during the rollback");
            std::vector<std::string> bad, needCurrent;
            unsigned int restored = 0, rewrapped = 0;
            for (const auto& row : loadAll(txn)) {
                if (row.prev && row.prev->master == prev) {
                    const auto raw = unwrapWith(previous, *row.prev);
                    bool ok = raw && matchesRecord(row, raw->bytes());
                    if (ok && current && row.cur.master == cur) {
                        const auto now = unwrapWith(current, row.cur);
                        ok = now && std::ranges::equal(now->bytes(), raw->bytes());
                    }
                    if (!ok) {
                        bad.push_back(row.name());
                        continue;
                    }
                    txn.exec(fmt::format("UPDATE {} SET encrypted_key = encrypted_key_prev, iv = iv_prev, "
                                         "master_version = master_version_prev, encrypted_key_prev = NULL, "
                                         "iv_prev = NULL, master_version_prev = NULL, encrypted_key_next = NULL, "
                                         "iv_next = NULL, master_version_next = NULL "
                                         "WHERE vault_id = $1 AND version = $2",
                                         row.table),
                             pqxx::params{row.vault_id, row.version});
                    ++restored;
                    continue;
                }
                // Created or changed during the window: only the current master unwraps it.
                if (!current || row.cur.master != cur) {
                    needCurrent.push_back(row.name());
                    continue;
                }
                const auto raw = unwrapWith(current, row.cur);
                if (!raw || !matchesRecord(row, raw->bytes())) {
                    bad.push_back(row.name());
                    continue;
                }
                const auto w = wrapUnder(previous, raw->bytes(), prev);
                if (!roundTrips(previous, w, raw->bytes())) {
                    bad.push_back(row.name());
                    continue;
                }
                txn.exec(fmt::format("UPDATE {} SET encrypted_key = $3, iv = $4, master_version = $5, "
                                     "encrypted_key_prev = NULL, iv_prev = NULL, master_version_prev = NULL, "
                                     "encrypted_key_next = NULL, iv_next = NULL, master_version_next = NULL "
                                     "WHERE vault_id = $1 AND version = $2",
                                     row.table),
                         pqxx::params{row.vault_id, row.version, to_hex_bytea(w.key), to_hex_bytea(w.iv), prev});
                ++rewrapped;
            }
            if (!needCurrent.empty())
                throw Refused("current_unavailable",
                              fmt::format("{} vault key row(s) were created or changed after the switch and only the "
                                          "current vault master (version {}), which doesn't unseal here, holds them: "
                                          "{}. Restore those vaults' keys (vh vault keys import) and roll back again. "
                                          "Nothing was changed.",
                                          needCurrent.size(), cur, listed(needCurrent)));
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} vault key row(s) failed verification under the previous vault master "
                                          "(version {}): {}. Nothing was changed.",
                                          bad.size(), prev, listed(bad)));
            if (const auto left = countMasterOtherThan(txn, prev); left != 0)
                throw std::runtime_error(fmt::format("{} vault key row(s) were not rolled back", left));
            txn.exec("UPDATE vault_master_state SET version = $1, previous_version = NULL, switched_at = NULL, "
                     "window_until = NULL, discard_versions = array_append(array_remove(discard_versions, $2), $2) "
                     "WHERE id",
                     pqxx::params{prev, cur});
            result.rows = restored;
            result.rewrapped = rewrapped;
        });
    }
    log::Registry::crypto()->warn("[VaultMasterRewrap] Rolled back from vault master version {} to {}: {} row(s) "
                                  "restored, {} rewrapped", cur, prev, result.rows, result.rewrapped);
    crashPoint("rollback_committed");
    forget(cur);
    (void)discardPending();
    return result;
}

FinalizeResult finalize() {
    std::scoped_lock op(opMutex);
    const auto st = state();
    FinalizeResult result;
    if (!st.previous_version) {
        result.deleted = discardPending();  // an interrupted finalize or rollback
        return result;
    }
    const auto prev = *st.previous_version, cur = st.version;
    Provider current, previous;
    try {
        current = provider(cur);
    } catch (const std::exception& e) {
        throw Refused("verification_failed",
                      fmt::format("the current vault master (version {}) doesn't unseal here ({}): the previous one "
                                  "is kept. Roll back (vh secret master rollback) to return to it.",
                                  cur, e.what()));
    }
    try {
        previous = provider(prev);
    } catch (const std::exception&) {}  // only needed for rows without a recorded key check

    {
        std::unique_lock gate(master::gate());
        db::Transactions::exec("rewrap::finalize", [&](pqxx::work& txn) {
            beginRewrapTxn(txn);
            const auto s = readState(txn, true);
            if (s.version != cur || s.previous_version != prev)
                throw std::runtime_error("the vault master state changed during the finalize");
            std::vector<std::string> bad;
            unsigned int rows = 0;
            for (const auto& row : loadAll(txn)) {
                ++rows;
                const auto raw = row.cur.master == cur ? unwrapWith(current, row.cur) : nullptr;
                bool ok = raw != nullptr;
                if (ok && row.key_check) {
                    ok = matchesRecord(row, raw->bytes());
                } else if (ok && row.prev && row.prev->master == prev) {
                    // No key check recorded: the retained wrap is the reference, so the previous master is needed.
                    const auto old = unwrapWith(previous, *row.prev);
                    ok = old && std::ranges::equal(old->bytes(), raw->bytes());
                }
                if (!ok) bad.push_back(row.name());
            }
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} vault key row(s) don't verify under the current vault master (version "
                                          "{}): {}. The recovery window stays open and nothing was deleted; roll back "
                                          "(vh secret master rollback) or restore those vaults' keys (vh vault keys "
                                          "import).",
                                          bad.size(), cur, listed(bad)));
            for (const auto* t : kTables)
                txn.exec(fmt::format("UPDATE {} SET encrypted_key_prev = NULL, iv_prev = NULL, "
                                     "master_version_prev = NULL WHERE master_version_prev IS NOT NULL OR "
                                     "encrypted_key_prev IS NOT NULL OR iv_prev IS NOT NULL",
                                     t));
            txn.exec("UPDATE vault_master_state SET previous_version = NULL, window_until = NULL, "
                     "discard_versions = array_append(array_remove(discard_versions, $1), $1) WHERE id",
                     pqxx::params{prev});
            result.rows = rows;
        });
    }
    result.finalized = true;
    result.previous = prev;
    log::Registry::crypto()->info("[VaultMasterRewrap] Finalized the vault master rotation to version {} ({} row(s) "
                                  "verified); deleting version {}", cur, result.rows, prev);
    crashPoint("finalize_committed");
    forget(prev);
    result.deleted = discardPending();
    return result;
}

FinalizeResult expireIfDue(const std::chrono::system_clock::time_point now) {
    // A refused or failed attempt is retried every 10 minutes, not on every retention pass.
    static std::atomic<std::int64_t> retryAfter{0};
    const auto nowSecs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (nowSecs < retryAfter.load()) return {};
    try {
        const auto st = state();
        if (!st.previous_version) {
            if (st.discard_versions.empty()) return {};
            FinalizeResult r;
            r.deleted = finalize().deleted;
            return r;
        }
        if (!st.window_until || *st.window_until > nowSecs) return {};
        auto r = finalize();
        if (r.finalized)
            vh::audit::record({.action = "secrets.master.finalize", .actor = "system",
                               .details = {{"from", *r.previous}, {"to", st.version}, {"rows", r.rows},
                                           {"automatic", true}}},
                              fmt::format("[VaultMasterRewrap] The recovery window of the vault master rotation to "
                                          "version {} expired: {} row(s) verified, version {} deleted",
                                          st.version, r.rows, *r.previous));
        return r;
    } catch (const std::exception& e) {
        retryAfter.store(nowSecs + 600);
        vh::audit::record({.action = "secrets.master.finalize", .outcome = vh::audit::Outcome::Failure,
                           .actor = "system", .details = {{"automatic", true}}},
                          std::string("[VaultMasterRewrap] The vault master recovery window could not be closed: ") +
                              e.what(),
                          spdlog::level::warn);
        return {};
    }
}

}
