#include "crypto/secrets/Rewrap.hpp"

#include "audit/Trail.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "log/Registry.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/Key.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <iterator>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <sstream>

namespace vh::crypto::secrets::rewrap {

namespace {

using Provider = std::shared_ptr<const KeyProvider>;
using db::encoding::from_hex_bytea;
using db::encoding::to_hex_bytea;
namespace vs = versioned;

// ---- what each slot wraps -------------------------------------------------------------------------------------------

// One wrapped secret of a row: its ciphertext and IV columns. The staged and retained wraps are the same names with
// "_next" and "_prev". A field may be NULL (an API key without a provider token); it is then NULL in every form.
struct Field {
    const char* ct;
    const char* iv;
};

struct Table {
    const char* name;
    std::vector<const char*> keys;  // the primary key columns (all integers)
    std::vector<Field> fields;
    bool keyCheck{false};  // vault key rows: a key_check column (migration 113) the secret must match
};

struct Spec {
    Slot slot;
    const char* rows;     // "vault key row(s)"
    const char* restore;  // what to do about a row that doesn't unwrap
    std::vector<Table> tables;
    std::size_t plainSize{0};  // every secret has this length (0: any)
};

const Spec& specOf(const Slot slot) {
    static const std::array<Spec, vs::kSlots.size()> specs{
        Spec{.slot = Slot::VaultMaster,
             .rows = "vault key row(s)",
             .restore = "Restore those vaults' keys first (vh vault keys import).",
             .tables = {{"vault_keys", {"vault_id", "version"}, {{"encrypted_key", "iv"}}, true},
                        {"vault_keys_trashed", {"vault_id", "version"}, {{"encrypted_key", "iv"}}, true},
                        {"vault_deletion_key", {"vault_id", "version"}, {{"encrypted_key", "iv"}}, true}},
             .plainSize = util::AES_KEY_SIZE},
        Spec{.slot = Slot::ApiKeyMaster,
             .rows = "API key(s)",
             .restore = "Enter those API keys' secrets again in the console, or remove them (vh api-key delete).",
             .tables = {{"api_keys",
                         {"id"},
                         {{"encrypted_secret_access_key", "iv"}, {"encrypted_provider_token", "provider_token_iv"}},
                         false}}},
        Spec{.slot = Slot::GatewayMaster,
             .rows = "S3 gateway credential(s)",
             .restore = "Revoke those credentials and issue new ones (vh s3-gateway credential revoke, then create).",
             .tables = {{"s3_gateway_credentials", {"id"}, {{"encrypted_secret_access_key", "iv"}}, false}}},
    };
    return specs.at(static_cast<std::size_t>(slot));
}

std::string slotId(const Slot slot) { return std::string(vs::id(slot)); }
std::string nounOf(const Slot slot) { return std::string(vs::noun(slot)); }

// "vh secret master <op>" for the vault master, with "--slot <name>" for the others.
std::string command(const Slot slot, const std::string_view op) {
    auto out = fmt::format("vh secret master {}", op);
    if (slot != Slot::VaultMaster) out += fmt::format(" --slot {}", vs::cliName(slot));
    return out;
}

constexpr std::size_t kListed = 10;  // rows named in a refusal

std::array<std::mutex, vs::kSlots.size()> opMutexes;  // one rewrap operation at a time per slot in this process
std::mutex& opMutex(const Slot slot) { return opMutexes.at(static_cast<std::size_t>(slot)); }

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

// ---- rows -----------------------------------------------------------------------------------------------------------

struct Blob {
    std::vector<uint8_t> ct{}, iv{};
};

// The wraps of a row under one master: one per field (nullopt: the field is NULL).
struct Wraps {
    std::vector<std::optional<Blob>> f{};
    unsigned int master{};
};

struct Row {
    const Table* table{};
    std::vector<unsigned int> ids{};
    Wraps cur{};
    std::optional<Wraps> next{}, prev{};
    std::optional<std::string> key_check{};

    [[nodiscard]] std::string name() const {
        std::string out = table->name;
        for (std::size_t i = 0; i < ids.size(); ++i) out += fmt::format(" {} {}", table->keys[i], ids[i]);
        return out;
    }
};

std::string joined(const std::vector<std::string>& parts, const std::string_view sep) {
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i) out += (i ? std::string(sep) : std::string{}) + parts[i];
    return out;
}

std::string keyList(const Table& t) { return joined(std::vector<std::string>(t.keys.begin(), t.keys.end()), ", "); }

// The columns rowsOf reads, in order: keys, master_version{,_next,_prev}, [key_check], then per field ct, iv, ct_next,
// iv_next, ct_prev, iv_prev.
std::string columns(const Table& t) {
    std::vector<std::string> cols(t.keys.begin(), t.keys.end());
    cols.insert(cols.end(), {"master_version", "master_version_next", "master_version_prev"});
    if (t.keyCheck) cols.emplace_back("key_check");
    for (const auto& f : t.fields)
        for (const auto* suffix : {"", "_next", "_prev"}) {
            cols.push_back(std::string(f.ct) + suffix);
            cols.push_back(std::string(f.iv) + suffix);
        }
    return joined(cols, ", ");
}

// "vault_id = $3 AND version = $4" for the row's keys, starting at parameter `first`.
std::string whereKeys(const Table& t, const int first) {
    std::vector<std::string> parts;
    for (std::size_t i = 0; i < t.keys.size(); ++i) parts.push_back(fmt::format("{} = ${}", t.keys[i], first + i));
    return joined(parts, " AND ");
}

void appendKeys(pqxx::params& p, const Row& row) {
    for (const auto id : row.ids) p.append(id);
}

std::optional<std::string> hexOr(const std::optional<Blob>& b, const bool iv) {
    if (!b) return std::nullopt;
    return to_hex_bytea(iv ? b->iv : b->ct);
}

std::optional<Blob> blobAt(const pqxx::row_ref r, const int ct) {
    if (r[ct].is_null() || r[ct + 1].is_null()) return std::nullopt;
    return Blob{from_hex_bytea(r[ct].as<std::string>()), from_hex_bytea(r[ct + 1].as<std::string>())};
}

std::vector<Row> rowsOf(const pqxx::result& res, const Table& t) {
    std::vector<Row> out;
    const int nk = static_cast<int>(t.keys.size());
    const int mv = nk, first = nk + 3 + (t.keyCheck ? 1 : 0);
    for (const auto& r : res) {
        Row row{.table = &t};
        for (int i = 0; i < nk; ++i) row.ids.push_back(r[i].as<unsigned int>());
        row.cur.master = r[mv].as<unsigned int>();
        if (!r[mv + 1].is_null()) row.next = Wraps{.master = r[mv + 1].as<unsigned int>()};
        if (!r[mv + 2].is_null()) row.prev = Wraps{.master = r[mv + 2].as<unsigned int>()};
        if (t.keyCheck && !r[nk + 3].is_null()) row.key_check = r[nk + 3].as<std::string>();
        for (std::size_t f = 0; f < t.fields.size(); ++f) {
            const int base = first + static_cast<int>(f) * 6;
            row.cur.f.push_back(blobAt(r, base));
            if (row.next) row.next->f.push_back(blobAt(r, base + 2));
            if (row.prev) row.prev->f.push_back(blobAt(r, base + 4));
        }
        out.push_back(std::move(row));
    }
    return out;
}

std::vector<Row> loadTable(pqxx::work& txn, const Table& t) {
    return rowsOf(txn.exec(fmt::format("SELECT {} FROM {} ORDER BY {}", columns(t), t.name, keyList(t))), t);
}

std::vector<Row> loadAll(pqxx::work& txn, const Spec& spec) {
    std::vector<Row> out;
    for (const auto& t : spec.tables) {
        auto rows = loadTable(txn, t);
        std::ranges::move(rows, std::back_inserter(out));
    }
    return out;
}

std::vector<Row> loadAll(const Spec& spec) {
    return db::Transactions::exec("rewrap::loadAll", [&](pqxx::work& txn) { return loadAll(txn, spec); });
}

// The wraps `w` holds the same fields as the row does now (a staged or retained wrap of another set of secrets, or a
// partial one, never counts).
bool sameShape(const Wraps& w, const Wraps& cur) {
    if (w.f.size() != cur.f.size()) return false;
    for (std::size_t i = 0; i < w.f.size(); ++i)
        if (w.f[i].has_value() != cur.f[i].has_value()) return false;
    return true;
}

bool stagedFor(const Row& row, const unsigned int target) {
    return row.next && row.next->master == target && sameShape(*row.next, row.cur);
}

bool retainedFor(const Row& row, const unsigned int prev) {
    return row.prev && row.prev->master == prev && sameShape(*row.prev, row.cur);
}

// ---- secrets in memory ----------------------------------------------------------------------------------------------

// The secrets a row's wraps hold, in locked memory, one per field (nullopt where the field is NULL).
struct Plain {
    std::vector<std::optional<SecretBytes>> f{};
};

// The secrets `w` wraps under `master` (nullopt when there is no master, a field doesn't authenticate, or a secret
// has the wrong length).
std::optional<Plain> unwrapWith(const Spec& spec, const Provider& master, const Wraps& w) {
    if (!master) return std::nullopt;
    Plain out;
    for (const auto& b : w.f) {
        if (!b) {
            out.f.emplace_back();
            continue;
        }
        try {
            const WipedKeyCopy raw(util::decrypt_aes256_gcm(b->ct, master->getMasterKey(), b->iv));
            if (spec.plainSize && raw.bytes.size() != spec.plainSize) return std::nullopt;
            out.f.emplace_back(SecretBytes(raw.bytes));
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return out;
}

bool samePlain(const Plain& a, const Plain& b) {
    if (a.f.size() != b.f.size()) return false;
    for (std::size_t i = 0; i < a.f.size(); ++i) {
        if (a.f[i].has_value() != b.f[i].has_value()) return false;
        if (a.f[i] && !std::ranges::equal(a.f[i]->bytes(), b.f[i]->bytes())) return false;
    }
    return true;
}

// The secret is the row's: its recorded key check (vault keys, migration 113) matches, when there is one.
bool matchesRecord(const Row& row, const Plain& plain) {
    if (!row.table->keyCheck || !row.key_check || plain.f.empty() || !plain.f[0]) return true;
    const auto check = ::vh::vault::keyCheck(plain.f[0]->bytes(), row.ids[0], row.ids[1]);
    return ::vh::vault::keyCheckEquals(check, *row.key_check);
}

Wraps wrapUnder(const Provider& master, const Plain& plain, const unsigned int version) {
    Wraps w{.master = version};
    for (const auto& p : plain.f) {
        if (!p) {
            w.f.emplace_back();
            continue;
        }
        Blob b;
        b.ct = util::encrypt_aes256_gcm(p->bytes(), master->getMasterKey(), b.iv);
        w.f.emplace_back(std::move(b));
    }
    return w;
}

// A wrap that came straight back from encryption is checked once more before it is stored.
bool roundTrips(const Spec& spec, const Provider& master, const Wraps& w, const Plain& plain) {
    const auto back = unwrapWith(spec, master, w);
    return back && samePlain(*back, plain);
}

// ---- writes ---------------------------------------------------------------------------------------------------------

// "ct_next = $3, iv_next = $4, ..., master_version_next = $n" (suffix "_next"), parameters from `first`.
std::string setWraps(const Table& t, const std::string_view suffix, int& next) {
    std::vector<std::string> parts;
    for (const auto& f : t.fields) {
        parts.push_back(fmt::format("{}{} = ${}", f.ct, suffix, next++));
        parts.push_back(fmt::format("{}{} = ${}", f.iv, suffix, next++));
    }
    parts.push_back(fmt::format("master_version{} = ${}", suffix, next++));
    return joined(parts, ", ");
}

void appendWraps(pqxx::params& p, const Wraps& w) {
    for (const auto& b : w.f) {
        p.append(hexOr(b, false));
        p.append(hexOr(b, true));
    }
    p.append(w.master);
}

// "ct_next = NULL, iv_next = NULL, ..., master_version_next = NULL".
std::string clearWraps(const Table& t, const std::string_view suffix) {
    std::vector<std::string> parts;
    for (const auto& f : t.fields) {
        parts.push_back(fmt::format("{}{} = NULL", f.ct, suffix));
        parts.push_back(fmt::format("{}{} = NULL", f.iv, suffix));
    }
    parts.push_back(fmt::format("master_version{} = NULL", suffix));
    return joined(parts, ", ");
}

// "ct_prev = ct, ..." : every wrap column (and master_version) of `to` takes the value of `from`.
std::string moveWraps(const Table& t, const std::string_view to, const std::string_view from) {
    std::vector<std::string> parts;
    for (const auto& f : t.fields) {
        parts.push_back(fmt::format("{}{} = {}{}", f.ct, to, f.ct, from));
        parts.push_back(fmt::format("{}{} = {}{}", f.iv, to, f.iv, from));
    }
    parts.push_back(fmt::format("master_version{} = master_version{}", to, from));
    return joined(parts, ", ");
}

void writeNext(pqxx::work& txn, const Row& row, const Wraps& w) {
    int n = static_cast<int>(row.ids.size()) + 1;
    const auto sets = setWraps(*row.table, "_next", n);
    pqxx::params p;
    appendKeys(p, row);
    appendWraps(p, w);
    txn.exec(fmt::format("UPDATE {} SET {} WHERE {}", row.table->name, sets, whereKeys(*row.table, 1)), p);
}

// Stages `w` only when the row still holds the wraps it was read with (a concurrent write wins; the row is restaged).
unsigned int writeNextIfUnchanged(pqxx::work& txn, const Row& row, const Wraps& w) {
    int n = static_cast<int>(row.ids.size()) + 1;
    const auto sets = setWraps(*row.table, "_next", n);
    pqxx::params p;
    appendKeys(p, row);
    appendWraps(p, w);
    std::vector<std::string> same;
    for (std::size_t i = 0; i < row.table->fields.size(); ++i) {
        const auto& f = row.table->fields[i];
        same.push_back(fmt::format("{} IS NOT DISTINCT FROM ${}::bytea", f.ct, n++));
        same.push_back(fmt::format("{} IS NOT DISTINCT FROM ${}::bytea", f.iv, n++));
        p.append(hexOr(row.cur.f[i], false));
        p.append(hexOr(row.cur.f[i], true));
    }
    same.push_back(fmt::format("master_version = ${}", n++));
    p.append(row.cur.master);
    return static_cast<unsigned int>(
        txn.exec(fmt::format("UPDATE {} SET {} WHERE {} AND {}", row.table->name, sets, whereKeys(*row.table, 1),
                             joined(same, " AND ")),
                 p)
            .affected_rows());
}

void dropNext(pqxx::work& txn, const Row& row) {
    pqxx::params p;
    appendKeys(p, row);
    txn.exec(fmt::format("UPDATE {} SET {} WHERE {}", row.table->name, clearWraps(*row.table, "_next"),
                         whereKeys(*row.table, 1)),
             p);
}

std::string listed(const std::vector<std::string>& names) {
    std::string out;
    for (std::size_t i = 0; i < names.size() && i < kListed; ++i) out += (i ? "; " : "") + names[i];
    if (names.size() > kListed) out += fmt::format("; and {} more", names.size() - kListed);
    return out;
}

unsigned int countMasterOtherThan(pqxx::work& txn, const Spec& spec, const unsigned int version) {
    unsigned int n = 0;
    for (const auto& t : spec.tables)
        n += txn.exec(fmt::format("SELECT COUNT(*) FROM {} WHERE master_version <> $1", t.name), pqxx::params{version})
                 .one_field_ref()
                 .as<unsigned int>();
    return n;
}

void beginRewrapTxn(pqxx::work& txn, const Spec& spec) {
    txn.exec("SELECT set_config('vh.master_rewrap', $1, true)", pqxx::params{slotId(spec.slot)});
    std::vector<std::string> names;
    for (const auto& t : spec.tables) names.emplace_back(t.name);
    txn.exec(fmt::format("LOCK TABLE {} IN EXCLUSIVE MODE", joined(names, ", ")));
}

// ---- state ----------------------------------------------------------------------------------------------------------

State readState(pqxx::work& txn, const Slot slot, const bool forUpdate) {
    const auto r = txn.exec(std::string("SELECT version, highest_version, staging_version, "
                                        "EXTRACT(EPOCH FROM staging_started_at)::bigint, previous_version, "
                                        "EXTRACT(EPOCH FROM switched_at)::bigint, "
                                        "EXTRACT(EPOCH FROM window_until)::bigint, "
                                        "array_to_string(discard_versions, ',') FROM master_secret_state "
                                        "WHERE slot = $1") +
                                (forUpdate ? " FOR UPDATE" : ""),
                            pqxx::params{slotId(slot)})
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

State readState(const Slot slot) {
    return db::Transactions::exec("rewrap::state", [&](pqxx::work& txn) { return readState(txn, slot, false); });
}

bool slotSealed(const Slot slot, const unsigned int version) {
    return KeyProvider(vs::slotName(slot, version)).sealedExists();
}

// Deletes the sealed slots listed in discard_versions, never one a row or the state still names.
std::vector<unsigned int> discardPending(const Spec& spec) {
    const auto slot = spec.slot;
    std::vector<unsigned int> deleted;
    const auto st = readState(slot);
    for (const auto v : st.discard_versions) {
        const bool inUse = v == st.version || v == st.staging_version || v == st.previous_version ||
                           db::Transactions::exec("rewrap::discard.inUse", [&](pqxx::work& txn) {
                               for (const auto& t : spec.tables)
                                   if (!txn.exec(fmt::format("SELECT 1 FROM {} WHERE master_version = $1 OR "
                                                             "master_version_next = $1 OR master_version_prev = $1 "
                                                             "LIMIT 1",
                                                             t.name),
                                                 pqxx::params{v})
                                            .empty())
                                       return true;
                               return false;
                           });
        if (inUse) {
            log::Registry::crypto()->error("[MasterRewrap] Not deleting {} version {}: it is still in use",
                                           nounOf(slot), v);
        } else {
            vs::forget(slot, v);
            KeyProvider(vs::slotName(slot, v)).destroySealed();
            deleted.push_back(v);
            log::Registry::crypto()->info("[MasterRewrap] Deleted the sealed {} version {} ('{}')", nounOf(slot), v,
                                          vs::slotName(slot, v));
        }
        db::Transactions::exec("rewrap::discard.done", [&](pqxx::work& txn) {
            txn.exec("UPDATE master_secret_state SET discard_versions = array_remove(discard_versions, $2) "
                     "WHERE slot = $1",
                     pqxx::params{slotId(slot), v});
        });
    }
    return deleted;
}

// The staged master `target`: unsealed when it is sealed and usable, else (absent, or it no longer unseals) generated
// afresh. Replacing it is safe: nothing is switched to it while it is staging; its staged wraps are dropped first.
Provider sealTarget(const Spec& spec, const unsigned int target) {
    const auto slot = spec.slot;
    {
        const auto st = readState(slot);
        if (target == st.version || st.previous_version == target || st.staging_version != target)
            throw std::logic_error(fmt::format("refusing to replace {} version {}: it is not the version being staged",
                                               nounOf(slot), target));
    }
    vs::forget(slot, target);
    if (slotSealed(slot, target)) {
        try {
            return vs::provider(slot, target);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[MasterRewrap] The staged {} version {} no longer unseals ({}); staging "
                                          "restarts under a new one",
                                          nounOf(slot), target, e.what());
        }
    }
    db::Transactions::exec("rewrap::dropStaged", [&](pqxx::work& txn) {
        for (const auto& t : spec.tables)
            txn.exec(fmt::format("UPDATE {} SET {} WHERE master_version_next = $1", t.name, clearWraps(t, "_next")),
                     pqxx::params{target});
    });
    KeyProvider fresh(vs::slotName(slot, target));
    fresh.destroySealed();
    fresh.init();  // generates and seals a fresh secret (libsodium CSPRNG)
    vs::forget(slot, target);
    return vs::provider(slot, target);
}

// Rows from before migration 113 that never unsealed since carry no key check: record it now, so the verification and
// the finalize can compare against it.
void backfillKeyCheck(const Row& row, const Plain& plain) {
    if (!row.table->keyCheck || row.key_check || plain.f.empty() || !plain.f[0]) return;
    ::vh::vault::model::Key rec;
    rec.vaultId = row.ids[0];
    rec.version = row.ids[1];
    rec.encrypted_key = row.cur.f[0]->ct;
    rec.iv = row.cur.f[0]->iv;
    rec.master_version = row.cur.master;
    ::vh::vault::attestation::backfill(rec, plain.f[0]->bytes());
}

}

void setCrashHookForTesting(CrashHook hook) {
    std::scoped_lock lock(hookMutex);
    crashHook = std::move(hook);
}

State state(const Slot slot) { return readState(slot); }

Status status(const Slot slot) {
    const auto& spec = specOf(slot);
    Status out{.slot = slot};
    out.state = state(slot);
    for (const auto& row : loadAll(spec)) {
        ++out.rows;
        ++out.by_master[row.cur.master];
        if (out.state.staging_version && stagedFor(row, *out.state.staging_version)) ++out.staged;
        if (out.state.previous_version && retainedFor(row, *out.state.previous_version)) ++out.retained;
    }
    out.current_sealed = slotSealed(slot, out.state.version);
    if (out.state.staging_version) out.staging_sealed = slotSealed(slot, *out.state.staging_version);
    if (out.state.previous_version) out.previous_sealed = slotSealed(slot, *out.state.previous_version);
    return out;
}

RotateResult rotate(const Slot slot, const Options& options) {
    if (options.batch == 0) throw ops::Invalid("the rewrap batch size must be at least 1");
    if (options.window < std::chrono::seconds(0)) throw ops::Invalid("the recovery window can't be negative");
    const auto& spec = specOf(slot);
    const auto noun = nounOf(slot);
    std::scoped_lock op(opMutex(slot));
    auto st = state(slot);
    if (st.previous_version)
        throw Refused("window_open",
                      fmt::format("the recovery window of the last {} rotation (version {} to {}) is still open: "
                                  "finalize it ({}) or roll it back first",
                                  noun, *st.previous_version, st.version, command(slot, "finalize")));

    RotateResult result{.from = st.version};
    const auto current = vs::provider(slot, st.version);  // MasterSecretLost propagates: nothing rewraps without it

    // Preflight, before anything is sealed: every row unwraps under the current master and is its recorded secret.
    {
        std::vector<std::string> unreadable;
        for (const auto& row : loadAll(spec)) {
            if (row.cur.master != st.version) {
                unreadable.push_back(row.name() + fmt::format(" (wrapped under version {})", row.cur.master));
                continue;
            }
            const auto raw = unwrapWith(spec, current, row.cur);
            if (!raw || !matchesRecord(row, *raw)) unreadable.push_back(row.name());
        }
        if (!unreadable.empty())
            throw Refused("unreadable_rows",
                          fmt::format("{} {} don't unwrap under the current {} (version {}){}, so they can't be "
                                      "rewrapped: {}. {} Nothing was changed.",
                                      unreadable.size(), spec.rows, noun, st.version,
                                      spec.slot == Slot::VaultMaster ? " or don't match their key check" : "",
                                      listed(unreadable), spec.restore));
    }

    unsigned int target = 0;
    if (st.staging_version) {
        target = *st.staging_version;
        result.resumed = true;
    } else {
        target = db::Transactions::exec("rewrap::beginStaging", [&](pqxx::work& txn) {
            return txn.exec("UPDATE master_secret_state SET staging_version = highest_version + 1, "
                            "highest_version = highest_version + 1, staging_started_at = NOW() "
                            "WHERE slot = $1 AND staging_version IS NULL AND previous_version IS NULL "
                            "RETURNING staging_version",
                            pqxx::params{slotId(slot)})
                .one_field_ref()
                .as<unsigned int>();
        });
        crashPoint("staging_recorded");
    }
    result.to = target;
    const auto next = sealTarget(spec, target);
    crashPoint("sealed");

    // Stage, in batches. A row whose bytes change meanwhile loses its staged wrap (trigger) and is picked up again.
    for (const auto& table : spec.tables) {
        std::vector<std::string> shape;  // a staged wrap missing a field the row has (or the other way round)
        for (const auto& f : table.fields)
            shape.push_back(fmt::format("({0} IS NULL) <> ({0}_next IS NULL) OR ({1} IS NULL) <> ({1}_next IS NULL)", f.ct, f.iv));
        const auto pending = fmt::format("master_version_next IS DISTINCT FROM $1 OR {}", joined(shape, " OR "));
        for (unsigned int stalled = 0;;) {
            const auto rows = db::Transactions::exec("rewrap::stage.select", [&](pqxx::work& txn) {
                return rowsOf(txn.exec(fmt::format("SELECT {} FROM {} WHERE {} ORDER BY {} LIMIT $2", columns(table),
                                                   table.name, pending, keyList(table)),
                                       pqxx::params{target, options.batch}),
                              table);
            });
            if (rows.empty()) break;
            std::vector<std::pair<const Row*, Wraps>> staged;
            for (const auto& row : rows) {
                const auto raw = row.cur.master == st.version ? unwrapWith(spec, current, row.cur) : std::nullopt;
                if (!raw || !matchesRecord(row, *raw))
                    throw Refused("unreadable_rows",
                                  fmt::format("{} no longer unwraps under the current {} (it changed during staging); "
                                              "nothing switched, run the rotation again",
                                              row.name(), noun));
                backfillKeyCheck(row, *raw);
                auto w = wrapUnder(next, *raw, target);
                if (!roundTrips(spec, next, w, *raw))
                    throw std::runtime_error(fmt::format("a new wrap under {} version {} did not unwrap to the same "
                                                         "secret",
                                                         noun, target));
                staged.emplace_back(&row, std::move(w));
            }
            const auto written = db::Transactions::exec("rewrap::stage.batch", [&](pqxx::work& txn) {
                unsigned int n = 0;
                for (const auto& [row, w] : staged) n += writeNextIfUnchanged(txn, *row, w);
                return n;
            });
            ++result.batches;
            result.staged_now += written;
            crashPoint("batch");
            if (written == 0 && ++stalled >= 3)
                throw std::runtime_error(fmt::format("staging {} makes no progress: its rows keep changing",
                                                     table.name));
            if (written) stalled = 0;
        }
    }

    // Verify, before taking any lock: every staged wrap is the row's secret under the new master.
    {
        std::vector<std::string> bad;
        std::vector<const Row*> drop;
        const auto rows = loadAll(spec);
        for (const auto& row : rows) {
            if (!stagedFor(row, target)) continue;  // changed since staging: the switch stages it
            const auto oldRaw = unwrapWith(spec, current, row.cur);
            const auto newRaw = unwrapWith(spec, next, *row.next);
            if (!oldRaw || !newRaw || !samePlain(*oldRaw, *newRaw) || !matchesRecord(row, *newRaw)) {
                bad.push_back(row.name());
                drop.push_back(&row);
            }
        }
        if (!bad.empty()) {
            db::Transactions::exec("rewrap::verify.drop", [&](pqxx::work& txn) {
                for (const auto* row : drop) dropNext(txn, *row);
            });
            throw Refused("mismatch",
                          fmt::format("{} staged wrap(s) under {} version {} are not the row's secret: {}. Nothing was "
                                      "switched; the bad wraps were dropped and the next rotation stages them again.",
                                      bad.size(), noun, target, listed(bad)));
        }
    }
    crashPoint("verified");

    // Switch: one transaction with the slot's tables locked against writes, every in-process Writer waiting.
    {
        std::unique_lock gate(vs::gate(slot));
        const auto window = static_cast<double>(options.window.count());
        db::Transactions::exec("rewrap::switch", [&](pqxx::work& txn) {
            beginRewrapTxn(txn, spec);
            const auto s = readState(txn, slot, true);
            if (s.version != result.from || s.staging_version != target || s.previous_version)
                throw std::runtime_error(fmt::format("the {} state changed during the rotation", noun));
            std::vector<std::string> bad;
            unsigned int caughtUp = 0, rows = 0;
            for (const auto& row : loadAll(txn, spec)) {
                ++rows;
                const auto raw = row.cur.master == result.from ? unwrapWith(spec, current, row.cur) : std::nullopt;
                if (!raw || !matchesRecord(row, *raw)) {
                    bad.push_back(row.name());
                    continue;
                }
                Wraps w;
                if (stagedFor(row, target)) {
                    w = *row.next;
                } else {
                    // Written or changed after staging: staged here, under the lock.
                    w = wrapUnder(next, *raw, target);
                    writeNext(txn, row, w);
                    ++caughtUp;
                }
                const auto back = unwrapWith(spec, next, w);
                if (!back || !samePlain(*back, *raw)) bad.push_back(row.name());
            }
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} {} failed verification at the switch: {}. Nothing was switched.",
                                          bad.size(), spec.rows, listed(bad)));
            for (const auto& t : spec.tables)
                txn.exec(fmt::format("UPDATE {} SET {}, {}, {} WHERE master_version_next = $1", t.name,
                                     moveWraps(t, "_prev", ""), moveWraps(t, "", "_next"), clearWraps(t, "_next")),
                         pqxx::params{target});
            if (const auto left = countMasterOtherThan(txn, spec, target); left != 0)
                throw std::runtime_error(fmt::format("{} {} were not switched", left, spec.rows));
            result.window_until =
                txn.exec("UPDATE master_secret_state SET version = $2, previous_version = $3, switched_at = NOW(), "
                         "window_until = NOW() + make_interval(secs => $4), staging_version = NULL, "
                         "staging_started_at = NULL WHERE slot = $1 RETURNING EXTRACT(EPOCH FROM window_until)::bigint",
                         pqxx::params{slotId(slot), target, result.from, window})
                    .one_field_ref()
                    .as<std::time_t>();
            result.rows = rows;
            result.caught_up = caughtUp;
        });
    }
    log::Registry::crypto()->info("[MasterRewrap] Switched {} {} from {} version {} to {}; the previous master stays "
                                  "until {}",
                                  result.rows, spec.rows, noun, result.from, result.to, result.window_until);
    crashPoint("switched");
    return result;
}

RollbackResult rollback(const Slot slot) {
    const auto& spec = specOf(slot);
    const auto noun = nounOf(slot);
    std::scoped_lock op(opMutex(slot));
    const auto st = state(slot);

    if (st.staging_version && !st.previous_version) {
        const auto target = *st.staging_version;
        db::Transactions::exec("rewrap::abandon", [&](pqxx::work& txn) {
            for (const auto& t : spec.tables)
                txn.exec(fmt::format("UPDATE {} SET {} WHERE master_version_next IS NOT NULL", t.name,
                                     clearWraps(t, "_next")));
            txn.exec("UPDATE master_secret_state SET staging_version = NULL, staging_started_at = NULL, "
                     "discard_versions = array_append(array_remove(discard_versions, $2), $2) WHERE slot = $1",
                     pqxx::params{slotId(slot), target});
        });
        crashPoint("rollback_committed");
        vs::forget(slot, target);
        (void)discardPending(spec);
        return {.kind = RollbackResult::Kind::AbandonedStaging, .from = target, .to = st.version};
    }
    if (!st.previous_version)
        throw Refused("no_window", fmt::format("there is no {} rotation to roll back: nothing is staged and no "
                                               "recovery window is open",
                                               noun));

    const auto prev = *st.previous_version, cur = st.version;
    Provider previous, current;
    try {
        previous = vs::provider(slot, prev);
    } catch (const std::exception& e) {
        throw Refused("previous_unavailable",
                      fmt::format("the previous {} (version {}) no longer unseals here ({}), so there is nothing to "
                                  "roll back to. The current master (version {}) stays.",
                                  noun, prev, e.what(), cur));
    }
    try {
        current = vs::provider(slot, cur);
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[MasterRewrap] The current {} (version {}) doesn't unseal ({}); rolling back "
                                      "from the retained wraps",
                                      noun, cur, e.what());
    }

    RollbackResult result{.kind = RollbackResult::Kind::Reverted, .from = cur, .to = prev};
    {
        std::unique_lock gate(vs::gate(slot));
        db::Transactions::exec("rewrap::rollback", [&](pqxx::work& txn) {
            beginRewrapTxn(txn, spec);
            const auto s = readState(txn, slot, true);
            if (s.version != cur || s.previous_version != prev)
                throw std::runtime_error(fmt::format("the {} state changed during the rollback", noun));
            std::vector<std::string> bad, needCurrent;
            unsigned int restored = 0, rewrapped = 0;
            for (const auto& row : loadAll(txn, spec)) {
                const auto& t = *row.table;
                if (retainedFor(row, prev)) {
                    const auto raw = unwrapWith(spec, previous, *row.prev);
                    bool ok = raw && matchesRecord(row, *raw);
                    if (ok && current && row.cur.master == cur) {
                        const auto now = unwrapWith(spec, current, row.cur);
                        ok = now && samePlain(*now, *raw);
                    }
                    if (!ok) {
                        bad.push_back(row.name());
                        continue;
                    }
                    pqxx::params p;
                    appendKeys(p, row);
                    txn.exec(fmt::format("UPDATE {} SET {}, {}, {} WHERE {}", t.name, moveWraps(t, "", "_prev"),
                                         clearWraps(t, "_prev"), clearWraps(t, "_next"), whereKeys(t, 1)),
                             p);
                    ++restored;
                    continue;
                }
                // Created or changed during the window: only the current master unwraps it.
                if (!current || row.cur.master != cur) {
                    needCurrent.push_back(row.name());
                    continue;
                }
                const auto raw = unwrapWith(spec, current, row.cur);
                if (!raw || !matchesRecord(row, *raw)) {
                    bad.push_back(row.name());
                    continue;
                }
                const auto w = wrapUnder(previous, *raw, prev);
                if (!roundTrips(spec, previous, w, *raw)) {
                    bad.push_back(row.name());
                    continue;
                }
                int n = static_cast<int>(row.ids.size()) + 1;
                const auto sets = setWraps(t, "", n);
                pqxx::params p;
                appendKeys(p, row);
                appendWraps(p, w);
                txn.exec(fmt::format("UPDATE {} SET {}, {}, {} WHERE {}", t.name, sets, clearWraps(t, "_prev"),
                                     clearWraps(t, "_next"), whereKeys(t, 1)),
                         p);
                ++rewrapped;
            }
            if (!needCurrent.empty())
                throw Refused("current_unavailable",
                              fmt::format("{} {} were created or changed after the switch and only the current {} "
                                          "(version {}), which doesn't unseal here, holds them: {}. {} Then roll back "
                                          "again. Nothing was changed.",
                                          needCurrent.size(), spec.rows, noun, cur, listed(needCurrent),
                                          spec.restore));
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} {} failed verification under the previous {} (version {}): {}. Nothing "
                                          "was changed.",
                                          bad.size(), spec.rows, noun, prev, listed(bad)));
            if (const auto left = countMasterOtherThan(txn, spec, prev); left != 0)
                throw std::runtime_error(fmt::format("{} {} were not rolled back", left, spec.rows));
            txn.exec("UPDATE master_secret_state SET version = $2, previous_version = NULL, switched_at = NULL, "
                     "window_until = NULL, discard_versions = array_append(array_remove(discard_versions, $3), $3) "
                     "WHERE slot = $1",
                     pqxx::params{slotId(slot), prev, cur});
            result.rows = restored;
            result.rewrapped = rewrapped;
        });
    }
    log::Registry::crypto()->warn("[MasterRewrap] Rolled back the {} from version {} to {}: {} row(s) restored, {} "
                                  "rewrapped",
                                  noun, cur, prev, result.rows, result.rewrapped);
    crashPoint("rollback_committed");
    vs::forget(slot, cur);
    (void)discardPending(spec);
    return result;
}

FinalizeResult finalize(const Slot slot) {
    const auto& spec = specOf(slot);
    const auto noun = nounOf(slot);
    std::scoped_lock op(opMutex(slot));
    const auto st = state(slot);
    FinalizeResult result;
    if (!st.previous_version) {
        result.deleted = discardPending(spec);  // an interrupted finalize or rollback
        return result;
    }
    const auto prev = *st.previous_version, cur = st.version;
    Provider current, previous;
    try {
        current = vs::provider(slot, cur);
    } catch (const std::exception& e) {
        throw Refused("verification_failed",
                      fmt::format("the current {} (version {}) doesn't unseal here ({}): the previous one is kept. "
                                  "Roll back ({}) to return to it.",
                                  noun, cur, e.what(), command(slot, "rollback")));
    }
    try {
        previous = vs::provider(slot, prev);
    } catch (const std::exception&) {}  // only needed for rows without a recorded key check

    {
        std::unique_lock gate(vs::gate(slot));
        db::Transactions::exec("rewrap::finalize", [&](pqxx::work& txn) {
            beginRewrapTxn(txn, spec);
            const auto s = readState(txn, slot, true);
            if (s.version != cur || s.previous_version != prev)
                throw std::runtime_error(fmt::format("the {} state changed during the finalize", noun));
            std::vector<std::string> bad;
            unsigned int rows = 0;
            for (const auto& row : loadAll(txn, spec)) {
                ++rows;
                const auto raw = row.cur.master == cur ? unwrapWith(spec, current, row.cur) : std::nullopt;
                bool ok = raw.has_value();
                if (ok && row.key_check) {
                    ok = matchesRecord(row, *raw);
                } else if (ok && retainedFor(row, prev)) {
                    // No key check recorded: the retained wrap is the reference, so the previous master is needed.
                    const auto old = unwrapWith(spec, previous, *row.prev);
                    ok = old && samePlain(*old, *raw);
                }
                if (!ok) bad.push_back(row.name());
            }
            if (!bad.empty())
                throw Refused("verification_failed",
                              fmt::format("{} {} don't verify under the current {} (version {}): {}. The recovery "
                                          "window stays open and nothing was deleted; roll back ({}), or: {}",
                                          bad.size(), spec.rows, noun, cur, listed(bad), command(slot, "rollback"),
                                          spec.restore));
            for (const auto& t : spec.tables)
                txn.exec(fmt::format("UPDATE {} SET {} WHERE master_version_prev IS NOT NULL OR {} IS NOT NULL", t.name,
                                     clearWraps(t, "_prev"), std::string(t.fields.front().ct) + "_prev"));
            txn.exec("UPDATE master_secret_state SET previous_version = NULL, window_until = NULL, "
                     "discard_versions = array_append(array_remove(discard_versions, $2), $2) WHERE slot = $1",
                     pqxx::params{slotId(slot), prev});
            result.rows = rows;
        });
    }
    result.finalized = true;
    result.previous = prev;
    log::Registry::crypto()->info("[MasterRewrap] Finalized the {} rotation to version {} ({} row(s) verified); "
                                  "deleting version {}",
                                  noun, cur, result.rows, prev);
    crashPoint("finalize_committed");
    vs::forget(slot, prev);
    result.deleted = discardPending(spec);
    return result;
}

FinalizeResult expireIfDue(const Slot slot, const std::chrono::system_clock::time_point now) {
    // A refused or failed attempt is retried every 10 minutes, not on every retention pass.
    static std::array<std::atomic<std::int64_t>, vs::kSlots.size()> retryAfter{};
    auto& retry = retryAfter.at(static_cast<std::size_t>(slot));
    const auto nowSecs = std::chrono::duration_cast<std::chrono::seconds>(now.time_since_epoch()).count();
    if (nowSecs < retry.load()) return {};
    const auto noun = nounOf(slot);
    try {
        const auto st = state(slot);
        if (!st.previous_version) {
            if (st.discard_versions.empty()) return {};
            FinalizeResult r;
            r.deleted = finalize(slot).deleted;
            return r;
        }
        if (!st.window_until || *st.window_until > nowSecs) return {};
        auto r = finalize(slot);
        if (r.finalized)
            vh::audit::record({.action = "secrets.master.finalize", .actor = "system",
                               .details = {{"slot", slotId(slot)}, {"from", *r.previous}, {"to", st.version},
                                           {"rows", r.rows}, {"automatic", true}}},
                              fmt::format("[MasterRewrap] The recovery window of the {} rotation to version {} "
                                          "expired: {} row(s) verified, version {} deleted",
                                          noun, st.version, r.rows, *r.previous));
        return r;
    } catch (const std::exception& e) {
        retry.store(nowSecs + 600);
        vh::audit::record({.action = "secrets.master.finalize", .outcome = vh::audit::Outcome::Failure,
                           .actor = "system", .details = {{"slot", slotId(slot)}, {"automatic", true}}},
                          fmt::format("[MasterRewrap] The {} recovery window could not be closed: {}", noun, e.what()),
                          spdlog::level::warn);
        return {};
    }
}

void expireAllIfDue(const std::chrono::system_clock::time_point now) {
    for (const auto slot : vs::kSlots) (void)expireIfDue(slot, now);
}

}
