#include "recovery/usage/Ledger.hpp"

#include "db/Transactions.hpp"
#include "db/query/recovery/Usage.hpp"
#include "log/Registry.hpp"
#include "recovery/cost/Alerts.hpp"
#include "sync/model/RemoteManifest.hpp"

#include <pqxx/pqxx>

#include <cstdio>
#include <ctime>
#include <map>
#include <mutex>
#include <optional>
#include <utility>

namespace vh::recovery::usage {

namespace {

using UsageCountersRow = db::query::recovery::UsageCounters;
using UsageDayRow = db::query::recovery::UsageDay;

thread_local RequestTag tlsRequestTag = RequestTag::None;

// Never more than this many pending (vault, day) deltas: a database that stays down for days must not grow memory
// without bound. Past it the oldest days go first (and are logged).
constexpr size_t kLedgerMaxPending = 20'000;

struct LedgerState {
    std::mutex mutex;
    std::map<std::pair<uint32_t, std::string>, UsageCountersRow> pending;
    std::function<std::time_t()> clock;
    std::function<void()> alertJob;
    std::optional<std::chrono::system_clock::time_point> lastFlush, lastAlerts;
    std::mutex flushMutex;   // one flush at a time (tick vs shutdown)
};

LedgerState& ledgerState() {
    static LedgerState s;
    return s;
}

std::time_t ledgerNow() {
    auto& s = ledgerState();
    std::function<std::time_t()> clock;
    {
        std::scoped_lock lock(s.mutex);
        clock = s.clock;
    }
    return clock ? clock() : std::time(nullptr);
}

void ledgerTrim(LedgerState& s) {
    while (s.pending.size() > kLedgerMaxPending) {
        // Oldest day first (the key orders by vault; find the minimum day).
        auto oldest = s.pending.begin();
        for (auto it = s.pending.begin(); it != s.pending.end(); ++it)
            if (it->first.second < oldest->first.second) oldest = it;
        log::Registry::storage()->warn("[recovery::usage] dropping unflushed usage of vault {} for {}", oldest->first.first,
                                       oldest->first.second);
        s.pending.erase(oldest);
    }
}

template <typename Fn>
void ledgerAdd(const uint32_t vaultId, Fn&& apply) noexcept {
    if (vaultId == 0) return;
    try {
        const auto day = utcDay(ledgerNow());
        auto& s = ledgerState();
        std::scoped_lock lock(s.mutex);
        apply(s.pending[{vaultId, day}]);
        ledgerTrim(s);
    } catch (...) {
        // Accounting is best effort; it never fails a request.
    }
}

void ledgerMergeBack(const std::vector<UsageDayRow>& deltas) {
    auto& s = ledgerState();
    std::scoped_lock lock(s.mutex);
    for (const auto& d : deltas) s.pending[{d.vault_id, d.day}] += d.counters;
    ledgerTrim(s);
}

// The object a write replaced: (size, etag) from the remote index, as the sync engine last knew it.
struct PreviousObject {
    uint64_t size = 0;
    std::optional<std::string> etag;
};

std::optional<PreviousObject> ledgerPreviousObject(const uint32_t vaultId, const std::string& key) {
    return db::Transactions::read("recovery::usage::previousObject",
                                  [&](pqxx::transaction_base& txn) -> std::optional<PreviousObject> {
        const auto res = txn.exec("SELECT size_bytes, etag FROM remote_object_index WHERE vault_id = $1 AND object_key = $2",
                                  pqxx::params{vaultId, key});
        if (res.empty()) return std::nullopt;
        const auto row = res.one_row_ref();
        PreviousObject p;
        const auto size = row["size_bytes"].as<int64_t>();
        p.size = size > 0 ? static_cast<uint64_t>(size) : 0;
        if (!row["etag"].is_null()) p.etag = row["etag"].as<std::string>();
        return p;
    });
}

std::string ledgerUnquote(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

}

// ---- tags ----------------------------------------------------------------------------------------------------------

ScopedRequestTag::ScopedRequestTag(const RequestTag tag) noexcept : previous_(tlsRequestTag) { tlsRequestTag = tag; }

ScopedRequestTag::~ScopedRequestTag() { tlsRequestTag = previous_; }

RequestTag currentRequestTag() noexcept { return tlsRequestTag; }

// ---- feeds ---------------------------------------------------------------------------------------------------------

std::string utcDay(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::snprintf(buf, sizeof buf, "%04d-%02d-%02d", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday);
    return buf;
}

void noteRequest(const uint32_t vaultId, const Request kind, const uint64_t count) noexcept {
    const auto tag = currentRequestTag();
    ledgerAdd(vaultId, [&](UsageCountersRow& c) {
        switch (kind) {
        case Request::List:
            c.list_requests += count;
            if (tag == RequestTag::VersionList) c.version_list_requests += count;
            break;
        case Request::Head: c.head_requests += count; break;
        case Request::Get:
            c.get_requests += count;
            if (tag == RequestTag::VersionRestore) c.version_restore_requests += count;
            break;
        case Request::Put:
            c.put_requests += count;
            if (tag == RequestTag::MultipartInitiate) c.multipart_uploads += count;
            if (tag == RequestTag::MultipartPart) c.multipart_parts += count;
            break;
        case Request::Copy:
            c.copy_requests += count;
            if (tag == RequestTag::VersionRestore) c.version_restore_requests += count;
            break;
        case Request::Delete: c.delete_requests += count; break;
        }
    });
}

void noteDownloadedBytes(const uint32_t vaultId, const uint64_t bytes) noexcept {
    if (bytes == 0) return;
    const auto tag = currentRequestTag();
    ledgerAdd(vaultId, [&](UsageCountersRow& c) {
        c.downloaded_bytes += bytes;
        if (tag == RequestTag::VersionRestore) c.version_restore_bytes += bytes;
    });
}

void noteUploadedBytes(const uint32_t vaultId, const uint64_t bytes) noexcept {
    if (bytes == 0) return;
    ledgerAdd(vaultId, [&](UsageCountersRow& c) { c.uploaded_bytes += bytes; });
}

void noteUpstreamWrite(const hooks::UpstreamWrite& write) noexcept {
    if (write.vault_id == 0 || write.key.empty()) return;
    try {
        // The index manifest is Vaulthalla's own bookkeeping, priced separately (manifest versions).
        if (sync::model::remote_manifest::isVaulthallaManifestKey(write.key)) return;
        const auto previous = ledgerPreviousObject(write.vault_id, write.key);
        if (write.is_delete) {
            // A delete on a versioned bucket always leaves a delete marker, whether or not the index knew the object.
            ledgerAdd(write.vault_id, [&](UsageCountersRow& c) {
                ++c.deleted_objects;
                if (previous) c.deleted_bytes += previous->size;
            });
            return;
        }
        if (!previous) {
            ledgerAdd(write.vault_id, [&](UsageCountersRow& c) {
                ++c.first_put_objects;
                c.first_put_bytes += write.object_size.value_or(0);
            });
            return;
        }
        // The index already shows this very write (it was recorded first): what it replaced is unknown here.
        if (write.etag && previous->etag && ledgerUnquote(*write.etag) == ledgerUnquote(*previous->etag)) return;
        ledgerAdd(write.vault_id, [&](UsageCountersRow& c) {
            ++c.overwrite_objects;
            c.overwritten_bytes += previous->size;
        });
    } catch (const std::exception& e) {
        log::Registry::storage()->debug("[recovery::usage] write of vault {} not classified: {}", write.vault_id, e.what());
    } catch (...) {
    }
}

// ---- flushing ------------------------------------------------------------------------------------------------------

FlushResult flush() noexcept {
    FlushResult out;
    auto& s = ledgerState();
    std::unique_lock flushLock(s.flushMutex);
    std::vector<UsageDayRow> deltas;
    try {
        {
            std::scoped_lock lock(s.mutex);
            deltas.reserve(s.pending.size());
            for (auto& [k, c] : s.pending)
                if (!c.empty()) deltas.push_back({.vault_id = k.first, .day = k.second, .counters = c});
            s.pending.clear();
        }
        if (deltas.empty()) return out;
        try {
            db::query::recovery::Usage::addMany(deltas);
            out.rows = deltas.size();
            return out;
        } catch (const pqxx::foreign_key_violation&) {
            // A vault went away since its requests were counted: write the others one by one, drop its rows.
            std::vector<UsageDayRow> keep;
            for (const auto& d : deltas) {
                try {
                    db::query::recovery::Usage::add(d.vault_id, d.day, d.counters);
                    ++out.rows;
                } catch (const pqxx::foreign_key_violation&) {
                    ++out.dropped;
                } catch (const std::exception&) {
                    keep.push_back(d);
                }
            }
            if (!keep.empty()) {
                out.ok = false;
                out.error = "some usage rows could not be written";
                ledgerMergeBack(keep);
            }
            return out;
        }
    } catch (const std::exception& e) {
        out.ok = false;
        out.error = e.what();
        out.rows = 0;
        try {
            ledgerMergeBack(deltas);
        } catch (...) {
        }
        log::Registry::storage()->warn("[recovery::usage] usage flush failed (kept for the next one): {}", e.what());
    } catch (...) {
        out.ok = false;
        out.error = "unknown error";
    }
    return out;
}

void tick(const std::chrono::system_clock::time_point now) noexcept {
    auto& s = ledgerState();
    bool doFlush = false, doAlerts = false;
    std::function<void()> job;
    {
        std::scoped_lock lock(s.mutex);
        if (!s.lastFlush || now - *s.lastFlush >= kFlushInterval || now < *s.lastFlush) {
            s.lastFlush = now;
            doFlush = true;
        }
        if (!s.lastAlerts || now - *s.lastAlerts >= kAlertInterval || now < *s.lastAlerts) {
            s.lastAlerts = now;
            doAlerts = true;
        }
        job = s.alertJob;
    }
    if (doFlush) (void)flush();
    if (!doAlerts) return;
    try {
        if (job) job();
        else cost::evaluateAlerts(std::chrono::system_clock::to_time_t(now));
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[recovery::usage] cost alert evaluation failed: {}", e.what());
    } catch (...) {
    }
}

// ---- tests ---------------------------------------------------------------------------------------------------------

std::vector<UsageDayRow> pendingForTesting() {
    auto& s = ledgerState();
    std::scoped_lock lock(s.mutex);
    std::vector<UsageDayRow> out;
    for (const auto& [k, c] : s.pending) out.push_back({.vault_id = k.first, .day = k.second, .counters = c});
    return out;
}

void resetForTesting() {
    auto& s = ledgerState();
    std::scoped_lock lock(s.mutex);
    s.pending.clear();
    s.lastFlush.reset();
    s.lastAlerts.reset();
}

void setClockForTesting(std::function<std::time_t()> clock) {
    auto& s = ledgerState();
    std::scoped_lock lock(s.mutex);
    s.clock = std::move(clock);
}

void setAlertJobForTesting(std::function<void()> job) {
    auto& s = ledgerState();
    std::scoped_lock lock(s.mutex);
    s.alertJob = std::move(job);
}

}
