#include "audit/Trail.hpp"

#include "config/Registry.hpp"
#include "db/query/audit/Trail.hpp"
#include "db/query/device/Device.hpp"
#include "log/AuditOrigin.hpp"
#include "log/Registry.hpp"
#include "vault/KeyAttestation.hpp"

#include <spdlog/sinks/base_sink.h>

#include <cctype>

namespace vh::audit {

namespace {

// The structured event record() is writing on this thread (the audit logger is synchronous, so its sinks run on the
// thread that logged), and whether the line being written must stay out of the chain (signed heads).
thread_local const Event* tl_event = nullptr;
thread_local bool tl_skipChain = false;

uint64_t nowUs() {
    return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
}

class ChainSink final : public spdlog::sinks::base_sink<std::mutex> {
protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (tl_skipChain) return;
        Record r;
        r.occurred_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(msg.time.time_since_epoch()).count());
        const auto level = spdlog::level::to_string_view(msg.level);
        r.level.assign(level.data(), level.size());
        r.message.assign(msg.payload.data(), msg.payload.size());
        if (const auto* origin = log::AuditOrigin::current()) r.origin = *origin;
        if (const auto* e = tl_event) {
            r.action = e->action;
            r.outcome = to_string(e->outcome);
            r.actor_id = e->actor_id;
            r.actor = e->actor;
            r.vault_id = e->vault_id;
            r.entry_id = e->entry_id;
            r.details = e->details.is_object() ? e->details.dump() : std::string("{}");
        } else {
            r.action = actionFromMessage(r.message);
            r.outcome = to_string(Outcome::Info);
        }
        Trail::instance()->submit(std::move(r));
    }

    void flush_() override {}
};

struct EventScope {
    explicit EventScope(const Event& e) : previous(tl_event) { tl_event = &e; }
    ~EventScope() { tl_event = previous; }
    const Event* previous;
};

}

std::string to_string(const Outcome outcome) {
    switch (outcome) {
        case Outcome::Success: return "success";
        case Outcome::Failure: return "failure";
        case Outcome::Denied: return "denied";
        case Outcome::Info: return "info";
    }
    return "info";
}

OnSuccess::OnSuccess(Event event, std::string message)
    : event_(std::move(event)), message_(std::move(message)), exceptions_(std::uncaught_exceptions()) {}

OnSuccess::~OnSuccess() {
    if (std::uncaught_exceptions() != exceptions_) return;
    try {
        record(event_, message_);
    } catch (...) {
        // Never throw from a destructor; the operation itself already succeeded.
    }
}

spdlog::sink_ptr makeChainSink() { return std::make_shared<ChainSink>(); }

void record(const Event& event, const std::string& message, const spdlog::level::level_enum level) {
    EventScope scope(event);
    log::Registry::audit()->log(level, "{}", message);
}

std::string actionFromMessage(const std::string_view message) {
    std::string_view tag;
    if (message.starts_with('[')) {
        if (const auto end = message.find(']'); end != std::string_view::npos && end > 1) tag = message.substr(1, end - 1);
    } else if (const auto colon = message.find(':'); colon != std::string_view::npos && colon > 0 && colon <= 40) {
        tag = message.substr(0, colon);  // "vh fs get: ...", "PUT /upload/content: ..."
    }
    std::string out;
    for (std::size_t i = 0; i < tag.size(); ++i) {
        const auto c = static_cast<unsigned char>(tag[i]);
        if (std::isalnum(c)) out.push_back(static_cast<char>(std::tolower(c)));
        else if (!out.empty() && out.back() != '.') out.push_back('.');
    }
    while (!out.empty() && out.back() == '.') out.pop_back();
    return out.empty() ? std::string("log") : out;
}

std::shared_ptr<Trail> Trail::instance() {
    static const auto trail = std::make_shared<Trail>();
    return trail;
}

Trail::Trail() : AsyncService("AuditTrail") {}

Trail::~Trail() { stop(); }

void Trail::submit(Record record) noexcept {
    try {
        {
            std::scoped_lock lock(mutex_);
            if (queue_.size() >= kQueueCapacity) {
                queue_.pop_front();
                ++dropped_;
            }
            queue_.push_back(std::move(record));
        }
        cv_.notify_one();
    } catch (...) {
        // Out of memory: the line is still in audit.log; nothing better to do here.
    }
}

bool Trail::loadTail() {
    try {
        const auto tail = db::query::audit::Trail::tail();
        seq_ = tail ? tail->seq : 0;
        hash_ = tail ? tail->hash : Hash{};
        const auto head = db::query::audit::Trail::lastHead();
        signedSeq_ = head ? head->seq : 0;
        return true;
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[AuditTrail] Cannot read the audit chain yet: {}", e.what());
        seq_.reset();
        return false;
    }
}

bool Trail::flushNow() {
    std::unique_lock writer(writeMutex_);
    if (!seq_ && !loadTail()) return false;
    for (;;) {
        std::unique_lock lock(mutex_);
        if (queue_.empty() && dropped_ == 0) return true;
        if (!writeBatch(lock)) return false;
    }
}

bool Trail::writeBatch(std::unique_lock<std::mutex>& lock) {
    // Take a batch; an overflow since the last write becomes an audit.gap event at its front.
    std::vector<Record> batch;
    const auto dropped = dropped_;
    if (dropped > 0) {
        Record gap;
        gap.occurred_us = nowUs();
        gap.level = "warning";
        gap.action = "audit.gap";
        gap.outcome = to_string(Outcome::Failure);
        gap.message = "[audit] " + std::to_string(dropped) +
                      " audit event(s) were dropped while the database could not take them; audit.log has them";
        gap.details = nlohmann::json{{"dropped", dropped}}.dump();
        batch.push_back(std::move(gap));
    }
    while (!queue_.empty() && batch.size() < kBatch) {
        batch.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    dropped_ = 0;
    lock.unlock();

    auto seq = *seq_;
    auto prev = hash_;
    for (auto& r : batch) {
        r.seq = ++seq;
        r.prev_hash = prev;
        r.hash = computeHash(r);
        prev = r.hash;
    }

    bool ok = false;
    try {
        db::query::audit::Trail::append(batch);
        ok = true;
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[AuditTrail] Could not append {} audit event(s): {}", batch.size(), e.what());
        // A commit whose acknowledgement was lost must not be written twice: re-read the tail and compare.
        if (loadTail() && *seq_ == seq && hash_ == prev) ok = true;
    }
    if (ok) {
        seq_ = seq;
        hash_ = prev;
        return true;
    }

    // Put the batch back, oldest first (without the gap event: its count goes back into dropped_).
    lock.lock();
    std::size_t start = 0;
    if (dropped > 0) {
        dropped_ += dropped;
        start = 1;
    }
    for (auto i = batch.size(); i > start; --i) {
        auto& r = batch[i - 1];
        r.seq = 0;
        if (queue_.size() >= kQueueCapacity) {
            ++dropped_;
            continue;
        }
        queue_.push_front(std::move(r));
    }
    seq_.reset();  // re-read the tail before the next attempt
    return false;
}

std::optional<SignedHead> Trail::signHead() {
    std::unique_lock writer(writeMutex_);
    if (!seq_ && !loadTail()) return std::nullopt;
    if (*seq_ == 0 || *seq_ == signedSeq_) return std::nullopt;
    try {
        SignedHead head{.seq = *seq_, .hash = hash_, .signed_us = nowUs(),
                        .node_id = db::query::device::Devices::nodeId()};
        const auto signature = vault::attestation::signNodeMessage(headMessage(head.node_id, head.seq, head.hash,
                                                                               head.signed_us));
        if (!signature) return std::nullopt;
        head.key_id = signature->key_id;
        head.signature = signature->signature;
        db::query::audit::Trail::appendHead(head);
        signedSeq_ = head.seq;

        // A copy outside this database: audit.log and, when enabled, syslog (not part of the chain itself).
        tl_skipChain = true;
        log::Registry::audit()->info("[audit.head] seq={} hash={} signed_us={} node={} key={} signature={}", head.seq,
                                     toHex(head.hash), head.signed_us, head.node_id, head.key_id,
                                     toHex(head.signature));
        tl_skipChain = false;
        return head;
    } catch (const std::exception& e) {
        tl_skipChain = false;
        log::Registry::runtime()->warn("[AuditTrail] Could not sign the audit chain head: {}", e.what());
        return std::nullopt;
    }
}

uint64_t Trail::purge() {
    const auto days = config::Registry::get().auditing.trail.retention_days;
    const auto cutoff = nowUs() - static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(days).count());
    try {
        const auto removed = db::query::audit::Trail::purgeBefore(cutoff);
        if (removed > 0)
            record({.action = "audit.purge", .outcome = Outcome::Info,
                    .details = {{"removed", removed}, {"retention_days", days.count()}}},
                   "[audit] retention removed " + std::to_string(removed) + " audit event(s) older than " +
                   std::to_string(days.count()) + " days");
        return removed;
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[AuditTrail] Audit retention failed: {}", e.what());
        return 0;
    }
}

void Trail::runLoop() {
    using Clock = std::chrono::steady_clock;
    const auto headInterval = std::chrono::minutes(config::Registry::get().auditing.trail.head_interval_minutes);
    auto nextHead = Clock::now() + headInterval;
    auto nextPurge = Clock::now() + std::chrono::minutes(5);
    auto backoff = std::chrono::seconds(1);

    while (!shouldStop()) {
        {
            std::unique_lock lock(mutex_);
            cv_.wait_for(lock, std::chrono::seconds(1), [&] { return !queue_.empty() || dropped_ > 0 || shouldStop(); });
        }
        if (!flushNow()) {
            lazySleep(backoff);
            backoff = std::min(backoff * 2, std::chrono::seconds(30));
            continue;
        }
        backoff = std::chrono::seconds(1);
        const auto now = Clock::now();
        if (now >= nextHead) {
            (void)signHead();
            nextHead = now + headInterval;
        }
        if (now >= nextPurge) {
            (void)purge();
            nextPurge = now + std::chrono::hours(24);
        }
    }
    // Shutdown: write what is queued and sign where the chain ends.
    if (flushNow()) (void)signHead();
}

void Trail::onStop() { cv_.notify_all(); }

void Trail::resetForTesting() {
    std::scoped_lock writer(writeMutex_);
    std::scoped_lock lock(mutex_);
    queue_.clear();
    dropped_ = 0;
    seq_.reset();
    hash_ = {};
    signedSeq_ = 0;
}

std::size_t Trail::queuedForTesting() {
    std::scoped_lock lock(mutex_);
    return queue_.size();
}

}
