#include "sync/manifest/Session.hpp"

#include <format>
#include <stdexcept>
#include <utility>

namespace vh::sync::manifest {

namespace session_detail {

bool versionLog(const ObjectStore& store) { return store.mode() == WriteCapability::VersionLog; }

std::optional<SettledWindow> settledOf(const ChainState& state) {
    if (!state.root_version_id || !state.base_version_id) return std::nullopt;
    return SettledWindow{*state.base_version_id, *state.root_version_id, state.settle_window};
}

bool refusal(const ChainError code) {
    return code == ChainError::Rollback || code == ChainError::Fork || code == ChainError::OrderViolation ||
           code == ChainError::Superseded || code == ChainError::PublishModeMismatch;
}

std::vector<std::string> sidsOf(const RootDocument& root) {
    std::vector<std::string> sids;
    for (const auto& s : root.segments) sids.push_back(s.sid);
    for (const auto& s : root.snapshots) sids.push_back(s.sid);
    return sids;
}

}

Session::Session(const Uid& vaultUid, std::shared_ptr<ObjectStore> store, std::shared_ptr<StateStore> state,
                 SessionHost host)
    : vaultUid_(vaultUid), store_(std::move(store)), state_(std::move(state)), host_(std::move(host)) {
    if (!store_ || !state_) throw std::invalid_argument("manifest::Session needs a store and a state store");
    if (!host_.collect || !host_.currentKey || !host_.keys || !host_.nodeId || !host_.now)
        throw std::invalid_argument("manifest::Session needs the vault's content and keys, a node id and a clock");
}

void Session::note(const Notice level, const std::string& message) const {
    if (host_.note) host_.note(level, message);
}

std::optional<Known> Session::known() const {
    const auto state = state_->state();
    if (!state.epoch || !state.root_sha256) return std::nullopt;
    return Known{*state.epoch, *state.root_sha256, state.root_version_id};
}

void Session::refused(const ChainRejected& e, const uint64_t epoch, const std::string& rootSha256) {
    const auto reason = std::string(chainErrorName(e.code()));
    note(Notice::Error, std::format("refused the bucket's manifest root ({}); the database keeps its state and nothing "
                                    "is published over it",
                                    e.what()));
    if (state_->recordRefused(reason, epoch, rootSha256) && host_.alert)
        host_.alert(Refusal{e.code(), epoch, rootSha256, known()});
}

PublishReport Session::publish() {
    std::scoped_lock lock(mutex_);
    return publishLocked(host_.collect());
}

std::optional<PublishReport> Session::publishIfChanged() {
    std::scoped_lock lock(mutex_);
    auto produced = host_.collect();
    const auto knownState = known();
    if (cache_.base && cache_.last_produced && knownState && cache_.base->known == *knownState &&
        *cache_.last_produced == produced)
        return std::nullopt;
    return publishLocked(produced);
}

PublishReport Session::publishLocked(const Content& produced) {
    namespace d = session_detail;
    const auto current = host_.currentKey();
    const auto state = state_->state();
    const auto knownState = known();
    PublishOptions options;
    options.now = isoTime(host_.now());
    options.self_node = produced.producer.node_id;
    options.own_epoch = state.own_epoch;
    options.settled = d::settledOf(state);
    try {
        auto report = manifest::publish(*store_, vaultUid_, host_.keys, current, produced, knownState, cache_, options);
        state_->recordRoot({.epoch = report.published.known.epoch,
                            .root_sha256 = report.published.known.root_sha256,
                            .etag = report.published.etag,
                            .sids = report.published.sids(),
                            .version_id = report.settled.version_id,
                            .base_version_id = report.settled.base_version_id,
                            .settle_window = report.settled.window,
                            .own = true});
        if (report.lost)
            note(Notice::Info, std::format("another writer's root won {} round(s) of this publish; merged onto it "
                                           "(spec 06 §5.2)",
                                           report.lost));
        if (!report.repaired.empty())
            note(Notice::Info, std::format("deleted {} stray root version(s) above the head", report.repaired.size()));
        if (!report.ahead.empty())
            note(Notice::Warning, std::format("{} authentic root version(s) of a higher epoch sit above the root just "
                                              "published; left in place, the next read judges them",
                                              report.ahead.size()));
        if (report.gap)
            note(Notice::Warning, std::format("another writer published several roots since epoch {} (gap); merged and "
                                              "continued at epoch {}",
                                              knownState ? knownState->epoch : 0, report.published.known.epoch));
        if (report.root_rebuilt)
            note(Notice::Warning, std::format("the bucket's manifest root was missing or unreadable; rebuilt from the "
                                              "database at epoch {}",
                                              report.published.known.epoch));
        return report;
    } catch (const ChainRejected& e) {
        if (d::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    }
}

std::optional<Acceptance> Session::verifyRemoteVersionLog() {
    namespace d = session_detail;
    const auto state = state_->state();
    // A pass that changed nothing still costs one HEAD: the settled head is the current version until someone writes.
    if (state.etag && state.epoch && state.root_sha256)
        if (const auto etag = store_->headEtag(std::string(kRootKey)); etag && *etag == *state.etag)
            return Acceptance{*state.epoch, *state.root_sha256, false};
    const std::optional<Known> knownState = state.epoch && state.root_sha256
        ? std::make_optional(Known{*state.epoch, *state.root_sha256, state.root_version_id})
        : std::nullopt;
    LoadOptions options;
    options.known = knownState;
    options.root_cache = &cache_.roots;
    options.settled = d::settledOf(state);
    try {
        auto loaded = load(*store_, vaultUid_, host_.keys, options);
        const auto sids = d::sidsOf(loaded.root);
        if (!knownState || loaded.known() != *knownState) {
            checkHeadForWriter(loaded.root, loaded.acceptance.root_sha256, *store_, host_.nodeId(), state.own_epoch);
            state_->recordRoot({.epoch = loaded.acceptance.epoch,
                                .root_sha256 = loaded.acceptance.root_sha256,
                                .etag = loaded.etag,
                                .sids = sids,
                                .version_id = loaded.version_id,
                                .base_version_id = loaded.base_version_id,
                                .settle_window = loaded.settle_window,
                                .own = false});
            cache_.base.reset();
        } else if (loaded.version_id && loaded.version_id != state.root_version_id) {
            // The same root, found by its hash (a state from before version ids were recorded, or recorded by a
            // restore).
            state_->recordRoot({.epoch = loaded.acceptance.epoch,
                                .root_sha256 = loaded.acceptance.root_sha256,
                                .etag = loaded.etag,
                                .sids = sids,
                                .version_id = loaded.version_id,
                                .base_version_id = loaded.base_version_id,
                                .settle_window = loaded.settle_window,
                                .own = false});
        }
        // Repair (spec 06 §5.4): versions newer than the head that aren't on the chain.
        for (const auto& id : loaded.strays) {
            try {
                store_->removeVersion(std::string(kRootKey), id);
            } catch (const std::exception& e) {
                note(Notice::Warning, std::format("a stray root version was not deleted: {}", e.what()));
            }
        }
        if (!loaded.strays.empty())
            note(Notice::Info, std::format("deleted {} stray root version(s) above the head", loaded.strays.size()));
        return loaded.acceptance;
    } catch (const ChainRejected& e) {
        if (d::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    } catch (const NoUsableRoot&) {
        return std::nullopt;
    }
}

std::optional<Acceptance> Session::verifyRemote() {
    namespace d = session_detail;
    std::scoped_lock lock(mutex_);
    const auto state = state_->state();
    if (d::versionLog(*store_)) return verifyRemoteVersionLog();
    // A pass that changed nothing costs one HEAD of the root (spec 01 §5): its ETag still the one we recorded.
    if (state.etag && state.epoch && state.root_sha256)
        if (const auto etag = store_->headEtag(std::string(kRootKey)); etag && *etag == *state.etag)
            return Acceptance{*state.epoch, *state.root_sha256, false};
    auto obj = store_->get(std::string(kRootKey));
    if (!obj) return std::nullopt;
    if (state.etag && obj->etag && *state.etag == *obj->etag && state.epoch && state.root_sha256)
        return Acceptance{*state.epoch, *state.root_sha256, false};
    const std::optional<Known> knownState =
        state.epoch && state.root_sha256 ? std::make_optional(Known{*state.epoch, *state.root_sha256}) : std::nullopt;
    try {
        // A full load: it authenticates the segments the new root pins and walks a gap through retained roots.
        auto loaded = load(*store_, vaultUid_, host_.keys, {knownState, true, std::move(obj)});
        if (!knownState || loaded.known() != *knownState) {
            // spec 06 §5.5, both modes: a head that excludes this writer after its last own root stops it here.
            checkHeadForWriter(loaded.root, loaded.acceptance.root_sha256, *store_, host_.nodeId(), state.own_epoch);
            state_->recordRoot({.epoch = loaded.acceptance.epoch,
                                .root_sha256 = loaded.acceptance.root_sha256,
                                .etag = loaded.etag,
                                .sids = d::sidsOf(loaded.root),
                                .version_id = std::nullopt,
                                .base_version_id = std::nullopt,
                                .settle_window = {},
                                .own = false});
            cache_.base.reset();
        }
        return loaded.acceptance;
    } catch (const ChainRejected& e) {
        if (d::refusal(e.code())) refused(e, e.epoch(), e.rootSha256());
        cache_ = {};
        throw;
    } catch (const NoUsableRoot&) {
        return std::nullopt;
    }
}

std::optional<GcReport> Session::collectGarbageIfDue(const std::time_t now) {
    namespace d = session_detail;
    std::scoped_lock lock(mutex_);
    const auto state = state_->state();
    if (!state.epoch) return std::nullopt;  // nothing published yet
    if (state.gc_at && now - *state.gc_at < 24 * 60 * 60) return std::nullopt;
    GcReport report;
    if (d::versionLog(*store_)) {
        const UnreferencedClock clock{
            .first = [&](const std::string& sid) { return state_->firstUnreferenced(sid); },
            .forget = [&](const std::string& sid) { state_->forgetUnreferenced(sid); }};
        report = collectGarbageVersionLog(*store_, state_->retainedSids(), now, clock);
        if (state.root_version_id) {
            const auto janitor = collectRootVersions(*store_, vaultUid_, host_.keys, cache_.roots,
                                                     *state.root_version_id, now);
            if (!janitor.deleted.empty())
                note(Notice::Info, std::format("deleted {} superseded root version(s)", janitor.deleted.size()));
        }
    } else {
        report = collectGarbage(*store_, state_->retainedSids(), now);
    }
    state_->markCollected();
    if (!report.deleted.empty())
        note(Notice::Info, std::format("collected {} superseded segment(s)", report.deleted.size()));
    return report;
}

}
