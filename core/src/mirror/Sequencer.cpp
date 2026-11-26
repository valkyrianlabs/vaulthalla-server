#include "mirror/Sequencer.hpp"

#include "log/Registry.hpp"
#include "mirror/follow/Follower.hpp"

#include <exception>

namespace vh::mirror {

Sequencer::Sequencer() : AsyncService("MirrorSequencer") {}

const std::shared_ptr<Sequencer>& Sequencer::instance() {
    static const auto sequencer = std::make_shared<Sequencer>();
    return sequencer;
}

vh::db::query::mirror::Sequenced Sequencer::tick() {
    passes_.fetch_add(1, std::memory_order_relaxed);
    auto numbered = vh::db::query::mirror::Log::sequence();
    for (const auto& v : numbered.vaults) {
        // The mirror's notice (peer.mirror.notify), sent from the follower's thread: never blocks this pass.
        vh::mirror::follow::Follower::instance()->numbered(v.vault_id, v.last);
        log::Registry::sync()->debug("[MirrorSequencer] Vault {}: {} change(s) in {} group(s) numbered through ({}, {})",
                                     v.vault_id, v.rows, v.groups, v.last.term, v.last.seq);
    }
    return numbered;
}

void Sequencer::runLoop() {
    while (!shouldStop()) {
        try {
            (void)tick();
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[MirrorSequencer] Replication log numbering pass failed: {}", e.what());
        }
        lazySleep(kPollInterval);
    }
}

}
