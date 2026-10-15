#pragma once

#include "sync/events/Event.hpp"
#include "storage/upstream/model/InboxEvent.hpp"

#include <cstdint>
#include <optional>
#include <vector>

// Decoded upstream events → durable inbox rows (#96). The queue poller and the manual `vh vault sync ingest-events`
// path share this: route each event to the live subscription of its bucket, then insert everything in one
// transaction (the durability point before a queue message is acknowledged).
namespace vh::sync::events {

struct IngestResult {
    size_t events = 0;      // events handed in
    size_t inserted = 0;    // new inbox rows (duplicates of earlier deliveries are dropped)
    size_t unrouted = 0;    // no live subscription for the bucket/prefix: stored as skipped "unrouted"
};

[[nodiscard]] storage::upstream::model::InboxEvent toInbox(const UpstreamEvent& event);

// Routing: the live subscriptions on (provider, account_ref, bucket); an AWS event carrying our rule id
// ("vaulthalla-<subscription id>") goes to that subscription, otherwise the longest matching prefix wins. With
// forcedVaultId (manual ingest) every event of that vault's bucket goes to the vault. Throws on a database error:
// nothing was stored, so the caller must not acknowledge.
IngestResult ingest(const std::vector<UpstreamEvent>& events, std::optional<int64_t> channelId,
                    std::optional<uint32_t> forcedVaultId = std::nullopt,
                    std::optional<std::string> forcedBucket = std::nullopt);

}
