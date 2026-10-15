#include "sync/events/Ingest.hpp"

#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/Subscription.hpp"

#include <map>
#include <tuple>

namespace vh::sync::events {

namespace imodel = storage::upstream::model;

imodel::InboxEvent toInbox(const UpstreamEvent& event) {
    imodel::InboxEvent row;
    row.provider = event.provider;
    row.account_ref = event.account_ref;
    row.bucket = event.bucket;
    row.object_key = event.key;
    row.kind = event.kind == Kind::Removed ? imodel::InboxKind::Removed : imodel::InboxKind::Created;
    row.event_name = event.event_name;
    row.dedupe_key = event.dedupe_key;
    if (!event.message_id.empty()) row.message_id = event.message_id;
    row.sequencer = event.sequencer;
    row.version_id = event.version_id;
    row.etag = event.etag;
    row.size_bytes = event.size;
    row.event_time = event.event_time;
    row.received_at = std::time(nullptr);
    return row;
}

IngestResult ingest(const std::vector<UpstreamEvent>& events, const std::optional<int64_t> channelId,
                    const std::optional<uint32_t> forcedVaultId, const std::optional<std::string> forcedBucket) {
    IngestResult result{.events = events.size()};
    if (events.empty()) return result;

    // One lookup per bucket identity.
    using Identity = std::tuple<std::string, std::string, std::string>;
    std::map<Identity, std::vector<db::query::upstream::SubscriptionModel>> subscriptions;
    const auto subscriptionsFor = [&](const UpstreamEvent& e) -> const std::vector<db::query::upstream::SubscriptionModel>& {
        const Identity id{e.provider, e.account_ref, e.bucket};
        auto it = subscriptions.find(id);
        if (it == subscriptions.end())
            it = subscriptions.emplace(id, db::query::upstream::Subscription::listLiveForBucket(e.provider, e.account_ref,
                                                                                            e.bucket)).first;
        return it->second;
    };

    std::vector<imodel::InboxEvent> rows;
    rows.reserve(events.size());
    for (const auto& e : events) {
        auto row = toInbox(e);
        row.channel_id = channelId;

        std::optional<db::query::upstream::SubscriptionModel> route;
        const auto& live = subscriptionsFor(e);
        if (forcedVaultId) {
            for (const auto& s : live)
                if (s.vault_id == forcedVaultId) route = s;
            if (!forcedBucket || *forcedBucket == e.bucket) row.vault_id = forcedVaultId;
        } else {
            for (const auto& s : live) {
                if (!s.vault_id) continue;
                if (!e.rule_id.empty() && e.rule_id == "vaulthalla-" + std::to_string(s.id)) {
                    route = s;
                    break;
                }
                if (!e.key.starts_with(s.prefix)) continue;
                if (!route || s.prefix.size() > route->prefix.size()) route = s;
            }
            if (route) row.vault_id = route->vault_id;
        }
        if (route) row.subscription_id = route->id;

        if (!row.vault_id) {
            row.state = imodel::InboxState::Skipped;
            row.note = "unrouted: no live subscription for this bucket/prefix";
            ++result.unrouted;
        }
        rows.push_back(std::move(row));
    }

    result.inserted = db::query::upstream::Inbox::insertMany(rows);
    return result;
}

}
