#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Event-driven upstream sync (#96). Provider notifications (AWS S3 → SQS, Cloudflare R2 → Queues) are decoded into
// UpstreamEvent, written to the durable inbox (upstream_event_inbox) *before* the queue message is acknowledged, then
// applied to the vault's remote object index and reconciled by a sync pass scoped to the affected keys.
//
// Events are change notifications, not manifests: an event moves the index towards what the provider said, ordered by
// the provider's sequencer (AWS, per key) or event time (R2), and a removal is only applied when nothing newer for the
// key was seen. Full inventory (`vh vault sync reconcile`) stays the recovery path.
namespace vh::sync::events {

enum class Kind : uint8_t { Created, Removed };

struct UpstreamEvent {
    std::string provider;                 // "aws-s3" | "cloudflare-r2"
    std::string account_ref;              // the account the message came from (AWS: queue's account, R2: `account`)
    std::string bucket;
    std::string key;                      // decoded (AWS keys arrive URL-encoded with '+' for space)
    Kind kind{Kind::Created};
    std::string event_name;               // "ObjectCreated:Put", "PutObject", "LifecycleDeletion", …
    std::string dedupe_key;               // stable per provider event: AWS sequencer+key+name, R2 message id
    std::optional<std::string> sequencer; // AWS hex sequencer (per-key ordering)
    std::optional<std::string> version_id;
    std::optional<std::string> etag;      // unquoted
    std::optional<uint64_t> size;
    std::time_t event_time{};
    int64_t event_time_ms{};              // milliseconds since the epoch (ordering within one second; R2 has no sequencer)
    std::string message_id;               // queue message id (diagnostics)
    std::string rule_id;                  // AWS s3.configurationId (our "vaulthalla-<id>" rules route by it); R2: empty
};

// Decoding outcome of one queue message: zero or more events, or a reason to ignore it (test events), or an error
// (undecodable: never acknowledged, so it lands in the DLQ).
struct Decoded {
    std::vector<UpstreamEvent> events;
    bool ignorable{false};                // e.g. s3:TestEvent
    std::string error;                    // non-empty: undecodable
};

[[nodiscard]] Decoded decodeAwsMessage(const std::string& body, const std::string& messageId);
[[nodiscard]] Decoded decodeR2Message(const std::string& body, const std::string& messageId,
                                      const std::optional<std::time_t>& sentAt = std::nullopt);

// S3 keys in event JSON: percent-decoding with '+' as space.
[[nodiscard]] std::string decodeS3EventKey(const std::string& encoded);

// "2024-05-24T19:36:44.379Z" → milliseconds since the epoch; nullopt when unparsable.
[[nodiscard]] std::optional<int64_t> parseEventTimeMs(const std::string& iso);

// Newer-or-equal ordering between two events for one key: sequencer when both have one (hex: left-pad with zeros,
// then compare; AWS documents it only for the same key), else event time in milliseconds, else dedupe key as a
// stable tiebreak.
[[nodiscard]] bool newerOrEqual(const UpstreamEvent& candidate, const UpstreamEvent& current);

}
