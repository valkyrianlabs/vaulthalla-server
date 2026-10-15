#include "sync/events/Event.hpp"

#include "db/encoding/timestamp.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>

namespace vh::sync::events {

namespace {

using json = nlohmann::json;

int hexValue(const char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::optional<std::string> stringField(const json& object, const char* name) {
    if (!object.is_object() || !object.contains(name) || !object.at(name).is_string()) return std::nullopt;
    auto value = object.at(name).get<std::string>();
    if (value.empty()) return std::nullopt;
    return value;
}

std::optional<uint64_t> sizeField(const json& object, const char* name) {
    if (!object.is_object() || !object.contains(name)) return std::nullopt;
    const auto& v = object.at(name);
    if (v.is_number_unsigned()) return v.get<uint64_t>();
    if (v.is_number_integer() && v.get<int64_t>() >= 0) return static_cast<uint64_t>(v.get<int64_t>());
    if (v.is_string()) {
        const auto s = v.get<std::string>();
        if (s.empty() || !std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; }))
            return std::nullopt;
        try {
            return std::stoull(s);
        } catch (const std::exception&) {
            return std::nullopt;
        }
    }
    return std::nullopt;
}

std::string unquote(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    return etag;
}

void setTime(UpstreamEvent& e, const std::optional<std::string>& iso, const std::optional<std::time_t>& fallback) {
    if (iso)
        if (const auto ms = parseEventTimeMs(*iso)) {
            e.event_time_ms = *ms;
            e.event_time = static_cast<std::time_t>(*ms / 1000);
            return;
        }
    const auto t = fallback.value_or(std::time(nullptr));
    e.event_time = t;
    e.event_time_ms = static_cast<int64_t>(t) * 1000;
}

// AWS eventName → Kind. Only creations and removals of the current version move the index; tagging, ACL, restore,
// transition and replication notifications don't change what an object is.
std::optional<Kind> awsKind(const std::string& eventName) {
    if (eventName.starts_with("ObjectCreated:")) return Kind::Created;
    if (eventName.starts_with("ObjectRemoved:")) return Kind::Removed;
    if (eventName.starts_with("LifecycleExpiration:")) return Kind::Removed;
    return std::nullopt;
}

void decodeAwsRecords(const json& payload, const std::string& messageId, Decoded& out, int depth) {
    if (depth > 3 || !payload.is_object()) {
        if (out.error.empty()) out.error = "not an S3 event notification";
        return;
    }

    // s3:TestEvent, sent when a notification configuration is written.
    if (payload.contains("Event") && payload.at("Event").is_string() &&
        payload.at("Event").get<std::string>() == "s3:TestEvent") {
        out.ignorable = true;
        return;
    }

    // SNS fan-out envelope (a bucket that notifies a topic the queue subscribes to).
    if (const auto type = stringField(payload, "Type"); type && *type == "Notification") {
        const auto message = stringField(payload, "Message");
        if (!message) {
            out.error = "SNS notification without a Message";
            return;
        }
        try {
            decodeAwsRecords(json::parse(*message), messageId, out, depth + 1);
        } catch (const json::exception&) {
            out.error = "SNS Message is not JSON";
        }
        return;
    }

    if (!payload.contains("Records") || !payload.at("Records").is_array()) {
        out.error = "message has no Records";
        return;
    }

    bool sawRecord = false;
    for (const auto& record : payload.at("Records")) {
        if (!record.is_object() || !record.contains("s3") || !record.at("s3").is_object()) continue;
        sawRecord = true;
        const auto eventName = stringField(record, "eventName").value_or("");
        const auto kind = awsKind(eventName);
        if (!kind) continue;

        const auto& s3 = record.at("s3");
        const auto bucket = s3.contains("bucket") ? stringField(s3.at("bucket"), "name") : std::nullopt;
        const auto& object = s3.contains("object") ? s3.at("object") : json::object();
        const auto rawKey = stringField(object, "key");
        if (!bucket || !rawKey) {
            out.error = "S3 record without bucket name or object key";
            continue;
        }

        UpstreamEvent e;
        e.provider = "aws-s3";
        e.bucket = *bucket;
        e.key = decodeS3EventKey(*rawKey);
        e.kind = *kind;
        e.event_name = eventName;
        e.sequencer = stringField(object, "sequencer");
        e.version_id = stringField(object, "versionId");
        if (const auto etag = stringField(object, "eTag")) e.etag = unquote(*etag);
        e.size = sizeField(object, "size");
        e.message_id = messageId;
        e.rule_id = stringField(s3, "configurationId").value_or("");
        setTime(e, stringField(record, "eventTime"), std::nullopt);

        // One logical event per (name, key, sequencer); S3 may deliver it more than once. Without a sequencer (not
        // documented to happen for PUT/DELETE) the identity falls back to what the record says.
        e.dedupe_key = "aws|" + eventName + "|" + e.key + "|" +
                       (e.sequencer ? *e.sequencer
                                    : std::to_string(e.event_time_ms) + "|" + e.etag.value_or("") + "|" +
                                          (e.size ? std::to_string(*e.size) : std::string{}) + "|" +
                                          e.version_id.value_or(""));
        out.events.push_back(std::move(e));
    }

    if (!sawRecord && out.events.empty() && out.error.empty()) out.error = "message has no S3 records";
    // Only records we deliberately ignore (tagging, restore, …): nothing to do, nothing wrong.
    if (sawRecord && out.events.empty() && out.error.empty()) out.ignorable = true;
}

}

std::string decodeS3EventKey(const std::string& encoded) {
    std::string out;
    out.reserve(encoded.size());
    for (size_t i = 0; i < encoded.size(); ++i) {
        if (encoded[i] == '+') {
            out.push_back(' ');
        } else if (encoded[i] == '%' && i + 2 < encoded.size()) {
            const auto hi = hexValue(encoded[i + 1]);
            const auto lo = hexValue(encoded[i + 2]);
            if (hi >= 0 && lo >= 0) {
                out.push_back(static_cast<char>((hi << 4) | lo));
                i += 2;
            } else {
                out.push_back(encoded[i]);
            }
        } else {
            out.push_back(encoded[i]);
        }
    }
    return out;
}

std::optional<int64_t> parseEventTimeMs(const std::string& iso) {
    try {
        const auto seconds = db::encoding::parsePostgresTimestamp(iso);
        int64_t ms = 0;
        // Fractional seconds right after "YYYY-MM-DDTHH:MM:SS".
        if (iso.size() > 20 && iso[19] == '.') {
            int digits = 0;
            for (size_t i = 20; i < iso.size() && std::isdigit(static_cast<unsigned char>(iso[i])); ++i) {
                if (digits < 3) ms = ms * 10 + (iso[i] - '0');
                ++digits;
            }
            for (int d = std::min(digits, 3); d < 3; ++d) ms *= 10;
        }
        return static_cast<int64_t>(seconds) * 1000 + ms;
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

Decoded decodeAwsMessage(const std::string& body, const std::string& messageId) {
    Decoded out;
    json payload;
    try {
        payload = json::parse(body);
    } catch (const json::exception&) {
        out.error = "message body is not JSON";
        return out;
    }
    decodeAwsRecords(payload, messageId, out, 0);
    // A message is all-or-nothing: an undecodable record poisons it (it goes to the DLQ instead of being half
    // applied and acknowledged).
    if (!out.error.empty()) out.events.clear();
    return out;
}

Decoded decodeR2Message(const std::string& body, const std::string& messageId, const std::optional<std::time_t>& sentAt) {
    Decoded out;
    json payload;
    try {
        payload = json::parse(body);
    } catch (const json::exception&) {
        out.error = "message body is not JSON";
        return out;
    }
    if (!payload.is_object()) {
        out.error = "message body is not a JSON object";
        return out;
    }

    const auto action = stringField(payload, "action");
    const auto bucket = stringField(payload, "bucket");
    const auto& object = payload.contains("object") ? payload.at("object") : json::object();
    const auto key = stringField(object, "key");
    if (!action || !bucket || !key) {
        out.error = "R2 notification without action, bucket or object key";
        return out;
    }

    UpstreamEvent e;
    e.provider = "cloudflare-r2";
    e.account_ref = stringField(payload, "account").value_or("");
    e.bucket = *bucket;
    e.key = *key;   // R2 keys arrive as stored (not URL-encoded)
    if (*action == "PutObject" || *action == "CopyObject" || *action == "CompleteMultipartUpload") {
        e.kind = Kind::Created;
    } else if (*action == "DeleteObject" || *action == "LifecycleDeletion") {
        e.kind = Kind::Removed;
    } else {
        out.ignorable = true;   // an action this version doesn't know: nothing we can apply
        return out;
    }
    e.event_name = *action;
    if (const auto etag = stringField(object, "eTag")) e.etag = unquote(*etag);
    e.size = sizeField(object, "size");
    e.message_id = messageId;
    setTime(e, stringField(payload, "eventTime"), sentAt);
    // Redeliveries of one notification carry the same content; two writes in the same millisecond with the same
    // ETag are the same object state, so collapsing them is harmless.
    e.dedupe_key = "r2|" + *action + "|" + e.key + "|" + std::to_string(e.event_time_ms) + "|" + e.etag.value_or("") +
                   "|" + (e.size ? std::to_string(*e.size) : std::string{});
    out.events.push_back(std::move(e));
    return out;
}

bool newerOrEqual(const UpstreamEvent& candidate, const UpstreamEvent& current) {
    if (candidate.sequencer && current.sequencer)
        return db::query::sync::s3SequencerIsNewerOrEqual(candidate.sequencer, current.sequencer);
    if (candidate.event_time_ms != current.event_time_ms) return candidate.event_time_ms > current.event_time_ms;
    return candidate.dedupe_key >= current.dedupe_key;
}

}
