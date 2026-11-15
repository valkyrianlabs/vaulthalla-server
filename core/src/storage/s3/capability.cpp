// The bucket capability probe (design/encryption/06-publish-without-preconditions.md §7): storage/s3/Capability.hpp.

#include "storage/s3/Capability.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/upstream/Guard.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <array>

namespace vh::storage::s3 {

namespace capability_detail {

constexpr std::string_view kOk = "ok";
constexpr std::string_view kPreconditionFailed = "precondition_failed";
constexpr std::string_view kNotImplemented = "not_implemented";
constexpr std::string_view kError = "error";
// No real object's ETag: a strong ETag S3 can never compute for these bytes.
constexpr std::string_view kWrongEtag = "\"00000000000000000000000000000000\"";

std::string md5Etag(const std::vector<uint8_t>& bytes) {
    std::array<unsigned char, 16> out{};
    unsigned int n = 0;
    if (EVP_Digest(bytes.data(), bytes.size(), out.data(), &n, EVP_md5(), nullptr) != 1 || n != out.size())
        throw std::runtime_error("MD5 failed");
    std::string hex = "\"";
    for (const auto b : out) hex += fmt::format("{:02x}", b);
    return hex + "\"";
}

std::vector<uint8_t> bodyOf(const std::string_view text) { return {text.begin(), text.end()}; }

struct PutAttempt {
    std::string got;
    std::optional<PutOutcome> outcome;  // set when the PUT succeeded
};

// One PUT with the given conditions, classified. Anything that is not a condition's answer (transport, 403, 5xx, a
// budget or a protection lock) is not a verdict: it propagates.
PutAttempt put(const Controller& c, const std::string& key, const std::vector<uint8_t>& body,
               const std::optional<std::string>& ifMatch, const std::optional<std::string>& ifNoneMatch) {
    try {
        c.uploadBufferWithMetadataConditional(key, body, RequestOptions{}, ifMatch, ifNoneMatch);
        return {std::string(kOk), Controller::lastPutOutcome()};
    } catch (const ConditionalRequestFailed&) {
        return {std::string(kPreconditionFailed), std::nullopt};
    } catch (const PreconditionsUnsupported&) {
        return {std::string(kNotImplemented), std::nullopt};
    }
}

// What a GET with If-Match answered.
std::string getIfMatch(const Controller& c, const std::string& key, const std::string& etag) {
    GetObjectOptions options;
    options.if_match = etag;
    options.max_body_bytes = 4096;
    try {
        (void)c.streamObject(key, options, [](std::span<const uint8_t>) {});
        return std::string(kOk);
    } catch (const ConditionalRequestFailed&) {
        return std::string(kPreconditionFailed);
    } catch (const ObjectNotFound&) {
        return std::string(kError);
    }
}

std::optional<std::vector<uint8_t>> getVersion(const Controller& c, const std::string& key,
                                               const std::string& versionId) {
    GetObjectOptions options;
    options.version_id = versionId;
    options.max_body_bytes = 4096;
    std::vector<uint8_t> out;
    try {
        (void)c.streamObject(key, options, [&](const std::span<const uint8_t> chunk) {
            out.insert(out.end(), chunk.begin(), chunk.end());
        });
    } catch (const ObjectNotFound&) {
        return std::nullopt;
    }
    return out;
}

std::vector<ObjectVersionInfo> versionsOf(const Controller& c, const std::string& key) {
    std::vector<ObjectVersionInfo> out;
    std::string keyMarker, versionMarker;
    for (unsigned page = 0; page < 8; ++page) {
        const auto p = c.listObjectVersionsPage(key, keyMarker, versionMarker, 100);
        for (const auto& v : p.versions)
            if (v.key == key) out.push_back(v);
        if (!p.truncated || p.next_key_marker > key) break;
        keyMarker = p.next_key_marker;
        versionMarker = p.next_version_id_marker;
    }
    return out;
}

bool realVersionId(const std::optional<std::string>& id) { return id && !id->empty() && *id != "null"; }

// Deletes every version (and delete marker) of the probe key by id, or the key itself on an unversioned bucket.
// Returns how many stayed.
unsigned cleanUp(const Controller& c, const std::string& key, const bool versioned) {
    unsigned left = 0;
    if (!versioned) {
        try {
            c.deleteObject(key);
        } catch (const std::exception&) {
            ++left;
        }
        return left;
    }
    std::vector<ObjectVersionInfo> listed;
    try {
        listed = versionsOf(c, key);
    } catch (const std::exception&) {
        return 1;
    }
    for (const auto& v : listed) {
        try {
            c.deleteObjectVersion(key, v.version_id);
        } catch (const std::exception&) {
            ++left;
        }
    }
    return left;
}

}

std::string_view to_string(const WriteCapability capability) {
    switch (capability) {
    case WriteCapability::Unknown: return "unknown";
    case WriteCapability::Conditional: return "conditional";
    case WriteCapability::VersionLog: return "version_log";
    case WriteCapability::Insufficient: return "insufficient";
    }
    return "unknown";
}

std::optional<WriteCapability> publishModeFromString(const std::string_view text) {
    if (text == "conditional") return WriteCapability::Conditional;
    if (text == "version_log") return WriteCapability::VersionLog;
    return std::nullopt;
}

bool sendsPreconditions(const WriteCapability capability) noexcept {
    return capability == WriteCapability::Conditional || capability == WriteCapability::Unknown;
}

ProbeResult probeBucket(const Controller& controller) {
    namespace d = capability_detail;
    ProbeResult r;
    r.probed_at = std::time(nullptr);
    const auto key = std::string(kProbePrefix) + crypto::id::toBase32(crypto::id::newObjectUid());
    const auto first = d::bodyOf("vaulthalla bucket probe: first write\n");
    const auto second = d::bodyOf("vaulthalla bucket probe: second write\n");
    const auto note = [&](const std::string_view step, const std::string_view expected, const std::string& got) {
        r.steps.push_back({std::string(step), std::string(expected), got});
    };

    std::vector<PutOutcome> written;  // in write order
    bool versioned = true;            // until a PUT says otherwise (for the cleanup)
    try {
        // 1-4: the conditions.
        auto a = d::put(controller, key, first, std::nullopt, "*");
        note("put_if_none_match_absent", d::kOk, a.got);
        if (a.got == d::kNotImplemented) {
            r.conditional_put = "rejected";
        } else if (a.got == d::kPreconditionFailed) {
            r.conditional_put = "inconsistent";
        } else {
            written.push_back(*a.outcome);
            const auto b = d::put(controller, key, second, std::nullopt, "*");
            note("put_if_none_match_present", d::kPreconditionFailed, b.got);
            if (b.outcome) written.push_back(*b.outcome);
            if (b.got == d::kNotImplemented) r.conditional_put = "rejected";
            else if (b.got == d::kOk) r.conditional_put = "ignored";
            if (r.conditional_put.empty()) {
                const auto c = d::put(controller, key, second, std::string(d::kWrongEtag), std::nullopt);
                note("put_if_match_wrong", d::kPreconditionFailed, c.got);
                if (c.outcome) written.push_back(*c.outcome);
                if (c.got == d::kNotImplemented) r.conditional_put = "rejected";
                else if (c.got == d::kOk) r.conditional_put = "ignored";
            }
            if (r.conditional_put.empty()) {
                const auto e = d::put(controller, key, second, written.back().etag, std::nullopt);
                note("put_if_match_right", d::kOk, e.got);
                if (e.outcome) written.push_back(*e.outcome);
                if (e.got == d::kNotImplemented) r.conditional_put = "rejected";
                else if (e.got == d::kPreconditionFailed) r.conditional_put = "inconsistent";
                else r.conditional_put = "supported";
            }
        }
        // Two plain writes at least, for the versioning check.
        while (written.size() < 2) {
            const auto plain = d::put(controller, key, written.empty() ? first : second, std::nullopt, std::nullopt);
            note("put_plain", d::kOk, plain.got);
            if (!plain.outcome) throw ProbeFailed("a plain PUT of the probe object failed");
            written.push_back(*plain.outcome);
        }
        versioned = std::ranges::all_of(written, [](const PutOutcome& o) { return d::realVersionId(o.version_id); });

        // 5: versions, newest first, readable by id.
        if (versioned) {
            const auto listed = d::versionsOf(controller, key);
            std::vector<std::string> ids;
            for (const auto& v : listed)
                if (!v.delete_marker) ids.push_back(v.version_id);
            std::vector<std::string> expected;
            for (auto it = written.rbegin(); it != written.rend(); ++it) expected.push_back(*it->version_id);
            const bool distinct = std::ranges::adjacent_find(expected) == expected.end();
            const bool ordered = ids == expected && !listed.empty() && listed.front().is_latest;
            note("list_versions_newest_first", d::kOk, ordered && distinct ? std::string(d::kOk) : std::string(d::kError));
            const auto oldest = d::getVersion(controller, key, *written.front().version_id);
            const bool readable = oldest && *oldest == first;
            note("get_by_version_id", d::kOk, readable ? std::string(d::kOk) : std::string(d::kError));
            r.versioning = ordered && distinct && readable;
        } else {
            note("versioning", d::kOk, "unversioned");
        }

        // GET If-Match: refused on a wrong ETag, served on the right one.
        const auto wrong = d::getIfMatch(controller, key, std::string(d::kWrongEtag));
        note("get_if_match_wrong", d::kPreconditionFailed, wrong);
        const auto right = d::getIfMatch(controller, key, written.back().etag);
        note("get_if_match_right", d::kOk, right);
        r.get_if_match = wrong == d::kPreconditionFailed && right == d::kOk;

        r.md5_etags = written.front().etag == d::md5Etag(first);
    } catch (const upstream::BucketProtected& e) {
        throw ProbeFailed(std::string("the bucket is protected: ") + e.what());
    } catch (const ProbeFailed&) {
        r.leftover_versions = d::cleanUp(controller, key, versioned);
        throw;
    } catch (const std::exception& e) {
        r.leftover_versions = d::cleanUp(controller, key, versioned);
        throw ProbeFailed(fmt::format("the bucket probe stopped after step {}: {}",
                                      r.steps.empty() ? std::string("none") : r.steps.back().step, e.what()));
    }
    r.leftover_versions = d::cleanUp(controller, key, versioned);

    if (!r.get_if_match) {
        r.capability = WriteCapability::Insufficient;
        r.reason = "the bucket does not honour If-Match on GET, which every read of a remote object relies on";
    } else if (r.conditional_put == "supported") {
        r.capability = WriteCapability::Conditional;
        r.reason = "the bucket honours conditional writes (If-None-Match, If-Match)";
    } else if (r.versioning) {
        r.capability = WriteCapability::VersionLog;
        r.reason = r.conditional_put == "rejected"
            ? "the bucket rejects conditional writes (not implemented) and keeps object versions"
            : "the bucket does not enforce conditional writes and keeps object versions";
    } else {
        r.capability = WriteCapability::Insufficient;
        r.reason = "the bucket neither honours conditional writes nor keeps object versions";
    }
    return r;
}

nlohmann::json toJson(const ProbeResult& r) {
    nlohmann::json steps = nlohmann::json::array();
    for (const auto& s : r.steps) steps.push_back({{"step", s.step}, {"expected", s.expected}, {"got", s.got}});
    return {{"v", 1},
            {"capability", std::string(to_string(r.capability))},
            {"conditional_put", r.conditional_put},
            {"versioning", r.versioning},
            {"get_if_match", r.get_if_match},
            {"md5_etags", r.md5_etags},
            {"reason", r.reason},
            {"steps", std::move(steps)},
            {"leftover_versions", r.leftover_versions},
            {"probed_at", static_cast<int64_t>(r.probed_at)}};
}

ProbeResult probeResultFromJson(const nlohmann::json& j) {
    ProbeResult r;
    const auto cap = j.value("capability", std::string("unknown"));
    if (cap == "conditional") r.capability = WriteCapability::Conditional;
    else if (cap == "version_log") r.capability = WriteCapability::VersionLog;
    else if (cap == "insufficient") r.capability = WriteCapability::Insufficient;
    r.conditional_put = j.value("conditional_put", std::string{});
    r.versioning = j.value("versioning", false);
    r.get_if_match = j.value("get_if_match", false);
    r.md5_etags = j.value("md5_etags", false);
    r.reason = j.value("reason", std::string{});
    if (const auto it = j.find("steps"); it != j.end() && it->is_array())
        for (const auto& s : *it)
            r.steps.push_back({s.value("step", std::string{}), s.value("expected", std::string{}),
                               s.value("got", std::string{})});
    r.leftover_versions = j.value("leftover_versions", 0u);
    r.probed_at = static_cast<std::time_t>(j.value("probed_at", int64_t{0}));
    return r;
}

}
