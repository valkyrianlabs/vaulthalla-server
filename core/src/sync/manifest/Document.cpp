#include "sync/manifest/Document.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <array>
#include <set>
#include <utility>

namespace vh::sync::manifest {

namespace document_detail {

// Typed access to one JSON object for a reader that must fail closed with its document's error code.
class Fields {
public:
    Fields(const Json& j, const std::string& code, std::string_view what) : j_(j), code_(code), what_(what) {
        if (!j_.is_object()) fail("is not an object");
    }

    [[noreturn]] void fail(std::string_view why) const { throw FormatError(code_, fmt::format("{} {}", what_, why)); }

    [[nodiscard]] bool has(const char* key) const { return j_.contains(key); }
    [[nodiscard]] bool present(const char* key) const { return j_.contains(key) && !j_.at(key).is_null(); }
    [[nodiscard]] const Json& at(const char* key) const {
        if (!j_.contains(key)) fail(fmt::format("is missing \"{}\"", key));
        return j_.at(key);
    }

    [[nodiscard]] std::string str(const char* key) const {
        const auto& v = at(key);
        if (!v.is_string()) fail(fmt::format("member \"{}\" is not a string", key));
        return v.get<std::string>();
    }
    [[nodiscard]] std::optional<std::string> optStr(const char* key) const {
        if (!present(key)) return std::nullopt;
        return str(key);
    }
    [[nodiscard]] uint64_t u64(const char* key) const {
        const auto& v = at(key);
        if (v.is_number_unsigned()) return v.get<uint64_t>();
        if (v.is_number_integer() && v.get<int64_t>() >= 0) return static_cast<uint64_t>(v.get<int64_t>());
        fail(fmt::format("member \"{}\" is not a non-negative integer", key));
    }
    [[nodiscard]] std::optional<uint64_t> optU64(const char* key) const {
        if (!present(key)) return std::nullopt;
        return u64(key);
    }
    [[nodiscard]] uint32_t u32(const char* key) const {
        const auto v = u64(key);
        if (v > UINT32_MAX) fail(fmt::format("member \"{}\" is out of range", key));
        return static_cast<uint32_t>(v);
    }
    [[nodiscard]] std::optional<uint32_t> optU32(const char* key) const {
        if (!present(key)) return std::nullopt;
        return u32(key);
    }
    [[nodiscard]] int64_t i64(const char* key) const {
        const auto& v = at(key);
        if (v.is_number_integer()) return v.get<int64_t>();
        fail(fmt::format("member \"{}\" is not an integer", key));
    }
    [[nodiscard]] bool boolean(const char* key, const bool fallback) const {
        if (!present(key)) return fallback;
        const auto& v = at(key);
        if (!v.is_boolean()) fail(fmt::format("member \"{}\" is not a boolean", key));
        return v.get<bool>();
    }
    [[nodiscard]] const Json& array(const char* key) const {
        const auto& v = at(key);
        if (!v.is_array()) fail(fmt::format("member \"{}\" is not an array", key));
        return v;
    }
    [[nodiscard]] const Json* optArray(const char* key) const {
        if (!present(key)) return nullptr;
        return &array(key);
    }

    [[nodiscard]] const std::string& code() const { return code_; }

private:
    const Json& j_;
    const std::string& code_;
    std::string_view what_;
};

const std::string kBadRoot = "bad_root";
const std::string kBadSegment = "bad_segment";
const std::string kBadSnapshot = "bad_snapshot";

Json nullable(const std::optional<std::string>& v) { return v ? Json(*v) : Json(nullptr); }

void putIf(Json& j, const char* key, const std::optional<std::string>& v) {
    if (v) j[key] = *v;
}
template <typename T>
void putIfNum(Json& j, const char* key, const std::optional<T>& v) {
    if (v) j[key] = *v;
}

std::string hexByte(const uint8_t b) { return fmt::format("{:02x}", b); }

uint8_t parseHexByte(const Json& v, const Fields& f) {
    if (!v.is_string()) f.fail("range bound is not a string");
    const auto s = v.get<std::string>();
    const auto digit = [&](const char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        return -1;
    };
    if (s.size() != 2 || digit(s[0]) < 0 || digit(s[1]) < 0) f.fail("range bound is not two lower-case hex digits");
    return static_cast<uint8_t>(digit(s[0]) * 16 + digit(s[1]));
}

Json rangeJson(const Range& r) { return Json::array({hexByte(r.lo), hexByte(r.hi)}); }

Range parseRange(const Json& v, const Fields& f) {
    if (!v.is_array() || v.size() != 2) f.fail("range is not [lo, hi]");
    const Range r{parseHexByte(v[0], f), parseHexByte(v[1], f)};
    if (r.lo > r.hi) f.fail("range is inverted");
    return r;
}

bool isLowerHex(const std::string& s, const std::size_t size) {
    return s.size() == size && std::ranges::all_of(s, [](const char c) {
        return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f');
    });
}

void checkType(const Fields& f, const std::string_view type) {
    if (f.str("type") != type) f.fail(fmt::format("is not a {}", type));
    if (f.u64("v") != kDocumentVersion) f.fail("has an unsupported version");
}

void checkVaultUid(const Fields& f, const std::string& text, const Uid& expected) {
    if (parseUid(text, f.code(), "vault_uid") != expected) f.fail("belongs to another vault");
}

EntryKind parseKind(const std::string& s, const Fields& f) {
    if (s == "dir") return EntryKind::Dir;
    if (s == "file") return EntryKind::File;
    if (s == "symlink") return EntryKind::Symlink;
    if (s == "tombstone") return EntryKind::Tombstone;
    f.fail("has an unknown kind");
}

Json versionJson(const FileVersion& v) {
    Json j = {{"version_id", v.version_id}, {"delete_marker", v.delete_marker}};
    putIf(j, "generation", v.generation);
    putIfNum(j, "key_version", v.key_version);
    putIfNum(j, "size", v.size);
    putIf(j, "etag", v.etag);
    putIf(j, "last_modified", v.last_modified);
    putIf(j, "noncurrent_at", v.noncurrent_at);
    putIf(j, "origin_last_modified", v.origin_last_modified);
    return j;
}

FileVersion parseVersion(const Json& j, const std::string& code) {
    const Fields f(j, code, "version");
    FileVersion v;
    v.version_id = f.str("version_id");
    v.generation = f.optStr("generation");
    v.key_version = f.optU32("key_version");
    v.size = f.optU64("size");
    v.etag = f.optStr("etag");
    v.last_modified = f.optStr("last_modified");
    v.noncurrent_at = f.optStr("noncurrent_at");
    v.delete_marker = f.boolean("delete_marker", false);
    v.origin_last_modified = f.optStr("origin_last_modified");
    return v;
}

}

FormatError::FormatError(std::string code, const std::string& detail)
    : std::runtime_error("manifest " + code + ": " + detail), code_(std::move(code)) {}

std::string uidText(const Uid& uid) { return crypto::id::toBase32(uid); }

Uid parseUid(const std::string_view text, const std::string& code, const std::string_view what) {
    const auto uid = crypto::id::fromBase32(text);
    if (!uid) throw FormatError(code, fmt::format("{} is not a canonical base32 uid", what));
    return *uid;
}

std::string_view to_string(const EntryKind kind) {
    switch (kind) {
    case EntryKind::Dir: return "dir";
    case EntryKind::File: return "file";
    case EntryKind::Symlink: return "symlink";
    case EntryKind::Tombstone: return "tombstone";
    }
    return "file";
}

bool Grant::usableForDecryption() const { return recipient_class == kCustomerClass && !revoked_at; }

// ---- entries ----------------------------------------------------------------------------------------------------

Json toJson(const Entry& e) {
    using namespace document_detail;
    Json j = {{"uid", e.uid}, {"kind", std::string(to_string(e.kind))}, {"parent", nullable(e.parent)}, {"name", e.name}};
    putIfNum(j, "mode", e.mode);
    if (e.owner) j["owner"] = {{"uid", e.owner->uid}, {"gid", e.owner->gid}};
    putIf(j, "mtime", e.mtime);
    putIf(j, "ctime", e.ctime);
    putIfNum(j, "size", e.size);
    putIf(j, "mime", e.mime);
    putIfNum(j, "format", e.format);
    putIfNum(j, "key_version", e.key_version);
    putIf(j, "generation", e.generation);
    putIf(j, "content_hash", e.content_hash);
    if (e.object) {
        Json o = {{"size", e.object->size}, {"version_id", nullable(e.object->version_id)}};
        putIf(o, "etag", e.object->etag);
        putIf(o, "storage_class", e.object->storage_class);
        j["object"] = std::move(o);
    }
    if (e.kind == EntryKind::File || e.kind == EntryKind::Tombstone) {
        Json versions = Json::array();
        for (const auto& v : e.versions) versions.push_back(versionJson(v));
        j["versions"] = std::move(versions);
        Json names = Json::array();
        for (const auto& n : e.names) names.push_back({{"until", n.until}, {"parent", nullable(n.parent)}, {"name", n.name}});
        j["names"] = std::move(names);
    }
    if (e.trashed) {
        Json t = {{"at", e.trashed->at}};
        putIf(t, "by", e.trashed->by);
        putIf(t, "path", e.trashed->path);
        j["trashed"] = std::move(t);
    }
    putIf(j, "target", e.target);
    return j;
}

Entry entryFromJson(const Json& j) {
    using namespace document_detail;
    const Fields f(j, kBadSegment, "entry");
    Entry e;
    e.uid = f.str("uid");
    (void)parseUid(e.uid, kBadSegment, "entry uid");
    e.kind = parseKind(f.str("kind"), f);
    if (!f.has("parent")) f.fail("is missing \"parent\"");
    e.parent = f.optStr("parent");
    if (e.parent) (void)parseUid(*e.parent, kBadSegment, "entry parent");
    e.name = f.str("name");
    e.mode = f.optU32("mode");
    if (f.present("owner")) {
        const Fields o(f.at("owner"), kBadSegment, "owner");
        e.owner = Owner{o.i64("uid"), o.i64("gid")};
    }
    e.mtime = f.optStr("mtime");
    e.ctime = f.optStr("ctime");
    e.size = f.optU64("size");
    e.mime = f.optStr("mime");
    e.format = f.optU32("format");
    e.key_version = f.optU32("key_version");
    e.generation = f.optStr("generation");
    if (e.generation && !isLowerHex(*e.generation, 64)) f.fail("generation is not 32 bytes of lower-case hex");
    e.content_hash = f.optStr("content_hash");
    if (f.present("object")) {
        const Fields o(f.at("object"), kBadSegment, "object");
        e.object = ObjectRef{o.optStr("etag"), o.u64("size"), o.optStr("version_id"), o.optStr("storage_class")};
    }
    if (const auto* versions = f.optArray("versions"))
        for (const auto& v : *versions) e.versions.push_back(parseVersion(v, kBadSegment));
    if (const auto* names = f.optArray("names")) {
        for (const auto& n : *names) {
            const Fields nf(n, kBadSegment, "prior name");
            if (!nf.has("parent")) nf.fail("is missing \"parent\"");
            e.names.push_back(PriorName{nf.str("until"), nf.optStr("parent"), nf.str("name")});
        }
    }
    if (f.present("trashed")) {
        const Fields t(f.at("trashed"), kBadSegment, "trashed");
        e.trashed = Trashed{t.str("at"), t.optStr("by"), t.optStr("path")};
    }
    e.target = f.optStr("target");
    if (e.kind == EntryKind::Symlink && !e.target) f.fail("is a symlink without a target");
    // Only the vault root has no parent, and it has no name. A trashed file or a tombstone whose folder is gone has
    // no parent but keeps its name.
    if (!e.parent && !e.name.empty() && !e.trashed && e.kind != EntryKind::Tombstone)
        f.fail("has no parent but a name (only the vault root has no parent)");
    return e;
}

// ---- segments ---------------------------------------------------------------------------------------------------

Json toJson(const SegmentDocument& doc) {
    Json entries = Json::array();
    for (const auto& e : doc.entries) entries.push_back(toJson(e));
    return {{"type", std::string(kSegmentType)}, {"v", kDocumentVersion}, {"vault_uid", doc.vault_uid},
            {"range", document_detail::rangeJson(doc.range)}, {"entries", std::move(entries)}};
}

SegmentDocument segmentFromJson(const Json& j, const Uid& expectedVaultUid) {
    using namespace document_detail;
    const Fields f(j, kBadSegment, "segment");
    checkType(f, kSegmentType);
    SegmentDocument doc;
    doc.vault_uid = f.str("vault_uid");
    checkVaultUid(f, doc.vault_uid, expectedVaultUid);
    doc.range = parseRange(f.at("range"), f);
    std::set<std::string> seen;
    for (const auto& item : f.array("entries")) {
        auto e = entryFromJson(item);
        if (!doc.range.contains(parseUid(e.uid, kBadSegment, "entry uid"))) f.fail("has an entry outside its range");
        if (!seen.insert(e.uid).second) f.fail("lists an entry twice");
        doc.entries.push_back(std::move(e));
    }
    return doc;
}

// ---- snapshots --------------------------------------------------------------------------------------------------

Json toJson(const SnapshotDocument& doc) {
    using namespace document_detail;
    Json members = Json::array();
    for (const auto& m : doc.snapshot.members) {
        Json mj = {{"uid", nullable(m.uid)}, {"path_at_capture", m.path_at_capture},
                   {"provider_version_id", nullable(m.provider_version_id)},
                   {"restorable_from_bucket", m.restorable_from_bucket}};
        putIf(mj, "generation", m.generation);
        putIfNum(mj, "key_version", m.key_version);
        members.push_back(std::move(mj));
    }
    Json snap = {{"id", doc.snapshot.id}, {"name", nullable(doc.snapshot.name)}, {"created_at", doc.snapshot.created_at},
                 {"root_path", doc.snapshot.root_path}, {"members", std::move(members)}};
    return {{"type", std::string(kSnapshotType)}, {"v", kDocumentVersion}, {"vault_uid", doc.vault_uid},
            {"snapshot", std::move(snap)}};
}

SnapshotDocument snapshotFromJson(const Json& j, const Uid& expectedVaultUid) {
    using namespace document_detail;
    const Fields f(j, kBadSnapshot, "snapshot segment");
    checkType(f, kSnapshotType);
    SnapshotDocument doc;
    doc.vault_uid = f.str("vault_uid");
    checkVaultUid(f, doc.vault_uid, expectedVaultUid);
    const Fields s(f.at("snapshot"), kBadSnapshot, "snapshot");
    doc.snapshot.id = s.u64("id");
    doc.snapshot.name = s.optStr("name");
    doc.snapshot.created_at = s.str("created_at");
    doc.snapshot.root_path = s.str("root_path");
    for (const auto& item : s.array("members")) {
        const Fields m(item, kBadSnapshot, "snapshot member");
        SnapshotMember member;
        member.uid = m.optStr("uid");
        if (member.uid) (void)parseUid(*member.uid, kBadSnapshot, "member uid");
        member.path_at_capture = m.str("path_at_capture");
        member.generation = m.optStr("generation");
        member.key_version = m.optU32("key_version");
        member.provider_version_id = m.optStr("provider_version_id");
        member.restorable_from_bucket = m.boolean("restorable_from_bucket", false);
        doc.snapshot.members.push_back(std::move(member));
    }
    return doc;
}

// ---- root -------------------------------------------------------------------------------------------------------

Json toJson(const RootDocument& r) {
    using namespace document_detail;
    Json keys = Json::array();
    for (const auto& k : r.keys) {
        Json kj = {{"version", k.version}, {"key_check", nullable(k.key_check)}, {"created_at", nullable(k.created_at)},
                   {"retired_at", nullable(k.retired_at)}, {"attestation", nullptr}};
        if (k.attestation) {
            Json a = {{"key_id", k.attestation->key_id}, {"signature", k.attestation->signature}};
            putIf(a, "public_key", k.attestation->public_key);
            kj["attestation"] = std::move(a);
        }
        if (k.envelopes) kj["envelopes"] = *k.envelopes;
        keys.push_back(std::move(kj));
    }
    Json segments = Json::array();
    for (const auto& s : r.segments)
        segments.push_back({{"sid", s.sid}, {"range", rangeJson(s.range)}, {"count", s.count},
                            {"object_sha256", s.object_sha256}, {"size", s.size}});
    Json snapshots = Json::array();
    for (const auto& s : r.snapshots)
        snapshots.push_back({{"sid", s.sid}, {"object_sha256", s.object_sha256}, {"size", s.size}});

    Json producer = {{"node_id", r.producer.node_id}, {"software", r.producer.software}};
    putIfNum(producer, "vault_id", r.producer.vault_id);

    Json j = {{"type", std::string(kRootType)}, {"v", kDocumentVersion}, {"vault_uid", r.vault_uid},
              {"layout", r.layout}, {"epoch", r.epoch}, {"prev", nullable(r.prev)},
              {"published_at", r.published_at}, {"producer", std::move(producer)}, {"keys", std::move(keys)},
              {"segments", std::move(segments)}, {"snapshots", std::move(snapshots)},
              {"stats", {{"files", r.stats.files}, {"dirs", r.stats.dirs}, {"bytes", r.stats.bytes}}}};
    if (r.vault) {
        Json v = {{"name", r.vault->name}, {"created_at", nullable(r.vault->created_at)},
                  {"quota_bytes", r.vault->quota_bytes ? Json(*r.vault->quota_bytes) : Json(nullptr)}};
        putIf(v, "sync_strategy", r.vault->sync_strategy);
        if (r.vault->recovery_policy) {
            const auto& p = *r.vault->recovery_policy;
            v["recovery_policy"] = {{"mode", p.mode},
                                    {"retention", p.retention_days ? Json{{"days", *p.retention_days}} : Json(nullptr)}};
        }
        j["vault"] = std::move(v);
    }
    if (r.recovery_policy) {
        Json grants = Json::array();
        for (const auto& g : r.recovery_policy->grants) {
            Json gj = {{"grant_id", g.grant_id}, {"recipient_id", g.recipient_id}, {"class", g.recipient_class},
                       {"suite", g.suite}, {"revoked_at", nullable(g.revoked_at)}};
            putIf(gj, "label", g.label);
            putIf(gj, "added_at", g.added_at);
            putIf(gj, "authorized_by", g.authorized_by);
            grants.push_back(std::move(gj));
        }
        j["recovery_policy"] = {{"v", r.recovery_policy->v}, {"threshold", nullptr}, {"grants", std::move(grants)}};
    }
    return j;
}

RootDocument rootFromJson(const Json& j, const Uid& expectedVaultUid) {
    using namespace document_detail;
    const Fields f(j, kBadRoot, "root");
    checkType(f, kRootType);
    RootDocument r;
    r.vault_uid = f.str("vault_uid");
    checkVaultUid(f, r.vault_uid, expectedVaultUid);
    r.layout = f.str("layout");
    if (r.layout != kLayoutOpaqueV1) f.fail("names an unknown layout");
    r.epoch = f.u64("epoch");
    if (r.epoch == 0) f.fail("has epoch 0");
    if (!f.has("prev")) f.fail("is missing \"prev\"");
    r.prev = f.optStr("prev");
    if ((r.epoch == 1) != !r.prev) f.fail("prev must be null exactly at epoch 1");
    if (r.prev && !isLowerHex(*r.prev, 64)) f.fail("prev is not a SHA-256");
    r.published_at = f.str("published_at");

    const Fields p(f.at("producer"), kBadRoot, "producer");
    r.producer = Producer{p.str("node_id"), p.optU64("vault_id"), p.str("software")};

    if (f.present("vault")) {
        const Fields v(f.at("vault"), kBadRoot, "vault");
        VaultInfo info;
        info.name = v.str("name");
        info.created_at = v.optStr("created_at");
        info.quota_bytes = v.optU64("quota_bytes");
        info.sync_strategy = v.optStr("sync_strategy");
        if (v.present("recovery_policy")) {
            const Fields rp(v.at("recovery_policy"), kBadRoot, "vault recovery policy");
            FileRecovery fr{rp.str("mode"), std::nullopt};
            if (rp.present("retention")) {
                const Fields ret(rp.at("retention"), kBadRoot, "retention");
                fr.retention_days = ret.optU32("days");
            }
            info.recovery_policy = std::move(fr);
        }
        r.vault = std::move(info);
    }

    uint32_t lastVersion = 0;
    for (const auto& item : f.array("keys")) {
        const Fields k(item, kBadRoot, "key");
        KeyRecord rec;
        rec.version = k.u32("version");
        if (rec.version <= lastVersion) f.fail("lists key versions out of order or twice");
        lastVersion = rec.version;
        rec.key_check = k.optStr("key_check");
        if (rec.key_check && !isLowerHex(*rec.key_check, 32)) f.fail("has a key check that is not 16 bytes of hex");
        if (k.present("attestation")) {
            const Fields a(k.at("attestation"), kBadRoot, "attestation");
            rec.attestation = KeyAttestation{a.u32("key_id"), a.optStr("public_key"), a.str("signature")};
        }
        rec.created_at = k.optStr("created_at");
        rec.retired_at = k.optStr("retired_at");
        if (const auto* env = k.optArray("envelopes")) {
            std::vector<std::string> kids;
            for (const auto& e : *env) {
                if (!e.is_string()) f.fail("has an envelope id that is not a string");
                kids.push_back(e.get<std::string>());
            }
            rec.envelopes = std::move(kids);
        }
        r.keys.push_back(std::move(rec));
    }

    if (f.present("recovery_policy")) {
        const Fields rp(f.at("recovery_policy"), kBadRoot, "recovery policy");
        RecoveryPolicy policy;
        policy.v = rp.u32("v");
        // A policy of another version, or one that uses the reserved threshold, is a design this reader doesn't
        // know: kept as "not understood" with no usable grants, never a reason to refuse the root (§5.7).
        policy.understood = policy.v == kRecoveryPolicyVersion && !rp.present("threshold");
        if (policy.understood) {
            for (const auto& item : rp.array("grants")) {
                const Fields g(item, kBadRoot, "grant");
                Grant grant;
                grant.grant_id = g.str("grant_id");
                grant.recipient_id = g.str("recipient_id");
                grant.recipient_class = g.str("class");
                grant.suite = g.u32("suite");
                grant.label = g.optStr("label");
                grant.added_at = g.optStr("added_at");
                grant.authorized_by = g.optStr("authorized_by");
                grant.revoked_at = g.optStr("revoked_at");
                policy.grants.push_back(std::move(grant));
            }
        }
        r.recovery_policy = std::move(policy);
    }

    std::set<std::string> sids;
    int nextLo = 0;
    for (const auto& item : f.array("segments")) {
        const Fields s(item, kBadRoot, "segment reference");
        SegmentRef ref;
        ref.sid = s.str("sid");
        (void)parseUid(ref.sid, kBadRoot, "segment sid");
        if (!sids.insert(ref.sid).second) f.fail("names a segment twice");
        ref.range = parseRange(s.at("range"), s);
        if (ref.range.lo != nextLo) f.fail("has segment ranges with a gap or overlap");
        nextLo = ref.range.hi + 1;
        ref.count = s.u64("count");
        ref.object_sha256 = s.str("object_sha256");
        if (!isLowerHex(ref.object_sha256, 64)) f.fail("has a segment hash that is not a SHA-256");
        ref.size = s.u64("size");
        r.segments.push_back(std::move(ref));
    }
    if (nextLo != 0x100) f.fail("has segment ranges that don't cover 00..ff");

    for (const auto& item : f.array("snapshots")) {
        const Fields s(item, kBadRoot, "snapshot reference");
        SnapshotRef ref{s.str("sid"), s.str("object_sha256"), s.u64("size")};
        (void)parseUid(ref.sid, kBadRoot, "snapshot sid");
        if (!sids.insert(ref.sid).second) f.fail("names a segment twice");
        if (!isLowerHex(ref.object_sha256, 64)) f.fail("has a snapshot hash that is not a SHA-256");
        r.snapshots.push_back(std::move(ref));
    }

    const Fields st(f.at("stats"), kBadRoot, "stats");
    r.stats = Stats{st.u64("files"), st.u64("dirs"), st.u64("bytes")};
    return r;
}

std::string canonicalJson(const Json& j) { return j.dump(-1, ' ', false, Json::error_handler_t::strict); }

std::string isoTime(const std::time_t t) {
    std::tm tm{};
    gmtime_r(&t, &tm);
    return fmt::format("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour,
                       tm.tm_min, tm.tm_sec);
}

}
