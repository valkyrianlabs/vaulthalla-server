// Encrypted manifest v2 (#368, WS3-a; design/encryption/03-metadata-recovery.md §3-§4, §8), DB-free.
//
// ManifestVectors   every manifest vector of vectors.json (objects, chain, negative): the C++ reader agrees with the
//                   reference, and the documents re-encode to the vectors' bytes.
// ManifestDocument  the root/segment/snapshot schema: round trips, unknown members, the extensible recovery_policy,
//                   structural refusals.
// ManifestPartition segment split/merge rules.
// ManifestPublish*  the publish protocol on the versioned fake bucket: CoW order, costs, If-Match conflicts merged,
//                   GC keeping the last three roots' segments, prior names, a missing root rebuilt.
// ManifestChain*    rollback, fork, gap (walked and not), missing/mismatched segments and every fallback, the blind
//                   rebuild floor.
// ManifestContent   everything a vault's content holds survives publish → bucket → load (the DB half is
//                   test_manifest_db.cpp).
// ManifestReplay*   an older complete state authenticates; without a checkpoint the report says "freshness
//                   unverified"; with one, older states are refused (spec 03 §4.5).

#include "crypto/SecretKey.hpp"
#include "crypto/vhf1/Format.hpp"
#include "crypto/vhf1/Writer.hpp"
#include "sync/manifest/Chain.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Partition.hpp"
#include "sync/manifest/Publisher.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Store.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vh::sync::manifest::test_manifest_suite {

namespace {

using Bytes = std::vector<uint8_t>;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using crypto::SecretKey;
using crypto::SecretKeyPtr;

// ---- vectors -------------------------------------------------------------------------------------------------------

const Json& vectors() {
    static const Json doc = [] {
        const auto path = std::filesystem::path(VH_TEST_VECTORS_DIR) / "vectors.json";
        std::ifstream in(path);
        if (!in) throw std::runtime_error("missing golden vectors: " + path.string());
        return Json::parse(in);
    }();
    return doc;
}

Bytes fromHex(const std::string& hex) {
    Bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return out;
}

Uid uidFromHex(const std::string& hex) {
    const auto raw = fromHex(hex);
    Uid out{};
    std::copy(raw.begin(), raw.end(), out.begin());
    return out;
}

crypto::vhf1::KeyLookup lookupOf(std::map<uint32_t, SecretKeyPtr> keys) {
    return [keys = std::move(keys)](const uint32_t v) -> SecretKeyPtr {
        const auto it = keys.find(v);
        return it == keys.end() ? nullptr : it->second;
    };
}

std::map<uint32_t, SecretKeyPtr> vectorKeys() {
    std::map<uint32_t, SecretKeyPtr> keys;
    for (const auto& [version, hex] : vectors()["conventions"]["keys"].items())
        keys[static_cast<uint32_t>(std::stoul(version))] = std::make_shared<const SecretKey>(fromHex(hex.get<std::string>()));
    return keys;
}

const Uid& vectorVaultUid() {
    static const Uid uid = uidFromHex(vectors()["vhf1"]["positive"][0]["params"]["vault_uid_hex"].get<std::string>());
    return uid;
}

const Json& vectorObject(const std::string& name) {
    for (const auto& o : vectors()["manifest"]["objects"])
        if (o["name"] == name) return o;
    throw std::runtime_error("no manifest object " + name);
}

// ---- fixtures ------------------------------------------------------------------------------------------------------

SecretKeyPtr keyOf(const uint8_t seed) {
    Bytes k(32);
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i);
    return std::make_shared<const SecretKey>(k);
}

Uid uidOf(const uint8_t first, const uint8_t fill) {
    Uid u{};
    u.fill(fill);
    u[0] = first;
    return u;
}

std::string uidT(const uint8_t first, const uint8_t fill) { return uidText(uidOf(first, fill)); }

Entry dirEntry(const std::string& uid, std::optional<std::string> parent, std::string name) {
    Entry e;
    e.uid = uid;
    e.kind = EntryKind::Dir;
    e.parent = std::move(parent);
    e.name = std::move(name);
    e.mode = 0755;
    e.mtime = "2026-11-05T12:00:00Z";
    return e;
}

Entry fileEntry(const std::string& uid, const std::string& parent, std::string name, const uint64_t size) {
    Entry e;
    e.uid = uid;
    e.kind = EntryKind::File;
    e.parent = parent;
    e.name = std::move(name);
    e.mode = 0644;
    e.mtime = "2026-11-05T12:01:00Z";
    e.size = size;
    e.format = 1;
    e.key_version = 1;
    e.object = ObjectRef{"\"etag-" + e.uid.substr(0, 6) + "\"", size + 136, std::nullopt, std::nullopt};
    return e;
}

const std::string kRootUid = uidT(0x01, 0x11);
const std::string kReportsUid = uidT(0x80, 0x22);

// A vault with every kind of fact the manifest carries.
Content richContent() {
    Content c;
    c.producer = {"8f14e45f-ceea-467a-9575-0c6d2b6a1b8a", 42, "vaulthalla test"};
    c.vault = VaultInfo{"Finance", "2026-10-01T00:00:00Z", std::nullopt, "cache",
                        FileRecovery{"provider_versioning", 90}};
    c.keys = {KeyRecord{1, "72e4c8b7f8ab43b8ed8869a57cef1703",
                        KeyAttestation{3, "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=", std::string(86, 'A') + "=="},
                        "2026-10-01T00:00:00Z", "2026-11-01T00:00:00Z", std::nullopt, std::nullopt},
              KeyRecord{2, std::nullopt, std::nullopt, "2026-11-01T00:00:00Z", std::nullopt, std::nullopt, std::nullopt}};
    c.recovery_policy = RecoveryPolicy{};
    c.entries.push_back(dirEntry(kRootUid, std::nullopt, ""));
    c.entries.push_back(dirEntry(kReportsUid, kRootUid, "Reports"));
    auto pdf = fileEntry(uidT(0x40, 0x33), kReportsUid, "Q3 board pack.pdf", 3172);
    pdf.mime = "application/pdf";
    pdf.owner = Owner{1000, 1000};
    pdf.versions = {FileVersion{"v2", std::nullopt, 1, 3308, "\"e2\"", "2026-11-05T12:01:00Z", std::nullopt, false, std::nullopt},
                    FileVersion{"v1", std::nullopt, 1, 3300, "\"e1\"", "2026-11-04T12:00:00Z", "2026-11-05T12:01:00Z",
                                false, std::nullopt}};
    pdf.names = {PriorName{"2026-11-05T00:00:00Z", kRootUid, "draft.pdf"}};
    c.entries.push_back(pdf);
    Entry link;
    link.uid = uidT(0xc0, 0x44);
    link.kind = EntryKind::Symlink;
    link.parent = kReportsUid;
    link.name = "latest";
    link.target = "Reports/Q3 board pack.pdf";
    c.entries.push_back(link);
    auto trashed = fileEntry(uidT(0xd0, 0x55), kReportsUid, "old.txt", 12);
    trashed.trashed = Trashed{"2026-11-05T11:00:00Z", "admin", "/Reports/old.txt"};
    c.entries.push_back(trashed);
    Entry tomb;
    tomb.uid = uidT(0xe0, 0x66);
    tomb.kind = EntryKind::Tombstone;
    tomb.name = "purged.bin";
    tomb.versions = {FileVersion{"v9", std::nullopt, 1, 200, "\"e9\"", "2026-11-03T00:00:00Z", std::nullopt, false, std::nullopt}};
    c.entries.push_back(tomb);
    c.snapshots = {SnapshotRecord{7, "before audit", "2026-11-05T10:00:00Z", "/Reports",
                                  {SnapshotMember{uidT(0x40, 0x33), "/Reports/Q3 board pack.pdf", std::nullopt, 1, "v1", true},
                                   SnapshotMember{std::nullopt, "/Reports/gone.txt", std::nullopt, 1, std::nullopt, false}}}};
    normalize(c);
    return c;
}

// The publish protocol against the versioned fake bucket, through the production S3 adapter.
struct Writer {
    std::shared_ptr<VersionedBucket> bucket;
    std::shared_ptr<S3Store> store;
    Uid vault = uidOf(0x56, 0x48);
    std::map<uint32_t, SecretKeyPtr> keys{{1, keyOf(1)}, {2, keyOf(40)}};
    uint32_t current = 2;
    PublisherCache cache;
    std::optional<Known> known;
    int clock = 0;

    explicit Writer(std::shared_ptr<VersionedBucket> b) : bucket(std::move(b)), store(std::make_shared<S3Store>(bucket)) {}
    explicit Writer(const Versioning v = Versioning::Enabled) : Writer(std::make_shared<VersionedBucket>(v)) {}

    [[nodiscard]] crypto::vhf1::KeyLookup lookup() const { return lookupOf(keys); }

    PublishReport publish(const Content& c, const PartitionLimits& limits = {}) {
        PublishOptions o;
        o.now = isoTime(1793880000 + 60 * (++clock));
        o.limits = limits;
        auto r = manifest::publish(*store, vault, lookup(), {current, keys.at(current)}, c, known, cache, o);
        known = r.published.known;
        return r;
    }

    Loaded loadKnown() {
        LoadOptions o;
        o.known = known;
        return load(*store, vault, lookup(), o);
    }
};

std::string rootBytesSha(const VersionedBucket& b) {
    const auto v = b.current(std::string(kRootKey));
    return v ? sha256Hex(v->body) : std::string{};
}

Content smallVault(const std::size_t files, const uint8_t salt = 0) {
    Content c;
    c.producer = {"node", 1, "vaulthalla test"};
    c.recovery_policy = RecoveryPolicy{};
    c.keys = {KeyRecord{2, std::nullopt, std::nullopt, "2026-11-01T00:00:00Z", std::nullopt, std::nullopt, std::nullopt}};
    c.entries.push_back(dirEntry(kRootUid, std::nullopt, ""));
    for (std::size_t i = 0; i < files; ++i) {
        Uid u{};
        u.fill(static_cast<uint8_t>(i * 7 + salt));
        u[0] = static_cast<uint8_t>((i * 37) & 0xff);
        u[1] = static_cast<uint8_t>(i >> 8);
        u[2] = static_cast<uint8_t>(i);
        c.entries.push_back(fileEntry(uidText(u), kRootUid, "file-" + std::to_string(i), 100 + i));
    }
    normalize(c);
    return c;
}

// The n-th file of a content (entries are in uid order; the vault root sits among them).
Entry& nthFile(Content& c, const std::size_t n) {
    std::size_t seen = 0;
    for (auto& e : c.entries)
        if (e.kind == EntryKind::File && seen++ == n) return e;
    throw std::out_of_range("no such file");
}

}

// ── ManifestVectors ──────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestVectors, ObjectsOpenAndReencodeToTheirPlaintext) {
    const auto keys = lookupOf(vectorKeys());
    for (const auto& o : vectors()["manifest"]["objects"]) {
        SCOPED_TRACE(o["name"].get<std::string>());
        const auto object = fromHex(o["object_hex"].get<std::string>());
        const auto objectUid = uidFromHex(o["object_uid_hex"].get<std::string>());
        if (o.contains("object_sha256")) { EXPECT_EQ(sha256Hex(object), o["object_sha256"].get<std::string>()); }
        const auto plaintext = o["plaintext_utf8"].get<std::string>();
        if (o["kind"].get<int>() == 3) {
            EXPECT_EQ(o["object_key"].get<std::string>(), kRootKey);
            EXPECT_EQ(objectUid, vectorVaultUid());
            const auto root = openRoot(object, vectorVaultUid(), keys);
            EXPECT_EQ(canonicalJson(toJson(root)), plaintext);
            EXPECT_EQ(rootFromJson(Json::parse(plaintext), vectorVaultUid()), root);
        } else {
            ASSERT_EQ(o["kind"].get<int>(), 2);
            const auto key = o["object_key"].get<std::string>();
            const auto sid = sidOfKey(key);
            ASSERT_TRUE(sid);
            EXPECT_EQ(parseUid(*sid, "bad_root", "sid"), objectUid);
            const auto seg = openSegment(object, vectorVaultUid(), objectUid, keys);
            EXPECT_EQ(canonicalJson(toJson(seg)), plaintext);
        }
    }
}

TEST(ManifestVectors, ChainCasesMatchTheReference) {
    const auto keys = lookupOf(vectorKeys());
    const Json seg = vectorObject("segment_1");
    const auto segSid = *sidOfKey(seg["object_key"].get<std::string>());
    std::size_t warnings = 0;
    for (const auto& c : vectors()["manifest"]["chain"]) {
        SCOPED_TRACE(c["name"].get<std::string>());
        const Bytes rootObject = c.contains("root_hex") ? fromHex(c["root_hex"].get<std::string>())
                                                        : fromHex(vectorObject(c["root"].get<std::string>())["object_hex"].get<std::string>());
        const auto root = openRoot(rootObject, vectorVaultUid(), keys);
        if (c.contains("root_plaintext_utf8")) { EXPECT_EQ(canonicalJson(toJson(root)), c["root_plaintext_utf8"].get<std::string>()); }
        std::map<std::string, Bytes> segments{{segSid, fromHex(seg["object_hex"].get<std::string>())}};
        if (c.contains("segments_override")) {
            segments.clear();
            for (const auto& [sid, hex] : c["segments_override"].items()) segments[sid] = fromHex(hex.get<std::string>());
        }
        std::optional<Known> known;
        if (!c["known"].is_null())
            known = Known{c["known"]["epoch"].get<uint64_t>(), c["known"]["root_sha256"].get<std::string>()};

        Json got;
        try {
            const auto a = acceptRoot(root, rootObject, known, segments);
            got = {{"epoch", a.epoch}, {"root_sha256", a.root_sha256}};
            if (a.gap) {
                got["warning"] = "gap";
                ++warnings;
            }
        } catch (const ChainRejected& e) {
            got = {{"error", std::string(chainErrorName(e.code()))}};
        }
        EXPECT_EQ(got, c["expect"]);
    }
    EXPECT_GE(warnings, 1u) << "the vectors carry a gap case";
}

TEST(ManifestVectors, NegativesFailClosed) {
    const auto keys = lookupOf(vectorKeys());
    for (const auto& n : vectors()["manifest"]["negative"]) {
        SCOPED_TRACE(n["name"].get<std::string>());
        const auto object = fromHex(n["object_hex"].get<std::string>());
        const auto kind = static_cast<crypto::vhf1::Kind>(n["expect_kind"].get<int>());
        const auto uid = uidFromHex(n["expect_object_uid_hex"].get<std::string>());
        std::optional<std::string> error;
        try {
            if (kind == crypto::vhf1::Kind::ManifestRoot) (void)openRoot(object, vectorVaultUid(), keys);
            else (void)openSegment(object, vectorVaultUid(), uid, keys);
        } catch (const crypto::vhf1::Error& e) {
            error = std::string(crypto::vhf1::errorCodeName(e.code()));
        }
        ASSERT_TRUE(error) << "accepted";
        EXPECT_EQ(*error, n["expect"]["error"].get<std::string>());
    }
}

TEST(ManifestVectors, EveryChainErrorNameIsKnown) {
    for (const auto& c : vectors()["manifest"]["chain"])
        if (c["expect"].contains("error")) {
            EXPECT_TRUE(chainErrorFromName(c["expect"]["error"].get<std::string>()))
                << c["expect"]["error"].get<std::string>();
        }
}

// ── ManifestDocument ─────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestDocument, RichRootSegmentAndSnapshotRoundTrip) {
    const auto content = richContent();
    const Uid vault = uidOf(0x56, 0x48);
    RootDocument root;
    root.vault_uid = uidText(vault);
    root.epoch = 2;
    root.prev = std::string(64, 'a');
    root.published_at = "2026-11-05T12:02:00Z";
    root.producer = content.producer;
    root.vault = content.vault;
    root.keys = content.keys;
    root.keys[1].envelopes = std::vector<std::string>{"abcdefghjkmnpqrstvwxyz0123"};
    root.recovery_policy = RecoveryPolicy{1, true, {Grant{"g1", std::string(64, 'b'), "customer", 1, "Recovery kit",
                                                           "2026-11-01T00:00:00Z", "device-3", std::nullopt, std::nullopt}}};
    root.segments = {SegmentRef{uidT(0x10, 0x01), {0x00, 0x7f}, 3, std::string(64, 'c'), 900},
                     SegmentRef{uidT(0x10, 0x02), {0x80, 0xff}, 4, std::string(64, 'd'), 1200}};
    root.snapshots = {SnapshotRef{uidT(0x10, 0x03), std::string(64, 'e'), 400}};
    root.stats = statsOf(content);
    const auto text = canonicalJson(toJson(root));
    EXPECT_EQ(rootFromJson(Json::parse(text), vault), root);
    EXPECT_EQ(canonicalJson(toJson(rootFromJson(Json::parse(text), vault))), text);

    SegmentDocument seg{uidText(vault), {0x00, 0xff}, content.entries};
    const auto segText = canonicalJson(toJson(seg));
    EXPECT_EQ(segmentFromJson(Json::parse(segText), vault), seg);

    SnapshotDocument snap{uidText(vault), content.snapshots[0]};
    EXPECT_EQ(snapshotFromJson(Json::parse(canonicalJson(toJson(snap))), vault), snap);

    EXPECT_EQ(root.stats, (Stats{1, 2, 3172}));  // the trashed file and the tombstone are not live files
}

TEST(ManifestDocument, ReadersIgnoreUnknownMembersAndKeepUnknownGrantsUnusable) {
    const Uid vault = uidOf(0x56, 0x48);
    auto j = toJson(RootDocument{uidText(vault), std::string(kLayoutOpaqueV1), 1, std::nullopt, "t", {"n", 1, "s"},
                                 std::nullopt, {}, RecoveryPolicy{}, {SegmentRef{uidT(1, 1), {0, 255}, 0, std::string(64, 'f'), 1}},
                                 {}, {}});
    j["future_member"] = {{"anything", true}};
    j["recovery_policy"]["grants"] = Json::array(
        {{{"grant_id", "g-cust"}, {"recipient_id", std::string(64, '1')}, {"class", "customer"}, {"suite", 1},
          {"revoked_at", nullptr}},
         {{"grant_id", "g-cust-revoked"}, {"recipient_id", std::string(64, '2')}, {"class", "customer"}, {"suite", 1},
          {"revoked_at", "2026-11-04T00:00:00Z"}},
         {{"grant_id", "g-future"}, {"recipient_id", std::string(64, '3')}, {"class", "custodian"}, {"suite", 3},
          {"revoked_at", nullptr}, {"participant_share", 2}}});
    const auto root = rootFromJson(j, vault);
    ASSERT_TRUE(root.recovery_policy);
    ASSERT_EQ(root.recovery_policy->grants.size(), 3u);
    EXPECT_TRUE(root.recovery_policy->grants[0].usableForDecryption());
    EXPECT_FALSE(root.recovery_policy->grants[1].usableForDecryption());  // revoked
    EXPECT_FALSE(root.recovery_policy->grants[2].usableForDecryption());  // a class this reader doesn't know

    // A later policy version, or the reserved threshold in use: not understood, nothing usable, the root still loads.
    for (const auto& [v, threshold] : {std::pair{Json(2), Json(nullptr)}, std::pair{Json(1), Json(2)}}) {
        auto k = j;
        k["recovery_policy"]["v"] = v;
        k["recovery_policy"]["threshold"] = threshold;
        const auto r = rootFromJson(k, vault);
        ASSERT_TRUE(r.recovery_policy);
        EXPECT_FALSE(r.recovery_policy->understood);
        EXPECT_TRUE(r.recovery_policy->grants.empty());
    }
}

TEST(ManifestDocument, StructuralRefusals) {
    const Uid vault = uidOf(0x56, 0x48);
    RootDocument good{uidText(vault), std::string(kLayoutOpaqueV1), 2, std::string(64, 'a'), "t", {"n", 1, "s"},
                      std::nullopt, {}, std::nullopt,
                      {SegmentRef{uidT(1, 1), {0x00, 0x7f}, 0, std::string(64, 'f'), 1},
                       SegmentRef{uidT(1, 2), {0x80, 0xff}, 0, std::string(64, 'f'), 1}},
                      {}, {}};
    ASSERT_NO_THROW((void)rootFromJson(toJson(good), vault));
    const auto refuses = [&](const std::function<void(Json&)>& mutate, const std::string& why) {
        auto j = toJson(good);
        mutate(j);
        try {
            (void)rootFromJson(j, vault);
            ADD_FAILURE() << "accepted: " << why;
        } catch (const FormatError& e) {
            EXPECT_EQ(e.code(), "bad_root") << why;
        }
    };
    refuses([](Json& j) { j["type"] = "vh.manifest.segment"; }, "another document type");
    refuses([](Json& j) { j["v"] = 2; }, "an unknown version");
    refuses([](Json& j) { j["epoch"] = 0; }, "epoch 0");
    refuses([](Json& j) { j["prev"] = nullptr; }, "no prev after epoch 1");
    refuses([](Json& j) { j["epoch"] = 1; }, "a prev at epoch 1");
    refuses([&](Json& j) { j["vault_uid"] = uidT(9, 9); }, "another vault");
    refuses([](Json& j) { j["segments"][1]["range"] = Json::array({"7f", "ff"}); }, "overlapping ranges");
    refuses([](Json& j) { j["segments"][1]["range"] = Json::array({"81", "ff"}); }, "a gap in the ranges");
    refuses([](Json& j) { j["segments"].erase(1); }, "ranges that don't reach ff");
    refuses([](Json& j) { j["segments"][1]["sid"] = j["segments"][0]["sid"]; }, "a sid named twice");
    refuses([](Json& j) { j["segments"][0]["sid"] = "NOT-BASE32"; }, "a malformed sid");
    refuses([](Json& j) { j["layout"] = "PathV0"; }, "another layout");

    SegmentDocument seg{uidText(vault), {0x00, 0x7f}, {dirEntry(uidT(0x90, 1), std::nullopt, "")}};
    try {
        (void)segmentFromJson(toJson(seg), vault);
        ADD_FAILURE() << "an entry outside the segment's range was accepted";
    } catch (const FormatError& e) {
        EXPECT_EQ(e.code(), "bad_segment");
    }
}

TEST(ManifestDocument, SealedObjectsBindKindVaultAndObjectUid) {
    const Uid vault = uidOf(0x56, 0x48);
    const auto keys = lookupOf({{2, keyOf(40)}});
    SegmentDocument seg{uidText(vault), {0x00, 0xff}, {}};
    const auto sid = uidOf(0x20, 0x20);
    const auto bytes = sealSegment(seg, vault, sid, {2, keyOf(40)});
    EXPECT_EQ(openSegment(bytes, vault, sid, keys), seg);
    const auto codeOf = [&](auto&& f) -> std::string {
        try {
            f();
        } catch (const crypto::vhf1::Error& e) {
            return std::string(crypto::vhf1::errorCodeName(e.code()));
        }
        return "accepted";
    };
    EXPECT_EQ(codeOf([&] { (void)openRoot(bytes, vault, keys); }), "kind_mismatch");
    EXPECT_EQ(codeOf([&] { (void)openSegment(bytes, vault, uidOf(0x20, 0x21), keys); }), "object_mismatch");
    EXPECT_EQ(codeOf([&] { (void)openSegment(bytes, uidOf(0x57, 0x48), sid, keys); }), "vault_mismatch");
    EXPECT_EQ(codeOf([&] { (void)openSegment(bytes, vault, sid, lookupOf({})); }), "key_unavailable");
}

// ── ManifestPartition ────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestPartition, SplitsAboveTheLimitsAndMergesBelowWithinThem) {
    const PartitionLimits limits{8, 1u << 20, 2};
    const auto c = smallVault(30);
    const auto plan = partition(c.entries, {}, "v", limits);
    ASSERT_GT(plan.size(), 1u);
    int next = 0;
    std::size_t total = 0;
    for (const auto& p : plan) {
        EXPECT_EQ(p.doc.range.lo, next);
        next = p.doc.range.hi + 1;
        EXPECT_LE(p.doc.entries.size(), limits.split_entries);
        total += p.doc.entries.size();
        for (const auto& e : p.doc.entries) { EXPECT_TRUE(p.doc.range.contains(parseUid(e.uid, "x", "uid"))); }
    }
    EXPECT_EQ(next, 0x100);
    EXPECT_EQ(total, c.entries.size());

    // Shrunk to a few entries, the same ranges merge back (each merge stays within the split limits).
    const auto shrunk = smallVault(3);
    std::vector<Range> ranges;
    for (const auto& p : plan) ranges.push_back(p.doc.range);
    const auto merged = partition(shrunk.entries, ranges, "v", limits);
    EXPECT_LT(merged.size(), plan.size());
    for (const auto& p : merged) { EXPECT_LE(p.doc.entries.size(), limits.split_entries); }

    // Bytes count too: one big entry over the byte limit splits its range.
    const auto bytesPlan = partition(c.entries, {}, "v", PartitionLimits{100000, 2000, 1});
    EXPECT_GT(bytesPlan.size(), 1u);
    EXPECT_EQ(partition({}, {}, "v").size(), 1u) << "an empty vault is one empty segment";
}

// ── ManifestPublish ──────────────────────────────────────────────────────────────────────────────────────────────

// A store that records the order of writes.
class RecordingStore final : public ObjectStore {
public:
    explicit RecordingStore(ObjectStore& inner) : inner_(inner) {}
    std::vector<std::string> writes;

    std::optional<StoredObject> get(const std::string& k, const std::optional<std::string>& v) override { return inner_.get(k, v); }
    std::optional<Bytes> getRange(const std::string& k, uint64_t o, uint64_t l) override { return inner_.getRange(k, o, l); }
    std::string putIfAbsent(const std::string& k, const Bytes& b) override {
        writes.push_back("put-if-absent " + k);
        return inner_.putIfAbsent(k, b);
    }
    std::string putIfMatch(const std::string& k, const Bytes& b, const std::string& e) override {
        writes.push_back("put-if-match " + k);
        return inner_.putIfMatch(k, b, e);
    }
    std::vector<ListedObject> list(const std::string& p) override { return inner_.list(p); }
    std::vector<StoredVersion> versions(const std::string& k) override { return inner_.versions(k); }
    void remove(const std::string& k) override {
        writes.push_back("delete " + k);
        inner_.remove(k);
    }

private:
    ObjectStore& inner_;
};

TEST(ManifestPublish, SegmentsBeforeRootAndTheRootIsConditional) {
    Writer w;
    RecordingStore rec(*w.store);
    PublishOptions o;
    o.now = "2026-11-05T12:00:00Z";
    const auto content = richContent();
    auto r = publish(rec, w.vault, w.lookup(), {2, w.keys.at(2)}, content, std::nullopt, w.cache, o);
    ASSERT_GE(rec.writes.size(), 3u);
    EXPECT_EQ(rec.writes.back(), "put-if-absent .vaulthalla/root") << "epoch 1 is If-None-Match: *";
    for (std::size_t i = 0; i + 1 < rec.writes.size(); ++i) {
        EXPECT_TRUE(rec.writes[i].starts_with("put-if-absent .vaulthalla/seg/") ||
                    rec.writes[i] == "put-if-absent .vaulthalla/layout.json")
            << rec.writes[i];
    }
    EXPECT_EQ(r.published.known.epoch, 1u);
    EXPECT_FALSE(r.published.root.prev);
    EXPECT_EQ(r.published.known.root_sha256, rootBytesSha(*w.bucket));
    // The cleartext hint names only the layout and the vault uid.
    const auto hint = w.bucket->current(std::string(kLayoutKey));
    ASSERT_TRUE(hint);
    EXPECT_EQ(std::string(hint->body.begin(), hint->body.end()), layoutHint(w.vault));
    for (const auto& key : w.bucket->keys()) { EXPECT_TRUE(w.bucket->current(key)->meta.empty()) << key << " carries x-amz-meta"; }

    // Epoch 2 replaces it with If-Match on the root's ETag and chains prev.
    w.known = r.published.known;
    rec.writes.clear();
    auto next = content;
    nthFile(next, 0).size = 9999;
    o.now = "2026-11-05T12:01:00Z";
    const auto r2 = publish(rec, w.vault, w.lookup(), {2, w.keys.at(2)}, next, w.known, w.cache, o);
    EXPECT_EQ(rec.writes.back(), "put-if-match .vaulthalla/root");
    EXPECT_EQ(r2.published.known.epoch, 2u);
    EXPECT_EQ(r2.published.root.prev, r.published.known.root_sha256);
}

TEST(ManifestPublish, OneFileChangeCostsOneSegmentAndOneRootPut) {
    Writer w;
    auto c = smallVault(200);
    (void)w.publish(c);
    w.bucket->resetCounters();
    nthFile(c, 50).size = 4242;
    const auto r = w.publish(c);
    const auto n = w.bucket->counters();
    EXPECT_EQ(n.put, 2u) << "one segment PUT + one root PUT";
    EXPECT_EQ(n.get, 0u) << "the cache holds the previous publish";
    EXPECT_EQ(n.list, 0u);
    EXPECT_EQ(r.segments_written, 1u);
    EXPECT_EQ(r.attempts, 1u);
}

TEST(ManifestPublish, OneFileChangeInALargeVaultRewritesOnlyItsSegment) {
    Writer w;
    const PartitionLimits limits{64, 1u << 20, 16};
    auto c = smallVault(600);
    const auto first = w.publish(c, limits);
    ASSERT_GT(first.published.root.segments.size(), 4u);
    w.bucket->resetCounters();
    nthFile(c, 123).name = "renamed";
    const auto r = w.publish(c, limits);
    EXPECT_EQ(w.bucket->counters().put, 2u);
    EXPECT_EQ(r.segments_written, 1u);
    EXPECT_EQ(r.segments_reused, first.published.root.segments.size() - 1);
}

TEST(ManifestPublish, AFolderRenameChangesOneEntry) {
    Writer w;
    const PartitionLimits limits{64, 1u << 20, 16};
    auto c = smallVault(400);
    for (auto& e : c.entries)
        if (e.parent) e.parent = kReportsUid;
    c.entries.push_back(dirEntry(kReportsUid, kRootUid, "Reports"));
    normalize(c);
    (void)w.publish(c, limits);
    w.bucket->resetCounters();
    for (auto& e : c.entries)
        if (e.uid == kReportsUid) e.name = "Reports 2026";
    const auto r = w.publish(c, limits);
    EXPECT_EQ(r.segments_written, 1u) << "the tree is parent + name: only the folder's entry changes";
    EXPECT_EQ(w.bucket->counters().put, 2u);
}

TEST(ManifestPublish, ConflictReloadsVerifiesMergesAndRetriesWithIfMatch) {
    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    Writer a(bucket), b(bucket);
    b.vault = a.vault;
    b.keys = a.keys;
    auto base = smallVault(10);
    (void)a.publish(base);
    b.known = a.known;  // both know epoch 1
    (void)b.publish(base);  // b builds its cache: epoch 2, nothing changed but a fresh root

    // a adds a file, b (stale: knows epoch 2 from its own publish, a hasn't seen it) changes another one.
    a.known = b.known;
    a.cache = {};
    auto aContent = base;
    aContent.entries.push_back(fileEntry(uidT(0x77, 0x77), kRootUid, "from-a.txt", 5));
    normalize(aContent);
    (void)a.publish(aContent);  // epoch 3

    auto bContent = base;
    nthFile(bContent, 3).name = "changed-by-b";
    const auto r = b.publish(bContent);  // its If-Match fails, it loads epoch 3, verifies, merges, publishes epoch 4
    EXPECT_EQ(r.attempts, 2u);
    EXPECT_TRUE(r.merged);
    EXPECT_EQ(r.published.known.epoch, 4u);
    EXPECT_EQ(r.published.root.prev, a.known->root_sha256);

    const auto loaded = b.loadKnown();
    std::set<std::string> names;
    for (const auto& e : loaded.content.entries) names.insert(e.name);
    EXPECT_TRUE(names.contains("from-a.txt")) << "the other writer's addition survives";
    EXPECT_TRUE(names.contains("changed-by-b")) << "our pending change is on top";
}

TEST(ManifestPublish, AConflictingRootThatForksIsNeverOverwritten) {
    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    Writer a(bucket);
    (void)a.publish(smallVault(3));
    const auto known1 = *a.known;
    // Someone puts an authentic root at epoch 2 that does not follow epoch 1 (prev = another hash).
    RootDocument forged = a.cache.base->root;
    forged.epoch = 2;
    forged.prev = std::string(64, '0');
    bucket->seed(std::string(kRootKey), sealRoot(forged, a.vault, {2, a.keys.at(2)}));
    const auto before = rootBytesSha(*bucket);
    try {
        (void)a.publish(smallVault(4));
        ADD_FAILURE() << "published over a fork";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Fork);
        EXPECT_EQ(e.epoch(), 2u);
    }
    EXPECT_EQ(rootBytesSha(*bucket), before);
    EXPECT_EQ(*a.known, known1);
}

TEST(ManifestPublish, GcKeepsTheLastThreeRootsSegmentsAndYoungOnes) {
    Writer w;
    auto c = smallVault(5);
    std::vector<std::vector<std::string>> rootSids;
    for (int i = 0; i < 5; ++i) {
        nthFile(c, 1).size = 1000 + i;
        rootSids.push_back(w.publish(c).published.sids());
    }
    std::set<std::string> retained;
    for (std::size_t i = rootSids.size() - 3; i < rootSids.size(); ++i) retained.insert(rootSids[i].begin(), rootSids[i].end());

    // Within 24 h nothing goes.
    auto early = collectGarbage(*w.store, retained, w.bucket->now());
    EXPECT_TRUE(early.deleted.empty());
    EXPECT_EQ(early.young, 2u);

    w.bucket->advance(25 * 60 * 60);
    const auto report = collectGarbage(*w.store, retained, w.bucket->now());
    EXPECT_EQ(report.deleted.size(), 2u) << "the first two roots' segments";
    EXPECT_EQ(report.retained, retained.size());
    for (const auto& sid : retained) { EXPECT_TRUE(w.bucket->current(segmentKey(sid))) << sid; }
    // Every retained root still loads with all its segments.
    EXPECT_TRUE(w.loadKnown().issues.empty());
}

TEST(ManifestPublish, PriorNamesAreCarriedAndBounded) {
    Writer w;
    auto c = richContent();
    (void)w.publish(c);
    auto& pdf = *std::ranges::find(c.entries, uidT(0x40, 0x33), &Entry::uid);
    pdf.names.clear();  // the database never holds names: the manifest carries them
    pdf.name = "Q3 final.pdf";
    pdf.parent = kRootUid;
    (void)w.publish(c);
    const auto loaded = w.loadKnown();
    const auto& got = *std::ranges::find(loaded.content.entries, uidT(0x40, 0x33), &Entry::uid);
    ASSERT_EQ(got.names.size(), 2u);
    EXPECT_EQ(got.names[0].name, "Q3 board pack.pdf");
    EXPECT_EQ(got.names[0].parent, kReportsUid);
    EXPECT_EQ(got.names[1].name, "draft.pdf");

    // Names older than the oldest retained version, or past 32, are dropped; no versions, no names.
    Content prev;
    Content next;
    Entry e = fileEntry(uidT(0x41, 1), kRootUid, "a", 1);
    e.versions = {FileVersion{"v", std::nullopt, 1, 1, std::nullopt, "2026-01-01T00:00:00Z", std::nullopt, false, std::nullopt}};
    for (int i = 0; i < 40; ++i) e.names.push_back({"2026-02-01T00:00:00Z", kRootUid, "n" + std::to_string(i)});
    e.names.push_back({"2025-12-01T00:00:00Z", kRootUid, "too-old"});
    prev.entries = {e};
    next.entries = {e};
    next.entries[0].name = "b";
    carryHistory(prev, next, "2026-03-01T00:00:00Z");
    EXPECT_EQ(next.entries[0].names.size(), kMaxPriorNames);
    EXPECT_EQ(next.entries[0].names.front().name, "a");
    for (const auto& n : next.entries[0].names) { EXPECT_NE(n.name, "too-old"); }
    next.entries[0].versions.clear();
    carryHistory(prev, next, "2026-03-01T00:00:00Z");
    EXPECT_TRUE(next.entries[0].names.empty());
}

TEST(ManifestPublish, AMissingRootIsRebuiltContinuingTheChain) {
    Writer w(Versioning::Unversioned);
    (void)w.publish(smallVault(3));
    (void)w.publish(smallVault(4));
    const auto known = *w.known;
    w.bucket->seedDeleteMarker(std::string(kRootKey));
    w.cache = {};
    const auto r = w.publish(smallVault(5));
    EXPECT_TRUE(r.root_rebuilt);
    EXPECT_EQ(r.published.known.epoch, known.epoch + 1);
    EXPECT_EQ(r.published.root.prev, known.root_sha256);
}

TEST(ManifestPublish, AnUnreadableRootWithoutStateIsNotOverwritten) {
    Writer w;
    w.bucket->seed(std::string(kRootKey), Bytes(300, 0x42));
    EXPECT_THROW((void)w.publish(smallVault(1)), NoUsableRoot);
    EXPECT_EQ(w.bucket->current(std::string(kRootKey))->body, Bytes(300, 0x42));
}

// ── ManifestChain ────────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestChain, RollbackAndForkAreRefused) {
    Writer w;
    (void)w.publish(smallVault(2));
    const auto epoch1 = *w.bucket->current(std::string(kRootKey));
    (void)w.publish(smallVault(3));
    (void)w.publish(smallVault(4));
    // An older authentic root put back (a bucket writer kept a copy).
    w.bucket->seed(std::string(kRootKey), epoch1.body);
    try {
        (void)w.loadKnown();
        ADD_FAILURE() << "rollback accepted";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Rollback);
        EXPECT_EQ(e.epoch(), 1u);
    }
    // Another authentic root at the known epoch.
    RootDocument other = w.cache.base->root;
    other.published_at = "2030-01-01T00:00:00Z";
    w.bucket->seed(std::string(kRootKey), sealRoot(other, w.vault, {2, w.keys.at(2)}));
    try {
        (void)w.loadKnown();
        ADD_FAILURE() << "fork accepted";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Fork);
    }
}

TEST(ManifestChain, AGapIsWalkedThroughRetainedRootsOrWarned) {
    for (const auto mode : {Versioning::Enabled, Versioning::Unversioned}) {
        SCOPED_TRACE(mode == Versioning::Enabled ? "versioned" : "unversioned");
        Writer w(mode);
        (void)w.publish(smallVault(2));
        const auto known1 = *w.known;
        for (int i = 0; i < 3; ++i) (void)w.publish(smallVault(3 + i));
        LoadOptions o;
        o.known = known1;
        const auto loaded = load(*w.store, w.vault, w.lookup(), o);
        EXPECT_EQ(loaded.root.epoch, 4u);
        EXPECT_EQ(loaded.acceptance.gap, mode == Versioning::Unversioned) << "a versioned bucket retains the chain";
    }
}

TEST(ManifestChain, AGapWhoseChainReachesTheKnownEpochThroughAnotherRootIsAFork) {
    Writer w;
    (void)w.publish(smallVault(2));
    for (int i = 0; i < 3; ++i) (void)w.publish(smallVault(3 + i));
    LoadOptions o;
    o.known = Known{1, std::string(64, '9')};  // we knew another epoch 1
    try {
        (void)load(*w.store, w.vault, w.lookup(), o);
        ADD_FAILURE() << "accepted";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Fork);
    }
}

TEST(ManifestChain, ACorruptRootFallsBackToTheNewestAuthenticVersion) {
    Writer w;
    (void)w.publish(smallVault(2));
    (void)w.publish(smallVault(3));
    const auto good = *w.known;
    auto corrupt = w.bucket->current(std::string(kRootKey))->body;
    corrupt[200] ^= 1;
    w.bucket->seed(std::string(kRootKey), corrupt);
    const auto loaded = w.loadKnown();
    EXPECT_EQ(loaded.source, RootSource::ProviderVersion);
    EXPECT_EQ(loaded.known(), good);
    EXPECT_FALSE(loaded.etag);

    Writer bare(Versioning::Unversioned);
    (void)bare.publish(smallVault(2));
    auto body = bare.bucket->current(std::string(kRootKey))->body;
    body[150] ^= 1;
    bare.bucket->seed(std::string(kRootKey), body);
    EXPECT_THROW((void)bare.loadKnown(), NoUsableRoot);
}

TEST(ManifestChain, MissingAndMismatchedSegmentsFallBackInOrder) {
    const PartitionLimits limits{16, 1u << 20, 4};
    Writer w;
    auto c = smallVault(100);
    const auto r1 = w.publish(c, limits);
    nthFile(c, 10).size = 1;  // epoch 2 rewrites the one segment holding that file
    const auto r2 = w.publish(c, limits);
    ASSERT_EQ(r2.segments_written, 1u);
    const auto& segs = r2.published.root.segments;
    ASSERT_GE(segs.size(), 4u);
    const auto oldSids = r1.published.sids();
    const auto rewritten = std::ranges::find_if(segs, [&](const SegmentRef& s) {
        return std::ranges::find(oldSids, s.sid) == oldSids.end();
    });
    ASSERT_NE(rewritten, segs.end());
    std::vector<SegmentRef> shared;
    for (const auto& s : segs)
        if (s.sid != rewritten->sid) shared.push_back(s);
    const auto purge = [&](const std::string& sid) {
        for (const auto& v : w.bucket->history(segmentKey(sid))) w.bucket->purgeVersion(segmentKey(sid), v.version_id);
    };

    // (a) overwritten (mismatch), its own provider version intact.
    w.bucket->seed(segmentKey(shared[0].sid), Bytes{1, 2, 3});
    // (b) the segment epoch 2 rewrote, gone with its versions: epoch 1's root holds the range intact (stale).
    purge(rewritten->sid);
    // (c) a segment both roots share, gone with its versions: nothing intact covers its range.
    purge(shared[1].sid);

    const auto loaded = w.loadKnown();
    ASSERT_EQ(loaded.issues.size(), 3u);
    std::map<std::string, SegmentIssue> got;
    for (const auto& i : loaded.issues) got[i.sid] = i;
    EXPECT_EQ(got.at(shared[0].sid).problem, "segment_mismatch");
    EXPECT_EQ(got.at(shared[0].sid).resolution, Resolution::ProviderVersion);
    EXPECT_EQ(got.at(rewritten->sid).problem, "segment_missing");
    EXPECT_EQ(got.at(rewritten->sid).resolution, Resolution::OlderRoot);
    EXPECT_EQ(got.at(rewritten->sid).from_epoch, 1u);
    EXPECT_EQ(got.at(shared[1].sid).resolution, Resolution::Blind);
    ASSERT_EQ(loaded.blind_ranges.size(), 1u);
    EXPECT_EQ(loaded.blind_ranges[0], shared[1].range);
    // The stale range carries epoch 1's value of the changed file.
    const auto changed = std::ranges::find(loaded.content.entries, nthFile(c, 10).uid, &Entry::uid);
    ASSERT_NE(changed, loaded.content.entries.end());
    EXPECT_NE(changed->size, 1u);

    // Strict acceptance (the vectors' rule) refuses the same state.
    std::map<std::string, Bytes> present;
    for (const auto& s : segs)
        if (const auto v = w.bucket->current(segmentKey(s.sid))) present[s.sid] = v->body;
    const auto rootObj = w.bucket->current(std::string(kRootKey))->body;
    EXPECT_THROW((void)acceptRoot(openRoot(rootObj, w.vault, w.lookup()), rootObj, w.known, present), ChainRejected);
}

TEST(ManifestChain, ASegmentLostEverywhereIsLeftToTheBlindRebuild) {
    Writer w(Versioning::Unversioned);
    (void)w.publish(smallVault(20));
    const auto sid = w.cache.base->root.segments[0].sid;
    w.bucket->seedDeleteMarker(segmentKey(sid));
    const auto loaded = w.loadKnown();
    ASSERT_EQ(loaded.issues.size(), 1u);
    EXPECT_EQ(loaded.issues[0].problem, "segment_missing");
    EXPECT_EQ(loaded.issues[0].resolution, Resolution::Blind);
    ASSERT_EQ(loaded.blind_ranges.size(), 1u);
    EXPECT_TRUE(loaded.content.entries.empty());
}

TEST(ManifestChain, BlindRebuildRecoversAuthenticObjectsFromHeadersOnly) {
    Writer w;
    const auto seal = [&](const Uid& vault, const Uid& uid, const std::size_t size, const uint32_t keyVersion) {
        crypto::vhf1::HeaderParams p;
        p.kind = crypto::vhf1::Kind::FileContent;
        p.keyVersion = keyVersion;
        p.vaultUid = vault;
        p.objectUid = uid;
        p.salt = crypto::vhf1::freshSalt();
        return std::pair{crypto::vhf1::seal(Bytes(size, 0x5a), p, *w.keys.at(keyVersion)), p.salt};
    };
    const auto a = uidOf(0x10, 0xa1), b = uidOf(0x90, 0xb2), foreign = uidOf(0x20, 0xc3), moved = uidOf(0x30, 0xd4);
    const auto [objA, saltA] = seal(w.vault, a, 100000, 1);
    const auto [objB, saltB] = seal(w.vault, b, 0, 2);
    w.bucket->seed("o/" + uidText(a), objA);
    w.bucket->seed("o/" + uidText(b), objB);
    w.bucket->seed("o/" + uidText(foreign), seal(uidOf(0x99, 0x99), foreign, 10, 2).first);  // another vault's object
    w.bucket->seed("o/" + uidText(moved), objA);                                              // ciphertext moved between files
    w.bucket->seed("o/not-a-uid", Bytes(200, 1));
    w.bucket->resetCounters();

    const auto report = blindRebuild(*w.store, w.vault, w.lookup());
    ASSERT_EQ(report.recovered.size(), 2u);
    std::map<std::string, RecoveredObject> byKey;
    for (const auto& r : report.recovered) byKey[r.key] = r;
    const auto& ra = byKey.at("o/" + uidText(a));
    EXPECT_EQ(ra.path, "/Recovered/" + uidText(a));
    EXPECT_EQ(ra.plaintext_size, 100000u);
    EXPECT_EQ(ra.key_version, 1u);
    EXPECT_EQ(ra.object_size, objA.size());
    EXPECT_EQ(ra.generation.size(), 64u);
    EXPECT_EQ(byKey.at("o/" + uidText(b)).plaintext_size, 0u);
    EXPECT_EQ(report.rejected.size(), 3u);
    EXPECT_EQ(report.header_bytes, 4 * crypto::vhf1::kHeaderSize) << "headers only";
    EXPECT_EQ(w.bucket->counters().bytes_served, 4 * crypto::vhf1::kHeaderSize);

    const auto only = blindRebuild(*w.store, w.vault, w.lookup(), Range{0x80, 0xff});
    ASSERT_EQ(only.recovered.size(), 1u);
    EXPECT_EQ(only.recovered[0].uid, b);
}

// ── ManifestContent ──────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestContent, EveryFactSurvivesPublishAndLoad) {
    Writer w;
    const auto content = richContent();
    const auto r = w.publish(content);
    const auto loaded = w.loadKnown();
    EXPECT_TRUE(loaded.issues.empty());
    EXPECT_EQ(loaded.content, content);
    EXPECT_EQ(loaded.root.stats, statsOf(content));
    EXPECT_EQ(loaded.root.snapshots.size(), 1u);
    EXPECT_EQ(r.snapshots_written, 1u);

    // A fresh reader (no cache, no known state) sees the same.
    const auto fresh = load(*w.store, w.vault, w.lookup());
    EXPECT_EQ(fresh.content, content);
    EXPECT_FALSE(fresh.acceptance.gap);

    // Republishing the same content writes only a new root (snapshot segments are immutable and reused).
    w.bucket->resetCounters();
    const auto again = w.publish(content);
    EXPECT_EQ(again.segments_written, 0u);
    EXPECT_EQ(again.snapshots_written, 0u);
    EXPECT_EQ(w.bucket->counters().put, 1u);
}

TEST(ManifestContent, AnotherKeyVersionStillReadsOlderSegments) {
    Writer w;
    w.current = 1;
    const auto c = smallVault(10);
    (void)w.publish(c);
    w.current = 2;  // rotation: new segments and roots are sealed under v2, old segments keep v1
    auto c2 = c;
    nthFile(c2, 1).size = 7;
    const auto r = w.publish(c2);
    EXPECT_EQ(r.segments_written, 1u);
    const auto rootObj = w.bucket->current(std::string(kRootKey))->body;
    EXPECT_EQ(crypto::vhf1::openHeader(rootObj, {crypto::vhf1::Kind::ManifestRoot, w.vault, w.vault, std::nullopt},
                                       w.lookup()).params().keyVersion, 2u);
    EXPECT_EQ(w.loadKnown().content, c2);
}

// ── ManifestReplay ───────────────────────────────────────────────────────────────────────────────────────────────

TEST(ManifestReplay, AnOlderCompleteStateAuthenticatesAndOnlyACheckpointCatchesIt) {
    Writer w;
    auto c = smallVault(8);
    (void)w.publish(c);
    nthFile(c, 2).size = 2;
    (void)w.publish(c);
    const auto epoch2Root = w.bucket->current(std::string(kRootKey))->body;
    const Checkpoint at2{2, sha256Hex(epoch2Root), "2026-11-05T12:02:00Z"};
    nthFile(c, 3).size = 3;
    (void)w.publish(c);
    nthFile(c, 4).size = 4;
    (void)w.publish(c);
    const Checkpoint at4{4, w.known->root_sha256, std::nullopt};

    // The latest state, with and without a checkpoint.
    const auto plain = loadForRestore(*w.store, w.vault, w.lookup(), std::nullopt);
    EXPECT_EQ(plain.freshness, Freshness::Unverified);
    EXPECT_EQ(plain.report, "freshness unverified: no checkpoint supplied");
    const auto verified = loadForRestore(*w.store, w.vault, w.lookup(), at2);
    EXPECT_EQ(verified.freshness, Freshness::Verified);
    EXPECT_EQ(verified.loaded.root.epoch, 4u);

    // A bucket writer replays the epoch-2 state: its root, its (still retained) segments and object versions.
    w.bucket->seed(std::string(kRootKey), epoch2Root);
    const auto replayed = loadForRestore(*w.store, w.vault, w.lookup(), std::nullopt);
    EXPECT_EQ(replayed.loaded.root.epoch, 2u) << "an older complete state authenticates";
    EXPECT_TRUE(replayed.loaded.issues.empty());
    EXPECT_EQ(replayed.freshness, Freshness::Unverified);
    EXPECT_EQ(replayed.report, kFreshnessUnverified);

    // A checkpoint at epoch 2 can't tell it apart from the latest: it is as new as the checkpoint.
    EXPECT_EQ(loadForRestore(*w.store, w.vault, w.lookup(), at2).freshness, Freshness::Verified);

    // The newer checkpoint refuses it, unless the operator explicitly accepts the rollback.
    try {
        (void)loadForRestore(*w.store, w.vault, w.lookup(), at4);
        ADD_FAILURE() << "a replay older than the checkpoint was accepted";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Rollback);
    }
    const auto accepted = loadForRestore(*w.store, w.vault, w.lookup(), at4, true);
    EXPECT_EQ(accepted.freshness, Freshness::RollbackAccepted);
    EXPECT_EQ(accepted.loaded.root.epoch, 2u);
    EXPECT_NE(accepted.report.find("rollback accepted"), std::string::npos);

    // A fork against the checkpoint is never accepted.
    EXPECT_THROW((void)loadForRestore(*w.store, w.vault, w.lookup(), Checkpoint{2, std::string(64, '7'), std::nullopt}, true),
                 ChainRejected);
}

}
