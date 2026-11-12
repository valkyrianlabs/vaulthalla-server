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
// ManifestStore*    the Store seam on buckets without conditional writes (design/encryption/
//                   06-publish-without-preconditions.md §7): plain PUTs with version ids, putOnce by mode, versions
//                   with ETags in provider order, DELETE of one version; the publish refuses before any request.

#include "../helpers/bytes.hpp"
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
#include "../helpers/hooked_store.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <functional>
#include <set>

namespace vh::sync::manifest::test_manifest_suite {

namespace {

using Bytes = std::vector<uint8_t>;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using crypto::SecretKey;
using crypto::SecretKeyPtr;

// ---- vectors -------------------------------------------------------------------------------------------------------

const Json& vectors() { return vh::test::bin::goldenVectors(); }

using vh::test::bin::fromHex;

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
    std::shared_ptr<ObjectStore> store;
    Uid vault = uidOf(0x56, 0x48);
    std::map<uint32_t, SecretKeyPtr> keys{{1, keyOf(1)}, {2, keyOf(40)}};
    uint32_t current = 2;
    PublisherCache cache;
    std::optional<Known> known;
    int clock = 0;

    // version_log (spec 06): this writer's node id, its last own epoch and the settled window, as Service keeps them.
    std::string node;
    std::optional<uint64_t> ownEpoch;
    std::optional<SettledWindow> settled;

    explicit Writer(std::shared_ptr<VersionedBucket> b,
                    const storage::s3::WriteCapability mode = storage::s3::WriteCapability::Unknown)
        : bucket(std::move(b)), store(std::make_shared<S3Store>(bucket, mode)) {}
    explicit Writer(const Versioning v = Versioning::Enabled) : Writer(std::make_shared<VersionedBucket>(v)) {}

    [[nodiscard]] crypto::vhf1::KeyLookup lookup() const { return lookupOf(keys); }

    PublishReport publish(const Content& c, const PartitionLimits& limits = {}) {
        PublishOptions o;
        o.now = isoTime(1793880000 + 60 * (++clock));
        o.limits = limits;
        o.self_node = node;
        o.own_epoch = ownEpoch;
        o.settled = settled;
        o.sleep = [b = bucket](const std::chrono::milliseconds d) { b->advance(std::max<std::time_t>(1, d.count() / 1000)); };
        auto r = manifest::publish(*store, vault, lookup(), {current, keys.at(current)}, c, known, cache, o);
        known = r.published.known;
        ownEpoch = r.published.known.epoch;
        if (r.settled.version_id && r.settled.base_version_id)
            settled = SettledWindow{*r.settled.base_version_id, *r.settled.version_id, r.settled.window};
        else settled.reset();
        return r;
    }

    Loaded loadKnown() {
        LoadOptions o;
        o.known = known;
        o.settled = settled;
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

// ── ManifestStore: buckets without conditional writes (spec 06 §7) ──────────────────────────────────────────────

TEST(ManifestStore, PutOnceSendsAConditionOnlyWhereTheBucketHonoursIt) {
    using storage::s3::WriteCapability;
    const auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    const Bytes body{1, 2, 3};

    // Conditional (and Unknown: never probed, no silent downgrade): If-None-Match: *, so an existing name refuses.
    for (const auto mode : {WriteCapability::Conditional, WriteCapability::Unknown}) {
        S3Store store(bucket, mode);
        const auto key = ".vaulthalla/seg/" + uidText(uidOf(static_cast<uint8_t>(mode), 1));
        (void)store.putOnce(key, body);
        EXPECT_THROW((void)store.putOnce(key, body), PreconditionFailed) << storage::s3::to_string(mode);
    }

    // Backblaze B2: a condition is refused outright (typed, nothing written)...
    bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
    S3Store unprobed(bucket);
    const auto key = std::string(".vaulthalla/key/") + uidText(uidOf(9, 9));
    EXPECT_THROW((void)unprobed.putIfAbsent(key, body), ConditionsUnsupported);
    EXPECT_TRUE(bucket->history(key).empty()) << "a refused condition writes nothing";

    // ...and a store whose bucket was probed version_log writes plainly, with the version id.
    S3Store plain(bucket, WriteCapability::VersionLog);
    EXPECT_EQ(plain.mode(), WriteCapability::VersionLog);
    (void)plain.putOnce(key, body);
    const auto second = plain.put(key, Bytes{4, 5});
    ASSERT_TRUE(second.version_id);
    EXPECT_FALSE(second.etag.empty());

    // Versions in provider order, newest first, with their ETags and the current one marked.
    const auto versions = plain.versions(key);
    ASSERT_EQ(versions.size(), 2u);
    EXPECT_EQ(versions.front().version_id, *second.version_id);
    EXPECT_EQ(versions.front().etag, second.etag);
    EXPECT_TRUE(versions.front().is_latest);
    EXPECT_FALSE(versions.back().is_latest);

    // DELETE of one version: exactly that one goes, the previous one is current again.
    plain.removeVersion(key, *second.version_id);
    ASSERT_EQ(plain.versions(key).size(), 1u);
    EXPECT_EQ(bucket->current(key)->body, body);
}

TEST(ManifestStore, AVersionListingStopsAtTheVersionItNeeds) {
    // spec 06 §7: the publish lists down to its base, the anchored read down to its anchor, not the whole history.
    const auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    bucket->versionPageSize = 2;
    std::vector<std::string> ids;   // oldest first
    for (int i = 0; i < 7; ++i) ids.push_back(bucket->seed("k", "v" + std::to_string(i)));
    S3Store store(bucket, storage::s3::WriteCapability::VersionLog);
    bucket->resetCounters();
    EXPECT_EQ(store.versions("k").size(), 7u);
    EXPECT_EQ(bucket->counters().list, 4u) << "pages of 2";
    bucket->resetCounters();
    const auto since = store.versionsSince("k", ids[4]);
    ASSERT_EQ(since.size(), 3u) << "ids 6, 5, 4: newest first, down to and including the stop";
    EXPECT_EQ(since.back().version_id, ids[4]);
    EXPECT_EQ(bucket->counters().list, 2u) << "the page holding the stop is the last one read";
    EXPECT_EQ(store.versionsSince("k", std::string("not-a-version")).size(), 7u) << "a stop that isn't there: all";
    // The base store's default cuts a full listing the same way.
    RecordingStore wrapped(store);
    EXPECT_EQ(wrapped.versionsSince("k", ids[4]).size(), 3u);
}

TEST(ManifestStore, TheBaseStoreRefusesPlainWritesItCannotMake) {
    Writer w;
    RecordingStore rec(*w.store);
    EXPECT_THROW((void)rec.put("k", {}), std::logic_error);
    EXPECT_THROW(rec.removeVersion("k", "v"), std::logic_error);
    EXPECT_EQ(rec.mode(), storage::s3::WriteCapability::Unknown);
}

TEST(ManifestPublish, ABucketThatCanArbitrateNothingRefusesBeforeAnyRequest) {
    // Neither conditional writes nor versions (spec 06 §7, Insufficient): never half a publish.
    Writer w;
    w.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
    w.store = std::make_shared<S3Store>(w.bucket, storage::s3::WriteCapability::Insufficient);
    w.bucket->resetCounters();
    EXPECT_THROW((void)w.publish(smallVault(3)), PublishUnsupported);
    const auto c = w.bucket->counters();
    EXPECT_EQ(c.put + c.get + c.head + c.list + c.del, 0u) << "no request at all";
    EXPECT_TRUE(w.bucket->keys().empty());
}

TEST(ManifestPublish, ABucketThatRejectsConditionsFailsTypedWithoutAPartialPublish) {
    // The failure every opaque_v1 vault on Backblaze B2 hit before spec 06: the first segment PUT answered 501. It is
    // now a typed refusal (ConditionsUnsupported, which the engine turns into a stall and a re-probe), and the bucket
    // holds nothing of the publish.
    Writer w;
    w.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
    EXPECT_THROW((void)w.publish(smallVault(3)), ConditionsUnsupported);
    EXPECT_TRUE(w.bucket->keys().empty());
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
        const auto versions = w.bucket->history(segmentKey(sid));  // copy: purging mutates the history
        for (const auto& v : versions) w.bucket->purgeVersion(segmentKey(sid), v.version_id);
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


// ── ManifestPublishVersionLog / ManifestChainVersionLog: buckets without conditional writes (spec 06 §5) ────────

namespace version_log_fixture {

std::shared_ptr<VersionedBucket> b2Bucket() {
    auto b = std::make_shared<VersionedBucket>(Versioning::Enabled);
    b->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;   // as Backblaze B2 answers them
    b->md5Etags = true;
    return b;
}

Writer vlWriter(std::shared_ptr<VersionedBucket> b, std::string node) {
    Writer w(std::move(b), storage::s3::WriteCapability::VersionLog);
    w.node = std::move(node);
    return w;
}

Content ofNode(Content c, const std::string& node) {
    c.producer.node_id = node;
    return c;
}

Content withFile(Content c, const std::string& uid, const std::string& name) {
    c.entries.push_back(fileEntry(uid, kRootUid, name, 7));
    normalize(c);
    return c;
}

std::set<std::string> namesOf(const Content& c) {
    std::set<std::string> out;
    for (const auto& e : c.entries) out.insert(e.name);
    return out;
}

// A root as another writer would publish it: a copy of `like` at another epoch / prev, sealed under the same key.
std::vector<uint8_t> rootLike(const Writer& w, RootDocument like, const uint64_t epoch, const std::optional<std::string>& prev,
                              const std::string& node, std::optional<std::vector<std::string>> writers = std::nullopt) {
    like.epoch = epoch;
    like.prev = prev;
    like.producer.node_id = node;
    like.writers = writers ? std::move(writers) : std::vector<std::string>{node};
    return sealRoot(like, w.vault, {w.current, w.keys.at(w.current)});
}

// Another key holder sets the vault's writers (the mirror join does that; this branch doesn't build it): a root on
// w's head that names `nodes`. w's cache is dropped, so its next publish loads that root.
void setWriters(Writer& w, const std::vector<std::string>& nodes) {
    const auto& head = w.cache.base->root;
    (void)w.bucket->seed(std::string(kRootKey), rootLike(w, head, head.epoch + 1, w.known->root_sha256, w.node, nodes));
    w.cache = {};
}

// Two writers of one vault, both in its writers: a has published the base and built on the root naming both.
std::pair<Writer, Writer> twoWriters(const std::shared_ptr<VersionedBucket>& bucket, const Content& base) {
    auto a = vlWriter(bucket, "node-a");
    auto b = vlWriter(bucket, "node-b");
    (void)a.publish(base);                     // epoch 1
    setWriters(a, {"node-a", "node-b"});       // epoch 2
    auto touched = base;
    nthFile(touched, 0).size = 77;
    (void)a.publish(touched);                  // epoch 3, on 2: writers carried
    return {std::move(a), std::move(b)};
}

std::vector<std::string> rootIds(const VersionedBucket& b) {
    std::vector<std::string> out;
    for (const auto& v : b.history(std::string(kRootKey))) out.push_back(v.version_id);   // newest first
    return out;
}

}

TEST(ManifestPublishVersionLog, EveryPutIsPlainAndTheRootNamesItsModeWritersAndVersion) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    const auto r = w.publish(f::ofNode(smallVault(3), "node-a"));   // a condition would throw: Reject501
    EXPECT_EQ(r.published.known.epoch, 1u);
    ASSERT_TRUE(r.settled.version_id);
    EXPECT_EQ(*r.settled.version_id, w.bucket->current(std::string(kRootKey))->version_id);
    EXPECT_EQ(r.published.known.version_id, r.settled.version_id);
    EXPECT_FALSE(r.settled.base_version_id) << "a first root has no base";
    EXPECT_EQ(r.published.root.publish, std::string(kPublishVersionLog));
    EXPECT_EQ(r.published.root.writers, std::vector<std::string>{"node-a"});
    EXPECT_TRUE(w.bucket->current(std::string(kLayoutKey)));
    // The root is what the bucket holds; a reader with nothing known finds it.
    const auto loaded = load(*w.store, w.vault, w.lookup(), {});
    EXPECT_EQ(loaded.known(), r.published.known);
    EXPECT_EQ(loaded.version_id, r.settled.version_id);
}

TEST(ManifestPublishVersionLog, ASoloPublishCostsExactlyOneListMoreThanAConditionalOne) {
    namespace f = version_log_fixture;
    VersionedBucket::Counters cost[2];
    for (const int vl : {0, 1}) {
        auto w = vl ? f::vlWriter(f::b2Bucket(), "node-a") : Writer(std::make_shared<VersionedBucket>(Versioning::Enabled));
        w.node = "node-a";
        auto c = f::ofNode(smallVault(3), "node-a");
        (void)w.publish(c);
        nthFile(c, 1).size = 4242;
        w.bucket->resetCounters();
        (void)w.publish(c);
        cost[vl] = w.bucket->counters();
    }
    EXPECT_EQ(cost[0].put, 2u) << "one segment, one root";
    EXPECT_EQ(cost[1].put, cost[0].put);
    EXPECT_EQ(cost[1].list, cost[0].list + 1) << "the listing that settles the root";
    EXPECT_EQ(cost[1].get, cost[0].get) << "our own version is known without a GET";
    EXPECT_EQ(cost[1].head, cost[0].head);
    EXPECT_EQ(cost[1].del, cost[0].del);
}

TEST(ManifestPublishVersionLog, ALosingWriterDeletesItsVersionAndMergesOntoTheWinner) {
    namespace f = version_log_fixture;
    const auto bucket = f::b2Bucket();
    auto base = f::ofNode(smallVault(4), "node-a");
    auto [a, b] = f::twoWriters(bucket, base);
    nthFile(base, 0).size = 77;
    (void)b.publish(f::withFile(f::ofNode(base, "node-b"), uidT(0x90, 2), "from-b"));   // epoch 4, on 3
    EXPECT_EQ(b.known->epoch, 4u);
    EXPECT_EQ(b.cache.base->root.writers, (std::vector<std::string>{"node-a", "node-b"}));
    // A still builds on epoch 3 (its cache): its root is a sibling of B's, later in provider order, and loses.
    const auto r = a.publish(f::withFile(base, uidT(0x91, 3), "from-a"));
    EXPECT_EQ(r.lost, 1u);
    EXPECT_EQ(r.attempts, 2u);
    EXPECT_EQ(r.published.known.epoch, 5u);
    EXPECT_EQ(r.published.root.prev, b.known->root_sha256);
    EXPECT_EQ(f::rootIds(*bucket).size(), 5u) << "epochs 1 to 5: the losing sibling was deleted by id";
    const auto names = f::namesOf(a.loadKnown().content);
    EXPECT_TRUE(names.contains("from-a"));
    EXPECT_TRUE(names.contains("from-b")) << "the winner's change survives the merge";
    // B reads A's root as the next one of its chain.
    EXPECT_EQ(b.loadKnown().acceptance.epoch, 5u);
}

TEST(ManifestPublishVersionLog, AStrayVersionAboveTheHeadIsIgnoredByReadersAndRepairedByThePublishThatSeesIt) {
    namespace f = version_log_fixture;
    namespace ms = vh::test_support::manifest_store;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    const auto e1 = *w.known;
    nthFile(c, 0).size = 1;
    (void)w.publish(c);
    const auto e2 = *w.known;
    // A crashed writer's sibling of epoch 2 (prev epoch 1) and a delete marker land above the head.
    const auto strayBytes = f::rootLike(w, w.cache.base->root, 2, e1.root_sha256, "node-x");
    const auto stray = w.bucket->seed(std::string(kRootKey), strayBytes);
    const auto marker = w.bucket->seedDeleteMarker(std::string(kRootKey));
    const auto read = w.loadKnown();
    EXPECT_EQ(read.known(), e2) << "the canonical head, not the current object";
    EXPECT_EQ(read.strays, (std::vector<std::string>{stray, marker}));

    // The next publish lands above them: below its root they are non-canonical history, the janitor's after a day
    // (spec 06 §5.4); a stray that lands after its PUT and before its listing is above the new head and repaired.
    auto hooked = std::make_shared<ms::HookedStore>(w.store);
    std::vector<std::string> late;
    hooked->after = [&](const ms::StoreOp op, const std::string& key, const std::string&, const bool failed) {
        if (op != ms::StoreOp::Put || key != kRootKey || failed || !late.empty()) return;
        late.push_back(w.bucket->seed(std::string(kRootKey), strayBytes));
        late.push_back(w.bucket->seedDeleteMarker(std::string(kRootKey)));
    };
    w.store = hooked;
    nthFile(c, 0).size = 2;
    const auto r = w.publish(c);
    EXPECT_EQ(r.published.known.epoch, 3u);
    EXPECT_EQ(r.repaired, late);
    EXPECT_EQ(f::rootIds(*w.bucket).front(), *r.settled.version_id) << "the head is the current version again";
    EXPECT_EQ(r.settled.window, (std::vector<std::string>{stray, marker})) << "listed between its base and itself";
    EXPECT_EQ(f::rootIds(*w.bucket).size(), 5u) << "epochs 1-3 and the two older strays";
    w.bucket->advance(25 * 60 * 60);
    const auto j = collectRootVersions(*w.store, w.vault, w.lookup(), w.cache.roots, *r.settled.version_id, w.bucket->now());
    EXPECT_EQ(j.deleted, (std::vector<std::string>{stray, marker}));
    EXPECT_EQ(w.loadKnown().known(), *w.known);
}

TEST(ManifestPublishVersionLog, GcDeletesEveryVersionOfASegmentUnreferencedForADay) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(5), "node-a");
    std::vector<std::vector<std::string>> rootSids;
    for (int i = 0; i < 5; ++i) {
        nthFile(c, 1).size = 1000 + i;
        rootSids.push_back(w.publish(c).published.sids());
    }
    std::set<std::string> retained;
    for (std::size_t i = rootSids.size() - 3; i < rootSids.size(); ++i) retained.insert(rootSids[i].begin(), rootSids[i].end());
    const auto oldKey = segmentKey(rootSids[0].front());
    (void)w.bucket->seed(oldKey, Bytes{1, 2, 3});   // a second version of a superseded segment
    std::map<std::string, std::time_t> marked;
    const UnreferencedClock clock{
        .first = [&](const std::string& sid) { return marked.try_emplace(sid, w.bucket->now()).first->second; },
        .forget = [&](const std::string& sid) { marked.erase(sid); }};

    // Unreferenced since now: nothing goes for a day, however old the objects are.
    w.bucket->advance(30 * 24 * 60 * 60);
    auto early = collectGarbageVersionLog(*w.store, retained, w.bucket->now(), clock);
    EXPECT_TRUE(early.deleted.empty());
    EXPECT_EQ(early.young, 2u);

    w.bucket->advance(25 * 60 * 60);
    const auto report = collectGarbageVersionLog(*w.store, retained, w.bucket->now(), clock);
    EXPECT_EQ(report.deleted.size(), 2u) << "the first two roots' segments";
    EXPECT_TRUE(w.bucket->history(oldKey).empty()) << "every version deleted by id, no delete marker left";
    for (const auto& sid : retained) { EXPECT_TRUE(w.bucket->current(segmentKey(sid))) << sid; }
    EXPECT_TRUE(marked.empty());
    EXPECT_TRUE(w.loadKnown().issues.empty());
}

TEST(ManifestPublishVersionLog, TheJanitorKeepsTheHeadItsTwoPredecessorsAndAWeekOfHistory) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    std::vector<std::string> ids;
    std::vector<uint8_t> epoch2;
    for (int i = 0; i < 5; ++i) {
        nthFile(c, 0).size = 100 + i;
        ids.push_back(*w.publish(c).settled.version_id);
        if (i == 1) epoch2 = w.bucket->current(std::string(kRootKey))->body;
    }
    // A non-canonical version between the second predecessor and the head (a replay of epoch 2's bytes).
    const auto replay = w.bucket->seed(std::string(kRootKey), epoch2);
    nthFile(c, 0).size = 200;
    ids.push_back(*w.publish(c).settled.version_id);   // epoch 6: the replay stays below the head
    ASSERT_EQ(f::rootIds(*w.bucket).size(), 7u);

    w.bucket->advance(25 * 60 * 60);
    auto day = collectRootVersions(*w.store, w.vault, w.lookup(), w.cache.roots, ids.back(), w.bucket->now());
    EXPECT_EQ(day.deleted, std::vector<std::string>{replay}) << "only the non-canonical one, after a day";

    w.bucket->advance(7 * 24 * 60 * 60);
    auto week = collectRootVersions(*w.store, w.vault, w.lookup(), w.cache.roots, ids.back(), w.bucket->now());
    EXPECT_EQ(week.deleted, (std::vector<std::string>{ids[0], ids[1], ids[2]}));
    EXPECT_EQ(f::rootIds(*w.bucket), (std::vector<std::string>{ids[5], ids[4], ids[3]}));
    EXPECT_EQ(w.loadKnown().acceptance.epoch, 6u);
}

TEST(ManifestPublishVersionLog, ALostResponseIsFoundByHashAndSettlesWithoutADuplicate) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    c.vault = VaultInfo{"renamed", std::nullopt, std::nullopt, std::nullopt, std::nullopt};   // the root alone changes
    w.bucket->loseResponses = 1;   // the PUT is applied, its answer lost (as B2's 500 on a stalled body may be)
    const auto r = w.publish(c);
    EXPECT_EQ(r.published.known.epoch, 2u);
    EXPECT_EQ(f::rootIds(*w.bucket).size(), 2u) << "no second PUT of the same publish";
    EXPECT_EQ(r.settled.version_id, w.bucket->current(std::string(kRootKey))->version_id);
}

TEST(ManifestPublishVersionLog, A5xxBeforeTheCommitFailsThePublishAndTheNextOneSettles) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    c.vault = VaultInfo{"renamed", std::nullopt, std::nullopt, std::nullopt, std::nullopt};
    w.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Http503);
    EXPECT_THROW((void)w.publish(c), std::runtime_error);
    EXPECT_EQ(f::rootIds(*w.bucket).size(), 1u);
    EXPECT_EQ(w.known->epoch, 1u) << "nothing recorded";
    EXPECT_EQ(w.publish(c).published.known.epoch, 2u);
}

TEST(ManifestPublishVersionLog, AFailedDeleteOfALosingVersionIsIgnoredByReadersAndLeftToTheJanitor) {
    namespace f = version_log_fixture;
    const auto bucket = f::b2Bucket();
    auto base = f::ofNode(smallVault(4), "node-a");
    auto [a, b] = f::twoWriters(bucket, base);
    nthFile(base, 0).size = 77;
    (void)b.publish(f::withFile(f::ofNode(base, "node-b"), uidT(0x90, 2), "from-b"));
    bucket->refuseDeletes = true;
    const auto r = a.publish(f::withFile(base, uidT(0x91, 3), "from-a"));
    EXPECT_EQ(r.lost, 1u);
    EXPECT_EQ(r.published.known.epoch, 5u);
    EXPECT_EQ(f::rootIds(*bucket).size(), 6u) << "the losing sibling stays: its DELETE was refused";
    // A reader with nothing known takes the longest chain, never the sibling.
    const auto blind = load(*a.store, a.vault, a.lookup(), {});
    EXPECT_EQ(blind.known(), *a.known);
    bucket->refuseDeletes = false;
    bucket->advance(25 * 60 * 60);
    const auto j = collectRootVersions(*a.store, a.vault, a.lookup(), a.cache.roots, *r.settled.version_id, bucket->now());
    EXPECT_EQ(j.deleted.size(), 1u);
    EXPECT_EQ(f::rootIds(*bucket).size(), 5u);
}

TEST(ManifestPublishVersionLog, AServerTheHeadNoLongerNamesStopsAndANewcomerDoesNot) {
    namespace f = version_log_fixture;
    const auto bucket = f::b2Bucket();
    auto a = f::vlWriter(bucket, "node-a");
    const auto base = f::ofNode(smallVault(3), "node-a");
    (void)a.publish(base);   // own epoch 1
    // A restore elsewhere publishes epoch 2 naming only itself.
    auto restored = f::vlWriter(bucket, "node-r");
    (void)restored.publish(f::ofNode(base, "node-r"));
    ASSERT_EQ(restored.known->epoch, 2u);
    a.cache = {};   // a cold cache: it loads the head
    try {
        (void)a.publish(f::withFile(base, uidT(0x92, 4), "late"));
        ADD_FAILURE() << "a server the head excludes published over it";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Superseded);
        EXPECT_EQ(e.epoch(), 2u);
    }
    EXPECT_EQ(f::rootIds(*bucket).size(), 2u);
    // A server that never published here (no own epoch: a fresh restore) builds on it.
    auto fresh = f::vlWriter(bucket, "node-f");
    EXPECT_EQ(fresh.publish(f::ofNode(base, "node-f")).published.known.epoch, 3u);
}

TEST(ManifestPublishVersionLog, AnotherWritersRootInAnotherModeIsRefusedOurOwnModeSwitchIsNot) {
    namespace f = version_log_fixture;
    // A conditional bucket whose head another server published as version_log.
    Writer cond(std::make_shared<VersionedBucket>(Versioning::Enabled), storage::s3::WriteCapability::Conditional);
    cond.node = "node-c";
    auto other = f::vlWriter(cond.bucket, "node-o");
    other.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Ignore;   // so its plain PUTs land
    (void)other.publish(f::ofNode(smallVault(2), "node-o"));
    try {
        (void)cond.publish(f::ofNode(smallVault(2), "node-c"));
        ADD_FAILURE() << "built on a root of another publish mode";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::PublishModeMismatch);
    }
    // One writer that re-probed its bucket switches mode on top of its own roots.
    auto solo = Writer(std::make_shared<VersionedBucket>(Versioning::Enabled), storage::s3::WriteCapability::Conditional);
    solo.node = "node-s";
    auto c = f::ofNode(smallVault(2), "node-s");
    (void)solo.publish(c);
    solo.store = std::make_shared<S3Store>(solo.bucket, storage::s3::WriteCapability::VersionLog);
    nthFile(c, 0).size = 5;
    const auto r = solo.publish(c);
    EXPECT_EQ(r.published.known.epoch, 2u);
    EXPECT_EQ(r.published.root.publish, std::string(kPublishVersionLog));
}

TEST(ManifestPublishVersionLog, AListingThatLagsIsWaitedForOrLeavesThePublishUnsettled) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    // Listings omit versions younger than 5 s: the retries (1, 2, 4 s on the bucket clock) see it.
    w.bucket->listingLag(5);
    nthFile(c, 0).size = 1;
    EXPECT_EQ(w.publish(c).published.known.epoch, 2u);
    // Longer than every retry: unsettled, nothing recorded.
    w.bucket->listingLag(1000);
    nthFile(c, 0).size = 2;
    EXPECT_THROW((void)w.publish(c), PublishUnsettled);
    EXPECT_EQ(w.known->epoch, 2u);
    // Once it is listed, the next publish finds that root already succeeding its base: its own new root loses to it,
    // and the publish merges onto it (the same changes) and settles on top.
    w.bucket->listingLag(0);
    nthFile(c, 0).size = 3;
    const auto r = w.publish(c);
    EXPECT_EQ(r.lost, 1u);
    EXPECT_EQ(r.published.known.epoch, 4u);
    auto landed = w.loadKnown().content;
    EXPECT_EQ(nthFile(landed, 0).size, 3u);
}

TEST(ManifestPublishVersionLog, AVersionInsertedBelowASettledRootIsAnOrderViolation) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    const auto e1 = *w.known;
    w.bucket->holdPut(std::string(kRootKey));   // a PUT that started now...
    nthFile(c, 0).size = 1;
    (void)w.publish(c);                          // (epoch 2 settles while the order is still commit order)
    ASSERT_TRUE(w.settled);
    // ...commits later and is ordered by its start: below epoch 2, as succ(epoch 1). The provider broke A4.
    w.bucket->orderBy(VersionedBucket::Order::Start);
    (void)w.bucket->seed(std::string(kRootKey), f::rootLike(w, w.cache.base->root, 2, e1.root_sha256, "node-x"));
    try {
        (void)w.loadKnown();
        ADD_FAILURE() << "a displaced settled root went unnoticed";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::OrderViolation);
    }
    nthFile(c, 0).size = 2;
    EXPECT_THROW((void)w.publish(c), ChainRejected) << "and the publish refuses too";
}

TEST(ManifestChainVersionLog, ReadersTakeTheCanonicalHeadWhateverTheyKnowOrTheBucketsMode) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    const auto e1 = *w.known;
    nthFile(c, 0).size = 9;
    (void)w.publish(c);
    const auto e2 = *w.known;
    // A later sibling of epoch 2 is the current object.
    (void)w.bucket->seed(std::string(kRootKey), f::rootLike(w, w.cache.base->root, 2, e1.root_sha256, "node-x"));
    LoadOptions fromE1;
    fromE1.known = e1;
    EXPECT_EQ(load(*w.store, w.vault, w.lookup(), fromE1).known(), e2) << "rule C1 from the anchor";
    EXPECT_EQ(load(*w.store, w.vault, w.lookup(), {}).known(), e2) << "blind: equal chains, the earliest end";
    // A reader that doesn't know the bucket's capability (a restore) follows the root's declared mode.
    S3Store unknown(w.bucket);
    EXPECT_EQ(load(unknown, w.vault, w.lookup(), {}).known(), e2);
    EXPECT_EQ(loadForRestore(unknown, w.vault, w.lookup(), Checkpoint{1, e1.root_sha256, std::nullopt}).loaded.known(), e2);
    // Also when the current object is no root at all (a delete marker above the sibling): the newest authentic version
    // names the mode. Before, such a reader took that sibling as the root and refused it as a fork.
    (void)w.bucket->seedDeleteMarker(std::string(kRootKey));
    EXPECT_EQ(load(unknown, w.vault, w.lookup(), {}).known(), e2);
    EXPECT_EQ(loadForRestore(unknown, w.vault, w.lookup(), Checkpoint{2, e2.root_sha256, std::nullopt}).loaded.known(), e2);
}

TEST(ManifestChainVersionLog, WithoutItsAnchorTheChainRulesStillRefuseRollbackAndForkAndWarnOfAGap) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    std::vector<Known> k;
    for (int i = 0; i < 3; ++i) {
        nthFile(c, 0).size = 10 + i;
        (void)w.publish(c);
        k.push_back(*w.known);
    }
    LoadOptions o;
    // A known epoch 4 the bucket never shows: the bucket's best is older.
    o.known = Known{4, std::string(64, 'a'), std::nullopt};
    try {
        (void)load(*w.store, w.vault, w.lookup(), o);
        ADD_FAILURE();
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Rollback);
    }
    // Another root at the known epoch.
    o.known = Known{3, std::string(64, 'b'), std::nullopt};
    try {
        (void)load(*w.store, w.vault, w.lookup(), o);
        ADD_FAILURE();
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Fork);
    }
    // Epochs 1 and 2 gone from the bucket: from epoch 1 the head of epoch 3 can't be linked, a gap.
    for (const auto& v : w.bucket->history(std::string(kRootKey)))
        if (v.version_id != *k[2].version_id) (void)w.bucket->purgeVersion(std::string(kRootKey), v.version_id);
    o.known = k[0];
    const auto gap = load(*w.store, w.vault, w.lookup(), o);
    EXPECT_TRUE(gap.acceptance.gap);
    EXPECT_EQ(gap.known(), k[2]);
}

TEST(ManifestChainVersionLog, AVersionThatDoesNotAuthenticateIsSkipped) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    const auto e1 = *w.known;
    nthFile(c, 0).size = 3;
    (void)w.publish(c);
    w.bucket->tamper(std::string(kRootKey), *w.known->version_id);
    EXPECT_EQ(load(*w.store, w.vault, w.lookup(), {}).known(), e1);
}

TEST(ManifestChainVersionLog, AHeadThatALifecycleRuleExpiresUnderACrashedLoserFailsLoudly) {
    namespace f = version_log_fixture;
    auto w = f::vlWriter(f::b2Bucket(), "node-a");
    w.bucket->expireNoncurrent(".vaulthalla/", 1);   // A6 broken on purpose
    auto c = f::ofNode(smallVault(3), "node-a");
    (void)w.publish(c);
    const auto e1 = *w.known;
    nthFile(c, 0).size = 3;
    (void)w.publish(c);
    // A crashed writer's sibling sits above the head; nobody repairs it for two days.
    (void)w.bucket->seed(std::string(kRootKey), f::rootLike(w, w.cache.base->root, 2, e1.root_sha256, "node-x"));
    w.bucket->advance(2 * 24 * 60 * 60);
    try {
        (void)w.loadKnown();
        ADD_FAILURE() << "the loser was taken for the expired head";
    } catch (const ChainRejected& e) {
        EXPECT_EQ(e.code(), ChainError::Fork);
    }
}

}
