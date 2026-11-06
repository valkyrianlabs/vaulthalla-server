// VHF1 codec (crypto::vhf1, spec design/encryption/02-authenticated-file-format.md) against the golden vectors in
// design/encryption/vectors/vectors.json, read at test time: every VHF1 vector there (positives, range reads,
// negatives, range negatives, manifest objects and manifest negatives) is exercised, and a section or error code this
// suite doesn't know fails Vhf1Vectors.EverySectionIsClassified, so the file and this suite can't drift apart
// (tools/contracts/test_vhf1_vectors_contract.py checks the same from the Python side and runs --check).
#include "crypto/SecretKey.hpp"
#include "crypto/vhf1/Format.hpp"
#include "crypto/vhf1/Reader.hpp"
#include "crypto/vhf1/Writer.hpp"
#include "../fuzz/vhf1_fuzz_body.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

namespace vh::crypto::vhf1::test_vhf1 {

namespace {

using Json = nlohmann::json;
using Bytes = std::vector<uint8_t>;

// Sections of vectors.json and who verifies them. VHF1-owned sections are exercised here; the others belong to the
// suites of their own workstreams (#329: object ids and KEV1/recovery seed with WS1/WS3, the manifest chain with
// WS3-a). A new section fails until it is classified here (and, if it is VHF1's, tested).
const std::set<std::string> kTopLevel = {"schema", "generated_by", "conventions", "object_ids", "vhf1",
                                         "kev1", "recovery_seed", "manifest"};
const std::set<std::string> kVhf1Sections = {"positive", "range_reads", "negative", "range_negative"};
const std::set<std::string> kManifestSections = {"objects", "chain", "negative"};  // chain: WS3-a (spec 03)

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
    if (hex.size() % 2 != 0) throw std::invalid_argument("odd hex length");
    Bytes out(hex.size() / 2);
    for (std::size_t i = 0; i < out.size(); ++i) out[i] = static_cast<uint8_t>(std::stoul(hex.substr(2 * i, 2), nullptr, 16));
    return out;
}

std::string toHex(const std::span<const uint8_t> bytes) {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (const auto b : bytes) {
        out += kDigits[b >> 4];
        out += kDigits[b & 0xF];
    }
    return out;
}

Bytes fromHex(const Json& hex) { return fromHex(hex.get<std::string>()); }

template <std::size_t N>
std::array<uint8_t, N> fixed(const std::string& hex) {
    const auto raw = fromHex(hex);
    if (raw.size() != N) throw std::invalid_argument("hex field has the wrong length");
    std::array<uint8_t, N> out{};
    std::ranges::copy(raw, out.begin());
    return out;
}

template <std::size_t N>
std::array<uint8_t, N> fixed(const Json& hex) {
    return fixed<N>(hex.get<std::string>());
}

Bytes sha256(const std::span<const uint8_t> data) {
    Bytes out(32);
    unsigned int len = 0;
    EVP_Digest(data.data(), data.size(), out.data(), &len, EVP_sha256(), nullptr);
    return out;
}

// pattern(n, seed): byte i = (i * 131 + seed * 17 + 7) mod 256 (the vectors' plaintext generator).
Bytes pattern(const std::size_t n, const unsigned seed) {
    Bytes out(n);
    for (std::size_t i = 0; i < n; ++i) out[i] = static_cast<uint8_t>((i * 131 + seed * 17 + 7) & 0xFF);
    return out;
}

std::map<uint32_t, SecretKeyPtr> allKeys() {
    std::map<uint32_t, SecretKeyPtr> keys;
    for (const auto& [version, hex] : vectors()["conventions"]["keys"].items())
        keys[static_cast<uint32_t>(std::stoul(version))] = std::make_shared<const SecretKey>(fromHex(hex.get<std::string>()));
    return keys;
}

KeyLookup lookupOf(std::map<uint32_t, SecretKeyPtr> keys) {
    return [keys = std::move(keys)](const uint32_t v) -> SecretKeyPtr {
        const auto it = keys.find(v);
        return it == keys.end() ? nullptr : it->second;
    };
}

HeaderParams paramsOf(const Json& p) {
    HeaderParams out;
    out.kind = static_cast<Kind>(p["kind"].get<int>());
    out.keyVersion = p["key_version"].get<uint32_t>();
    out.vaultUid = fixed<kUidSize>(p["vault_uid_hex"]);
    out.objectUid = fixed<kUidSize>(p["object_uid_hex"]);
    out.salt = fixed<kSaltSize>(p["salt_hex"]);
    out.chunkLog2 = p["chunk_log2"].get<uint8_t>();
    return out;
}

// expect_from() of the reference reader: the vector's params, then the override (kind, uids, held key versions).
struct ReaderSetup {
    Expectation expect;
    KeyLookup keys;
};

ReaderSetup readerFor(const Json& params, const Json& override = Json::object()) {
    ReaderSetup s;
    s.expect.kind = static_cast<Kind>(override.value("kind", params.value("kind", 1)));
    s.expect.vaultUid = fixed<kUidSize>(override.value("vault_uid_hex", params["vault_uid_hex"].get<std::string>()));
    s.expect.objectUid = fixed<kUidSize>(override.value("object_uid_hex", params["object_uid_hex"].get<std::string>()));
    auto keys = allKeys();
    if (override.contains("keys")) {
        std::map<uint32_t, SecretKeyPtr> held;
        for (const auto& v : override["keys"]) held[v.get<uint32_t>()] = keys.at(v.get<uint32_t>());
        keys = std::move(held);
    }
    s.keys = lookupOf(std::move(keys));
    return s;
}

Json positiveNamed(const std::string& name) {
    for (const auto& v : vectors()["vhf1"]["positive"])
        if (v["name"].get<std::string>() == name) return v;
    throw std::out_of_range("no positive vector " + name);
}

Bytes plaintextOf(const Json& v) {
    if (v.contains("plaintext_hex")) return fromHex(v["plaintext_hex"]);
    const auto gen = v["plaintext_generator"].get<std::string>();  // "pattern(n, seed)"
    const auto open = gen.find('('), comma = gen.find(',');
    if (gen.rfind("pattern(", 0) != 0 || comma == std::string::npos) throw std::invalid_argument("generator " + gen);
    return pattern(std::stoul(gen.substr(open + 1, comma - open - 1)), static_cast<unsigned>(std::stoul(gen.substr(comma + 1))));
}

Bytes objectOf(const Json& v) {
    if (v.contains("object_hex")) return fromHex(v["object_hex"]);
    const auto params = paramsOf(v["params"]);
    return seal(plaintextOf(v), params, *allKeys().at(params.keyVersion));
}

Json errorJson(const Error& e) {
    Json out = {{"error", std::string(errorCodeName(e.code()))}};
    if (e.chunkIndex()) out["chunk_index"] = *e.chunkIndex();
    return out;
}

Bytes bytesOf(const SecureBytes& b) { return {b.span().begin(), b.span().end()}; }

// Collects what reaches readers' sinks and what the wipe observer sees, for "never emits a failed chunk".
struct WipeWatch {
    std::vector<std::pair<uint64_t, bool>> wiped;  // index, scratch all zero
    WipeWatch() {
        setChunkWipeObserverForTesting([this](const uint64_t i, const std::span<const uint8_t> s) {
            wiped.emplace_back(i, std::ranges::all_of(s, [](const uint8_t b) { return b == 0; }));
        });
    }
    ~WipeWatch() { setChunkWipeObserverForTesting({}); }
    WipeWatch(const WipeWatch&) = delete;
    WipeWatch& operator=(const WipeWatch&) = delete;
};

// Expected failure of an operation as the vectors spell it ({"error": …, "chunk_index"?: …}).
template <typename F>
std::optional<Json> failureOf(F&& f) {
    try {
        f();
    } catch (const Error& e) {
        return errorJson(e);
    }
    return std::nullopt;
}

}

// ── Golden vectors ───────────────────────────────────────────────────────────────────────────────────────────────

TEST(Vhf1Vectors, EverySectionIsClassified) {
    const auto& doc = vectors();
    EXPECT_EQ(doc["schema"].get<std::string>(), "vh-crypto-vectors/1");
    for (const auto& [key, _] : doc.items()) EXPECT_TRUE(kTopLevel.contains(key)) << "unclassified section " << key;
    std::set<std::string> vhf1, manifest;
    for (const auto& [key, _] : doc["vhf1"].items()) vhf1.insert(key);
    for (const auto& [key, _] : doc["manifest"].items()) manifest.insert(key);
    EXPECT_EQ(vhf1, kVhf1Sections);
    EXPECT_EQ(manifest, kManifestSections);
    EXPECT_FALSE(doc["vhf1"]["positive"].empty());
    EXPECT_FALSE(doc["vhf1"]["negative"].empty());
}

TEST(Vhf1Vectors, EveryErrorCodeIsKnown) {
    const auto& doc = vectors();
    std::vector<Json> expects;
    for (const auto* section : {"negative", "range_negative"})
        for (const auto& n : doc["vhf1"][section]) expects.push_back(n["expect"]);
    for (const auto& n : doc["manifest"]["negative"]) expects.push_back(n["expect"]);
    for (const auto& e : expects) {
        if (e.contains("ok")) continue;
        const auto name = e["error"].get<std::string>();
        const auto code = errorCodeFromName(name);
        ASSERT_TRUE(code.has_value()) << "vector error code " << name << " has no ErrorCode";
        EXPECT_EQ(errorCodeName(*code), name);
    }
}

TEST(Vhf1Vectors, PositivesSealByteForByteFromTheirParams) {
    const auto keys = allKeys();
    for (const auto& v : vectors()["vhf1"]["positive"]) {
        SCOPED_TRACE(v["name"].get<std::string>());
        const auto params = paramsOf(v["params"]);
        const auto plaintext = plaintextOf(v);
        ASSERT_EQ(plaintext.size(), v["plaintext_size"].get<std::size_t>());
        EXPECT_EQ(toHex(sha256(plaintext)), v["plaintext_sha256"].get<std::string>());

        const auto object = seal(plaintext, params, *keys.at(params.keyVersion));
        EXPECT_EQ(object.size(), v["object_size"].get<std::size_t>());
        EXPECT_EQ(objectSizeFor(plaintext.size(), params.chunkLog2), object.size());
        EXPECT_EQ(toHex(sha256(object)), v["object_sha256"].get<std::string>());
        if (v.contains("object_hex")) { EXPECT_EQ(toHex(object), v["object_hex"].get<std::string>()); }

        // The published intermediate values, one by one (a byte mismatch above says which step diverged).
        const auto& in = v["intermediate"];
        const auto body = encodeHeaderBody(params);
        EXPECT_EQ(toHex(body), in["header_body_hex"].get<std::string>());
        const auto hh = headerHash(body);
        EXPECT_EQ(toHex(hh), in["header_hash_hex"].get<std::string>());
        const auto ks = deriveKeys(*keys.at(params.keyVersion), params.salt, hh);
        EXPECT_EQ(toHex(ks.prk->bytes()), in["prk_hex"].get<std::string>());
        EXPECT_EQ(toHex(ks.headerKey->bytes()), in["k_hdr_hex"].get<std::string>());
        EXPECT_EQ(toHex(ks.contentKey->bytes()), in["k_enc_hex"].get<std::string>());
        EXPECT_EQ(toHex(headerTag(*ks.headerKey, body)), in["header_tag_hex"].get<std::string>());
        const auto layout = layoutFor(object.size(), params.chunkLog2);
        EXPECT_EQ(layout.chunkCount, in["chunk_count"].get<uint64_t>());
        EXPECT_EQ(layout.plaintextSize, plaintext.size());
        for (const auto& c : in["chunks"]) {
            const auto i = c["index"].get<uint64_t>();
            const bool final = c["final"].get<bool>();
            EXPECT_EQ(final, i + 1 == layout.chunkCount);
            EXPECT_EQ(toHex(chunkNonce(i)), c["nonce_hex"].get<std::string>());
            EXPECT_EQ(toHex(chunkAad(hh, i, final)), c["aad_hex"].get<std::string>());
            const auto cs = chunkSpan(i, layout, params.chunkLog2);
            EXPECT_EQ(cs.size() - kTagSize, c["plaintext_len"].get<uint64_t>());
            EXPECT_EQ(toHex(std::span(object).subspan(cs.end - kTagSize, kTagSize)), c["tag_hex"].get<std::string>());
        }
    }
}

TEST(Vhf1Vectors, PositivesOpenWholeAndStreamed) {
    for (const auto& v : vectors()["vhf1"]["positive"]) {
        SCOPED_TRACE(v["name"].get<std::string>());
        const auto object = objectOf(v);
        const auto plaintext = plaintextOf(v);
        const auto r = readerFor(v["params"]);
        EXPECT_EQ(bytesOf(open(object, r.expect, r.keys, v["object_size"].get<uint64_t>())), plaintext);
        EXPECT_EQ(bytesOf(open(object, r.expect, r.keys)), plaintext);

        // The chunk walker in awkward splits gives the same chunks in order.
        for (const std::size_t step : {std::size_t{1}, std::size_t{17}, std::size_t{1040}, std::size_t{70001}}) {
            if (step == 1 && object.size() > 8192) continue;
            ChunkWalker walker(openHeader(object, r.expect, r.keys), object.size());
            Bytes got;
            uint64_t expectIndex = 0;
            for (std::size_t off = kHeaderSize; off < object.size(); off += step) {
                walker.update(std::span(object).subspan(off, std::min(step, object.size() - off)),
                              [&](const uint64_t i, const std::span<const uint8_t> p) {
                                  EXPECT_EQ(i, expectIndex++);
                                  got.insert(got.end(), p.begin(), p.end());
                              });
            }
            walker.finish();
            EXPECT_EQ(got, plaintext) << "step " << step;
        }
    }
}

TEST(Vhf1Vectors, RangeReadsMatchPlanAndPlaintext) {
    for (const auto& rv : vectors()["vhf1"]["range_reads"]) {
        SCOPED_TRACE(rv["description"].get<std::string>());
        const auto base = positiveNamed(rv["object"]);
        const auto object = objectOf(base);
        const auto r = readerFor(base["params"]);
        RangeReader reader(openHeader(object, r.expect, r.keys), rv["expected_object_size"].get<uint64_t>(),
                           object.size());
        const auto start = rv["start"].get<uint64_t>(), end = rv["end"].get<uint64_t>();
        const auto plan = reader.plan(start, end);
        if (rv["chunk_first"].is_null()) {
            EXPECT_FALSE(plan.chunkFirst);
            EXPECT_FALSE(plan.chunkLast);
            EXPECT_TRUE(rv["object_range"].is_null());
            EXPECT_FALSE(plan.objectRange);
        } else {
            EXPECT_EQ(plan.chunkFirst, rv["chunk_first"].get<uint64_t>());
            EXPECT_EQ(plan.chunkLast, rv["chunk_last"].get<uint64_t>());
            ASSERT_TRUE(plan.objectRange);
            EXPECT_EQ(plan.objectRange->begin, rv["object_range"][0].get<uint64_t>());
            EXPECT_EQ(plan.objectRange->end, rv["object_range"][1].get<uint64_t>());
        }
        // Only the planned bytes are fetched, in one call.
        int fetches = 0;
        const auto plain = reader.read(start, end, [&](const uint64_t off, const uint64_t len) {
            ++fetches;
            EXPECT_EQ(off, plan.objectRange->begin);
            EXPECT_EQ(len, plan.objectRange->size());
            return Bytes(object.begin() + static_cast<std::ptrdiff_t>(off),
                         object.begin() + static_cast<std::ptrdiff_t>(off + len));
        });
        EXPECT_EQ(fetches, plan.objectRange ? 1 : 0);
        EXPECT_EQ(toHex(plain.span()), rv["plaintext_hex"].get<std::string>());
    }
}

TEST(Vhf1Vectors, NegativesFailClosedWithTheirCodeAndChunk) {
    for (const auto& n : vectors()["vhf1"]["negative"]) {
        SCOPED_TRACE(n["name"].get<std::string>());
        const auto object = fromHex(n["object_hex"]);
        const auto base = positiveNamed(n["base"]);
        const auto basePlain = plaintextOf(base);
        const auto r = readerFor(base["params"], n["expect_override"]);
        const auto& expect = n["expect"];

        WipeWatch watch;
        const auto got = failureOf([&] { (void)open(object, r.expect, r.keys); });
        ASSERT_TRUE(got.has_value()) << "accepted";
        EXPECT_EQ(*got, expect);

        // Streamed: whatever reached the sink before the failure is authentic plaintext of the base object at its
        // offset, and never the failing chunk; a failed chunk's scratch is wiped before the error leaves.
        watch.wiped.clear();
        std::vector<uint64_t> emitted;
        const auto streamed = failureOf([&] {
            ChunkWalker walker(openHeader(object, r.expect, r.keys), object.size());
            walker.update(std::span(object).subspan(kHeaderSize), [&](const uint64_t i, const std::span<const uint8_t> p) {
                emitted.push_back(i);
                const auto c = uint64_t{1} << base["params"]["chunk_log2"].get<int>();
                ASSERT_LE(i * c + p.size(), basePlain.size());
                EXPECT_TRUE(std::equal(p.begin(), p.end(), basePlain.begin() + static_cast<std::ptrdiff_t>(i * c)));
            });
            walker.finish();
        });
        ASSERT_TRUE(streamed.has_value());
        EXPECT_EQ(*streamed, expect);
        if (expect.contains("chunk_index")) {
            const auto bad = expect["chunk_index"].get<uint64_t>();
            EXPECT_EQ(std::ranges::find(emitted, bad), emitted.end());
            ASSERT_EQ(watch.wiped.size(), 1u);
            EXPECT_EQ(watch.wiped[0].first, bad);
            EXPECT_TRUE(watch.wiped[0].second) << "failed chunk's plaintext not wiped";
        } else {
            EXPECT_TRUE(watch.wiped.empty());
        }
    }
}

TEST(Vhf1Vectors, RangeNegatives) {
    const auto base = positiveNamed("multi_chunk");
    for (const auto& n : vectors()["vhf1"]["range_negative"]) {
        SCOPED_TRACE(n["name"].get<std::string>());
        const auto object = fromHex(n["object_hex"]);
        const auto r = readerFor(base["params"]);
        const std::optional<uint64_t> size =
            n["expected_object_size"].is_null() ? std::nullopt : std::optional(n["expected_object_size"].get<uint64_t>());
        const auto start = n["start"].get<uint64_t>(), end = n["end"].get<uint64_t>();
        std::optional<SecureBytes> plain;
        WipeWatch watch;
        const auto got = failureOf([&] {
            RangeReader reader(openHeader(object, r.expect, r.keys), size, object.size());
            const auto plan = reader.plan(start, end);
            plain = reader.read(start, end, std::span(object).subspan(plan.objectRange->begin, plan.objectRange->size()));
        });
        if (n["expect"].value("ok", false)) {
            ASSERT_FALSE(got.has_value()) << got->dump();
            ASSERT_TRUE(plain);
            EXPECT_EQ(toHex(plain->span()), n["plaintext_hex"].get<std::string>());
            EXPECT_TRUE(watch.wiped.empty());
        } else {
            ASSERT_TRUE(got.has_value()) << "accepted";
            EXPECT_EQ(*got, n["expect"]);
            EXPECT_FALSE(plain);
        }
    }
}

TEST(Vhf1Vectors, ManifestObjectsOpen) {
    for (const auto& o : vectors()["manifest"]["objects"]) {
        SCOPED_TRACE(o["name"].get<std::string>());
        const auto object = fromHex(o["object_hex"]);
        Expectation expect;
        expect.kind = static_cast<Kind>(o["kind"].get<int>());
        expect.vaultUid = fixed<kUidSize>(vectors()["vhf1"]["positive"][0]["params"]["vault_uid_hex"]);
        expect.objectUid = fixed<kUidSize>(o["object_uid_hex"]);
        const auto keys = lookupOf(allKeys());
        const auto header = openHeader(object, expect, keys);
        EXPECT_EQ(header.params().keyVersion, o["key_version"].get<uint32_t>());
        if (o.contains("header_hash_hex")) { EXPECT_EQ(toHex(header.hash()), o["header_hash_hex"].get<std::string>()); }
        if (o.contains("object_sha256")) { EXPECT_EQ(toHex(sha256(object)), o["object_sha256"].get<std::string>()); }
        const auto plain = open(object, expect, keys, object.size());
        EXPECT_EQ(std::string(plain.span().begin(), plain.span().end()), o["plaintext_utf8"].get<std::string>());
    }
}

TEST(Vhf1Vectors, ManifestNegatives) {
    for (const auto& n : vectors()["manifest"]["negative"]) {
        SCOPED_TRACE(n["name"].get<std::string>());
        Expectation expect;
        expect.kind = static_cast<Kind>(n["expect_kind"].get<int>());
        expect.vaultUid = fixed<kUidSize>(vectors()["vhf1"]["positive"][0]["params"]["vault_uid_hex"]);
        expect.objectUid = fixed<kUidSize>(n["expect_object_uid_hex"]);
        const auto got = failureOf([&] { (void)open(fromHex(n["object_hex"]), expect, lookupOf(allKeys())); });
        ASSERT_TRUE(got.has_value()) << "accepted";
        EXPECT_EQ(*got, n["expect"]);
    }
}

// ── Streaming writer ─────────────────────────────────────────────────────────────────────────────────────────────

namespace {

HeaderParams smallParams() {
    HeaderParams p = paramsOf(positiveNamed("multi_chunk")["params"]);
    p.salt = freshSalt();
    return p;
}

SecretKeyPtr keyV1() { return allKeys().at(1); }

}

TEST(Vhf1Streaming, WriterEqualsOneShotForEverySplit) {
    const auto params = smallParams();
    const auto key = keyV1();
    for (const std::size_t size : {0u, 1u, 1023u, 1024u, 1025u, 2048u, 3172u}) {
        const auto plain = pattern(size, 9);
        const auto expected = seal(plain, params, *key);
        for (const std::size_t step : {1u, 7u, 1024u, 1027u, 100000u}) {
            Bytes out;
            Writer w(params, *key, [&](const std::span<const uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); });
            for (std::size_t off = 0; off < plain.size(); off += step)
                w.write(std::span(plain).subspan(off, std::min(step, plain.size() - off)));
            w.finish();
            EXPECT_EQ(out, expected) << "size " << size << " step " << step;
            EXPECT_EQ(w.objectSize(), objectSizeFor(size, params.chunkLog2));
            EXPECT_EQ(w.plaintextSize(), size);
        }
    }
}

TEST(Vhf1Streaming, HoldsBackTheFinalChunkUntilMoreArrivesOrFinish) {
    const auto params = smallParams();
    Bytes out;
    Writer w(params, *keyV1(), [&](const std::span<const uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); });
    EXPECT_EQ(out.size(), kHeaderSize);  // the header goes first, tag included
    const auto plain = pattern(2048, 3);
    w.write(std::span(plain).first(1024));
    EXPECT_EQ(out.size(), kHeaderSize) << "a full chunk can't be sealed before we know whether it is the last";
    w.write(std::span(plain).subspan(1024, 1));
    EXPECT_EQ(out.size(), kHeaderSize + 1024 + kTagSize) << "chunk 0 sealed as non-final once more data arrived";
    w.write(std::span(plain).subspan(1025));
    EXPECT_EQ(out.size(), kHeaderSize + 1024 + kTagSize);
    w.finish();
    EXPECT_EQ(out.size(), kHeaderSize + 2 * (1024 + kTagSize)) << "exact multiple: no empty trailing chunk";
    const Expectation expect{params.kind, params.vaultUid, params.objectUid, params.salt};
    EXPECT_EQ(bytesOf(open(out, expect, lookupOf(allKeys()))), plain);
}

TEST(Vhf1Streaming, EmptyPlaintextIsOneEmptyFinalChunk) {
    const auto params = smallParams();
    const auto object = seal({}, params, *keyV1());
    EXPECT_EQ(object.size(), kHeaderSize + kTagSize);
    EXPECT_EQ(layoutFor(object.size(), params.chunkLog2), (Layout{1, 0}));
    const Expectation expect{params.kind, params.vaultUid, params.objectUid, std::nullopt};
    EXPECT_TRUE(open(object, expect, lookupOf(allKeys())).empty());
}

TEST(Vhf1Streaming, WriterRefusesBadParamsReuseAndRestartAfterFailure) {
    const auto key = keyV1();
    auto bad = smallParams();
    bad.keyVersion = 0;
    EXPECT_THROW((void)seal({}, bad, *key), std::invalid_argument);
    bad = smallParams();
    bad.chunkLog2 = 9;
    EXPECT_THROW((void)seal({}, bad, *key), std::invalid_argument);
    bad = smallParams();
    bad.kind = static_cast<Kind>(4);
    EXPECT_THROW((void)seal({}, bad, *key), std::invalid_argument);

    Writer done(smallParams(), *key, [](std::span<const uint8_t>) {});
    done.finish();
    EXPECT_THROW(done.write(pattern(1, 1)), std::logic_error);
    EXPECT_THROW(done.finish(), std::logic_error);

    int calls = 0;
    Writer failing(smallParams(), *key, [&](std::span<const uint8_t>) {
        if (++calls == 2) throw std::runtime_error("disk full");
    });
    EXPECT_THROW(failing.write(pattern(3000, 1)), std::runtime_error);
    EXPECT_THROW(failing.write(pattern(1, 1)), std::logic_error);
    EXPECT_THROW(failing.finish(), std::logic_error);
}

TEST(Vhf1Streaming, FreshSaltsDiffer) {
    EXPECT_NE(freshSalt(), freshSalt());
}

TEST(Vhf1Streaming, SizeMathMatchesTheSpecTable) {
    // Spec 02 §3.4 at the writer's 64 KiB chunks.
    const std::vector<std::pair<uint64_t, uint64_t>> table = {
        {0, 136}, {1, 137}, {1000, 1136}, {65536, 65672}, {1u << 20, 1048952}, {5u << 20, 5244280},
        {100u << 20, 104883320}, {uint64_t{1} << 30, 1074004088}, {uint64_t{10} << 30, 10740039800}};
    for (const auto& [p, s] : table) {
        EXPECT_EQ(objectSizeFor(p, kWriterChunkLog2), s) << p;
        EXPECT_EQ(layoutFor(s, kWriterChunkLog2).plaintextSize, p) << s;
    }
    const uint64_t c = 1024;
    for (const uint64_t s : {uint64_t{0}, uint64_t{120}, uint64_t{135}, kHeaderSize + c + kTagSize + kTagSize,
                             kHeaderSize + c + kTagSize + 5})
        EXPECT_EQ(failureOf([&] { (void)layoutFor(s, 10); }), (Json{{"error", "bad_size"}})) << s;
    EXPECT_THROW((void)objectSizeFor(~uint64_t{0} - 100, 10), std::overflow_error);
    // Every size round-trips across the boundaries of the small chunk size.
    for (uint64_t p = 0; p < 4 * c + 3; ++p) {
        const auto s = objectSizeFor(p, 10);
        const auto l = layoutFor(s, 10);
        EXPECT_EQ(l.plaintextSize, p);
        EXPECT_EQ(chunkSpan(l.chunkCount - 1, l, 10).end, s);
    }
}

// ── Readers ──────────────────────────────────────────────────────────────────────────────────────────────────────

namespace {

struct Sample {
    HeaderParams params;
    Bytes plain;
    Bytes object;
    Expectation expect;
};

Sample sample(const std::size_t size = 3172) {
    Sample s;
    s.params = smallParams();
    s.plain = pattern(size, 11);
    s.object = seal(s.plain, s.params, *keyV1());
    s.expect = {s.params.kind, s.params.vaultUid, s.params.objectUid, s.params.salt};
    return s;
}

}

TEST(Vhf1Reader, GenerationCheckRejectsAnotherVersionOfTheFile) {
    const auto s = sample();
    auto other = s.expect;
    other.generation = freshSalt();
    EXPECT_EQ(failureOf([&] { (void)open(s.object, other, lookupOf(allKeys())); }),
              (Json{{"error", "generation_mismatch"}}));
    other.generation.reset();
    EXPECT_EQ(bytesOf(open(s.object, other, lookupOf(allKeys()))), s.plain);
}

TEST(Vhf1Reader, StructureChecksTheVectorsDontCoverFailInSpecOrder) {
    const auto s = sample();
    const auto keys = lookupOf(allKeys());
    const auto with = [&](std::initializer_list<std::pair<std::size_t, uint8_t>> edits) {
        auto obj = s.object;
        for (const auto& [at, value] : edits) obj[at] = value;
        return failureOf([&] { (void)open(obj, s.expect, keys); });
    };
    const auto err = [](const char* code) { return std::optional<Json>(Json{{"error", code}}); };
    EXPECT_EQ(with({{11, 121}}), err("bad_header_length"));
    EXPECT_EQ(with({{13, 2}}), err("unsupported_suite"));
    EXPECT_EQ(with({{14, 9}}), err("bad_chunk_size"));
    EXPECT_EQ(with({{14, 23}}), err("bad_chunk_size"));
    EXPECT_EQ(with({{15, 7}}), err("kind_mismatch"));
    EXPECT_EQ(with({{16, 0}, {17, 0}, {18, 0}, {19, 0}}), err("key_unavailable")) << "key version 0";
    EXPECT_EQ(with({{14, 11}}), err("header_auth_failed")) << "a valid but different chunk size is tagged";
    // Several faults: the first check in §3.6 order wins.
    EXPECT_EQ(with({{9, 2}, {11, 121}, {23, 1}}), err("unsupported_version"));
    EXPECT_EQ(with({{11, 121}, {13, 2}}), err("bad_header_length"));
    EXPECT_EQ(with({{23, 1}, {15, 2}}), err("reserved_nonzero"));
    EXPECT_EQ(with({{15, 2}, {24, 0}}), err("kind_mismatch"));
}

TEST(Vhf1Reader, ShortHeaderAndAuthenticatedSizeMismatch) {
    const auto s = sample();
    const auto keys = lookupOf(allKeys());
    EXPECT_EQ(failureOf([&] { (void)openHeader(std::span(s.object).first(119), s.expect, keys); }),
              (Json{{"error", "bad_magic"}}));
    EXPECT_EQ(failureOf([&] { (void)open(s.object, s.expect, keys, s.object.size() + 1); }),
              (Json{{"error", "size_mismatch"}}));
    EXPECT_EQ(failureOf([&] { (void)open(s.object, s.expect, KeyLookup{}); }), (Json{{"error", "key_unavailable"}}));
}

TEST(Vhf1Reader, WalkerRejectsExtraOrMissingBytesAndStaysFailed) {
    const auto s = sample();
    const auto keys = lookupOf(allKeys());
    const auto body = std::span(s.object).subspan(kHeaderSize);
    const auto ignore = [](uint64_t, std::span<const uint8_t>) {};
    {
        ChunkWalker w(openHeader(s.object, s.expect, keys), s.object.size());
        w.update(body, ignore);
        const uint8_t extra = 0;
        EXPECT_EQ(failureOf([&] { w.update({&extra, 1}, ignore); }), (Json{{"error", "size_mismatch"}}));
        EXPECT_EQ(failureOf([&] { w.finish(); }), (Json{{"error", "size_mismatch"}})) << "sticky";
    }
    {
        ChunkWalker w(openHeader(s.object, s.expect, keys), s.object.size());
        w.update(body.first(body.size() - 1), ignore);
        EXPECT_EQ(failureOf([&] { w.finish(); }), (Json{{"error", "size_mismatch"}}));
    }
    {
        auto tampered = s.object;
        tampered[kHeaderSize + 3] ^= 1;
        ChunkWalker w(openHeader(tampered, s.expect, keys), tampered.size());
        int calls = 0;
        const auto counting = [&](uint64_t, std::span<const uint8_t>) { ++calls; };
        EXPECT_EQ(failureOf([&] { w.update(std::span(tampered).subspan(kHeaderSize), counting); }),
                  (Json{{"error", "chunk_auth_failed"}, {"chunk_index", 0}}));
        EXPECT_EQ(failureOf([&] { w.update({}, counting); }), (Json{{"error", "chunk_auth_failed"}, {"chunk_index", 0}}));
        EXPECT_EQ(calls, 0);
    }
}

TEST(Vhf1RangeReader, NeverReturnsBytesOfAFailedChunkAndTheFailureIsSticky) {
    auto s = sample();
    const auto keys = lookupOf(allKeys());
    const auto layout = layoutFor(s.object.size(), s.params.chunkLog2);
    s.object[chunkSpan(1, layout, s.params.chunkLog2).begin + 5] ^= 0x40;
    WipeWatch watch;
    RangeReader reader(openHeader(s.object, s.expect, keys), s.object.size(), s.object.size());
    const auto window = [&](uint64_t a, uint64_t b) {
        const auto p = reader.plan(a, b);
        return std::span<const uint8_t>(s.object).subspan(p.objectRange->begin, p.objectRange->size());
    };
    // Chunk 0 alone is fine before the failure is seen.
    EXPECT_EQ(bytesOf(reader.read(0, 100, window(0, 100))), Bytes(s.plain.begin(), s.plain.begin() + 100));
    // A range over chunks 0-2 fails at chunk 1: nothing is returned, the failed chunk's scratch was wiped.
    std::optional<SecureBytes> got;
    EXPECT_EQ(failureOf([&] { got = reader.read(500, 2500, window(500, 2500)); }),
              (Json{{"error", "chunk_auth_failed"}, {"chunk_index", 1}}));
    EXPECT_FALSE(got);
    ASSERT_EQ(watch.wiped.size(), 1u);
    EXPECT_EQ(watch.wiped[0], (std::pair<uint64_t, bool>{1, true}));
    // Sticky: even a range that avoids chunk 1 fails now.
    EXPECT_TRUE(reader.failed());
    EXPECT_EQ(failureOf([&] { got = reader.read(0, 100, window(0, 100)); }),
              (Json{{"error", "chunk_auth_failed"}, {"chunk_index", 1}}));
    EXPECT_FALSE(got);
}

TEST(Vhf1RangeReader, RequiresAnAuthenticatedObjectSize) {
    const auto s = sample();
    const auto keys = lookupOf(allKeys());
    EXPECT_EQ(failureOf([&] { (void)RangeReader{openHeader(s.object, s.expect, keys), std::nullopt, s.object.size()}; }),
              (Json{{"error", "size_unknown"}}));
    EXPECT_EQ(failureOf([&] { (void)RangeReader{openHeader(s.object, s.expect, keys), s.object.size() - 1, s.object.size()}; }),
              (Json{{"error", "size_mismatch"}}));
    RangeReader reader(openHeader(s.object, s.expect, keys), s.object.size(), s.object.size());
    EXPECT_EQ(failureOf([&] { (void)reader.read(0, 10, std::span(s.object).subspan(kHeaderSize, 10)); }),
              (Json{{"error", "size_mismatch"}}))
        << "a window that isn't exactly the planned bytes";
    EXPECT_EQ(failureOf([&] { (void)reader.plan(5, 4); }), (Json{{"error", "range_out_of_bounds"}}));
    EXPECT_FALSE(reader.failed());
}

TEST(Vhf1RangeReader, EveryRangeMatchesThePlaintext) {
    const auto s = sample(3172);
    RangeReader reader(openHeader(s.object, s.expect, lookupOf(allKeys())), s.object.size(), s.object.size());
    const auto fetch = [&](const uint64_t off, const uint64_t len) {
        return Bytes(s.object.begin() + static_cast<std::ptrdiff_t>(off),
                     s.object.begin() + static_cast<std::ptrdiff_t>(off + len));
    };
    for (uint64_t a = 0; a <= s.plain.size(); a += 97)
        for (uint64_t b = a; b <= s.plain.size(); b += 131)
            ASSERT_EQ(bytesOf(reader.read(a, b, fetch)),
                      Bytes(s.plain.begin() + static_cast<std::ptrdiff_t>(a), s.plain.begin() + static_cast<std::ptrdiff_t>(b)))
                << a << ".." << b;
    EXPECT_EQ(bytesOf(reader.read(0, s.plain.size(), fetch)), s.plain);
}

TEST(Vhf1Format, SecureBytesNeverGrowsAndWipes) {
    SecureBytes b(4);
    b.append(Bytes{1, 2, 3});
    EXPECT_THROW(b.append(Bytes{4, 5}), std::length_error);
    b.resize(1);
    EXPECT_EQ(b.storage()[1], 0) << "shrinking wipes the dropped bytes";
    SecureBytes moved = std::move(b);
    EXPECT_EQ(moved.size(), 1u);
    EXPECT_EQ(b.size(), 0u);  // NOLINT(bugprone-use-after-move): moved-from state is specified
    moved.clear();
    EXPECT_EQ(moved.storage()[0], 0);
}

// ── Fuzz body replay ─────────────────────────────────────────────────────────────────────────────────────────────
// The libFuzzer target (-Dfuzz=true, clang) runs on the dev box; here the same iteration replays the golden objects
// and a deterministic input set on every CI build, so the harness compiles everywhere and its oracles hold.

TEST(Vhf1Fuzz, ReplaysVectorsAndDeterministicInputsClean) {
    const auto replay = [](const uint8_t mode, const std::span<const uint8_t> body) {
        Bytes input{mode};
        input.insert(input.end(), body.begin(), body.end());
        fuzz::runOne(input);
    };
    for (const auto* section : {"negative", "range_negative"})
        for (const auto& n : vectors()["vhf1"][section]) replay(0, fromHex(n["object_hex"]));
    for (const auto& v : vectors()["vhf1"]["positive"])
        if (v.contains("object_hex")) replay(0, fromHex(v["object_hex"]));

    uint64_t state = 0x9E3779B97F4A7C15ull;  // splitmix64: reproducible, not a security RNG
    const auto next = [&state] {
        uint64_t z = (state += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    };
    for (int iter = 0; iter < 1500; ++iter) {
        Bytes input(static_cast<std::size_t>(next() % 4096));
        for (auto& b : input) b = static_cast<uint8_t>(next());
        if (!input.empty()) input[0] = static_cast<uint8_t>(iter % 3);
        fuzz::runOne(input);
    }
}

}
