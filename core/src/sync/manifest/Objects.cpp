#include "sync/manifest/Objects.hpp"

#include "crypto/util/digest.hpp"
#include "crypto/vhf1/Reader.hpp"
#include "crypto/vhf1/Writer.hpp"

#include <fmt/format.h>

namespace vh::sync::manifest {

std::string segmentKey(const std::string_view sid) { return std::string(kSegmentPrefix) + std::string(sid); }

std::optional<std::string> sidOfKey(const std::string_view key) {
    if (!key.starts_with(kSegmentPrefix)) return std::nullopt;
    const auto sid = key.substr(kSegmentPrefix.size());
    if (!crypto::id::fromBase32(sid)) return std::nullopt;
    return std::string(sid);
}

std::optional<Uid> uidOfObjectKey(const std::string_view key) {
    if (!key.starts_with(kObjectPrefix)) return std::nullopt;
    return crypto::id::fromBase32(key.substr(kObjectPrefix.size()));
}

std::string layoutHint(const Uid& vaultUid) {
    return canonicalJson({{"format", 1}, {"layout", std::string(kLayoutOpaqueV1)}, {"vault_uid", uidText(vaultUid)}});
}

std::string sha256Hex(const std::span<const uint8_t> bytes) {
    const auto digest = crypto::util::EvpDigest::of(EVP_sha256(), bytes.data(), bytes.size());
    std::string out;
    out.reserve(digest.size() * 2);
    for (const auto b : digest) out += fmt::format("{:02x}", b);
    return out;
}

std::vector<uint8_t> sealDocument(const Json& doc, const crypto::vhf1::Kind kind, const Uid& vaultUid,
                                  const Uid& objectUid, const SealingKey& key) {
    if (!key.key || key.version == 0) throw std::invalid_argument("manifest: sealing needs a vault key version");
    const auto text = canonicalJson(doc);
    crypto::vhf1::HeaderParams params;
    params.kind = kind;
    params.keyVersion = key.version;
    params.vaultUid = vaultUid;
    params.objectUid = objectUid;
    params.salt = crypto::vhf1::freshSalt();
    return crypto::vhf1::seal({reinterpret_cast<const uint8_t*>(text.data()), text.size()}, params, *key.key);
}

std::vector<uint8_t> sealRoot(const RootDocument& root, const Uid& vaultUid, const SealingKey& key) {
    return sealDocument(toJson(root), crypto::vhf1::Kind::ManifestRoot, vaultUid, vaultUid, key);
}

std::vector<uint8_t> sealSegment(const SegmentDocument& doc, const Uid& vaultUid, const Uid& sid, const SealingKey& key) {
    return sealDocument(toJson(doc), crypto::vhf1::Kind::ManifestSegment, vaultUid, sid, key);
}

std::vector<uint8_t> sealSnapshot(const SnapshotDocument& doc, const Uid& vaultUid, const Uid& sid,
                                  const SealingKey& key) {
    return sealDocument(toJson(doc), crypto::vhf1::Kind::ManifestSegment, vaultUid, sid, key);
}

Json openDocument(const std::span<const uint8_t> object, const crypto::vhf1::Kind kind, const Uid& vaultUid,
                  const Uid& objectUid, const crypto::vhf1::KeyLookup& keys, const std::string& code) {
    const crypto::vhf1::Expectation expect{kind, vaultUid, objectUid, std::nullopt};
    const auto plaintext = crypto::vhf1::open(object, expect, keys);
    const auto bytes = plaintext.span();
    auto parsed = Json::parse(bytes.begin(), bytes.end(), nullptr, false);
    if (parsed.is_discarded()) throw FormatError(code, "the authenticated plaintext is not JSON");
    return parsed;
}

RootDocument openRoot(const std::span<const uint8_t> object, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys) {
    return rootFromJson(openDocument(object, crypto::vhf1::Kind::ManifestRoot, vaultUid, vaultUid, keys, "bad_root"),
                        vaultUid);
}

SegmentDocument openSegment(const std::span<const uint8_t> object, const Uid& vaultUid, const Uid& sid,
                            const crypto::vhf1::KeyLookup& keys) {
    return segmentFromJson(
        openDocument(object, crypto::vhf1::Kind::ManifestSegment, vaultUid, sid, keys, "bad_segment"), vaultUid);
}

SnapshotDocument openSnapshot(const std::span<const uint8_t> object, const Uid& vaultUid, const Uid& sid,
                              const crypto::vhf1::KeyLookup& keys) {
    return snapshotFromJson(
        openDocument(object, crypto::vhf1::Kind::ManifestSegment, vaultUid, sid, keys, "bad_snapshot"), vaultUid);
}

}
