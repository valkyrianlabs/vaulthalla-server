#include "vault/Recover.hpp"

#include <vl/keykit/kev1.hpp>
#include "crypto/vhf1/Format.hpp"
#include "log/Registry.hpp"
#include "sync/manifest/Chain.hpp"
#include "sync/manifest/Objects.hpp"
#include "vault/Content.hpp"
#include "vault/KeyCheck.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <functional>
#include <ranges>
#include <unordered_map>
#include <unordered_set>

namespace vh::vault::recover {

namespace recover_detail {

namespace mf = sync::manifest;

constexpr std::size_t kMaxEnvelopes = 4096;
constexpr uint64_t kMaxEnvelopeBytes = 1024;
constexpr std::string_view kRecoveredDir = "Recovered";

std::optional<std::vector<uint8_t>> b64(const nlohmann::json& v) {
    if (!v.is_string()) return std::nullopt;
    const auto& text = v.get_ref<const std::string&>();
    std::vector<uint8_t> out(text.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return std::nullopt;
    out.resize(len);
    return out;
}

std::optional<std::vector<uint8_t>> b64(const std::string& v) { return b64(nlohmann::json(v)); }

std::string b64Of(std::span<const uint8_t> bytes) {
    std::string out(sodium_base64_ENCODED_LEN(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

std::string hexOf(std::span<const uint8_t> bytes) {
    std::string out;
    for (const auto b : bytes) out += fmt::format("{:02x}", b);
    return out;
}

std::optional<std::vector<uint8_t>> fromHex(const std::string& hex) {
    if (hex.size() % 2) return std::nullopt;
    std::vector<uint8_t> out(hex.size() / 2);
    std::size_t len = 0;
    if (sodium_hex2bin(out.data(), out.size(), hex.data(), hex.size(), nullptr, &len, nullptr) != 0 ||
        len != out.size())
        return std::nullopt;
    return out;
}

bool sameBytes(const crypto::SecretKey& a, const crypto::SecretKey& b) {
    return sodium_memcmp(a.bytes().data(), b.bytes().data(), a.bytes().size()) == 0;
}

std::optional<attestation::Attestation> attestationOf(const mf::KeyAttestation& a) {
    const auto sig = b64(a.signature);
    if (!sig || sig->size() != attestation::kSignatureSize) return std::nullopt;
    return attestation::Attestation{.key_id = a.key_id, .signature = *sig};
}

// The generation id (base64 salt) of a manifest generation (hex salt).
std::optional<std::string> generationB64(const std::optional<std::string>& hex) {
    if (!hex) return std::nullopt;
    const auto bytes = fromHex(*hex);
    if (!bytes || bytes->size() != crypto::vhf1::kSaltSize) return std::nullopt;
    return b64Of(*bytes);
}

struct Candidate {
    crypto::SecretKeyPtr key;
    bool envelope{false}, exported{false};
};

void addCandidate(std::map<uint32_t, std::vector<Candidate>>& out, const uint32_t version,
                  const crypto::SecretKeyPtr& key, const bool fromEnvelope) {
    auto& list = out[version];
    for (auto& c : list)
        if (sameBytes(*c.key, *key)) {
            (fromEnvelope ? c.envelope : c.exported) = true;
            return;
        }
    Candidate c{key, fromEnvelope, !fromEnvelope};
    // Customer-held exports first: when the bucket offers another key for the version, the export's is tried first.
    if (!fromEnvelope) list.insert(list.begin(), std::move(c));
    else list.push_back(std::move(c));
}

std::string sourceOf(const Candidate& c) {
    if (c.envelope && c.exported) return "envelope+export";
    return c.envelope ? "envelope" : "export";
}

// One o/<uid> object's 120-byte header, authenticated against this vault, the uid and a held key.
struct HeaderResult {
    std::optional<mf::RecoveredObject> object;
    std::string reason;
    std::optional<uint32_t> version;  // the key version the header asked for (also when it wasn't held)
};

HeaderResult readHeader(mf::ObjectStore& store, const mf::ListedObject& listed, const Uid& vaultUid, const Uid& uid,
                        const crypto::vhf1::KeyLookup& keys) {
    HeaderResult out;
    const auto head = store.getRange(listed.key, 0, crypto::vhf1::kHeaderSize);
    if (!head) {
        out.reason = "gone since the listing";
        return out;
    }
    try {
        const auto header = crypto::vhf1::openHeader(*head, {crypto::vhf1::Kind::FileContent, vaultUid, uid, std::nullopt},
                                                     [&](const uint32_t v) {
                                                         out.version = v;
                                                         return keys(v);
                                                     });
        const auto layout = crypto::vhf1::layoutFor(listed.size, header.params().chunkLog2);
        mf::RecoveredObject r;
        r.uid = uid;
        r.key = listed.key;
        r.path = std::string("/") + std::string(kRecoveredDir) + "/" + mf::uidText(uid);
        r.object_size = listed.size;
        r.plaintext_size = layout.plaintextSize;
        r.key_version = header.params().keyVersion;
        r.generation = hexOf(header.params().salt);
        out.object = std::move(r);
    } catch (const crypto::vhf1::Error& e) {
        out.reason = std::string(crypto::vhf1::errorCodeName(e.code()));
        if (e.code() == crypto::vhf1::ErrorCode::KeyUnavailable && out.version)
            out.reason += fmt::format(" (key version {})", *out.version);
    } catch (const std::exception& e) {
        out.reason = e.what();
    }
    return out;
}

mf::Entry fileEntryOf(const mf::RecoveredObject& r, const std::string& parent) {
    mf::Entry e;
    e.uid = mf::uidText(r.uid);
    e.kind = mf::EntryKind::File;
    e.parent = parent;
    e.name = mf::uidText(r.uid);
    e.mode = 0644;
    e.size = r.plaintext_size;
    // An empty file needs no key to be read (every empty file is stored as nothing): its row names no generation.
    if (r.plaintext_size > 0) {
        e.format = 1;
        e.key_version = r.key_version;
        e.generation = r.generation;
    }
    e.object = mf::ObjectRef{std::nullopt, r.object_size, std::nullopt, std::nullopt};
    return e;
}

mf::Entry dirEntry(const std::optional<std::string>& parent, const std::string& name) {
    mf::Entry e;
    e.uid = mf::uidText(crypto::id::newObjectUid());
    e.kind = mf::EntryKind::Dir;
    e.parent = parent;
    e.name = name;
    e.mode = 0755;
    return e;
}

bool inTree(const mf::Entry& e) {
    return !e.trashed && e.kind != mf::EntryKind::Tombstone;
}

}  // namespace recover_detail

// ---- names ----------------------------------------------------------------------------------------------------------

std::string_view to_string(const Anchor anchor) {
    switch (anchor) {
        case Anchor::Verified: return "verified";
        case Anchor::NoAnchor: return "no_anchor";
        case Anchor::EmptyAnchor: return "empty_anchor";
        case Anchor::Unattested: return "unattested";
        case Anchor::Unverified: return "unverified";
        case Anchor::WrongNode: return "wrong_node";
        case Anchor::WrongVault: return "wrong_vault";
        case Anchor::SelfAttested: return "self_attested";
        case Anchor::KeyCheckMismatch: return "key_check_mismatch";
    }
    return "unknown";
}

// ---- material -------------------------------------------------------------------------------------------------------

std::vector<ExportedVault> parseExport(const nlohmann::json& doc) {
    using namespace recover_detail;
    const auto one = [](const nlohmann::json& entry) {
        if (!entry.is_object()) throw std::invalid_argument("an export entry is not a JSON object");
        ExportedVault v;
        if (entry.contains("vault_id") && entry.at("vault_id").is_number_unsigned())
            v.vault_id = entry.at("vault_id").get<uint64_t>();
        if (entry.contains("node_id") && entry.at("node_id").is_string()) v.node_id = entry.at("node_id").get<std::string>();
        if (entry.contains("vault_uid") && entry.at("vault_uid").is_string()) {
            v.vault_uid = crypto::id::fromBase32(entry.at("vault_uid").get<std::string>());
            if (!v.vault_uid) throw std::invalid_argument("the export's vault_uid is not a vault uid");
        }
        const auto fieldIn = [](const nlohmann::json& e, const char* name) -> const nlohmann::json* {
            if (e.contains(name) && !e.at(name).is_null()) return &e.at(name);
            if (e.contains("key_info") && e.at("key_info").is_object() && e.at("key_info").contains(name) &&
                !e.at("key_info").at(name).is_null())
                return &e.at("key_info").at(name);
            return nullptr;
        };
        const auto add = [&](const nlohmann::json& keyField, const uint64_t version, const nlohmann::json* check,
                             const nlohmann::json* att) {
            if (version == 0 || version > UINT32_MAX) throw std::invalid_argument("a key version is not a positive integer");
            auto bytes = b64(keyField);
            if (!bytes || bytes->size() != crypto::util::AES_KEY_SIZE) {
                if (bytes) sodium_memzero(bytes->data(), bytes->size());
                throw std::invalid_argument(fmt::format("key version {} is not a base64 32-byte key", version));
            }
            ExportedVersion ev;
            ev.version = static_cast<uint32_t>(version);
            ev.key = std::make_shared<const crypto::SecretKey>(*bytes);
            sodium_memzero(bytes->data(), bytes->size());
            if (check && check->is_string()) ev.key_check = check->get<std::string>();
            if (att && att->is_object() && att->contains("key_id") && att->at("key_id").is_number_unsigned() &&
                att->contains("signature")) {
                const auto id = att->at("key_id").get<uint64_t>();
                const auto sig = b64(att->at("signature"));
                if (id >= attestation::kMinKeyId && id <= attestation::kMaxKeyId && sig &&
                    sig->size() == attestation::kSignatureSize) {
                    ev.attestation = attestation::Attestation{.key_id = static_cast<unsigned>(id), .signature = *sig};
                    if (att->contains("public_key")) {
                        const auto pk = b64(att->at("public_key"));
                        if (pk && pk->size() == attestation::kPublicKeySize) ev.attestation_public_key = *pk;
                    }
                }
            }
            for (const auto& existing : v.versions)
                if (existing.version == ev.version) {
                    if (!sameBytes(*existing.key, *ev.key))
                        throw std::invalid_argument(
                            fmt::format("the export holds two different keys for version {}", ev.version));
                    return;
                }
            v.versions.push_back(std::move(ev));
        };
        if (!entry.contains("key") || !entry.contains("key_info") || !entry.at("key_info").is_object() ||
            !entry.at("key_info").contains("key_version") || !entry.at("key_info").at("key_version").is_number_unsigned())
            throw std::invalid_argument("an export entry lacks key or key_info.key_version");
        add(entry.at("key"), entry.at("key_info").at("key_version").get<uint64_t>(), fieldIn(entry, "key_check"),
            fieldIn(entry, "attestation"));
        if (entry.contains("historical_keys") && entry.at("historical_keys").is_array())
            for (const auto& h : entry.at("historical_keys")) {
                if (!h.is_object() || !h.contains("key") || !h.contains("key_version") ||
                    !h.at("key_version").is_number_unsigned())
                    throw std::invalid_argument("a historical key lacks key or key_version");
                add(h.at("key"), h.at("key_version").get<uint64_t>(), h.contains("key_check") ? &h.at("key_check") : nullptr,
                    h.contains("attestation") ? &h.at("attestation") : nullptr);
            }
        std::ranges::sort(v.versions, {}, &ExportedVersion::version);
        return v;
    };
    std::vector<ExportedVault> out;
    if (doc.is_array()) {
        for (const auto& e : doc) out.push_back(one(e));
    } else {
        out.push_back(one(doc));
    }
    if (out.empty()) throw std::invalid_argument("the export lists no vault");
    return out;
}

Pins pinsFor(const Material& material, const Uid& vaultUid) {
    Pins pins;
    if (material.kit)
        if (const auto* v = material.kit->find(vaultUid)) {
            pins.supplied = true;
            pins.node_id = v->origin_node_id;
            pins.vault_id = v->origin_vault_id;
            for (const auto& k : v->attestation_public_keys)
                pins.keys.push_back({k.key_id, k.public_key, "kit"});
        }
    for (const auto& e : material.exports) {
        if (e.vault_uid && *e.vault_uid != vaultUid) continue;
        for (const auto& version : e.versions)
            if (version.attestation && version.attestation_public_key) {
                pins.supplied = true;
                PinnedKey k{version.attestation->key_id, *version.attestation_public_key, "export"};
                if (std::ranges::find(pins.keys, k) == pins.keys.end() &&
                    std::ranges::none_of(pins.keys, [&](const PinnedKey& p) { return p.public_key == k.public_key; }))
                    pins.keys.push_back(std::move(k));
            }
    }
    return pins;
}

// ---- D1 -------------------------------------------------------------------------------------------------------------

Proof prove(const uint32_t version, const std::span<const uint8_t> key, const std::vector<Evidence>& evidence,
            const Pins& pins, const std::vector<std::vector<uint8_t>>& selfKeys) {
    Proof p;
    p.version = version;

    // The bytes against every recorded key check (with the vault id each claim names): a key that isn't the one the
    // records describe is damaged or foreign, and nothing it proves counts.
    for (const auto& e : evidence) {
        if (!e.key_check || e.vault_id == 0 || e.vault_id > UINT32_MAX) continue;
        const auto computed = keyCheck(key, static_cast<unsigned>(e.vault_id), version);
        if (!keyCheckEquals(computed, *e.key_check)) {
            p.verdict = Anchor::KeyCheckMismatch;
            p.detail = fmt::format("the key's check over vault {} differs from the one the {} records: a damaged key or "
                                   "another vault's; refused", e.vault_id, e.source);
            return p;
        }
    }

    std::vector<const Evidence*> attested;
    for (const auto& e : evidence)
        if (e.attestation) attested.push_back(&e);
    if (attested.empty()) {
        p.verdict = Anchor::Unattested;
        p.detail = "neither the bucket nor the supplied material carries an attestation of this version";
        return p;
    }
    if (!pins.supplied) {
        p.verdict = Anchor::NoAnchor;
        p.detail = "no customer material pins an attestation key (a kit entry for this vault, or an export with "
                   "attestation public keys): the version's origin can't be proven";
        return p;
    }
    if (pins.keys.empty()) {
        p.verdict = Anchor::EmptyAnchor;
        p.detail = "the kit pins no attestation keys for this vault: the version's origin can't be proven";
        return p;
    }

    const auto isSelf = [&](const PinnedKey& k) { return std::ranges::find(selfKeys, k.public_key) != selfKeys.end(); };
    bool selfVerified = false;
    std::optional<std::string> wrongNode, wrongVault;
    std::vector<unsigned> signers;
    for (const auto* ep : attested) {
        const auto& e = *ep;
        signers.push_back(e.attestation->key_id);
        if (e.node_id.empty() || e.vault_id == 0 || e.vault_id > UINT32_MAX) continue;
        const auto check = keyCheck(key, static_cast<unsigned>(e.vault_id), version);
        const auto message = attestation::message(e.node_id, e.vault_id, version, check);
        for (const auto& k : pins.keys) {
            if (k.public_key.size() != attestation::kPublicKeySize) continue;
            if (!attestation::verifySignature(k.public_key, message, e.attestation->signature)) continue;
            if (isSelf(k)) {
                selfVerified = true;
                continue;
            }
            if (pins.node_id && *pins.node_id != e.node_id) {
                wrongNode = fmt::format("the {} attestation verifies under pinned key {} but names node {}, not the "
                                        "kit's origin node {}", e.source, k.key_id, e.node_id, *pins.node_id);
                continue;
            }
            if (pins.vault_id && *pins.vault_id != e.vault_id) {
                wrongVault = fmt::format("the {} attestation verifies under pinned key {} but is over vault {}, not the "
                                         "kit's origin vault {}", e.source, k.key_id, e.vault_id, *pins.vault_id);
                continue;
            }
            p.verdict = Anchor::Verified;
            p.anchor = k;
            p.evidence = e;
            p.detail = fmt::format("attested by node {} (vault {}, signing key {}), verified with the {}'s pinned key",
                                   e.node_id, e.vault_id, e.attestation->key_id, k.source);
            return p;
        }
    }
    if (wrongNode) {
        p.verdict = Anchor::WrongNode;
        p.detail = *wrongNode;
    } else if (wrongVault) {
        p.verdict = Anchor::WrongVault;
        p.detail = *wrongVault;
    } else if (selfVerified) {
        p.verdict = Anchor::SelfAttested;
        p.detail = "only the restoring node's own attestation key verifies it: this node's signature never proves where "
                   "a key came from";
    } else {
        p.verdict = Anchor::Unverified;
        std::string ids;
        for (const auto id : signers) ids += (ids.empty() ? "" : ", ") + std::to_string(id);
        p.detail = fmt::format("no pinned attestation key verifies the attestation (signing key {}): another node's or a "
                               "forged key, or an attestation over another vault, node or version", ids);
    }
    return p;
}

// ---- metering -------------------------------------------------------------------------------------------------------

void MeteredStore::count(const std::string& key, const uint64_t bytes, const bool ranged) {
    if (ranged) ++downloads_.ranged_gets;
    else ++downloads_.gets;
    if (key.starts_with(vl::keykit::kev1::kObjectPrefix)) downloads_.envelope_bytes += bytes;
    else if (key.starts_with(".vaulthalla/")) downloads_.manifest_bytes += bytes;
    else if (key.starts_with(sync::manifest::kObjectPrefix) && ranged && bytes <= crypto::vhf1::kHeaderSize)
        downloads_.header_bytes += bytes;
    else if (key.starts_with(sync::manifest::kObjectPrefix)) downloads_.content_bytes += bytes;
    else downloads_.other_bytes += bytes;
}

std::optional<sync::manifest::StoredObject> MeteredStore::get(const std::string& key,
                                                             const std::optional<std::string>& versionId) {
    auto out = inner_->get(key, versionId);
    count(key, out ? out->bytes.size() : 0, false);
    return out;
}

std::optional<std::vector<uint8_t>> MeteredStore::getRange(const std::string& key, const uint64_t offset,
                                                          const uint64_t length) {
    auto out = inner_->getRange(key, offset, length);
    count(key, out ? out->size() : 0, offset == 0 && length <= crypto::vhf1::kHeaderSize);
    return out;
}

std::vector<sync::manifest::ListedObject> MeteredStore::list(const std::string& prefix) {
    ++downloads_.lists;
    return inner_->list(prefix);
}

std::vector<sync::manifest::StoredVersion> MeteredStore::versions(const std::string& key) {
    ++downloads_.version_lists;
    return inner_->versions(key);
}

// ---- the plan -------------------------------------------------------------------------------------------------------

const VersionPlan* Plan::version(const uint32_t v) const {
    for (const auto& p : versions)
        if (p.version == v) return &p;
    return nullptr;
}

std::vector<uint32_t> Plan::canonical() const {
    std::vector<uint32_t> out;
    for (const auto& p : versions)
        if (p.key && p.proof.canonical()) out.push_back(p.version);
    return out;
}

std::vector<uint32_t> Plan::blocking() const {
    std::vector<uint32_t> out;
    for (const auto& p : versions)
        if (p.needed && !(p.key && p.proof.canonical())) out.push_back(p.version);
    return out;
}

std::vector<uint32_t> Plan::salvageable() const {
    std::vector<uint32_t> out;
    for (const auto& p : versions)
        if (p.needed && p.key && !p.proof.canonical() && !p.proof.refused()) out.push_back(p.version);
    return out;
}

Plan plan(sync::manifest::ObjectStore& inner, const Material& material, const Options& options) {
    using namespace recover_detail;
    MeteredStore store(std::shared_ptr<sync::manifest::ObjectStore>(&inner, [](auto*) {}));
    Plan out;

    // 1. Which vault: the caller's, the kit's (one vault, or the one the bucket's hint names), the export's, the hint.
    std::optional<Uid> hint;
    try {
        if (const auto layout = store.get(std::string(mf::kLayoutKey), std::nullopt)) {
            const auto j = nlohmann::json::parse(layout->bytes.begin(), layout->bytes.end(), nullptr, false);
            if (j.is_object() && j.contains("vault_uid") && j["vault_uid"].is_string())
                hint = crypto::id::fromBase32(j["vault_uid"].get<std::string>());
        }
    } catch (const std::exception& e) {
        log::Registry::crypto()->info("[vault::recover] the bucket's layout hint is unreadable ({}); ignored", e.what());
    }
    std::optional<Uid> uid = options.vault_uid;
    const auto kitVaults = material.kit ? material.kit->vaults.size() : 0;
    if (!uid && kitVaults > 0) {
        if (hint && material.kit->find(*hint)) uid = hint;
        else if (hint)
            throw Refusal("kit_vault_mismatch",
                          fmt::format("the recovery kit does not list the vault this bucket holds (uid {}): it is "
                                      "another vault's kit; nothing was written", mf::uidText(*hint)));
        else if (kitVaults == 1) uid = material.kit->vaults.front().vault_uid;
    }
    if (!uid)
        for (const auto& e : material.exports)
            if (e.vault_uid) {
                uid = e.vault_uid;
                break;
            }
    if (!uid) uid = hint;
    if (!uid)
        throw Refusal("vault_unknown", "can't tell which vault the bucket holds: it has no layout hint, and neither the kit "
                                       "nor the export names one; pass the vault uid");
    if (material.kit && kitVaults > 0 && !material.kit->find(*uid))
        throw Refusal("kit_vault_mismatch",
                      fmt::format("the recovery kit does not list vault {}: it is another vault's kit; nothing was "
                                  "written", mf::uidText(*uid)));
    out.vault_uid = *uid;
    out.pins = pinsFor(material, *uid);

    // 2. Key material: the vault's KEV1 envelopes unwrapped with the kit's seed, and the export's versions.
    std::map<uint32_t, std::vector<Candidate>> candidates;
    std::set<uint32_t> seen;
    {
        std::optional<vl::keykit::SecretBytes> sk;
        if (material.kit) sk.emplace(material.kit->seed.x25519SecretKey());
        for (const auto& o : store.list(std::string(vl::keykit::kev1::kObjectPrefix))) {
            if (out.envelopes.listed >= kMaxEnvelopes) break;
            ++out.envelopes.listed;
            if (o.size > kMaxEnvelopeBytes) {
                ++out.envelopes.rejected;
                continue;
            }
            const auto obj = store.get(o.key, std::nullopt);
            if (!obj) continue;
            try {
                const auto h = vl::keykit::kev1::inspect(obj->bytes);
                if (h.vault_uid == *uid) {
                    seen.insert(h.key_version);
                    out.envelope_index[o.key.substr(vl::keykit::kev1::kObjectPrefix.size())] = {hexOf(h.recipient_id),
                                                                                           h.key_version};
                }
            } catch (const std::exception&) {}
            if (!sk) continue;
            try {
                auto u = vl::keykit::kev1::unwrap(obj->bytes, sk->bytes(), vl::keykit::kev1::Suite::X25519, *uid);
                ++out.envelopes.unwrapped;
                addCandidate(candidates, u.key_version, std::make_shared<const crypto::SecretKey>(u.key.bytes()), true);
            } catch (const vl::keykit::kev1::Error& e) {
                if (vl::keykit::kev1::skippedByRestore(e.code())) ++out.envelopes.skipped;
                else ++out.envelopes.rejected;
            }
        }
    }
    if (material.kit && out.envelopes.unwrapped == 0 && material.exports.empty())
        throw Refusal("recovery_material_mismatch",
                      fmt::format("none of the {} recovery envelope(s) in the bucket is addressed to this kit's "
                                  "recipient for vault {}: a wrong seed, another vault's kit, or a recipient that was "
                                  "never enrolled; nothing was written", out.envelopes.listed, mf::uidText(*uid)));
    const ExportedVault* exported = nullptr;
    for (const auto& e : material.exports)
        if (!e.vault_uid || *e.vault_uid == *uid) {
            if (e.vault_uid || material.exports.size() == 1) {
                exported = &e;
                break;
            }
        }
    if (!material.exports.empty() && !exported)
        throw Refusal("export_vault_mismatch", "the export has no entry for the vault this bucket holds (uid " +
                                                   mf::uidText(*uid) + "); nothing was written");
    if (exported)
        for (const auto& v : exported->versions) addCandidate(candidates, v.version, v.key, false);
    if (candidates.empty())
        throw Refusal("no_key_material", "no supplied material holds a key of vault " + mf::uidText(*uid) +
                                             ": pass the recovery kit (--kit) and/or a key export (--export)");

    std::map<uint32_t, crypto::SecretKeyPtr> chosen;
    for (const auto& [v, list] : candidates) chosen[v] = list.front().key;
    const crypto::vhf1::KeyLookup lookup = [&](const uint32_t v) -> crypto::SecretKeyPtr {
        const auto it = chosen.find(v);
        return it == chosen.end() ? nullptr : it->second;
    };

    // The root's own version: the candidate its header authenticates under (the bucket may offer planted keys).
    try {
        if (const auto root = store.get(std::string(mf::kRootKey), std::nullopt))
            for (std::size_t i = 1;; ++i) {
                std::optional<uint32_t> asked;
                try {
                    (void)crypto::vhf1::openHeader(root->bytes, {crypto::vhf1::Kind::ManifestRoot, *uid, *uid, std::nullopt},
                                                   [&](const uint32_t v) {
                                                       asked = v;
                                                       return lookup(v);
                                                   });
                    break;
                } catch (const crypto::vhf1::Error& e) {
                    if (e.code() != crypto::vhf1::ErrorCode::HeaderAuthFailed || !asked) break;
                    const auto it = candidates.find(*asked);
                    if (it == candidates.end() || i >= it->second.size()) break;
                    chosen[*asked] = it->second[i].key;
                }
            }
    } catch (const std::exception&) {}

    // 3. The manifest (chain rules against the kit's checkpoint, else the one supplied with the material), or the blind
    // floor.
    std::optional<mf::Checkpoint> checkpoint;
    if (material.kit)
        if (const auto* kv = material.kit->find(*uid); kv && kv->checkpoint)
            checkpoint = mf::Checkpoint{kv->checkpoint->epoch, kv->checkpoint->root_sha256, kv->checkpoint->at};
    if (!checkpoint && material.checkpoint)
        checkpoint = mf::Checkpoint{material.checkpoint->epoch, material.checkpoint->root_sha256, material.checkpoint->at};
    std::optional<mf::RestoreLoad> loaded;
    try {
        loaded = mf::loadForRestore(store, *uid, lookup, checkpoint, options.accept_rollback);
    } catch (const mf::ChainRejected& e) {
        if (e.code() == mf::ChainError::Rollback)
            throw Refusal("rollback", fmt::format(
                "the bucket's manifest root (epoch {}) is older than your checkpoint (epoch {}): the bucket may have been "
                "rolled back to an earlier state. Nothing was written; --accept-rollback restores that older state",
                e.epoch(), checkpoint ? checkpoint->epoch : 0));
        throw Refusal("fork", fmt::format("the bucket's manifest root (epoch {}) contradicts your checkpoint ({}): "
                                          "refused; nothing was written", e.epoch(), mf::chainErrorName(e.code())));
    } catch (const mf::NoUsableRoot& e) {
        out.blind = true;
        out.issues.push_back(std::string("no usable manifest root (") + e.what() +
                             "): blind rebuild, names and the tree are lost, content is recovered under /Recovered");
    }

    // The listing every reconciliation uses (one LIST of o/).
    const auto listed = store.list(std::string(mf::kObjectPrefix));
    std::unordered_map<std::string, const mf::ListedObject*> listedByUid;
    for (const auto& o : listed)
        if (const auto u = mf::uidOfObjectKey(o.key)) listedByUid[mf::uidText(*u)] = &o;

    std::map<uint32_t, const mf::KeyRecord*> records;
    if (loaded) {
        const auto& root = loaded->loaded.root;
        out.epoch = loaded->loaded.acceptance.epoch;
        out.root_sha256 = loaded->loaded.acceptance.root_sha256;
        out.root_etag = loaded->loaded.etag;
        out.freshness = loaded->freshness;
        out.freshness_report = loaded->report;
        out.origin_node_id = root.producer.node_id;
        out.origin_vault_id = root.producer.vault_id;
        if (root.vault) out.vault_name = root.vault->name;
        out.recovery_policy = root.recovery_policy;
        if (loaded->loaded.source == mf::RootSource::ProviderVersion)
            out.issues.push_back("the current manifest root was missing or did not authenticate: restored from a retained "
                                 "provider version of it");
        if (loaded->loaded.acceptance.gap) out.issues.push_back("the chain has a gap since the checkpoint");
        for (const auto& i : loaded->loaded.issues)
            out.issues.push_back(fmt::format("segment {}: {} ({})", i.sid, i.problem, mf::to_string(i.resolution)));
        out.content = loaded->loaded.content;
        for (const auto& k : root.keys) {
            records[k.version] = &k;
            seen.insert(k.version);
        }
        // Per version, the candidate whose key check matches the root's record (planted keys lose).
        for (auto& [v, list] : candidates) {
            const auto r = records.find(v);
            if (r == records.end() || !r->second->key_check || !root.producer.vault_id) continue;
            for (const auto& c : list)
                if (keyCheckEquals(keyCheck(c.key->bytes(), static_cast<unsigned>(*root.producer.vault_id), v),
                                   *r->second->key_check)) {
                    chosen[v] = c.key;
                    break;
                }
        }
    } else {
        out.freshness_report = std::string(mf::kFreshnessUnverified);
        if (exported) {
            out.origin_node_id = exported->node_id.value_or("");
            out.origin_vault_id = exported->vault_id;
        }
        if (out.origin_node_id.empty() && out.pins.node_id) out.origin_node_id = *out.pins.node_id;
        if (!out.origin_vault_id) out.origin_vault_id = out.pins.vault_id;
        auto root = dirEntry(std::nullopt, "");
        out.content.entries.push_back(root);
    }

    // 4. The tree's root and /Recovered (created when something needs it).
    for (const auto& e : out.content.entries)
        if (e.kind == mf::EntryKind::Dir && !e.parent) out.root_uid = e.uid;
    if (out.root_uid.empty()) {
        auto root = dirEntry(std::nullopt, "");
        out.root_uid = root.uid;
        out.content.entries.push_back(std::move(root));
    }
    std::optional<std::string> recoveredUid;
    const auto recoveredDir = [&]() -> std::string {
        if (recoveredUid) return *recoveredUid;
        for (const auto& e : out.content.entries)
            if (e.kind == mf::EntryKind::Dir && e.parent == out.root_uid && e.name == kRecoveredDir && inTree(e))
                return *(recoveredUid = e.uid);
        bool taken = std::ranges::any_of(out.content.entries, [&](const mf::Entry& e) {
            return e.parent == out.root_uid && e.name == kRecoveredDir && inTree(e);
        });
        auto dir = dirEntry(out.root_uid, taken ? std::string(kRecoveredDir) + " (restore)" : std::string(kRecoveredDir));
        recoveredUid = dir.uid;
        out.content.entries.push_back(std::move(dir));
        return *recoveredUid;
    };

    // 5. Objects vs manifest (§4.4): orphans that authenticate go to /Recovered; entries whose object is gone are
    //    restored as unavailable (names kept); objects whose size moved since the manifest are read by their header.
    std::unordered_set<std::string> named;
    for (const auto& e : out.content.entries)
        if (e.kind != mf::EntryKind::Tombstone) named.insert(e.uid);
    for (const auto& o : listed) {
        const auto u = mf::uidOfObjectKey(o.key);
        if (!u) {
            out.rejected.push_back(o.key + ": not an o/<uid> key");
            continue;
        }
        if (named.contains(mf::uidText(*u))) continue;
        auto h = readHeader(store, o, *uid, *u, lookup);
        if (h.version) seen.insert(*h.version);
        if (!h.object) {
            out.rejected.push_back(o.key + ": " + h.reason);
            continue;
        }
        auto entry = fileEntryOf(*h.object, recoveredDir());
        // A tombstone of this uid keeps its versions with the recovered file.
        for (auto& t : out.content.entries)
            if (t.uid == entry.uid && t.kind == mf::EntryKind::Tombstone) {
                entry.versions = std::move(t.versions);
                entry.names = std::move(t.names);
                t.kind = mf::EntryKind::Dir;  // marked for removal below
                t.uid.clear();
            }
        out.orphans.push_back(entry.uid);
        named.insert(entry.uid);
        out.content.entries.push_back(std::move(entry));
    }
    std::erase_if(out.content.entries, [](const mf::Entry& e) { return e.uid.empty(); });
    for (auto& e : out.content.entries) {
        if (e.kind != mf::EntryKind::File) continue;
        const auto it = listedByUid.find(e.uid);
        if (it == listedByUid.end()) {
            if (e.size.value_or(0) > 0 || e.object) out.missing_objects.push_back(e.uid);
            continue;
        }
        const auto unquote = [](std::string t) {
            std::erase(t, '"');
            return t;
        };
        const bool etagMoved = e.object && e.object->etag && it->second->etag &&
                               unquote(*e.object->etag) != unquote(*it->second->etag);
        if (e.object && (e.object->size != it->second->size || etagMoved)) {
            // Another generation than the manifest's (a write after its last publish, or a root older than the
            // bucket): its 120-byte header says which generation and key version the object holds.
            const auto uidBytes = mf::parseUid(e.uid, "bad_segment", "entry uid");
            auto h = readHeader(store, *it->second, *uid, uidBytes, lookup);
            e.object->etag = it->second->etag;
            e.object->version_id.reset();
            e.object->size = it->second->size;
            if (h.object) {
                e.generation = h.object->generation;
                e.key_version = h.object->key_version;
                e.size = h.object->plaintext_size;
            } else {
                e.generation.reset();
                e.key_version = h.version;
                if (const auto plain = content::plaintextSizeOf(it->second->size, content::Format::Vhf1)) e.size = *plain;
            }
            if (h.version) seen.insert(*h.version);
            out.issues.push_back("o/" + e.uid + ": the object changed since the manifest (" +
                                 (h.object ? "its header names generation " + h.object->generation.substr(0, 8) + "…"
                                           : h.reason) +
                                 ")");
        }
    }

    // 6. A tree reachable from the root: entries whose parent is gone (a lost segment) or that form a cycle go under
    //    /Recovered with their names; duplicate names in one folder get the uid appended.
    for (;;) {
        std::unordered_map<std::string, std::vector<std::size_t>> children;
        std::unordered_map<std::string, std::size_t> byUid;
        for (std::size_t i = 0; i < out.content.entries.size(); ++i) {
            const auto& e = out.content.entries[i];
            if (!inTree(e)) continue;
            byUid[e.uid] = i;
            if (e.parent) children[*e.parent].push_back(i);
        }
        std::unordered_set<std::string> reached{out.root_uid};
        std::vector<std::string> todo{out.root_uid};
        while (!todo.empty()) {
            const auto cur = todo.back();
            todo.pop_back();
            const auto it = byUid.find(cur);
            if (it == byUid.end() || out.content.entries[it->second].kind != mf::EntryKind::Dir) continue;
            for (const auto c : children[cur])
                if (reached.insert(out.content.entries[c].uid).second) todo.push_back(out.content.entries[c].uid);
        }
        std::optional<std::size_t> detached;
        for (std::size_t i = 0; i < out.content.entries.size(); ++i) {
            const auto& e = out.content.entries[i];
            if (!inTree(e) || reached.contains(e.uid)) continue;
            const auto parent = e.parent ? byUid.find(*e.parent) : byUid.end();
            const bool parentGone = parent == byUid.end() ||
                                    out.content.entries[parent->second].kind != mf::EntryKind::Dir;
            if (parentGone || !detached) detached = i;
            if (parentGone) break;
        }
        if (!detached) break;
        const auto target = recoveredDir();
        auto& e = out.content.entries[*detached];
        out.issues.push_back(fmt::format("{} {}: its folder is not in the manifest; restored under /{}",
                                         to_string(e.kind), e.uid, kRecoveredDir));
        e.parent = target;
    }
    {
        std::map<std::pair<std::string, std::string>, int> names;
        for (auto& e : out.content.entries) {
            if (!inTree(e) || !e.parent) continue;
            if (names[{*e.parent, e.name}]++ > 0) e.name += " (" + e.uid.substr(0, 8) + ")";
        }
    }

    // 7. Versions: everything the root's history, the entries and the bucket name.
    std::map<uint32_t, bool> live;  // version → live files need it
    for (const auto& e : out.content.entries) {
        if (e.key_version) {
            seen.insert(*e.key_version);
            if (e.kind == mf::EntryKind::File && inTree(e) && e.size.value_or(0) > 0) live[*e.key_version] = true;
        }
        for (const auto& v : e.versions)
            if (v.key_version) seen.insert(*v.key_version);
    }
    for (const auto& s : out.content.snapshots)
        for (const auto& m : s.members)
            if (m.key_version) seen.insert(*m.key_version);
    for (const auto& v : candidates | std::views::keys) seen.insert(v);
    out.highest_seen = seen.empty() ? 0 : *seen.rbegin();

    if (!records.empty()) {
        uint32_t current = 0;
        for (const auto& [v, r] : records)
            if (!r->retired_at) current = std::max(current, v);
        out.current_version = current ? current : records.rbegin()->first;
    } else {
        for (const auto& [v, _] : live) out.current_version = std::max(out.current_version, v);
        if (out.current_version == 0 && !candidates.empty()) out.current_version = candidates.rbegin()->first;
    }

    std::set<uint32_t> versions;
    for (const auto& v : records | std::views::keys) versions.insert(v);
    for (const auto& v : live | std::views::keys) versions.insert(v);
    for (const auto& v : candidates | std::views::keys) versions.insert(v);
    if (out.current_version) versions.insert(out.current_version);
    for (const auto v : versions) {
        VersionPlan vp;
        vp.version = v;
        vp.current = v == out.current_version;
        vp.needed = vp.current || live.contains(v);
        std::vector<Evidence> evidence;
        if (const auto r = records.find(v); r != records.end()) {
            const auto& rec = *r->second;
            vp.created_at = rec.created_at;
            vp.retired_at = rec.retired_at;
            if (rec.envelopes) vp.kids = *rec.envelopes;
            if (out.origin_vault_id) {
                Evidence ev{"root", out.origin_node_id, *out.origin_vault_id, rec.key_check, std::nullopt};
                if (rec.attestation) ev.attestation = attestationOf(*rec.attestation);
                evidence.push_back(std::move(ev));
            }
            if (rec.origin)
                evidence.push_back(Evidence{"origin", rec.origin->node_id, rec.origin->vault_id, rec.origin->key_check,
                                            attestationOf(rec.origin->attestation)});
        }
        if (exported)
            for (const auto& ev : exported->versions)
                if (ev.version == v && exported->vault_id) {
                    std::string node = exported->node_id.value_or("");
                    if (node.empty()) node = out.pins.node_id.value_or(out.origin_node_id);
                    evidence.push_back(Evidence{"export", node, *exported->vault_id, ev.key_check, ev.attestation});
                }
        const auto c = candidates.find(v);
        if (c == candidates.end()) {
            vp.proof.version = v;
            vp.proof.verdict = Anchor::Unattested;
            vp.proof.detail = "no supplied material holds this version's key";
        } else {
            vp.key = chosen.at(v);
            for (const auto& cand : c->second)
                if (cand.key == vp.key) vp.key_source = sourceOf(cand);
            vp.proof = prove(v, vp.key->bytes(), evidence, out.pins, options.self_keys);
        }
        out.versions.push_back(std::move(vp));
    }

    // Snapshot members: restorable only where the bucket still holds their generation (a listed provider version).
    std::unordered_map<std::string, const mf::Entry*> byUid;
    for (const auto& e : out.content.entries) byUid[e.uid] = &e;
    for (auto& s : out.content.snapshots)
        for (auto& m : s.members) {
            if (!m.restorable_from_bucket) continue;
            const auto e = m.uid ? byUid.find(*m.uid) : byUid.end();
            if (e == byUid.end()) {
                m.restorable_from_bucket = false;
                continue;
            }
            const auto& entry = *e->second;
            const bool objectHeld = entry.object && std::ranges::find(out.missing_objects, entry.uid) ==
                                                        out.missing_objects.end();
            m.restorable_from_bucket =
                std::ranges::any_of(entry.versions, [&](const mf::FileVersion& v) {
                    if (v.delete_marker) return false;
                    return (m.provider_version_id && v.version_id == *m.provider_version_id) ||
                           (m.generation && v.generation == m.generation);
                }) ||
                (m.generation && objectHeld && entry.generation == m.generation);
        }

    mf::normalize(out.content);
    out.downloads = store.downloads();
    return out;
}

// ---- report ---------------------------------------------------------------------------------------------------------

nlohmann::json toJson(const Proof& p) {
    nlohmann::json j{{"version", p.version}, {"verdict", std::string(to_string(p.verdict))}, {"detail", p.detail}};
    if (p.anchor) j["anchor"] = {{"key_id", p.anchor->key_id}, {"source", p.anchor->source}};
    if (p.evidence) j["origin"] = {{"node_id", p.evidence->node_id}, {"vault_id", p.evidence->vault_id},
                                   {"source", p.evidence->source}};
    return j;
}

nlohmann::json toJson(const Downloads& d) {
    return {{"manifest_bytes", d.manifest_bytes}, {"envelope_bytes", d.envelope_bytes}, {"header_bytes", d.header_bytes},
            {"content_bytes", d.content_bytes}, {"other_bytes", d.other_bytes}, {"gets", d.gets},
            {"ranged_gets", d.ranged_gets}, {"lists", d.lists}, {"version_lists", d.version_lists}};
}

nlohmann::json toJson(const Plan& p) {
    using namespace recover_detail;
    unsigned files = 0, dirs = 0, symlinks = 0, trashed = 0, tombstones = 0, providerVersions = 0, members = 0,
             restorable = 0;
    uint64_t bytes = 0;
    for (const auto& e : p.content.entries) {
        providerVersions += static_cast<unsigned>(e.versions.size());
        if (e.trashed) ++trashed;
        else if (e.kind == mf::EntryKind::File) {
            ++files;
            bytes += e.size.value_or(0);
        } else if (e.kind == mf::EntryKind::Dir) ++dirs;
        else if (e.kind == mf::EntryKind::Symlink) ++symlinks;
        else ++tombstones;
    }
    for (const auto& s : p.content.snapshots)
        for (const auto& m : s.members) {
            ++members;
            if (m.restorable_from_bucket) ++restorable;
        }
    nlohmann::json versions = nlohmann::json::array();
    for (const auto& v : p.versions) {
        auto j = toJson(v.proof);
        j["held"] = v.key != nullptr;
        if (v.key) j["key_source"] = v.key_source;
        j["current"] = v.current;
        j["needed"] = v.needed;
        if (!v.key) j["state"] = "missing";
        else if (v.proof.canonical()) j["state"] = "canonical";
        else if (v.proof.refused()) j["state"] = "refused";
        else j["state"] = "salvage_only";
        versions.push_back(std::move(j));
    }
    const auto list = [](const std::vector<uint32_t>& v) { return nlohmann::json(v); };
    nlohmann::json j{
        {"vault_uid", mf::uidText(p.vault_uid)},
        {"origin", {{"node_id", p.origin_node_id.empty() ? nlohmann::json(nullptr) : nlohmann::json(p.origin_node_id)},
                    {"vault_id", p.origin_vault_id ? nlohmann::json(*p.origin_vault_id) : nlohmann::json(nullptr)}}},
        {"manifest_vault_name", p.vault_name ? nlohmann::json(*p.vault_name) : nlohmann::json(nullptr)},
        {"blind", p.blind},
        {"epoch", p.epoch ? nlohmann::json(*p.epoch) : nlohmann::json(nullptr)},
        {"root_sha256", p.root_sha256 ? nlohmann::json(*p.root_sha256) : nlohmann::json(nullptr)},
        {"freshness", std::string(mf::to_string(p.freshness))},
        {"freshness_report", p.freshness_report},
        {"issues", p.issues},
        {"counts", {{"files", files}, {"folders", dirs}, {"symlinks", symlinks}, {"trashed", trashed},
                    {"tombstones", tombstones}, {"provider_versions", providerVersions}, {"bytes", bytes},
                    {"snapshots", p.content.snapshots.size()}, {"snapshot_members", members},
                    {"snapshot_members_restorable", restorable}}},
        {"key_versions", std::move(versions)},
        {"current_version", p.current_version},
        {"highest_version_seen", p.highest_seen},
        {"canonical_versions", list(p.canonical())},
        {"blocking_versions", list(p.blocking())},
        {"salvageable_versions", list(p.salvageable())},
        {"orphans", p.orphans},
        {"missing_objects", p.missing_objects},
        {"rejected_objects", p.rejected},
        {"envelopes", {{"listed", p.envelopes.listed}, {"unwrapped", p.envelopes.unwrapped},
                       {"skipped", p.envelopes.skipped}, {"rejected", p.envelopes.rejected}}},
        {"anchors", {{"supplied", p.pins.supplied}, {"keys", p.pins.keys.size()}}},
        {"downloads", toJson(p.downloads)},
    };
    return j;
}

}
