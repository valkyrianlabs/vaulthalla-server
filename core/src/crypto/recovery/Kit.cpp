#include "crypto/recovery/Kit.hpp"

#include <sodium.h>

#include <algorithm>

namespace vh::crypto::recovery {

namespace kit_detail {

std::string base64(const std::vector<uint8_t>& bytes) {
    std::string out(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(out.size() - 1);  // the terminating NUL
    return out;
}

std::optional<std::vector<uint8_t>> unbase64(const std::string& text) {
    std::vector<uint8_t> out(text.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), text.data(), text.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        return std::nullopt;
    out.resize(len);
    return out;
}

const nlohmann::json& member(const nlohmann::json& j, const char* name, const nlohmann::json::value_t type) {
    if (!j.contains(name) || j.at(name).type() != type)
        throw KitError("bad_kit", std::string("`") + name + "` is missing or has the wrong type");
    return j.at(name);
}

// A non-negative integer (a document parsed from text has unsigned ones; one built in code may have signed ones).
bool isUint(const nlohmann::json& j) {
    return j.is_number_unsigned() || (j.is_number_integer() && j.get<int64_t>() >= 0);
}

bool isHex64(const std::string& s) {
    return s.size() == 64 && std::ranges::all_of(s, [](const char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

}

KitError::KitError(std::string code, const std::string& detail)
    : std::runtime_error("not a usable recovery kit: " + detail), code_(std::move(code)) {}

const KitVault* Kit::find(const id::ObjectUid& vaultUid) const {
    for (const auto& v : vaults)
        if (v.vault_uid == vaultUid) return &v;
    return nullptr;
}

KitVault kitVaultFromJson(const nlohmann::json& j) {
    using namespace kit_detail;
    using vt = nlohmann::json::value_t;
    if (!j.is_object()) throw KitError("bad_kit", "a vault entry is not an object");
    KitVault v;
    const auto uid = id::fromBase32(member(j, "vault_uid", vt::string).get<std::string>());
    if (!uid) throw KitError("bad_kit", "`vault_uid` is not a vault uid");
    v.vault_uid = *uid;
    if (j.contains("origin") && !j.at("origin").is_null()) {
        const auto& o = j.at("origin");
        if (!o.is_object()) throw KitError("bad_kit", "`origin` is not an object");
        if (o.contains("node_id") && o.at("node_id").is_string()) v.origin_node_id = o.at("node_id").get<std::string>();
        if (o.contains("vault_id") && isUint(o.at("vault_id")))
            v.origin_vault_id = o.at("vault_id").get<uint64_t>();
    }
    if (j.contains("attestation_public_keys") && !j.at("attestation_public_keys").is_null()) {
        const auto& keys = j.at("attestation_public_keys");
        if (!keys.is_array()) throw KitError("bad_kit", "`attestation_public_keys` is not an array");
        for (const auto& k : keys) {
            if (!k.is_object() || !k.contains("key_id") || !isUint(k.at("key_id")) ||
                !k.contains("public_key") || !k.at("public_key").is_string())
                throw KitError("bad_kit", "an attestation public key needs key_id and public_key");
            auto pk = unbase64(k.at("public_key").get<std::string>());
            if (!pk || pk->size() != crypto_sign_PUBLICKEYBYTES)
                throw KitError("bad_kit", "an attestation public key is not base64 of 32 bytes");
            v.attestation_public_keys.push_back({k.at("key_id").get<unsigned>(), std::move(*pk)});
        }
    }
    if (j.contains("checkpoint") && !j.at("checkpoint").is_null()) {
        const auto& c = j.at("checkpoint");
        if (!c.is_object()) throw KitError("bad_kit", "`checkpoint` is not an object");
        KitCheckpoint cp;
        if (!c.contains("epoch") || !isUint(c.at("epoch"))) throw KitError("bad_kit", "`checkpoint.epoch` is not a number");
        cp.epoch = c.at("epoch").get<uint64_t>();
        cp.root_sha256 = member(c, "root_sha256", vt::string).get<std::string>();
        if (!isHex64(cp.root_sha256)) throw KitError("bad_kit", "`checkpoint.root_sha256` is not 64 hex digits");
        if (c.contains("at") && c.at("at").is_string()) cp.at = c.at("at").get<std::string>();
        v.checkpoint = std::move(cp);
    }
    return v;
}

Kit parseKit(const nlohmann::json& j) {
    using namespace kit_detail;
    using vt = nlohmann::json::value_t;
    if (!j.is_object() || !j.contains("type") || !j.at("type").is_string() ||
        j.at("type").get<std::string>() != kKitType)
        throw KitError("bad_kit", "the document is not a vh.recovery-kit");
    if (!j.contains("v") || !isUint(j.at("v")) || j.at("v").get<uint64_t>() != kKitVersion)
        throw KitError("unsupported_version", "this server reads recovery kits of version 1");
    const auto& seedText = member(j, "recovery_seed", vt::string).get_ref<const std::string&>();
    std::optional<RecoverySeed> seed;
    try {
        seed.emplace(RecoverySeed::parse(seedText));
    } catch (const SeedError& e) {
        throw KitError(e.code(), "the recovery seed is not valid (" + e.code() + ")");
    }
    Kit kit{std::move(*seed), {}};
    if (j.contains("vaults") && !j.at("vaults").is_null()) {
        if (!j.at("vaults").is_array()) throw KitError("bad_kit", "`vaults` is not an array");
        for (const auto& v : j.at("vaults")) {
            auto parsed = kitVaultFromJson(v);
            if (kit.find(parsed.vault_uid)) throw KitError("bad_kit", "the kit lists a vault twice");
            kit.vaults.push_back(std::move(parsed));
        }
    }
    return kit;
}

nlohmann::json toJson(const KitVault& v) {
    nlohmann::json keys = nlohmann::json::array();
    for (const auto& k : v.attestation_public_keys)
        keys.push_back({{"key_id", k.key_id}, {"public_key", kit_detail::base64(k.public_key)}});
    nlohmann::json out{{"vault_uid", id::toBase32(v.vault_uid)}, {"attestation_public_keys", std::move(keys)}};
    if (v.origin_node_id || v.origin_vault_id) {
        nlohmann::json origin = nlohmann::json::object();
        if (v.origin_node_id) origin["node_id"] = *v.origin_node_id;
        if (v.origin_vault_id) origin["vault_id"] = *v.origin_vault_id;
        out["origin"] = std::move(origin);
    }
    if (v.checkpoint) {
        nlohmann::json cp{{"epoch", v.checkpoint->epoch}, {"root_sha256", v.checkpoint->root_sha256}};
        if (v.checkpoint->at) cp["at"] = *v.checkpoint->at;
        out["checkpoint"] = std::move(cp);
    }
    return out;
}

nlohmann::json toJson(const Kit& kit) {
    nlohmann::json vaults = nlohmann::json::array();
    for (const auto& v : kit.vaults) vaults.push_back(toJson(v));
    return {{"type", kKitType}, {"v", kKitVersion}, {"recovery_seed", kit.seed.text()}, {"vaults", std::move(vaults)}};
}

}
