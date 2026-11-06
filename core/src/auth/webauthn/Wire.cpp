#include "auth/webauthn/Wire.hpp"

#include "auth/webauthn/Base64Url.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <vector>

namespace vh::auth::webauthn::wire {

namespace {

using Doc = nlohmann::json;
constexpr std::size_t kMaxDepth = 8;
constexpr std::size_t kMaxTransports = 8;

// Structure-only SAX pass: refuses duplicate keys at any level and nesting deeper than kMaxDepth. nlohmann's DOM
// keeps the last of two equal keys without a word, so this runs first.
class StructureCheck {
public:
    bool null() { return true; }
    bool boolean(bool) { return true; }
    bool number_integer(Doc::number_integer_t) { return true; }
    bool number_unsigned(Doc::number_unsigned_t) { return true; }
    bool number_float(Doc::number_float_t, const Doc::string_t&) { return true; }
    bool string(Doc::string_t&) { return true; }
    bool binary(Doc::binary_t&) { return false; }
    bool start_object(std::size_t) { return open(true); }
    bool end_object() { return close(); }
    bool start_array(std::size_t) { return open(false); }
    bool end_array() { return close(); }
    bool key(Doc::string_t& k) {
        auto& keys = levels_.back();
        if (std::ranges::find(keys, k) != keys.end()) return false;
        keys.push_back(k);
        return true;
    }
    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) { return false; }

private:
    std::vector<std::vector<std::string>> levels_;
    bool open(bool) {
        levels_.emplace_back();
        return levels_.size() <= kMaxDepth;
    }
    bool close() {
        levels_.pop_back();
        return true;
    }
};

std::optional<Doc> strictObject(const std::string_view text) {
    if (text.empty() || text.size() > kMaxBytes) return std::nullopt;
    StructureCheck check;
    if (!Doc::sax_parse(text.begin(), text.end(), &check, nlohmann::detail::input_format_t::json, true, false))
        return std::nullopt;
    auto doc = Doc::parse(text.begin(), text.end(), nullptr, /*allow_exceptions=*/false, /*ignore_comments=*/false);
    if (doc.is_discarded() || !doc.is_object()) return std::nullopt;
    return doc;
}

std::optional<Bytes> b64Field(const Doc& obj, const char* key, const bool required = true) {
    const auto it = obj.find(key);
    if (it == obj.end()) return required ? std::nullopt : std::optional<Bytes>(Bytes{});
    if (!it->is_string()) return std::nullopt;
    return base64urlDecode(it->get_ref<const std::string&>());
}

// The fields every PublicKeyCredential JSON has: type, id == rawId, response, and the optional
// clientExtensionResults (object) and authenticatorAttachment (string or null).
const Doc* credentialEnvelope(const Doc& doc, Bytes& rawId) {
    const auto type = doc.find("type");
    const auto id = doc.find("id");
    const auto raw = doc.find("rawId");
    const auto response = doc.find("response");
    if (type == doc.end() || !type->is_string() || type->get_ref<const std::string&>() != "public-key") return nullptr;
    if (id == doc.end() || raw == doc.end() || !id->is_string() || !raw->is_string() || *id != *raw) return nullptr;
    if (response == doc.end() || !response->is_object()) return nullptr;
    if (const auto ext = doc.find("clientExtensionResults"); ext != doc.end() && !ext->is_object()) return nullptr;
    if (const auto att = doc.find("authenticatorAttachment"); att != doc.end() && !att->is_string() && !att->is_null())
        return nullptr;
    auto decoded = base64urlDecode(raw->get_ref<const std::string&>());
    if (!decoded || decoded->empty()) return nullptr;
    rawId = std::move(*decoded);
    return &*response;
}

}

std::optional<RegistrationResponse> parseRegistration(const std::string_view text) {
    const auto doc = strictObject(text);
    if (!doc) return std::nullopt;
    RegistrationResponse out;
    const Doc* response = credentialEnvelope(*doc, out.rawId);
    if (!response) return std::nullopt;
    auto clientData = b64Field(*response, "clientDataJSON");
    auto attestation = b64Field(*response, "attestationObject");
    if (!clientData || !attestation || clientData->empty() || attestation->empty()) return std::nullopt;
    out.clientDataJSON = std::move(*clientData);
    out.attestationObject = std::move(*attestation);

    if (const auto t = response->find("transports"); t != response->end()) {
        if (!t->is_array() || t->size() > kMaxTransports) return std::nullopt;
        for (const auto& v : *t) {
            if (!v.is_string() || v.get_ref<const std::string&>().empty() || v.get_ref<const std::string&>().size() > 32)
                return std::nullopt;
            out.transports.push_back(v.get<std::string>());
        }
    }
    if (const auto ext = doc->find("clientExtensionResults"); ext != doc->end()) {
        if (const auto props = ext->find("credProps"); props != ext->end()) {
            if (!props->is_object()) return std::nullopt;
            if (const auto rk = props->find("rk"); rk != props->end()) {
                if (!rk->is_boolean()) return std::nullopt;
                out.residentKey = rk->get<bool>();
            }
        }
    }
    return out;
}

std::optional<AssertionResponse> parseAssertion(const std::string_view text) {
    const auto doc = strictObject(text);
    if (!doc) return std::nullopt;
    AssertionResponse out;
    const Doc* response = credentialEnvelope(*doc, out.rawId);
    if (!response) return std::nullopt;
    auto clientData = b64Field(*response, "clientDataJSON");
    auto authData = b64Field(*response, "authenticatorData");
    auto signature = b64Field(*response, "signature");
    if (!clientData || !authData || !signature || clientData->empty() || authData->empty() || signature->empty())
        return std::nullopt;
    out.clientDataJSON = std::move(*clientData);
    out.authenticatorData = std::move(*authData);
    out.signature = std::move(*signature);
    if (const auto h = response->find("userHandle"); h != response->end() && !h->is_null()) {
        if (!h->is_string()) return std::nullopt;
        auto handle = base64urlDecode(h->get_ref<const std::string&>());
        if (!handle) return std::nullopt;
        out.userHandle = std::move(*handle);
    }
    return out;
}

}
