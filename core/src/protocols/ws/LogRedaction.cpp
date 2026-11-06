#include "protocols/ws/LogRedaction.hpp"

#include <array>
#include <cctype>
#include <string>

namespace vh::protocols::ws {

bool isSensitiveLogKey(const std::string_view key) {
    std::string lower;
    lower.reserve(key.size());
    for (const unsigned char c : key) lower.push_back(static_cast<char>(std::tolower(c)));

    // MFA (#356): TOTP seeds and otpauth URIs, recovery codes, and WebAuthn ceremony material (credentials,
    // assertions, attestations, clientDataJSON, authenticatorData, signatures, user handles).
    static constexpr std::array<std::string_view, 20> kFragments{
        "password", "passwd", "passphrase", "token", "secret", "api_key", "apikey",
        "access_key", "private_key", "authorization", "cookie", "credential",
        "otpauth", "recovery_code", "assertion", "attestation", "client_data", "authenticator_data", "signature",
        "user_handle"
    };
    for (const auto fragment : kFragments)
        if (lower.find(fragment) != std::string::npos) return true;

    // Bare key-material names ("key", "master_key", "encryption_key", "otp", "code" for email challenges).
    return lower == "key" || lower.ends_with("_key") || lower == "otp" || lower == "pin" || lower == "code" ||
           lower == "codes";
}

namespace {

// An otpauth:// URI carries a TOTP seed whatever key it sits under.
bool isOtpauthUri(const std::string& value) {
    constexpr std::string_view kScheme = "otpauth:";
    if (value.size() < kScheme.size()) return false;
    for (std::size_t i = 0; i < kScheme.size(); ++i)
        if (std::tolower(static_cast<unsigned char>(value[i])) != kScheme[i]) return false;
    return true;
}

}

nlohmann::json redactForLog(const nlohmann::json& j) {
    if (j.is_object()) {
        nlohmann::json out = nlohmann::json::object();
        for (const auto& [k, v] : j.items())
            out[k] = isSensitiveLogKey(k) && !v.is_null() ? nlohmann::json("[REDACTED]") : redactForLog(v);
        return out;
    }
    if (j.is_array()) {
        nlohmann::json out = nlohmann::json::array();
        for (const auto& v : j) out.push_back(redactForLog(v));
        return out;
    }
    if (j.is_string() && isOtpauthUri(j.get_ref<const std::string&>())) return "[REDACTED]";
    return j;
}

}
