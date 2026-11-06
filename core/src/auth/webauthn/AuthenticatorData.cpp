#include "auth/webauthn/AuthenticatorData.hpp"

#include "auth/webauthn/Cbor.hpp"
#include "auth/webauthn/Cose.hpp"

#include <algorithm>

namespace vh::auth::webauthn::authdata {

namespace {

Parsed refuseAuthData() { return {std::nullopt, Failure::AuthenticatorDataMalformed}; }

}

Parsed parse(const ByteView raw) {
    if (raw.size() > kMaxBytes) return {std::nullopt, Failure::InputTooLarge};
    if (raw.size() < kMinBytes) return refuseAuthData();

    AuthenticatorData d;
    std::copy_n(raw.begin(), 32, d.rpIdHash.begin());
    d.flagsByte = raw[32];
    d.flags.userPresent = d.flagsByte & flag::UP;
    d.flags.userVerified = d.flagsByte & flag::UV;
    d.flags.backupEligible = d.flagsByte & flag::BE;
    d.flags.backupState = d.flagsByte & flag::BS;
    d.flags.attestedCredential = d.flagsByte & flag::AT;
    d.flags.extensions = d.flagsByte & flag::ED;
    d.signCount = static_cast<std::uint32_t>(raw[33]) << 24 | static_cast<std::uint32_t>(raw[34]) << 16
                  | static_cast<std::uint32_t>(raw[35]) << 8 | static_cast<std::uint32_t>(raw[36]);

    std::size_t pos = kMinBytes;
    if (d.flags.attestedCredential) {
        if (raw.size() - pos < 18) return refuseAuthData();
        AttestedCredential a;
        std::copy_n(raw.begin() + static_cast<std::ptrdiff_t>(pos), 16, a.aaguid.begin());
        pos += 16;
        const std::size_t idLen = static_cast<std::size_t>(raw[pos]) << 8 | raw[pos + 1];
        pos += 2;
        if (idLen > kMaxCredentialIdBytes || raw.size() - pos < idLen) return refuseAuthData();
        a.credentialId.assign(raw.begin() + static_cast<std::ptrdiff_t>(pos),
                              raw.begin() + static_cast<std::ptrdiff_t>(pos + idLen));
        pos += idLen;
        const auto keyLen = cbor::scan(raw.subspan(pos));
        if (!keyLen || *keyLen > cose::kMaxKeyBytes) return refuseAuthData();
        a.publicKeyCose.assign(raw.begin() + static_cast<std::ptrdiff_t>(pos),
                               raw.begin() + static_cast<std::ptrdiff_t>(pos + *keyLen));
        pos += *keyLen;
        d.attested = std::move(a);
    }
    if (d.flags.extensions) {
        // Authenticator extension outputs: one strict CBOR map, and it must end the data.
        const auto rest = raw.subspan(pos);
        const auto ext = cbor::decode(rest);
        if (!ext || !cbor::isMap(ext.get())) return refuseAuthData();
        pos = raw.size();
    }
    if (pos != raw.size()) return refuseAuthData();  // trailing bytes
    return {std::move(d), Failure::None};
}

}
