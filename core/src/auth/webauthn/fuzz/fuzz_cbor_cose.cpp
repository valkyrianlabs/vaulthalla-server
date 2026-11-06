// libFuzzer: the strict CBOR decoder, COSE_Key parsing and signature verification, and attestation objects end to end
// (statement checks included). Seeds: corpus/cbor_cose/.
#include "auth/webauthn/Attestation.hpp"
#include "auth/webauthn/AuthenticatorData.hpp"
#include "auth/webauthn/Cbor.hpp"
#include "auth/webauthn/Cose.hpp"

#include <array>
#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size) {
    namespace wa = vh::auth::webauthn;
    const wa::ByteView in(data, size);
    (void)wa::cbor::scan(in);
    (void)wa::cbor::decode(in);

    if (const auto key = wa::cose::parse(in); key.key) {
        static constexpr std::array<std::uint8_t, 4> message{1, 2, 3, 4};
        (void)wa::cose::verify(*key.key, message, in.subspan(0, size > 72 ? 72 : size));
    }

    const auto att = wa::attestation::parse(in);
    if (!att.object) return 0;
    const auto ad = wa::authdata::parse(att.object->authData);
    if (!ad.data || !ad.data->attested) return 0;
    const auto key = wa::cose::parse(ad.data->attested->publicKeyCose);
    if (!key.key) return 0;
    static constexpr std::array<std::uint8_t, 32> clientDataHash{};
    (void)wa::attestation::verify(*att.object, *key.key, ad.data->attested->aaguid, clientDataHash);
    return 0;
}
