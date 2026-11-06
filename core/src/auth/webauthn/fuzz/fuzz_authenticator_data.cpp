// libFuzzer: authenticatorData (flags, attested credential data, the embedded COSE key, extensions).
// Seeds: corpus/authenticator_data/.
#include "auth/webauthn/AuthenticatorData.hpp"
#include "auth/webauthn/Cose.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size) {
    namespace wa = vh::auth::webauthn;
    const auto ad = wa::authdata::parse(wa::ByteView(data, size));
    if (ad.data && ad.data->attested) (void)wa::cose::parse(ad.data->attested->publicKeyCose);
    return 0;
}
