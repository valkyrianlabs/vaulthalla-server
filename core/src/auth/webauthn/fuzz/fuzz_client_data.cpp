// libFuzzer: clientDataJSON and the browser's response JSON (RegistrationResponseJSON / AuthenticationResponseJSON).
// Seeds: corpus/client_data/.
#include "auth/webauthn/ClientData.hpp"
#include "auth/webauthn/Wire.hpp"

#include <cstddef>
#include <cstdint>
#include <string_view>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, const std::size_t size) {
    namespace wa = vh::auth::webauthn;
    (void)wa::clientdata::parse(wa::ByteView(data, size));
    const std::string_view text(reinterpret_cast<const char*>(data), size);
    (void)wa::wire::parseRegistration(text);
    (void)wa::wire::parseAssertion(text);
    return 0;
}
