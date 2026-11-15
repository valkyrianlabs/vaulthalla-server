#include "crypto/SecretBytes.hpp"

namespace vh::crypto {

WipedKeyCopy::~WipedKeyCopy() {
    vl::keykit::wipe(bytes);
    vl::keykit::notifySecretWiped(bytes.data(), bytes);
}

}
