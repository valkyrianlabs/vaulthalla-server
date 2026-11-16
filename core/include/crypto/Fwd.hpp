#pragma once

#include <vl/vaultfmt/Fwd.hpp>  // the format library's types (vl::vaultfmt::vhf1, ::manifest)

// Forward declarations for the crypto subsystem. Declarations only: include the defining header to use a type.

namespace vh::crypto::secrets {
    class Manager;
}

namespace vh::crypto {
    class ScratchFile;
    class SecretKey;
}

