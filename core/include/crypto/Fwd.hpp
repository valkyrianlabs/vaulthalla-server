#pragma once

// Forward declarations for the crypto subsystem. Declarations only: include the defining header to use a type.

namespace vh::crypto::secrets {
    class Manager;
}

namespace vh::crypto {
    class ScratchFile;
    class SecretBytes;
    class SecretKey;
}

namespace vh::crypto::vhf1 {
    struct Expectation;
    struct HeaderParams;
    struct Layout;
    struct RangePlan;
    class ChunkWalker;
    class Error;
    class OpenedHeader;
    class RangeReader;
    class SecureBytes;
    class Writer;
}
