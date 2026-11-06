#pragma once

// Forward declarations for the storage subsystem. Declarations only: include the defining header to use a type.

namespace vh::storage {
    struct Engine;
    class CloudEngine;
    class Manager;
    class PlaintextReader;
}

namespace vh::storage::s3 {
    class Controller;
}
