#pragma once

// Forward declarations for the vault subsystem. Declarations only: include the defining header to use a type.

namespace vh::vault {
    class RetentionService;
}

namespace vh::vault::model {
    struct Vault;
    struct S3Vault;
    struct APIKey;
    struct Key;
    enum class VaultType;
    struct Deletion;
    enum class DeletionState;
}
