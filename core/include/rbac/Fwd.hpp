#pragma once

// Forward declarations for RBAC roles and permissions. Declarations only: include the defining header to use a type.

#include <cstdint>

namespace vh::rbac::role {
    struct Admin;
    struct Vault;
}

namespace vh::rbac::permission {
    struct Override;
}

namespace vh::rbac::permission::vault {
    enum class FilesystemAction : uint16_t;  // rbac/permission/vault/Filesystem.hpp
}
