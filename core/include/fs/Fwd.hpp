#pragma once

// Forward declarations for the filesystem model. Declarations only: include the defining header to use a type.

namespace vh::fs::model {
    struct Entry;
    struct File;
    struct Directory;
    struct Symlink;
}

namespace vh::fs::model::file {
    struct Trashed;
}

namespace vh::fs {
    struct PlaintextSource;
}
