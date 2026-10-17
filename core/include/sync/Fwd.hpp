#pragma once

// Forward declarations for the sync subsystem. Declarations only: include the defining header to use a type.

namespace vh::sync {
    struct Cloud;
    class Controller;
}

namespace vh::sync::events {
    class Service;
}

namespace vh::sync::model {
    struct Policy;
    struct RemotePolicy;
    struct ScopedOp;
    struct Event;
    struct Conflict;
    struct Waiver;
    struct S3CostEstimate;
    struct Action;
    struct PassScope;
}
