#pragma once

// Forward declarations for the auth subsystem. Declarations only: include the defining header to use a type.

namespace vh::auth::model {
    struct Token;
    struct RefreshToken;
}

namespace vh::auth::session {
    class Manager;
    struct TokenClaims;
}

namespace vh::auth::mfa {
    class SessionState;
}

namespace vh::auth::stepup {
    class SessionState;
}
