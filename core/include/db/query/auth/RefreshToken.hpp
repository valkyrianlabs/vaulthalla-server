#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"

namespace vh::db::query::auth {

struct RefreshToken {
    // Inserts the row with the token's aal and amr (auth_time = NOW()). Write-once: false, and nothing written, when
    // the jti already has a row.
    [[nodiscard]] static bool insertOnce(const std::shared_ptr<vh::auth::model::RefreshToken>& token);
    static void remove(const std::string& jti);

    static std::shared_ptr<vh::auth::model::RefreshToken> get(const std::string& jti);
    static std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> list(unsigned int userId);

    // Swaps a legacy stored hash for its digest form. Conditional on the old value, so a concurrent rewrite or
    // re-issue is never clobbered; returns whether a row changed.
    static bool rewriteHash(const std::string& jti, const std::string& legacyHash, const std::string& digest);

    static void touch(const std::string& jti);
    // Records user activity on the session (#319): last_activity_at = NOW() for a live token.
    static void touchActivity(const std::string& jti);
    static void refresh(const std::string& jti);
    static void revokeAll(unsigned int userId);
    // Revokes one live row, only when it belongs to userId; whether a row changed.
    [[nodiscard]] static bool revokeOfUser(const std::string& jti, unsigned int userId);

    static void purgeExpired(unsigned int userId);
    static void purgeOldRevoked();
    static void revokeAndPurge(unsigned int userId);

};

}
