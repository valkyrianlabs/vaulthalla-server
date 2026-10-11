#pragma once

#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"

namespace vh::db::query::auth {

struct RefreshToken {
    static void set(const std::shared_ptr<vh::auth::model::RefreshToken>& token);
    static void remove(const std::string& jti);

    static std::shared_ptr<vh::auth::model::RefreshToken> get(const std::string& jti);
    static std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> list(unsigned int userId);

    // Swaps a legacy stored hash for its digest form. Conditional on the old value, so a concurrent rewrite or
    // re-issue is never clobbered; returns whether a row changed.
    static bool rewriteHash(const std::string& jti, const std::string& legacyHash, const std::string& digest);

    static void touch(const std::string& jti);
    static void refresh(const std::string& jti);
    static void revokeAll(unsigned int userId);

    static void purgeExpired(unsigned int userId);
    static void purgeOldRevoked();
    static void revokeAndPurge(unsigned int userId);

    [[nodiscard]] static std::optional<unsigned int> getUserIdByJti(const std::string& jti);
};

}
