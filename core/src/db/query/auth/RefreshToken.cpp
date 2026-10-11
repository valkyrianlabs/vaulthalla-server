#include "db/query/auth/RefreshToken.hpp"
#include "auth/model/RefreshToken.hpp"
#include "identities/User.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/timestamp.hpp"
#include "log/Registry.hpp"

#include <chrono>

namespace vh::db::query::auth {
    void RefreshToken::set(const std::shared_ptr<vh::auth::model::RefreshToken>& token) {
        if (!token) {
            log::Registry::db()->error("[RefreshToken] Attempted to set a null refresh token");
            return;
        }

        Transactions::exec("RefreshToken::setRefreshToken", [&](pqxx::work& txn) {
            const pqxx::params p{
                token->jti,
                token->userId,
                token->hashedToken,
                token->ipAddress,
                token->userAgent,
                encoding::timestampToString(std::chrono::system_clock::to_time_t(token->issuedAt)),
                encoding::timestampToString(std::chrono::system_clock::to_time_t(token->expiresAt)),
            };

            txn.exec(pqxx::prepped{"insert_refresh_token"}, p);
        });
    }

    void RefreshToken::remove(const std::string& jti) {
        Transactions::exec("RefreshToken::removeRefreshToken", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"delete_refresh_token_by_jti"}, pqxx::params{jti});
        });
    }

    std::shared_ptr<vh::auth::model::RefreshToken> RefreshToken::get(const std::string& jti) {
        // Checked on every cookie-authenticated HTTP request (revocation is immediate), so it is one round trip.
        return Transactions::read(
            "RefreshToken::getRefreshToken",
            [&](pqxx::transaction_base& txn) -> std::shared_ptr<vh::auth::model::RefreshToken> {
                const auto res = txn.exec(pqxx::prepped{"get_refresh_token_by_jti"}, pqxx::params{jti});

                if (res.empty()) {
                    log::Registry::db()->trace("[RefreshToken] No refresh token found for JTI: {}", jti);
                    return nullptr;
                }

                return std::make_shared<vh::auth::model::RefreshToken>(res.one_row_ref());
            });
    }

    std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> RefreshToken::list(const unsigned int userId) {
        return Transactions::exec("RefreshToken::listRefreshTokens", [&](pqxx::work& txn) {
            const auto res = txn.exec(pqxx::prepped{"list_active_refresh_tokens_for_user"}, pqxx::params{userId});

            std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> tokens;
            tokens.reserve(res.size());

            for (const auto& row : res)
                tokens.push_back(std::make_shared<vh::auth::model::RefreshToken>(row));

            return tokens;
        });
    }

    bool RefreshToken::rewriteHash(const std::string& jti, const std::string& legacyHash, const std::string& digest) {
        return Transactions::exec("RefreshToken::rewriteHash", [&](pqxx::work& txn) {
            return txn.exec(pqxx::prepped{"rewrite_refresh_token_hash"}, pqxx::params{jti, legacyHash, digest})
                       .affected_rows() > 0;
        });
    }

    void RefreshToken::touch(const std::string& jti) {
        Transactions::exec("RefreshToken::touchRefreshToken", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"touch_refresh_token_last_used"}, pqxx::params{jti});
        });
    }

    void RefreshToken::refresh(const std::string& jti) {
        Transactions::exec("RefreshToken::revokeRefreshToken", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"revoke_refresh_token_by_jti"}, pqxx::params{jti});
        });
    }

    void RefreshToken::revokeAll(const unsigned int userId) {
        Transactions::exec("RefreshToken::revokeAllRefreshTokens", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"revoke_all_refresh_tokens_for_user"}, pqxx::params{userId});
        });
    }

    void RefreshToken::purgeExpired(const unsigned int userId) {
        Transactions::exec("RefreshToken::purgeExpiredRefreshTokens", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"delete_expired_refresh_tokens_for_user"}, pqxx::params{userId});
        });
    }

    void RefreshToken::purgeOldRevoked() {
        Transactions::exec("RefreshToken::purgeOldRevokedRefreshTokens", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"delete_old_revoked_refresh_tokens_global"});
        });
    }

    void RefreshToken::revokeAndPurge(const unsigned int userId) {
        Transactions::exec("RefreshToken::revokeAndPurgeRefreshTokens", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"revoke_all_refresh_tokens_for_user"}, pqxx::params{userId});
            txn.exec(pqxx::prepped{"delete_expired_refresh_tokens_for_user"}, pqxx::params{userId});
        });
    }
}
