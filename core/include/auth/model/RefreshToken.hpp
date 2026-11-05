#pragma once

#include "auth/model/Token.hpp"
#include "protocols/ws/Fwd.hpp"
#include "db/Fwd.hpp"

namespace vh::auth::model {

struct RefreshToken final : Token {
    std::string hashedToken, userAgent, ipAddress;
    std::chrono::system_clock::time_point lastUsed = std::chrono::system_clock::now();
    // When the server last saw a person use this session (sign-in, auth.activity); the idle clock (#319).
    std::chrono::system_clock::time_point lastActivity = std::chrono::system_clock::now();

    ~RefreshToken() override = default;
    RefreshToken() = default;
    explicit RefreshToken(std::string rawToken);
    explicit RefreshToken(pqxx::row_ref row);

    [[nodiscard]] bool isValid() const override;

    void hardInvalidate();

    // Same stored hash but different metadata than `other` (a copy of one token that no longer matches its row).
    // Not an overload of Token::dangerousDivergence(claims), which validates claims and is virtual.
    [[nodiscard]] bool divergesFrom(const std::shared_ptr<RefreshToken>& other) const;

    [[nodiscard]] Type type() const override { return Type::Refresh; }

    static void addToSession(const std::shared_ptr<protocols::ws::Session>& session, std::string token);
    static void addShareToSession(const std::shared_ptr<protocols::ws::Session>& session, std::string token);
};

bool operator==(const std::shared_ptr<RefreshToken>& lhs, const std::shared_ptr<RefreshToken>& rhs);

}
