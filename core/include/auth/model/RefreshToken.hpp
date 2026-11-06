#pragma once

#include "auth/model/Token.hpp"
#include "protocols/ws/Fwd.hpp"
#include "db/Fwd.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace vh::auth::model {

struct RefreshToken final : Token {
    std::string hashedToken, userAgent, ipAddress;
    std::chrono::system_clock::time_point lastUsed = std::chrono::system_clock::now();
    // When the server last saw a person use this session (sign-in, auth.activity); the idle clock (#319).
    std::chrono::system_clock::time_point lastActivity = std::chrono::system_clock::now();
    // How the sign-in behind this row was proven (#354, migration 119; auth/session/Assurance.hpp). Written once, when
    // the row is inserted, and never changed: aal 1 or 2, the methods (amr: pwd, hwk, swk, otp, rec) and when the
    // person proved it (auth_time). A row written before migration 119 reads as aal 1, {pwd}, auth_time = issued_at.
    uint8_t aal{1};
    std::vector<std::string> amr{"pwd"};
    std::chrono::system_clock::time_point authTime = std::chrono::system_clock::now();

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
