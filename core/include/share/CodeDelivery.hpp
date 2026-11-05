#pragma once

#include "email/RenderedEmail.hpp"

#include <ctime>
#include <memory>
#include <string>

namespace vh::share {

// One verification code on its way to an email-validated link's recipient (#317).
struct ChallengeCodeMessage {
    std::string to;            // the recipient address the visitor entered (normalized)
    std::string code;          // never logged, never stored in clear
    std::time_t expires_at{};
    std::string challenge_id;  // idempotency key for the provider
};

// How verification codes leave the server. The default sends through the operator's email provider
// (email.* in config.yaml, Resend or SES); tests inject their own.
class ChallengeCodeSender {
public:
    virtual ~ChallengeCodeSender() = default;
    // Whether this server can send email at all. Without it an email-validated link can never be opened, so such
    // links are refused at creation and their challenges are refused up front with a clear error.
    [[nodiscard]] virtual bool available() const = 0;
    // Sends one message; throws on failure.
    virtual void send(const ChallengeCodeMessage& message) = 0;
};

[[nodiscard]] std::shared_ptr<ChallengeCodeSender> makeEmailChallengeCodeSender();

// The code email. It names no file, folder, link or sender: only the code and how long it lasts.
[[nodiscard]] email::RenderedEmail renderChallengeCodeEmail(const ChallengeCodeMessage& message, std::time_t now);

inline constexpr const char* kShareEmailUnavailableCode = "share_email_unavailable";
inline constexpr const char* kShareEmailUnavailableText =
    "This link needs email verification, but this server isn't set up to send email. Ask the person who shared it to "
    "set up email delivery (vh email) or to share it another way.";

}
