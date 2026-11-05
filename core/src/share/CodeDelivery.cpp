#include "share/CodeDelivery.hpp"

#include "config/Registry.hpp"
#include "email/Message.hpp"
#include "email/ProviderFactory.hpp"
#include "runtime/Deps.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::share {

namespace {

class EmailChallengeCodeSender final : public ChallengeCodeSender {
public:
    [[nodiscard]] bool available() const override {
        const auto& cfg = config::Registry::get().email;
        return cfg.enabled && cfg.provider != config::EmailProviderKind::None;
    }

    void send(const ChallengeCodeMessage& message) override {
        const auto& cfg = config::Registry::get().email;
        if (!available()) throw std::runtime_error("email delivery is not configured");

        const auto rendered = renderChallengeCodeEmail(message, std::time(nullptr));
        email::Message mail;
        mail.from = email::parseAddress(cfg.from);
        mail.to.push_back(email::parseAddress(message.to));
        if (cfg.reply_to) mail.replyTo = email::parseAddress(*cfg.reply_to);
        mail.subject = rendered.subject;
        mail.text = rendered.text;
        mail.html = rendered.html;
        mail.idempotencyKey = "share-challenge-" + message.challenge_id;
        mail.tags["category"] = "share_verification";
        email::validateMessage(mail);

        const auto provider = email::makeProvider(cfg, runtime::Deps::get().secretsManager);
        if (!provider) throw std::runtime_error("no email provider");
        const auto result = provider->send(mail);
        if (!result.ok)
            throw std::runtime_error("email provider refused the message" +
                                     (result.errorSummary ? ": " + *result.errorSummary : std::string{}));
    }
};

}

std::shared_ptr<ChallengeCodeSender> makeEmailChallengeCodeSender() {
    return std::make_shared<EmailChallengeCodeSender>();
}

email::RenderedEmail renderChallengeCodeEmail(const ChallengeCodeMessage& message, const std::time_t now) {
    const auto seconds = std::max<std::time_t>(0, message.expires_at - now);
    const auto minutes = std::max<std::time_t>(1, (seconds + 59) / 60);
    const auto lasts = std::to_string(minutes) + (minutes == 1 ? " minute" : " minutes");
    // The code is digits only (EmailChallenge::generateCode), so it needs no HTML escaping; refuse anything else.
    if (message.code.empty() || !std::ranges::all_of(message.code, [](const unsigned char c) { return c >= '0' && c <= '9'; }))
        throw std::invalid_argument("verification code must be digits");

    email::RenderedEmail out;
    out.subject = "Your Vaulthalla verification code";
    out.text = "Your verification code is " + message.code + ".\n\n"
               "Enter it on the page where you opened the shared link. It works once and expires in " + lasts + ".\n\n"
               "If you didn't ask for this code, you can ignore this email. Nothing is shared with you until the code "
               "is entered.\n";
    out.html = "<p>Your verification code is</p>"
               "<p style=\"font-size:28px;font-weight:600;letter-spacing:4px;font-family:monospace\">" + message.code +
               "</p><p>Enter it on the page where you opened the shared link. It works once and expires in " + lasts +
               ".</p><p style=\"color:#666\">If you didn't ask for this code, you can ignore this email. Nothing is "
               "shared with you until the code is entered.</p>";
    return out;
}

}
