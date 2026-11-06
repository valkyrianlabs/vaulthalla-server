#include "ops/Mfa.hpp"

#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/stepup/StepUp.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Users.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>

namespace vh::ops::mfa {

namespace {

namespace authmfa = vh::auth::mfa;

const char* opsMfaChannel(const Channel channel) { return channel == Channel::Cli ? "cli" : "web"; }

void opsMfaDenied(const Actor& actor, const char* action, const uint32_t targetId, const Channel channel,
                  const std::string& why) {
    vh::audit::record({.action = action, .outcome = vh::audit::Outcome::Denied,
                       .actor_id = actor ? std::optional<uint32_t>(actor->id) : std::nullopt,
                       .actor = actor ? actor->name() : std::string{},
                       .details = {{"target_id", targetId}, {"channel", opsMfaChannel(channel)}, {"why", why}}},
                      "[ops::mfa] " + (actor ? actor->name() : std::string("?")) + " was refused " + action +
                          " on user " + std::to_string(targetId) + ": " + why,
                      spdlog::level::warn);
}

// The CLI runs as the Linux user it is bound to; root (UID 0, the 'root' account) and sudo are refused, as
// `vh setup set-super-admin-password` refuses them.
void opsMfaRequireBoundCliUser(const Actor& actor) {
    const auto uid = actor->linuxUid();
    if (!uid || *uid == 0 || actor->systemOnly())
        throw Denied("run this as the Linux user bound to your Vaulthalla account, without sudo (root is refused)");
}

// Who may act on `targetId` through `channel` (see the header). Audits and rethrows a refusal.
// `selfOnCli`: the bound Linux user may act on its own account (reset, status: the host recovery path), never to
// change its own requirement.
std::shared_ptr<identities::User> opsMfaAuthorize(const Actor& actor, const uint32_t targetId, const Channel channel,
                                                  const char* action, const bool selfOnCli = true) {
    requireActor(actor);
    try {
        if (actor->id == targetId && !selfOnCli)
            throw Denied("an account can't change its own MFA requirement");
        if (channel == Channel::Cli) {
            opsMfaRequireBoundCliUser(actor);
            if (actor->id == targetId) {
                auto self = vh::identities::manager().user(targetId);
                if (!self) throw NotFound("user not found: " + std::to_string(targetId));
                return self;
            }
            return users::requireMfaManager(actor, targetId);
        }
        if (actor->id == targetId)
            throw Denied("manage your own sign-in factors in Account > Security (or with `vh user mfa reset` on the "
                         "server, as your own Linux user)");
        return users::requireMfaManager(actor, targetId);
    } catch (const Error& e) {
        opsMfaDenied(actor, action, targetId, channel, e.what());
        throw;
    }
}

void opsMfaRequireReason(const std::string& reason) {
    if (reason.empty() || reason.size() > kMaxReasonLength)
        throw Invalid("a reason of 1 to " + std::to_string(kMaxReasonLength) + " characters is required");
    if (!std::ranges::all_of(reason, [](const char c) { return static_cast<unsigned char>(c) >= 0x20 && c != 0x7f; }))
        throw Invalid("the reason can't contain control characters");
}

}

void to_json(nlohmann::json& j, const Status& s) {
    j = {{"user_id", s.user_id},
         {"required", s.required},
         {"reason", s.reason},
         {"required_flag", s.required_flag},
         {"factors", s.factors.is_null() ? nlohmann::json::array() : s.factors},
         {"recovery", {{"active", s.recovery_active}, {"remaining", s.recovery_remaining}}},
         {"cooldown_until", s.cooldown_until ? nlohmann::json(*s.cooldown_until) : nlohmann::json(nullptr)},
         {"reset_at", s.reset_at ? nlohmann::json(*s.reset_at) : nlohmann::json(nullptr)}};
}

Status status(const Actor& actor, const uint32_t userId, const Channel channel) {
    const auto target = opsMfaAuthorize(actor, userId, channel, "auth.mfa.admin.status");
    const auto requirement = authmfa::policy::requirement(*target);
    const auto state = authmfa::userState(target->id);
    const auto recovery = authmfa::recoveryStatus(target->id);
    Status out{.user_id = target->id,
               .required = requirement.required,
               .reason = std::string(authmfa::policy::to_string(requirement.reason)),
               .required_flag = state && state->required,
               .factors = nlohmann::json::array(),
               .recovery_remaining = recovery.remaining,
               .recovery_active = recovery.active_batch.has_value(),
               .cooldown_until = authmfa::recovery::cooldownUntil(target->id),
               .reset_at = state ? state->reset_at : std::nullopt};
    for (const auto& f : authmfa::factors(target->id)) {
        nlohmann::json fj = f;
        fj["allowed"] = authmfa::policy::factorAllowed(*target, f);
        out.factors.push_back(std::move(fj));
    }
    return out;
}

void require(const Actor& actor, const uint32_t userId, const bool required, const Channel channel) {
    const auto target = opsMfaAuthorize(actor, userId, channel, "auth.mfa.admin.require", false);
    // An account's MFA requirement is identity administration (design 10: auth.mfa.admin.require, identity.admin).
    vh::auth::stepup::require(vh::auth::stepup::Family::IdentityAdmin);
    const auto before = authmfa::userState(target->id);
    authmfa::setRequired(target->id, required);
    vh::audit::record({.action = "auth.mfa.admin.require", .actor_id = actor->id, .actor = actor->name(),
                       .details = {{"target_id", target->id}, {"required", required},
                                   {"was", before && before->required}, {"channel", opsMfaChannel(channel)}}},
                      "[ops::mfa] " + actor->name() + (required ? " required" : " stopped requiring") +
                          " MFA for " + target->name());
}

auth::mfa::recovery::ResetEffects reset(const Actor& actor, const uint32_t userId, const std::string& reason,
                                        const Channel channel) {
    requireActor(actor);
    opsMfaRequireReason(reason);
    const auto target = opsMfaAuthorize(actor, userId, channel, "auth.mfa.admin.reset");
    // A credential change (design 5.4). The host (`vh`) is exempt; an agent call is refused.
    vh::auth::stepup::require(vh::auth::stepup::Family::AccountCredentials);
    return authmfa::recovery::reset(*target,
                                    {.id = actor->id,
                                     .name = actor->name(),
                                     .channel = channel == Channel::Cli ? authmfa::recovery::Reason::CliReset
                                                                        : authmfa::recovery::Reason::AdminReset},
                                    reason);
}

}
