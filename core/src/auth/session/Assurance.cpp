#include "auth/session/Assurance.hpp"

#include "audit/Trail.hpp"
#include "auth/model/RefreshToken.hpp"
#include "concurrency/AtomicSharedPtr.hpp"
#include "identities/User.hpp"
#include "rbac/PolicyEpoch.hpp"

#include <memory>
#include <stdexcept>

namespace vh::auth::session::assurance {

namespace {
concurrency::AtomicSharedPtr<const Policy>& installedPolicy() {
    static concurrency::AtomicSharedPtr<const Policy> policy;
    return policy;
}
}

Proof password() { return {}; }

bool satisfied(const identities::User& user, const model::RefreshToken& row) {
    if (row.aal != 1 && row.aal != 2) return false;  // the schema allows only these; anything else is not a level
    const auto policy = installedPolicy().load(std::memory_order_acquire);
    return !policy || !*policy || (*policy)(user, row);
}

void enforce(const identities::User& user, model::RefreshToken& row) {
    if (satisfied(user, row)) return;
    row.hardInvalidate();  // revokes the stored row: the cookie never signs in again
    audit::record({.action = "auth.session.revoke", .outcome = audit::Outcome::Info, .actor_id = user.id,
                   .actor = user.name(), .details = {{"reason", "assurance_policy"}, {"aal", row.aal}}},
                  "[auth] ended a session of " + user.name() + ": its sign-in no longer meets the MFA policy");
    throw std::runtime_error("Session assurance is below the account's MFA policy");
}

void setPolicy(Policy policy) {
    installedPolicy().store(policy ? std::make_shared<const Policy>(std::move(policy)) : nullptr,
                            std::memory_order_release);
    policyChanged();
}

void policyChanged() noexcept { rbac::bumpPolicyEpoch(); }

}
