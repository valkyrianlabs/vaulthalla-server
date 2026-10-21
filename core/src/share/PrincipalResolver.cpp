#include "share/PrincipalResolver.hpp"
#include "ops/Error.hpp"

#include "share/Scope.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::share {

std::shared_ptr<Principal> PrincipalResolver::resolve(
    const Link& link,
    const Session& session,
    const PrincipalResolutionOptions& options
) {
    if (link.id.empty()) throw std::runtime_error("share principal resolution failed: missing share id");
    if (session.id.empty()) throw std::runtime_error("share principal resolution failed: missing session id");
    if (session.share_id != link.id) throw ops::Denied("share principal resolution failed: session/share mismatch");
    if (!link.isActive(options.now)) throw ops::Denied("share principal resolution failed: share inactive");
    if (!session.isActive(options.now)) throw ops::Denied("share principal resolution failed: session inactive");
    if (link.requiresEmail() && !session.isVerified())
        throw ops::Denied("share principal resolution failed: email verification required");

    auto grant = link.grant();
    grant.root_path = Scope::normalizeVaultPath(grant.root_path);
    grant.requireValid();

    auto principal = std::make_shared<Principal>();
    principal->share_id = link.id;
    principal->share_session_id = session.id;
    principal->vault_id = link.vault_id;
    principal->root_entry_id = link.root_entry_id;
    principal->link_created_by = link.created_by;
    principal->root_path = grant.root_path;
    principal->grant = grant;
    principal->access_mode = link.access_mode;
    principal->email_verified = session.isVerified();
    principal->expires_at = link.expires_at ? std::min(*link.expires_at, session.expires_at) : session.expires_at;
    principal->ip_address = session.ip_address;
    principal->user_agent = session.user_agent;
    return principal;
}

std::shared_ptr<Principal> PrincipalResolver::resolve(
    const Link& link,
    const Session& session,
    const std::time_t now
) {
    return resolve(link, session, PrincipalResolutionOptions{.now = now});
}

}
