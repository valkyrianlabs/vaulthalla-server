#pragma once

#include "rbac/fs/policy/Evaluator.hpp"
#include "rbac/resolver/vault/Context.hpp"
#include "rbac/resolver/vault/ResolvedContext.hpp"
#include "rbac/resolver/vault/policy/Base.hpp"
#include "log/Registry.hpp"

namespace vh::rbac::resolver::vault {
    // While one is alive on this thread, filesystem denials are not logged. For callers that probe what an account
    // could do across many vaults (ops::vaults::listAccessible): there a "no" is an answer, not a refused request, and
    // logging it would write one warning per vault per listing. The decision itself is unchanged.
    class QuietFilesystemDenials {
    public:
        QuietFilesystemDenials() noexcept : previous_(active()) { active() = true; }
        ~QuietFilesystemDenials() { active() = previous_; }
        QuietFilesystemDenials(const QuietFilesystemDenials&) = delete;
        QuietFilesystemDenials& operator=(const QuietFilesystemDenials&) = delete;

        [[nodiscard]] static bool engaged() noexcept { return active(); }

    private:
        static bool& active() noexcept {
            thread_local bool quiet = false;
            return quiet;
        }

        bool previous_;
    };

    template<>
    struct ContextPolicy<permission::vault::FilesystemAction> {
        static bool validate(
            const std::shared_ptr<identities::User> &actor,
            const ResolvedContext &resolved,
            const permission::vault::FilesystemAction action,
            const Context<permission::vault::FilesystemAction> &ctx
        ) {
            if (!actor) {
                log::Registry::auth()->warn("Access denied for unauthenticated user");
                return false;
            }

            if (!resolved.isValid()) return false;

            const fs::policy::Request req{
                .user = actor,
                .action = action,
                .vaultId = resolved.vault ? std::optional<uint32_t>{resolved.vault->id} : ctx.vault_id,
                .path = ctx.path,
                .entry = ctx.entry
            };

            const auto decision = fs::policy::Evaluator::evaluate(req);

            if (!decision.allowed && !QuietFilesystemDenials::engaged())
                log::Registry::auth()->warn("Filesystem permission denied. Context:\n{}", decision.toString());

            return decision.allowed;
        }
    };
}
