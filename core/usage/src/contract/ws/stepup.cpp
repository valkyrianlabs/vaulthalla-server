// The step-up family table (#359; docs/dev/mfa-design.md section 5.4): which ws command's operation asks for which
// family. The daemon enforces it in the operations (auth::stepup::require); this is what the contract publishes as
// `step_up`, and what core/tests/unit/test_mfa_stepup.cpp holds the daemon to.

#include "Contract.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::contract {

std::vector<WsStepUp> stepUpTable() {
    constexpr bool kTarget = true;
    std::vector<WsStepUp> out{
        // keys: target-bound (the vault, or all), single use
        {"vault.keys.export", "keys", kTarget,
         "outside the paired device's key-backup grant (device.backup.grant.*: a vault it names, while it is active, "
         "never prompts; the console is refused export_requires_device first)"},
        {"vault.keys.import", "keys", kTarget, "when it writes or salvages"},
        {"vault.keys.recipients.add", "keys", kTarget, "(the console is refused recipient_requires_device first)"},
        {"vault.keys.recipients.revoke", "keys", kTarget, "(the console is refused recipient_requires_device first)"},
        // device.trust: target-bound (request id + new key + chosen code), single use
        {"device.pairing.approve", "device.trust", kTarget, ""},
        {"device.remote.enable", "device.trust", kTarget, "when remote device connections are off"},
        {"device.approval.key.register", "device.trust", kTarget,
         "always: a person approves it in the web console (device.approval.request)"},
        {"device.backup.grant.create", "device.trust", kTarget,
         "always (during a recovery cooldown: only the device's approval key, D4)"},
        {"device.backup.grant.extend", "device.trust", kTarget, ""},
        {"device.backup.grant.confirm", "device.trust", kTarget, ""},
        // account.credentials: family-wide, the grant window
        {"auth.user.change_password", "account.credentials", false, ""},
        {"auth.mfa.factor.remove", "account.credentials", false, ""},
        {"auth.mfa.webauthn.register.options", "account.credentials", false,
         "when the account already has a usable factor (not during pending enrollment or a recovery-code session)"},
        {"auth.mfa.webauthn.register.finish", "account.credentials", false,
         "when the account already has a usable factor (not during pending enrollment or a recovery-code session)"},
        {"auth.mfa.totp.enroll.start", "account.credentials", false,
         "when the account already has a usable factor (not during pending enrollment or a recovery-code session)"},
        {"auth.mfa.totp.enroll.confirm", "account.credentials", false,
         "when the account already has a usable factor (not during pending enrollment or a recovery-code session)"},
        {"auth.mfa.recovery.generate", "account.credentials", false,
         "when recovery codes are in force (not on the recovery-code session spending them)"},
        {"auth.mfa.admin.reset", "account.credentials", false, ""},
        {"auth.mfa.admin.require", "identity.admin", false, ""},
        // identity.admin: family-wide
        {"auth.register", "identity.admin", false, ""},
        {"auth.user.update", "identity.admin", false, "a role or activation change, or any change to another account"},
        {"auth.user.delete", "identity.admin", false, ""},
        {"role.admin.add", "identity.admin", false, ""},
        {"role.admin.update", "identity.admin", false, ""},
        {"role.admin.delete", "identity.admin", false, ""},
        {"role.vault.add", "identity.admin", false, ""},
        {"role.vault.update", "identity.admin", false, ""},
        {"role.vault.delete", "identity.admin", false, ""},
        {"role.vault.assign", "identity.admin", false, ""},
        {"role.vault.unassign", "identity.admin", false, ""},
        {"role.vault.overrides.add", "identity.admin", false, ""},
        {"role.vault.overrides.update", "identity.admin", false, ""},
        {"role.vault.overrides.remove", "identity.admin", false, ""},
        {"group.member.add", "identity.admin", false, ""},
        {"group.member.remove", "identity.admin", false, ""},
        {"group.remove", "identity.admin", false, ""},
        // secrets: family-wide
        {"storage.apiKey.add", "secrets", false, ""},
        {"storage.apiKey.update", "secrets", false, ""},
        {"storage.apiKey.remove", "secrets", false, ""},
        {"email.provider.secret.set", "secrets", false, ""},
        {"s3.gateway.credentials.create", "secrets", false, ""},
        {"s3.gateway.credentials.scope.update", "secrets", false, ""},
        {"s3.gateway.credentials.roles.assign", "secrets", false, ""},
        {"s3.gateway.credentials.roles.revoke", "secrets", false, ""},
        {"s3.gateway.credentials.roles.overrides.add", "secrets", false, ""},
        {"s3.gateway.credentials.roles.overrides.remove", "secrets", false, ""},
        {"s3.gateway.credentials.defaultRole.set", "secrets", false, ""},
        {"s3.gateway.credentials.defaultRole.clear", "secrets", false, ""},
        {"s3.gateway.credentials.defaultRole.overrides.add", "secrets", false, ""},
        {"s3.gateway.credentials.defaultRole.overrides.remove", "secrets", false, ""},
        {"upstream.admin.enable", "secrets", false, ""},
        // settings: family-wide, any section (auth.webauthn and auth.mfa, sharing, websocket_server, ...)
        {"settings.update", "settings", false, ""},
        {"email.config.update", "settings", false, "the email sections of settings.update"},
        // data.destroy: target-bound, single use
        {"storage.vault.remove", "data.destroy", kTarget, ""},
        {"recovery.point.delete", "data.destroy", kTarget, ""},
        {"vault.recovery.suspend", "data.destroy", kTarget, ""},
        {"upstream.bucket.cleanup", "data.destroy", kTarget, ""},
        {"upstream.bucket.unprotect", "data.destroy", kTarget, "when the bucket is protected"},
        {"upstream.bucket.lifecycle.set", "data.destroy", kTarget,
         "when the rule makes the provider delete data or shortens the recovery history (the accepted "
         "destructive_lifecycle)"},
    };
    std::ranges::sort(out, {}, &WsStepUp::command);
    if (const auto dup = std::ranges::adjacent_find(out, {}, &WsStepUp::command); dup != out.end())
        throw std::logic_error("step-up table lists " + dup->command + " twice");
    return out;
}

}
