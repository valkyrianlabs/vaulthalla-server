// ws book: auth.* (core/src/protocols/ws/handler/Auth.cpp).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField authUserObject(std::string name = "user") { return object(std::move(name), "User"); }

// The session user (Auth::sessionUser): User with role permissions reduced to {qualified, value}.
WsField authSessionUserObject() { return object("user", "SessionUser"); }

WsField authUserId(std::string name = "id") { return uinteger(std::move(name)).gen(gen::ref("user", {"id"})); }

// ---- MFA (#357): the WebAuthn L3 JSON forms the console passes through (PublicKeyCredential.toJSON() and the
// options parseCreationOptionsFromJSON / parseRequestOptionsFromJSON read), spelled out as far as the daemon reads
// or writes them.

WsField mfaDescriptors(std::string name) {
    return objectArray(std::move(name), "",
                       {str("type").oneOf({"public-key"}), str("id").desc("base64url credential id."),
                        strArray("transports")});
}

WsField mfaCreationOptions() {
    return object("publicKey", "",
                  {object("rp", "", {str("id"), str("name")}),
                   object("user", "", {str("id").desc("base64url of the account's random 32-byte WebAuthn handle "
                                                      "(never the numeric id)."),
                                       str("name"), str("displayName")}),
                   str("challenge").desc("base64url, 32 bytes, single use, 120 s, bound to this connection."),
                   objectArray("pubKeyCredParams", "", {str("type").oneOf({"public-key"}), integer("alg")})
                       .desc("-8 (Ed25519), -7 (ES256), -257 (RS256), in that order."),
                   uinteger("timeout").desc("Milliseconds."),
                   mfaDescriptors("excludeCredentials").desc("The account's passkeys: not registered twice."),
                   object("authenticatorSelection", "",
                          {str("residentKey").oneOf({"preferred"}), boolean("requireResidentKey"),
                           str("userVerification").oneOf({"required"})}),
                   str("attestation").oneOf({"none"}),
                   object("extensions", "", {boolean("credProps")})})
        .desc("PublicKeyCredentialCreationOptionsJSON for navigator.credentials.create().");
}

WsField mfaCredential(const bool registration) {
    std::vector<WsField> response{str("clientDataJSON").desc("base64url.")};
    if (registration) {
        response.push_back(str("attestationObject").desc("base64url."));
        response.push_back(strArray("transports").opt().desc("getTransports(): a hint, never trusted."));
        response.push_back(str("authenticatorData").opt().desc("Ignored: the daemon reads attestationObject."));
        response.push_back(str("publicKey").opt().desc("Ignored."));
        response.push_back(integer("publicKeyAlgorithm").opt().desc("Ignored."));
    } else {
        response.push_back(str("authenticatorData").desc("base64url."));
        response.push_back(str("signature").desc("base64url."));
        response.push_back(str("userHandle").opt().nullable().desc("base64url."));
    }
    return object("credential", "",
                  {str("id"), str("rawId").desc("base64url; equals id."), str("type").oneOf({"public-key"}),
                   object("response", "", std::move(response)),
                   str("authenticatorAttachment").opt().nullable(),
                   object("clientExtensionResults", "", {object("credProps", "", {boolean("rk").opt()}).opt()})
                       .opt()})
        .gen(gen::constant("{}"))
        .desc(registration ? "RegistrationResponseJSON (PublicKeyCredential.toJSON() after create())."
                           : "AuthenticationResponseJSON (PublicKeyCredential.toJSON() after get()).");
}

// PublicKeyCredentialRequestOptionsJSON of discoverable sign-in (#358): no account named, so no credentials allowed.
WsField passkeyRequestOptions() {
    return object("publicKey", "",
                  {str("challenge").desc("base64url, 32 bytes, single use, 120 s, bound to this connection and to "
                                         "discoverable sign-in only."),
                   str("rpId"),
                   uinteger("timeout").desc("Milliseconds."),
                   str("userVerification").oneOf({"required"}),
                   mfaDescriptors("allowCredentials").desc("Always empty: the browser offers the passkeys it holds "
                                                           "for rpId.")})
        .desc("PublicKeyCredentialRequestOptionsJSON for navigator.credentials.get(), modal or with mediation "
              "\"conditional\" (autofill).");
}

// PublicKeyCredentialRequestOptionsJSON as passkeys::requestOptions / stepUpOptions build it.
WsField mfaRequestOptions() {
    return object("publicKey", "",
                  {str("challenge").desc("base64url, 32 bytes, single use, 120 s, bound to this connection, the "
                                         "purpose and (step-up) the family and target."),
                   str("rpId"), uinteger("timeout").desc("Milliseconds."),
                   str("userVerification").oneOf({"required"}),
                   mfaDescriptors("allowCredentials").desc("The account's usable passkeys.")})
        .desc("PublicKeyCredentialRequestOptionsJSON for navigator.credentials.get().");
}

WsField mfaRecoveryCodes() {
    return object("recovery_codes", "",
                  {str("batch_id"),
                   strArray("codes").desc("Ten codes, XXXXX-XXXXX, shown once. Inactive until "
                                          "auth.mfa.recovery.acknowledge.")})
        .opt()
        .desc("The account's first factor only (and every factor of a pending enrollment): its recovery codes.");
}

WsField mfaSessionUser() {
    return object("user", "SessionUser").desc("The signed-in user; role permissions reduced to {qualified, value}.");
}

// Pending-MFA (auth/mfa/Pending.hpp) as auth.login's mfa_required / mfa_enrollment_required and auth.mfa.verify's
// refusals carry it in data.pending.
constexpr const char* kMfaPendingShape =
    "data.pending is {kind: \"mfa\" | \"enrollment\", expires_at (Unix seconds), methods: [\"webauthn\" | \"totp\" | "
    "\"recovery_code\"], attempts_remaining, webauthn?: {publicKey: PublicKeyCredentialRequestOptionsJSON}}.";

// #359: the step-up families (auth/stepup/StepUp.hpp).
const std::vector<std::string> kStepUpFamilies{"keys",           "device.trust", "account.credentials",
                                               "identity.admin", "secrets",      "settings",
                                               "data.destroy"};

// A device's approval request (auth::approval::toJson), as the console and the device see it (#361).
std::vector<WsField> authApprovalFields() {
    return {str("approval_id"), str("state").oneOf({"pending", "approved", "denied", "expired"}),
            str("family").oneOf(kStepUpFamilies), str("target").nullable(),
            str("summary").desc("What the device says it is asking for (its own words: show it with family and "
                                "target, which the server checks)."),
            object("device", "", {uinteger("id").desc("The device row."), str("device_id"), str("name")}),
            integer("created_at").desc("Unix seconds."), integer("expires_at").desc("Unix seconds.")};
}

const std::vector<std::string> kMfaEnrollmentRefusals{"denied", "invalid", "not_found", "conflict", "unauthorized",
                                                      "error", "mfa_expired"};

}

std::vector<WsCommandUsage> authCommands() {
    using namespace std::chrono_literals;
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "auth.login",
        .description = std::string(
                       "Sign in with a username and password. The access token comes back in the response envelope "
                       "(`token`), the refresh token as an HttpOnly cookie set at the handshake. A connection signs in "
                       "once: one that already has a user (signed in, or restored from its cookie) is refused with "
                       "data.code already_signed_in; sign in again on a new connection. A password alone signs in "
                       "(aal 1, amr [\"pwd\"]) only an account with no factor that need not have MFA. Otherwise the "
                       "right password answers ERROR mfa_required (a factor is enrolled: finish with auth.mfa.verify) "
                       "or mfa_enrollment_required (the MFA policy requires one and there is none: set it up with the "
                       "enrollment commands), and the connection is pending: not signed in, no access token, no "
                       "session row, so auth.refresh, a reconnect, another tab and the HTTP lanes all refuse it. It "
                       "may run only auth.mfa.verify, auth.mfa.cancel and auth.logout (plus the enrollment commands "
                       "while enrolling) and ends after 5 minutes (10 enrolling), 5 failed factors or with the "
                       "socket. mfa_unavailable: the account's factors can't be used on this server. ") +
                       kMfaPendingShape,
        .auth = "session",
        .payload = {str("name").gen(gen::ref("user", {"name"})), str("password")},
        .response = {authSessionUserObject().desc("The signed-in user; role permissions reduced to {qualified, value}.")},
        .refusal_codes = {"error", "already_signed_in", "mfa_required", "mfa_enrollment_required", "mfa_unavailable"},
        .operation = "auth.login",
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.logout",
        .description = "End the session (access and refresh tokens).",
        .auth = "session",
        .input = "none",
        .response = {},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.refresh",
        .description = "Issue a new access token from the envelope token or the refresh cookie.",
        .auth = "session",
        .input = "token",
        .response = {authSessionUserObject()},
        .refusal_codes = {"error"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.activity",
        .description = "Report that the person at the console is using it (keyboard, pointer, scroll), at most about "
                       "once a minute. It resets the session's idle sign-out clock "
                       "(services.connection_lifecycle_manager.idle_timeout_minutes) with the server's own time; "
                       "background requests never do. An idle session is refused like any other expired one.",
        .input = "none",
        .response = {},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.isAuthenticated",
        .description = "Whether the envelope token is a valid session for this socket.",
        .auth = "session",
        .input = "token",
        .response = {boolean("isAuthenticated"), authSessionUserObject().opt().desc("Present when authenticated.")},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.register",
        .description = "Create a user. role is an admin role name or id; the password is required (only the CLI "
                       "generates one).",
        .payload = {str("name").gen(gen::freshName("user_")),
                    str("email").opt().gen(gen::email()),
                    str("password").gen(gen::bytes(16, 24)),
                    boolean("is_active").opt(),
                    str("role").gen(gen::ref("role.admin", {"name", "id"}))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .operation = "users.create",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.update",
        .description = "Patch a user (the caller when id is absent). Role changes and deactivation end the account's "
                       "sessions. linux_uid, updated_by, protected, is_protected, system_only and password are refused.",
        .payload = {authUserId().opt().nullable(),
                    str("name").opt().nullable().gen(gen::freshName("user_")),
                    str("email").opt().nullable().gen(gen::email()),
                    str("role").opt().gen(gen::ref("role.admin", {"name", "id"})),
                    boolean("is_active").opt().nullable()},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .operation = "users.update",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.delete",
        .description = "Delete a user. Without confirm the reply is a refusal with data.code 'user_delete' and the "
                       "question to ask. The user's vaults are destroyed unless transfer_to names who gets them.",
        .payload = {authUserId(), boolean("confirm").opt(), authUserId("transfer_to").opt().nullable()},
        .response = {uinteger("user_id")},
        .refusal_codes = opsRefusals(),
        .confirmations = {{.code = "user_delete",
                           .accept_field = "confirm",
                           .description = "The account (and the vaults it owns unless transfer_to is set) would be "
                                          "deleted: resend with confirm once the person agrees."}},
        .operation = "users.delete",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.change_password",
        .description = "Change (own, with old_password) or reset (another user's) a password.",
        .payload = {authUserId(), str("old_password").opt(), str("new_password").gen(gen::bytes(16, 24))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.get",
        .description = "One user with its full roles and permissions.",
        .payload = {authUserId()},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.user.get.byName",
        .description = "One user by name.",
        .payload = {str("name").gen(gen::ref("user", {"name"}))},
        .response = {authUserObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.users.list",
        .description = "Users visible to the caller, slim projection (admin_role without permissions).",
        .input = "none",
        .response = {objectArray("users", "UserSummary")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.sessions.list",
        .description = "The caller's signed-in web sessions (one per browser: its tabs share one), most recent sign-in "
                       "first: live, unexpired and not past the idle sign-out. Ids are opaque handles for "
                       "auth.sessions.revoke, never the refresh token's id, and change when the daemon restarts.",
        .input = "none",
        .response = {objectArray("sessions", "AuthSession")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.sessions.revoke",
        .description = "Sign out one of the caller's sessions (id from auth.sessions.list; the current one included) "
                       "or every other one (all_others). Revoked sessions end at once: their sockets close and their "
                       "cookies stop working for previews, downloads and uploads. Give exactly one of id and "
                       "all_others (else invalid); an id that is not one of the caller's live sessions is not_found.",
        .payload = {str("id").opt().gen(gen::ref("auth.session", {"id"})).desc("From auth.sessions.list."),
                    boolean("all_others").opt().gen(gen::boolean())},
        .response = {uinteger("revoked").desc("How many sessions were signed out.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });


    // ---- MFA (#357; docs/dev/mfa-design.md sections 5.2, 7.2, 8 and 10)

    out.push_back({
        .command = "auth.mfa.verify",
        .description = std::string(
                       "Finish a pending sign-in with a second factor: {method: \"webauthn\", credential} (a UV "
                       "assertion over the pending challenge), or {method: \"totp\" | \"recovery_code\", code}. "
                       "Success signs the connection in: one session row at aal 2 with amr [\"pwd\", \"hwk\" | "
                       "\"swk\" | \"otp\" | \"rec\"], the access token in the envelope. A recovery code signs "
                       "every other web session of the account out (paired devices are not touched), starts the "
                       "recovery cooldown and answers `recovery`. Refusals: mfa_invalid {attempts_remaining, pending?} "
                       "(the 5th ends the sign-in), mfa_expired (start again with the password), rate_limited "
                       "{retry_after} (5 failed factors on the account in 15 minutes), mfa_required {pending} for "
                       "{method: \"webauthn\"} without a credential: a fresh passkey challenge, not an attempt. ") +
                       kMfaPendingShape,
        .auth = "pending",
        .payload = {str("method").oneOf({"webauthn", "totp", "recovery_code"}),
                    mfaCredential(false).opt().desc("method webauthn: AuthenticationResponseJSON."),
                    str("code").opt().gen(gen::pattern("{9}{9}{9}{9}{9}{9}"))
                        .desc("totp: six digits; recovery_code: XXXXX-XXXXX.")},
        .response = {mfaSessionUser(),
                     uinteger("aal").min(2).max(2),
                     object("recovery", "",
                            {uinteger("codes_remaining"),
                             integer("cooldown_until").desc("Unix seconds: sensitive actions wait until then."),
                             uinteger("sessions_revoked").desc("Other web sessions signed out.")})
                         .opt()
                         .desc("Present after a recovery-code sign-in.")},
        .refusal_codes = {"invalid", "denied", "unauthorized", "error", "mfa_invalid", "mfa_expired", "mfa_required",
                          "rate_limited"},
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.mfa.cancel",
        .description = "End a pending sign-in now; the connection is anonymous again (sign in again with the password).",
        .auth = "pending",
        .input = "none",
        .response = {},
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.status",
        .description = "The caller's MFA: whether the policy requires it and why (policy admins: the super admin and "
                       "accounts whose admin role may add, edit or delete users or admins or reset their passwords, "
                       "add, edit or delete admin or vault roles, edit any settings section, or export or rotate "
                       "encryption keys; policy all: every account; user_required: set for this account), whether "
                       "passkeys are configured, the factors, the recovery codes, and the recovery cooldown. Web "
                       "sessions only (a paired device is denied).",
        .input = "none",
        .response = {object("policy", "",
                            {str("level").oneOf({"optional", "admins", "all"}),
                             boolean("required"),
                             str("reason").oneOf({"none", "policy_admins", "policy_all", "user_required"}),
                             boolean("webauthn_available").desc("auth.webauthn.rp_id and origins are configured."),
                             boolean("admin_webauthn_only"),
                             boolean("admin_device_bound_only")}),
                     objectArray("factors", "MfaFactor"),
                     object("recovery", "",
                            {boolean("active").desc("An acknowledged batch is in force."),
                             uinteger("remaining").desc("Its unused codes."),
                             boolean("acknowledged"),
                             boolean("pending").desc("A generated batch waits for its acknowledgement.")}),
                     integer("cooldown_until").nullable().desc("Unix seconds: the recovery cooldown, if one ran."),
                     boolean("recovery_restricted").desc("This session signed in with a recovery code."),
                     objectArray("step_up", "",
                                 {str("family").oneOf(kStepUpFamilies),
                                  str("target").nullable().desc("Target-bound families: what the grant is for."),
                                  integer("expires_at").desc("Unix seconds.")})
                         .desc("This session's live step-up grants (#359); never another session's.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.webauthn.register.options",
        .description = "Start registering a passkey (\"Passkey / Security key\": 1Password, the device's passkey "
                       "manager, a security key) on the caller's account, or as the first factor of a pending "
                       "enrollment. Pass publicKey to navigator.credentials.create() and the result to "
                       "auth.mfa.webauthn.register.finish with registration_id. invalid when passkeys are not "
                       "configured (auth.webauthn.rp_id).",
        .auth = "enrollment",
        .payload = {str("label").opt().gen(gen::freshName("key_")).desc("1..64 characters (default \"Passkey\").")},
        .response = {str("registration_id"), mfaCreationOptions()},
        .refusal_codes = kMfaEnrollmentRefusals,
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.webauthn.register.finish",
        .description = "Verify and store the passkey (attestation none or packed self; UV required). The account's "
                       "first factor answers its recovery codes too; a pending enrollment then finishes with "
                       "auth.mfa.recovery.acknowledge. invalid: the ceremony didn't verify; not_found: the "
                       "registration expired (120 s) or was used.",
        .auth = "enrollment",
        .payload = {str("registration_id").gen(gen::pattern("{*}{*}{*}{*}{*}{*}{*}{*}")),
                    mfaCredential(true),
                    str("label").opt().gen(gen::freshName("key_"))},
        .response = {object("factor", "MfaFactor"), mfaRecoveryCodes()},
        .refusal_codes = kMfaEnrollmentRefusals,
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.mfa.totp.enroll.start",
        .description = "Start setting up an authenticator app (RFC 6238, SHA-1, 6 digits, 30 s). The secret and "
                       "otpauth URI are shown once (the console draws the QR code itself); the factor is unusable "
                       "until auth.mfa.totp.enroll.confirm, within 10 minutes. Starting again replaces an unfinished "
                       "setup.",
        .auth = "enrollment",
        .payload = {str("label").opt().gen(gen::freshName("app_")).desc("1..64 characters (default "
                                                                        "\"Authenticator app\").")},
        .response = {uinteger("enrollment_id"), str("secret_base32"), str("otpauth_uri"),
                     integer("expires_at").desc("Unix seconds.")},
        .refusal_codes = kMfaEnrollmentRefusals,
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.totp.enroll.confirm",
        .description = "Finish the authenticator setup with its current code (one step of drift either way). The "
                       "account's first factor answers its recovery codes too. invalid: the code didn't match; "
                       "not_found: the setup expired or is finished.",
        .auth = "enrollment",
        .payload = {uinteger("enrollment_id").gen(gen::intRange(1, 1000)),
                    str("code").gen(gen::pattern("{9}{9}{9}{9}{9}{9}"))},
        .response = {object("factor", "MfaFactor"), mfaRecoveryCodes()},
        .refusal_codes = kMfaEnrollmentRefusals,
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.factor.rename",
        .description = "Rename one of the caller's factors (named by kind and id).",
        .payload = {str("kind").oneOf({"webauthn", "totp"}),
                    uinteger("id").gen(gen::intRange(1, 1000)),
                    str("label").gen(gen::freshName("key_")).desc("1..64 characters.")},
        .response = {object("factor", "MfaFactor")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.factor.remove",
        .description = "Remove one of the caller's factors (named by kind and id): it is disabled, kept for the audit "
                       "trail and never usable again, and the account's other web sessions are signed out (one of "
                       "them may hold it). mfa_last_factor: it is the last usable factor of an account that must "
                       "have MFA (add another first). account.credentials step-up.",
        .payload = {str("kind").oneOf({"webauthn", "totp"}), uinteger("id").gen(gen::intRange(1, 1000))},
        .response = {uinteger("sessions_revoked")},
        .refusal_codes = {"denied", "not_found", "invalid", "unauthorized", "mfa_last_factor"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.stepup.begin",
        .description = "Start confirming a sensitive change that answered step_up_required: name its family and, "
                       "for keys, device.trust and data.destroy, the target the refusal named. Answers the methods "
                       "the account can use (webauthn: pass webauthn.publicKey to navigator.credentials.get(); "
                       "password_totp: the password and an authenticator code together; password: only for an "
                       "account that need not have MFA and has no factor, never for keys, device.trust or "
                       "data.destroy) and a ceremony id valid for 120 s. A new begin replaces the open ceremony. "
                       "step_up_unavailable: the account has nothing that can confirm this family (add a passkey or "
                       "an authenticator app). Web sessions only: a paired device is denied.",
        .payload = {str("family").oneOf(kStepUpFamilies),
                    str("target").opt().nullable().desc(
                        "The refusal's target (keys, device.trust, data.destroy); ignored for the others.")},
        .response = {str("stepup_id"), str("family").oneOf(kStepUpFamilies), str("target").nullable(),
                     strArray("methods").desc("webauthn, password_totp, password: in this order of preference."),
                     object("webauthn", "", {mfaRequestOptions()}).opt().desc("Present when webauthn is offered."),
                     integer("expires_at").desc("Unix seconds: finish before this."),
                     uinteger("max_age_seconds").desc("How long the grant will last (auth.mfa.step_up_ttl_seconds).")},
        .refusal_codes = {"denied", "invalid", "unauthorized", "rate_limited", "step_up_unavailable"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.stepup.finish",
        .description = "Answer the ceremony: {method: webauthn, credential} (a UV assertion over its challenge), "
                       "{method: password_totp, password, code} or {method: password, password}. On success this "
                       "session holds a grant for the family (and target): family grants last max_age_seconds, "
                       "target-bound ones are spent by one use. Then resend the refused request. step_up_failed "
                       "{attempts_remaining}: the answer didn't hold; the fifth failure within 15 minutes signs this "
                       "session out. not_found: the ceremony expired or was used (begin again). Recovery codes, "
                       "refresh tokens and Desktop mTLS never satisfy a step-up.",
        .payload = {str("stepup_id").gen(gen::pattern("{*}{*}{*}{*}{*}{*}{*}{*}")),
                    str("method").oneOf({"webauthn", "password_totp", "password"}),
                    mfaCredential(false).opt().desc("method webauthn: AuthenticationResponseJSON."),
                    str("password").opt().desc("method password_totp or password."),
                    str("code").opt().gen(gen::pattern("{9}{9}{9}{9}{9}{9}")).desc("method password_totp: the "
                                                                                   "authenticator code.")},
        .response = {str("family").oneOf(kStepUpFamilies), str("target").nullable(),
                     integer("expires_at").desc("Unix seconds."),
                     uinteger("uses").nullable().desc("1 for a target-bound grant; null: any number until it "
                                                      "expires.")},
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized", "error", "step_up_failed"},
        .client_timeout = 20s,
    });

    // ---- #361: approving a paired device's request (auth/approval/Approvals.hpp, MFA design note 6.3)

    out.push_back({
        .command = "auth.approval.list",
        .description = "The signed-in account's open requests from its paired devices (device.approval.request), "
                       "oldest first: what each asks for (family, target), the device's own summary, and when it "
                       "expires. A new request also arrives as an unsolicited frame {\"command\": "
                       "\"auth.approval.pending\", \"data\": {approval_id, device: {id, name}, family, target, summary, "
                       "expires_at}} on every console session of the account. Web sessions only: a device is "
                       "refused.",
        .input = "none",
        .response = {objectArray("approvals", "", authApprovalFields())},
        .refusal_codes = {"denied", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.approval.approve",
        .description = "Approve a device's request with a passkey, nothing else: a TOTP code or a password is "
                       "refused (invalid), and an account without a usable passkey gets passkey_required (do the "
                       "action in the console instead). Without credential: answers webauthn.publicKey (a challenge "
                       "bound to this session and this request, 120 s) for navigator.credentials.get(); with "
                       "credential (a UV assertion over it): approves, and the device's next device.approval.status "
                       "makes its grant. approval_failed {attempts_remaining}: the assertion didn't hold; the fifth "
                       "failure within 15 minutes signs this session out. not_found: expired or already answered.",
        .payload = {str("approval_id").gen(gen::pattern("{*}{*}{*}{*}{*}{*}{*}{*}")),
                    mfaCredential(false).opt().nullable().desc("AuthenticationResponseJSON; leave out to get the "
                                                               "request options first.")},
        .response = {object("approval", "", authApprovalFields()),
                     object("webauthn", "", {mfaRequestOptions()}).opt().desc("Without credential: what to sign.")},
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized", "rate_limited", "passkey_required",
                          "approval_failed"},
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.approval.deny",
        .description = "Decline a device's request; its device.approval.status answers denied.",
        .payload = {str("approval_id").gen(gen::pattern("{*}{*}{*}{*}{*}{*}{*}{*}"))},
        .response = {object("approval", "", authApprovalFields())},
        .refusal_codes = {"denied", "invalid", "not_found", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.recovery.generate",
        .description = "Make ten new recovery codes, shown once. They replace the current ones only when "
                       "acknowledged. The account needs a factor (invalid otherwise). Replacing codes that are in "
                       "force is account.credentials step-up (except on the recovery-code session spending them).",
        .input = "none",
        .response = {str("batch_id"), strArray("codes").desc("XXXXX-XXXXX.")},
        .refusal_codes = {"denied", "invalid", "unauthorized", "error"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.mfa.recovery.acknowledge",
        .description = "The person saved the codes of batch_id: they come into force and the previous batch stops "
                       "working. On a pending enrollment this completes the sign-in (aal 2, amr [\"pwd\", the new "
                       "factor's]) and answers the user, with the access token in the envelope.",
        .auth = "enrollment",
        .payload = {str("batch_id").gen(gen::pattern("{*}{*}{*}{*}{*}{*}{*}{*}"))},
        .response = {uinteger("remaining"),
                     mfaSessionUser().opt().desc("Present when this completed a pending enrollment."),
                     uinteger("aal").min(2).max(2).opt()},
        .refusal_codes = kMfaEnrollmentRefusals,
        .client_timeout = kDefaultTimeout,
    });

    // ---- discoverable passkey sign-in (#358; docs/dev/mfa-design.md sections 4.1, 7.3 and 8.6)

    out.push_back({
        .command = "auth.passkey.options",
        .description = "Start signing in with a passkey alone, no username or password first: a challenge for "
                       "navigator.credentials.get() on this connection, with an empty allowCredentials (the browser "
                       "or passkey manager offers the passkeys it holds for this server) and user verification "
                       "required. It names no account, so the answer is the same for every caller but for its "
                       "challenge. Anonymous web connections only: already_signed_in on a signed-in one; a paired "
                       "device and a pending sign-in can't run it. invalid when passkeys are not configured "
                       "(auth.webauthn.rp_id). Rate limited to 30 a minute per client address; rate_limited when "
                       "10,000 sign-in challenges are open.",
        .auth = "session",
        .input = "none",
        .response = {passkeyRequestOptions(),
                     integer("expires_at").desc("Unix seconds: when the challenge lapses (ask again after).")},
        .refusal_codes = {"invalid", "denied", "error", "already_signed_in", "rate_limited"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "auth.passkey.login",
        .description = "Finish a passkey sign-in with the assertion over an auth.passkey.options challenge of this "
                       "connection. The assertion must carry userHandle, equal to the account's own WebAuthn handle "
                       "for that credential, and user verification. Success signs the connection in: one session row "
                       "at aal 2 with amr [\"hwk\"] (a device-bound passkey or security key) or [\"swk\"] (a "
                       "synced passkey), the access token in the envelope. Every failure (an unknown, suspended or "
                       "foreign passkey, another server's, no user verification, a spent or expired challenge, an "
                       "account that can't sign in) is the same error; the challenge is spent either way. "
                       "already_signed_in on a signed-in connection.",
        .auth = "session",
        .payload = {mfaCredential(false).desc("AuthenticationResponseJSON (PublicKeyCredential.toJSON() after "
                                              "get()); response.userHandle is required.")},
        .response = {mfaSessionUser(), uinteger("aal").min(2).max(2)},
        .refusal_codes = {"invalid", "denied", "error", "already_signed_in"},
        .client_timeout = 20s,
    });

    out.push_back({
        .command = "auth.security.status",
        .description = "Security posture warning for the signed-in account: the super admin's initial password file "
                       "while the generated password is still in use, else null.",
        .input = "none",
        .response = {str("initial_password_file").nullable()},
        .refusal_codes = {"unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
