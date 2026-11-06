#pragma once

// Signed-in web sockets for the DB-backed auth tests (MFA, step-up, approvals, key-backup grants, session assurance):
// the ws answer as the client sees it, a socket as the server accepts it, accounts with a known password, the TOTP
// sign-in flows, paired devices with approval keys, and the auth runtime a test swaps in.
//
//   namespace vh::auth::mfa::test_foo {
//   using namespace vh::test::web;
//   class FooDb : public vh::test::db::Suite {
//       AuthRuntime auth_{{.level = mfa::policy::Level::Optional}};
//       ...

#include "identities.hpp"
#include "../unit/webauthn/Fixtures.hpp"

#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/mfa/Totp.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "protocols/ws/handler/Approvals.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "protocols/ws/handler/Mfa.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace vh::test::web {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<vh::protocols::ws::Session>;
using UserPtr = std::shared_ptr<vh::identities::User>;

inline constexpr auto kPassword = "Web-Session-Pass-1-xyz";

// A name suffix unique in this process.
inline std::string tag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(::getpid()) + "_" + std::to_string(++n);
}

// ── ws answers ─────────────────────────────────────────────────────────────────────────────────────────────────────

// An answer as the ws client sees it: the data of a success, or {code, ...} of a refusal.
struct Answer {
    bool ok{false};
    json data{};
    std::string code{};
    std::string message{};
};

inline Answer call(const std::function<json()>& fn) {
    try {
        return {.ok = true, .data = fn()};
    } catch (...) {
        auto reply = vh::protocols::ws::core::describeCurrentError();
        const auto code = reply.data.is_object() ? reply.data.value("code", std::string{}) : std::string{};
        return {.ok = false, .data = reply.data, .code = code, .message = reply.message};
    }
}

// A command as the router runs it: under the request's step-up scope.
inline Answer run(const SessionPtr& s, const std::function<json()>& fn) {
    const vh::auth::stepup::Scope scope(s);
    return call(fn);
}

// ── the auth runtime of one test ───────────────────────────────────────────────────────────────────────────────────

// Puts `value` in a runtime::Deps slot for the guard's lifetime.
template <typename T>
class ScopedDep {
public:
    ScopedDep(std::shared_ptr<T>& slot, std::shared_ptr<T> value) : slot_(slot), previous_(std::exchange(slot, std::move(value))) {}
    ~ScopedDep() { slot_ = std::move(previous_); }
    ScopedDep(const ScopedDep&) = delete;
    ScopedDep& operator=(const ScopedDep&) = delete;

private:
    std::shared_ptr<T>& slot_;
    std::shared_ptr<T> previous_;
};

struct AuthOptions {
    std::optional<vh::auth::mfa::policy::Level> level{};
    bool mfaHook = false;  // install the MFA policy's session hook (else none)
    bool webauthn = true;  // test_webauthn's relying party
};

// A JWT secret, fresh session and auth managers, the test relying party, the MFA policy level and hook, and no account
// failures; everything (the config too) put back at the end.
class AuthRuntime {
public:
    explicit AuthRuntime(const AuthOptions options = {})
        : previousConfig_(vh::config::Registry::get()),
          sessions_(vh::runtime::Deps::get().sessionManager, std::make_shared<vh::auth::session::Manager>()),
          auth_(vh::runtime::Deps::get().authManager, std::make_shared<vh::auth::Manager>()) {
        vh::auth::session::Issuer::setJwtSecretForTesting("web-session-test-secret");
        if (options.webauthn) {
            auto cfg = previousConfig_;
            cfg.auth.webauthn.rp_id = std::string(vh::test_webauthn::kRpId);
            cfg.auth.webauthn.origins = {std::string(vh::test_webauthn::kOrigin)};
            vh::config::Registry::set(cfg);
        }
        if (options.level) vh::auth::mfa::policy::setLevel(*options.level);
        if (options.mfaHook) vh::auth::mfa::policy::install();
        else vh::auth::session::assurance::setPolicy(nullptr);
        vh::auth::mfa::signin::resetAccountFailuresForTesting();
    }

    ~AuthRuntime() {
        vh::auth::session::assurance::setPolicy(nullptr);
        vh::auth::mfa::signin::resetAccountFailuresForTesting();
        vh::config::Registry::set(previousConfig_);
        vh::auth::session::Issuer::clearJwtSecretForTesting();
    }

    AuthRuntime(const AuthRuntime&) = delete;
    AuthRuntime& operator=(const AuthRuntime&) = delete;

private:
    vh::config::Config previousConfig_;
    ScopedDep<vh::auth::session::Manager> sessions_;
    ScopedDep<vh::auth::Manager> auth_;
};

// ── sockets and accounts ───────────────────────────────────────────────────────────────────────────────────────────

inline vh::auth::session::Manager& sessions() { return *vh::runtime::Deps::get().sessionManager; }

// A websocket as the server accepts it: the handshake hands the session its refresh cookie (none: empty), and
// tryRehydrate either signs it in from the cookie's row or gives it a fresh refresh token (Session::hydrateFromRequest).
inline SessionPtr connect(const std::string& cookie = {}, const std::string& agent = "test-browser",
                          const std::string& ip = "127.0.0.1") {
    auto session = std::make_shared<vh::protocols::ws::Session>(std::make_shared<vh::protocols::ws::Router>());
    session->ipAddress = ip;
    session->userAgent = agent;
    vh::auth::model::RefreshToken::addToSession(session, cookie);
    sessions().tryRehydrate(session);
    return session;
}

inline std::string cookieOf(const SessionPtr& s) { return s->tokens->refreshToken->rawToken; }
inline std::string jtiOf(const SessionPtr& s) { return s->tokens->refreshToken->jti; }

// auth.login through its ws handler.
inline Answer login(const UserPtr& user, const SessionPtr& s, const std::string& password = kPassword) {
    return call([&] {
        return vh::protocols::ws::handler::Auth::login(json{{"name", user->name()}, {"password", password}}, s);
    });
}

// An HTTP lane (preview/download/upload): the cookie alone.
inline bool httpLaneAccepts(const std::string& cookie) {
    try {
        const auto session = sessions().validateRawRefreshToken(cookie);
        return session && session->user;
    } catch (const std::exception&) {
        return false;
    }
}

inline bool rowLive(const std::string& jti) {
    const auto row = vh::db::query::auth::RefreshToken::get(jti);
    return row && !row->revoked;
}

inline std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> liveRows(const UserPtr& user) {
    std::vector<std::shared_ptr<vh::auth::model::RefreshToken>> out;
    for (const auto& row : vh::db::query::auth::RefreshToken::list(user->id))
        if (row && !row->revoked) out.push_back(row);
    return out;
}

// An account of `role` whose password is kPassword.
inline UserPtr newUser(const std::string& role, const std::optional<uint32_t> linuxUid = std::nullopt) {
    const auto r = vh::db::query::rbac::role::Admin::get(role);
    if (!r) throw std::runtime_error("Missing role " + role);
    return vh::identities::manager().user(
        vh::test::identities::createUser("t_" + role + "_" + tag(), r, std::nullopt,
                                         vh::crypto::hash::password(kPassword), linuxUid)
            ->id);
}

// ── TOTP sign-in ───────────────────────────────────────────────────────────────────────────────────────────────────

inline std::vector<uint8_t> fromBase32(const std::string& text) {
    static constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> out;
    uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        buffer = (buffer << 5) | static_cast<uint32_t>(kAlphabet.find(c));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

struct Totp {
    uint32_t factor{};
    std::vector<uint8_t> seed{};
    std::vector<std::string> codes{};  // the recovery codes it came with
};

inline std::string codeAt(const std::vector<uint8_t>& seed, const int64_t stepOffset = 0) {
    namespace totp = vh::auth::mfa::totp;
    return totp::code(seed, totp::stepAt(totp::now()) + stepOffset);
}

// The TOTP step the last sign-in spent is used: moves the TOTP test clock to the next one. A fixture that calls this
// calls totp::resetClockForTesting() in its TearDown.
inline void nextStep() {
    vh::auth::mfa::totp::advanceClockForTesting(std::chrono::seconds(vh::auth::mfa::totp::kPeriodSeconds));
}

// The guided first run with an authenticator app, to completion: pending enrollment, start, confirm, acknowledge.
// `socket` ends signed in at aal 2.
inline Totp enrollTotpAtSignIn(const UserPtr& user, SessionPtr& socket) {
    using vh::protocols::ws::handler::Mfa;
    socket = connect();
    const auto answer = login(user, socket);
    EXPECT_EQ(answer.code, "mfa_enrollment_required") << answer.message;
    const auto started = Mfa::totpStart(json{{"label", "Phone"}}, socket);
    Totp t{.factor = started.at("enrollment_id").get<uint32_t>(),
           .seed = fromBase32(started.at("secret_base32").get<std::string>())};
    const auto confirmed = Mfa::totpConfirm(json{{"enrollment_id", t.factor}, {"code", codeAt(t.seed)}}, socket);
    t.codes = confirmed.at("recovery_codes").at("codes").get<std::vector<std::string>>();
    const auto done = Mfa::acknowledgeRecovery(json{{"batch_id", confirmed.at("recovery_codes").at("batch_id")}}, socket);
    EXPECT_EQ(done.at("aal"), 2);
    return t;
}

// A second sign-in with password + TOTP (on the next step: the last one is spent).
inline SessionPtr signInTotp(const UserPtr& user, const Totp& t) {
    nextStep();
    auto s = connect();
    EXPECT_EQ(login(user, s).code, "mfa_required");
    const auto ok = call([&] {
        return vh::protocols::ws::handler::Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed)}}, s);
    });
    EXPECT_TRUE(ok.ok) << ok.code << " " << ok.message;
    return s;
}

inline SessionPtr signInRecovery(const UserPtr& user, const std::string& code, Answer* answer = nullptr) {
    auto s = connect();
    EXPECT_EQ(login(user, s).code, "mfa_required");
    const auto ok = call([&] {
        return vh::protocols::ws::handler::Mfa::verify(json{{"method", "recovery_code"}, {"code", code}}, s);
    });
    EXPECT_TRUE(ok.ok) << ok.code << " " << ok.message;
    if (answer) *answer = ok;
    return s;
}

// ── passkeys and step-up grants ────────────────────────────────────────────────────────────────────────────────────

// `a` as the account's passkey, stored as a verified registration would store it.
inline void enrollPasskey(const UserPtr& user, const vh::test_webauthn::Authenticator& a) {
    (void)vh::auth::mfa::ensureUser(user->id);
    (void)vh::auth::mfa::addWebAuthnCredential(user->id, {.credential_id = a.credentialId, .public_key_cose = a.key.cose(),
                                                          .cose_alg = -7, .rp_id = std::string(vh::test_webauthn::kRpId),
                                                          .attestation_fmt = "none", .label = "Laptop"});
}

// A signed-in web socket without a database: a detached user and a refresh row in memory.
inline SessionPtr detachedWebSession(const uint32_t userId, const uint8_t aal = 1, std::vector<std::string> amr = {"pwd"},
                                     const std::chrono::system_clock::time_point authTime =
                                         std::chrono::system_clock::now() - std::chrono::hours(1)) {
    auto s = std::make_shared<vh::protocols::ws::Session>(std::make_shared<vh::protocols::ws::Router>());
    vh::identities::UserState state;
    state.name = "stepup-" + std::to_string(userId);
    s->user = vh::identities::User::detached(userId, std::move(state));
    s->tokens->refreshToken = std::make_shared<vh::auth::model::RefreshToken>();
    s->tokens->refreshToken->jti = "jti-" + std::to_string(userId);
    s->tokens->refreshToken->aal = aal;
    s->tokens->refreshToken->amr = std::move(amr);
    s->tokens->refreshToken->authTime = authTime;
    return s;
}

// A step-up grant on `s` for `family` (and `target`, when the family is target-bound).
inline vh::auth::stepup::Grant grantFor(const SessionPtr& s, const vh::auth::stepup::Family family,
                                        std::optional<std::string> target = std::nullopt,
                                        const std::chrono::seconds ttl = std::chrono::seconds(300)) {
    return {.user_id = s->user->id, .refresh_jti = s->tokens->refreshToken->jti, .family = family,
            .target = vh::auth::stepup::targetBound(family) ? std::move(target) : std::nullopt, .method = "test",
            .expires_at = std::chrono::system_clock::now() + ttl};
}

// ── paired devices ─────────────────────────────────────────────────────────────────────────────────────────────────

// A P-256 key standing in for Desktop's Secure Enclave approval key.
class ApprovalKey {
public:
    ApprovalKey() : key_(EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256")) {
        if (!key_) throw std::runtime_error("keygen");
    }
    ~ApprovalKey() { EVP_PKEY_free(key_); }
    ApprovalKey(const ApprovalKey&) = delete;
    ApprovalKey& operator=(const ApprovalKey&) = delete;

    [[nodiscard]] std::vector<uint8_t> spki() const {
        unsigned char* der = nullptr;
        const int len = i2d_PUBKEY(key_, &der);
        std::vector<uint8_t> out(der, der + len);
        OPENSSL_free(der);
        return out;
    }
    [[nodiscard]] std::string spkiB64() const { return vh::device::crypto::toBase64(spki()); }
    [[nodiscard]] std::string spkiHex() const { return vh::device::crypto::toHex(vh::device::crypto::sha256(spki())); }

    [[nodiscard]] std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::size_t len = 0;
        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, key_);
        EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size());
        std::vector<uint8_t> sig(len);
        EVP_DigestSign(ctx, sig.data(), &len, message.data(), message.size());
        EVP_MD_CTX_free(ctx);
        sig.resize(len);
        return sig;
    }

private:
    EVP_PKEY* key_;
};

struct Paired {
    vh::device::Device row;
    std::shared_ptr<vh::device::Peer> peer;
    SessionPtr session;
};

// A paired device of `user` (a random mTLS key hash) and its session, with `approvalKey` registered at pairing if given.
inline Paired pairedDevice(const UserPtr& user, const ApprovalKey* approvalKey = nullptr) {
    namespace crypto = vh::device::crypto;
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki = crypto::randomNonce();
    peer->spkiHex = crypto::toHex(peer->spki);
    peer->address = "192.0.2.10";
    vh::db::query::device::NewDevice d{.user_id = user->id, .approved_by = user->id, .name = "Mac " + tag(),
                                       .platform = "macOS", .app_version = "1.0", .spki_sha256 = peer->spkiHex,
                                       .last_ip = "192.0.2.10"};
    if (approvalKey) {
        d.approval_key_spki = approvalKey->spki();
        d.approval_key_sha256 = approvalKey->spkiHex();
    }
    const auto row = vh::db::query::device::Devices::insert(d);
    peer->deviceRowId = row.id;
    return {.row = row, .peer = peer, .session = vh::protocols::ws::Session::devicePrincipal(peer, user, [] {})};
}

// Another session of the same device (a reconnect).
inline SessionPtr reconnect(const Paired& d, const UserPtr& user) {
    return vh::protocols::ws::Session::devicePrincipal(d.peer, user, [] {});
}

// Asks for a challenge and answers it with `key`, over the payload `edit` makes of the canonical one if given.
inline Answer approveWithKey(const SessionPtr& s, const ApprovalKey& key, const std::string& family,
                             const std::string& target,
                             const std::function<std::vector<uint8_t>(const json&, std::vector<uint8_t>)>& edit = {}) {
    namespace crypto = vh::device::crypto;
    using vh::protocols::ws::handler::Approvals;
    const auto c = run(s, [&] { return Approvals::challenge(json{{"family", family}, {"target", target}}, s); });
    if (!c.ok) return c;
    auto payload = *crypto::fromBase64(c.data.at("payload_b64").get<std::string>());
    if (edit) payload = edit(c.data, payload);
    return run(s, [&] {
        return Approvals::submit(json{{"challenge_id", c.data.at("challenge_id")},
                                      {"signature_b64", crypto::toBase64(key.sign(payload))}},
                                 s);
    });
}

}
