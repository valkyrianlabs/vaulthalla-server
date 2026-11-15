// vh-test-tier: db-only
// Managed storage (design/cloud/managed-remotes.md) end to end against a fake account service that answers in the
// cloud's as-built shapes (src/storage/ManagedStorage.cpp, src/accounts/Deployments.cpp, src/billing/Billing.cpp) over
// the http transport seam, with real local vaults, the VersionedBucket fake as each vault's bucket and the attach and
// detach engines run inline. Covers: nothing runs unlinked or without the confirmed account key; a new vault is
// registered only once it holds a file, keyed through the sealed credential exchange, attached (origin cloud, the
// account key's system grant, opaque_v1, encrypting), its retention sent and enrolled automatically with only
// account-key envelopes; existing vaults only after the offer is accepted; cloud keys read-only to people; every
// waiting reason; a lost credential response; the access gate following storage_access; superseded keys; switch off
// before a bucket; unlink refusal; ejection in place leaving the data untouched; a move; and the end of the plan
// converting a vault to local in place without deleting anything.

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"

#include "audit/Trail.hpp"
#include "cloud/AccountPin.hpp"
#include "cloud/Identity.hpp"
#include "cloud/Signing.hpp"
#include "cloud/Storage.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/cloud/AccountKey.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/RecoveryVault.hpp"
#include "db/query/cloud/Storage.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/Policy.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "ops/APIKeys.hpp"
#include "ops/Cloud.hpp"
#include "ops/CloudKeys.hpp"
#include "ops/CloudRecovery.hpp"
#include "ops/CloudStorage.hpp"
#include "ops/Error.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/RemoteAccess.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "storage/s3/curl/Http.hpp"
#include "sync/Controller.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteDetach.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <vl/keykit/account_key.hpp>
#include <vl/keykit/base64url.hpp>
#include <vl/keykit/kev1.hpp>
#include <vl/keykit/kit.hpp>
#include <vl/keykit/recovery_policy.hpp>
#include <vl/keykit/seed.hpp>
#include <vl/keykit/storage_credential.hpp>
#include <vl/keykit/uid.hpp>
#include <vl/keykit/vault_label.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <fstream>
#include <map>
#include <set>

namespace vh::test_cloud_storage {

namespace http = storage::s3::curl::http;
namespace cs = ops::cloud_storage;
namespace ra = vault::remote;
namespace rd = vault::remote::detach;
namespace account = vl::keykit::account;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;
using DB = db::query::cloud::CloudStorage;
using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
using vh::test::bin::bytes;
using vh::test::bin::str;

// The account's key history, as a device holding the key makes it (vl-keykit's own signing).
struct KeyHistory {
    std::string publicId = "5f0c3a3e-8d1b-4c2a-9e47-6b1d2f3a4c5e";
    std::vector<vl::keykit::RecoverySeed> seeds;
    std::vector<account::KeyStatement> statements;
    std::vector<account::SignedStatement> chain;

    void initial() {
        seeds.push_back(vl::keykit::RecoverySeed::generate());
        auto st = account::statementFor(seeds.back(), publicId, 1, std::nullopt, account::Reason::Initial);
        chain.push_back(account::sign(st, seeds.back(), nullptr));
        statements.push_back(std::move(st));
    }
    // A recovery policy listing one recipient, signed by the account key (as Desktop or the portal does).
    [[nodiscard]] json policy(const uint32_t sequence) const {
        account::RecoveryPolicy p{.public_id = publicId, .sequence = sequence, .generation = 1,
                                  .issued_at = "2026-11-15T00:00:00Z", .recipients = {}};
        account::PolicyRecipient r{.x25519_public = {}, .label = "Kit " + std::to_string(sequence)};
        const auto seed = vl::keykit::RecoverySeed::generate();
        const auto pk = seed.x25519PublicKey();
        std::ranges::copy(pk, r.x25519_public.begin());
        p.recipients.push_back(r);
        const auto s = account::signPolicy(p, seeds.at(0), statements.at(0));
        return {{"sequence", sequence}, {"generation", 1}, {"policy", s.policy},
                {"signature", vl::keykit::base64UrlEncode(s.signature)}, {"created_by", "installation:test"},
                {"created_at", 1770000000}};
    }
    [[nodiscard]] std::string fingerprint() const {
        return account::fingerprintText(account::fingerprint(statements.at(0)));
    }
    [[nodiscard]] json answer() const {
        return {{"public_id", publicId},
                {"current", {{"generation", 1}, {"fingerprint", fingerprint()}, {"link", "initial"},
                             {"offline_copy_confirmed_at", 1770000000}}},
                {"offline_copy_confirmed_at", 1770000000},
                {"chain", json::array({{{"generation", 1}, {"statement", chain[0].statement},
                                        {"signature", vl::keykit::base64UrlEncode(chain[0].signature)},
                                        {"previous_signature", nullptr}, {"fingerprint", fingerprint()},
                                        {"reason", "initial"}, {"link", "initial"}, {"status", "current"},
                                        {"created_at", 1770000000}, {"retired_at", nullptr},
                                        {"offline_copy_confirmed_at", nullptr}}})},
                {"policy", nullptr}};
    }
};

// The account's service, in the shapes its code answers with. Each bucket is a VersionedBucket the test runs.
struct FakeCloud {
    std::string installation = "kceypk9vfn5tv6yx5c6qpfebdm";
    json keyAnswer;
    // The entitlement: state, quota, access and cause (ManagedStorage::overview's `entitlement`).
    std::optional<std::string> state = std::string("active");
    uint64_t quota = 1ull << 40;
    std::string access = "full";
    std::string cause = "active";
    bool offlineCopy = true;
    std::optional<uint64_t> stored;
    std::string waitingReason;   // set: switched-on buckets wait with it instead of becoming ready
    bool holdPending = false;    // switched-on buckets stay pending
    bool loseNextCredential = false;
    bool reachable = true;
    std::set<std::string> foreign;   // registered by another deployment
    std::vector<std::string> calls;

    struct Vault {
        bool registered = false;
        std::vector<uint8_t> label;
        bool enabled = false;
        std::string state = "none";
        unsigned retention = 30;
        std::string bucket;
        std::optional<std::string> detachedAt, convertedAt;
        bool hidden = false;   // removed from this deployment's view
        std::optional<std::string> movedTo;   // restored onto another deployment: listed with where it went
        // Replicated vaults (the cloud's src/storage/ManagedStorage.cpp vaultView): the servers holding it, the ones
        // removed lately, and `removed` once the account holder removed it from this server.
        json replicas = json::array(), formerReplicas = json::array();
        bool removedByOwner = false;
        bool heldHere = true;   // DELETE /v1/vaults/{uid}/replica: 204 while held, then 404 no_such_vault
    };
    std::map<std::string, Vault> vaults;
    struct Key {
        std::string uid;
        std::string state;   // issued | active | superseded | revoked
        std::string access;
        std::string secret;
    };
    std::map<std::string, Key> keys;
    std::map<std::string, json> enrollments;
    std::optional<uint32_t> dropEnvelopeVersion;
    std::optional<std::string> portal = "https://app.vaulthalla.test/storage/leave";
    std::map<std::string, std::shared_ptr<VersionedBucket>>* buckets = nullptr;
    unsigned nextKey = 1;

    static http::Response reply(const long status, const json& body) {
        http::Response r;
        r.status = status;
        r.body = body.is_null() ? "" : body.dump();
        return r;
    }
    static http::Response error(const long status, const std::string& code, const std::string& message,
                                const std::string& reason = {}) {
        json e{{"code", code}, {"message", message}};
        if (!reason.empty()) e["reason"] = reason;
        return reply(status, {{"error", e}});
    }

    std::string currentKeyOf(const std::string& uid, std::string* access = nullptr) const {
        std::string best, state = "none";
        for (const auto& [id, k] : keys) {
            if (k.uid != uid || k.state == "revoked") continue;
            if (best.empty() || k.state == "issued" || (k.state == "active" && state == "superseded")) {
                best = id;
                state = k.state;
                if (access) *access = k.access;
            }
        }
        return best;
    }

    json view(const std::string& uid) const {
        const auto& v = vaults.at(uid);
        const bool visible = v.state == "ready" || v.state == "off" || v.state == "ejecting" || v.state == "ejected";
        json out{{"vault_uid", uid}, {"enabled", v.enabled}, {"state", v.state},
                 {"reason", v.state == "waiting" && !waitingReason.empty() ? json(waitingReason) : json(nullptr)},
                 {"bucket", visible ? json(v.bucket) : json(nullptr)},
                 {"bucket_id", visible ? json("id-" + v.bucket) : json(nullptr)},
                 {"s3_endpoint", visible ? json("https://s3.fake.test") : json(nullptr)},
                 {"region", visible ? json("us-west-004") : json(nullptr)},
                 {"content_retention_days", v.state == "none" ? json(nullptr) : json(v.retention)},
                 {"detached_at", nullptr}, {"converted_at", nullptr}};
        if (v.movedTo) out["moved_to"] = {{"deployment_id", "dep-" + *v.movedTo}, {"name", *v.movedTo}};
        json key{{"state", "none"}};
        std::string a;
        if (const auto id = currentKeyOf(uid, &a); !id.empty())
            key = {{"key_id", id}, {"state", keys.at(id).state}, {"access", a}};
        out["credential"] = key;
        out["replicas"] = v.replicas;
        out["former_replicas"] = v.formerReplicas;
        if (v.removedByOwner) {
            out["removed"] = {{"reason", "owner"}, {"at", 1770000500}};
            out["credential"] = {{"state", "none"}};
        }
        return out;
    }

    void provision(Vault& v, const std::string& uid) {
        if (!v.enabled) return;
        if (holdPending) {
            v.state = "pending";
            return;
        }
        if (!waitingReason.empty() || access == "none") {
            v.state = "waiting";
            return;
        }
        v.state = "ready";
        if (v.bucket.empty()) v.bucket = "vhc-" + uid.substr(0, 20);
        if (buckets && !buckets->contains(v.bucket)) {
            auto b = std::make_shared<VersionedBucket>(Versioning::Enabled, v.bucket);
            b->md5Etags = true;
            (*buckets)[v.bucket] = b;
        }
    }

    // A change of access swaps keys the way account.enforce does: active keys of the wrong access are superseded.
    void enforce() {
        for (auto& [id, k] : keys) {
            if (access == "none" && k.state != "revoked") k.state = "revoked";
            else if (k.state == "active" && k.access != access) k.state = "superseded";
        }
    }

    http::Response operator()(const http::Request& r) {
        const std::string base = "https://api.vaulthalla.test";
        auto path = r.url.substr(base.size());
        calls.push_back(r.method + " " + path);
        if (!reachable) {
            http::Response res;
            res.transport_ok = false;
            res.transport_error = "Couldn't connect to server";
            return res;
        }
        std::string auth;
        for (const auto& [k, v] : r.headers)
            if (k == "Authorization") auth = v;
        if (auth.find("Installation=" + installation) == std::string::npos)
            return error(401, "unauthenticated", "request signature rejected");
        const auto body = r.body.empty() ? json() : json::parse(r.body);
        const auto segment = [&](const std::string& prefix) {
            const auto rest = path.substr(prefix.size());
            return rest.substr(0, rest.find('/'));
        };

        if (r.method == "GET" && path == "/v1/keys/account")
            return keyAnswer.is_null() ? error(404, "not_found", "this account has no recovery key yet") : reply(200, keyAnswer);
        if (r.method == "GET" && path == "/v1/installation")
            return reply(200, {{"id", installation}, {"account_id", 7}, {"account_public_id", keyAnswer.value("public_id", "")},
                               {"deployment_id", "d3p1qymnt00000000000000000"}});
        if (r.method == "POST" && path == "/v1/vaults") {
            const auto uid = body.at("vault_uid").get<std::string>();
            if (foreign.contains(uid))
                return error(409, "conflict", "this vault is registered on the account and this server doesn't hold it");
            auto& v = vaults[uid];
            const bool created = !v.registered;
            v.registered = true;
            return reply(created ? 201 : 200, {{"vault_uid", uid}, {"label", nullptr}, {"registered_at", 1770000000},
                                               {"replicas", json::array()}, {"created", created}});
        }
        if (r.method == "PUT" && path.starts_with("/v1/vaults/") && path.ends_with("/label")) {
            const auto uid = segment("/v1/vaults/");
            const auto label = vl::keykit::base64UrlDecode(body.at("label").get<std::string>());
            if (!label || label->size() != vl::keykit::label::kSealedSize)
                return error(400, "invalid_argument", "`label` is a sealed label: base64url of 240 bytes");
            vaults[uid].label = *label;
            return reply(204, nullptr);
        }
        if (r.method == "POST" && path.starts_with("/v1/vaults/") && path.ends_with("/replicas/unlisted")) {
            const auto uid = segment("/v1/vaults/");
            const auto node = body.value("node_id", "");
            for (auto& rep : vaults[uid].replicas)
                if (rep.value("node_id", "") == node) {
                    rep["unlisted"] = {{"by", {{"deployment_id", "dep-self"}, {"name", "this server"}}}, {"at", 3}};
                    return reply(204, nullptr);
                }
            return error(404, "not_found", "no server of this vault has that node id", "not_held");
        }
        if (r.method == "DELETE" && path.starts_with("/v1/vaults/") && path.ends_with("/replica")) {
            const auto uid = segment("/v1/vaults/");
            if (!vaults.contains(uid) || !vaults[uid].heldHere) return error(404, "not_found", "no such vault", "no_such_vault");
            vaults[uid].heldHere = false;
            return reply(204, nullptr);
        }
        if (r.method == "GET" && path == "/v1/storage") {
            json vaultList = json::array();
            for (const auto& [uid, v] : vaults)
                if (v.registered && !v.hidden) vaultList.push_back(view(uid));
            return reply(200, {{"entitlement", {{"state", state ? json(*state) : json(nullptr)}, {"plan", "storage-1tb"},
                                                {"storage_quota_bytes", quota}, {"storage_access", access}, {"cause", cause}}},
                               {"usage", {{"stored_bytes", stored ? json(*stored) : json(nullptr)},
                                          {"date", stored ? json("2026-11-13") : json(nullptr)}}},
                               {"account_key_offline_copy_confirmed", offlineCopy},
                               {"ejection", nullptr},
                               {"ejection_portal_url", portal ? json(*portal) : json(nullptr)},
                               {"provider", "fake"},
                               {"vaults", vaultList}});
        }
        if (r.method == "GET" && path == "/v1/billing")
            return reply(200, {{"state", state ? json(*state) : json(nullptr)}, {"state_since", 1770000000},
                               {"plan", "storage-1tb"}, {"storage_quota_bytes", quota}, {"storage_access", access},
                               {"next", nullptr}, {"deletion_at", nullptr}, {"current_period_end", nullptr},
                               {"cancel_at_period_end", false}});
        if (r.method == "POST" && path == "/v1/billing/handoffs")
            return reply(201, {{"id", "h1"}, {"url", "https://vaulthalla.test/handoff#h1"}, {"expires_at", 1770000600}});
        if (r.method == "PUT" && path.starts_with("/v1/storage/vaults/")) {
            const auto uid = segment("/v1/storage/vaults/");
            if (!vaults.contains(uid) || !vaults[uid].registered) return error(404, "not_found", "no such vault");
            auto& v = vaults[uid];
            if (v.state == "ejecting") return error(409, "conflict", "this account's storage is being ejected", "ejecting");
            if (body.contains("content_retention_days")) v.retention = body["content_retention_days"].get<unsigned>();
            if (body.contains("enabled")) {
                v.enabled = body["enabled"].get<bool>();
                if (v.enabled) provision(v, uid);
                else if (v.state == "ready" || v.state == "waiting" || v.state == "pending") v.state = "off";
            }
            return reply(202, view(uid));
        }
        if (r.method == "POST" && path.starts_with("/v1/storage/vaults/") && path.ends_with("/credentials")) {
            const auto uid = segment("/v1/storage/vaults/");
            if (!vaults.contains(uid)) return error(404, "not_found", "no such vault");
            auto& v = vaults[uid];
            if (!offlineCopy)
                return error(409, "conflict", "the account key's offline copy isn't confirmed yet", "account_key_unconfirmed");
            if (v.state == "off") return error(409, "conflict", "this vault's storage is switched off", "bucket_off");
            if (v.state != "ready") return error(409, "conflict", "this vault's bucket isn't ready", "bucket_not_ready");
            if (access == "none") return error(402, "payment_required", "managed storage needs an active plan");
            const auto pk = vl::keykit::base64UrlDecode(body.at("public_key").get<std::string>());
            const std::string keyId = "K" + std::to_string(nextKey++) + "x0000000000";
            const std::string secret = "fake-secret-" + keyId + "-0000000000000000";
            const auto sealed = vl::keykit::credential::seal(
                std::span(reinterpret_cast<const uint8_t*>(secret.data()), secret.size()),
                {.installation_id = installation, .vault_uid = *vl::keykit::fromBase32(uid), .key_id = keyId}, *pk);
            for (auto& [id, k] : keys)
                if (k.uid == uid && k.state == "issued") k.state = "revoked";   // a lost response's key goes
            keys[keyId] = {.uid = uid, .state = "issued", .access = access, .secret = secret};
            if (loseNextCredential) {
                loseNextCredential = false;
                http::Response res;
                res.transport_ok = false;
                res.transport_error = "Operation timed out";
                return res;
            }
            return reply(201, {{"key_id", keyId}, {"access", access}, {"bucket", v.bucket}, {"bucket_id", "id-" + v.bucket},
                               {"s3_endpoint", "https://s3.fake.test"}, {"region", "us-west-004"},
                               {"sealed_secret", vl::keykit::base64UrlEncode(sealed)}});
        }
        if (r.method == "POST" && path.starts_with("/v1/storage/credentials/") && path.ends_with("/ack")) {
            const auto id = segment("/v1/storage/credentials/");
            if (!keys.contains(id)) return error(404, "not_found", "no such key for this installation");
            auto& k = keys[id];
            if (k.state == "active") return reply(204, nullptr);
            if (k.state != "issued") return error(409, "conflict", "this key is " + k.state, "key_" + k.state);
            for (auto& [other, o] : keys)
                if (other != id && o.uid == k.uid && (o.state == "active" || o.state == "superseded")) o.state = "revoked";
            k.state = "active";
            return reply(204, nullptr);
        }
        if (r.method == "POST" && path.starts_with("/v1/storage/vaults/") && path.ends_with("/detached")) {
            vaults[segment("/v1/storage/vaults/")].detachedAt = "now";
            return reply(204, nullptr);
        }
        if (r.method == "POST" && path.starts_with("/v1/storage/vaults/") && path.ends_with("/ejected")) {
            auto& v = vaults[segment("/v1/storage/vaults/")];
            if (v.state != "ejecting" && v.state != "ejected")
                return error(409, "conflict", "this vault's storage isn't being ejected", "not_ejecting");
            v.convertedAt = "now";
            return reply(204, nullptr);
        }
        if (r.method == "GET" && path.starts_with("/v1/recovery/vaults/")) {
            const auto uid = segment("/v1/recovery/vaults/");
            if (!enrollments.contains(uid)) return error(404, "not_found", "no such vault");
            json versions = json::array();
            for (const auto& v : enrollments[uid]["key_versions"])
                versions.push_back({{"version", v["version"]}, {"recipients", json::array({"r"})}});
            return reply(200, {{"vault_uid", uid}, {"versions", versions}});
        }
        if (r.method == "GET" && path.starts_with("/v1/keys/vaults/") && path.ends_with("/envelopes")) {
            const auto uid = segment("/v1/keys/vaults/");
            if (!enrollments.contains(uid)) return error(404, "not_found", "this vault isn't enrolled for this account");
            json list = json::array();
            for (const auto& e : enrollments[uid]["envelopes"]) {
                const auto bytes = vl::keykit::base64Decode(e.get<std::string>());
                const auto h = vl::keykit::kev1::inspect(*bytes);
                if (dropEnvelopeVersion && h.key_version == *dropEnvelopeVersion) continue;
                list.push_back({{"key_version", h.key_version}, {"generation", 1}, {"fingerprint", "f"},
                                {"envelope", vl::keykit::base64UrlEncode(*bytes)}});
            }
            return reply(200, {{"vault_uid", uid}, {"envelopes", list}});
        }
        if (r.method == "PUT" && path.starts_with("/v1/recovery/vaults/")) {
            enrollments[segment("/v1/recovery/vaults/")] = body;
            return reply(200, {{"created", true}, {"envelopes_added", body["envelopes"].size()}, {"versions_added", 1},
                               {"coverage", nullptr}});
        }
        return error(404, "not_found", "no route");
    }
};

class CloudStorageTest : public vh::test::db::Suite {
protected:
    inline static std::map<std::string, std::shared_ptr<VersionedBucket>> buckets;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_cloud_storage")) return;
        ra::setControllerFactoryForTesting([](unsigned int, const std::string& bucket) -> std::shared_ptr<storage::s3::Controller> {
            const auto it = buckets.find(bucket);
            return it == buckets.end() ? nullptr : it->second;
        });
        cs::installHooks();
    }
    static void TearDownTestSuite() {
        if (skipTests) return;
        ra::setControllerFactoryForTesting({});
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        auto cfg = config::Registry::get();
        previousEndpoint_ = cfg.cloud.endpoint;
        cfg.cloud.endpoint = "https://api.vaulthalla.test";
        config::Registry::set(cfg);
        cloud_.buckets = &buckets;
        http::setTransportForTesting([this](const http::Request& r) { return cloud_(r); });
        cs::setKeyProbeForTesting([this](unsigned int, std::string& error) {
            if (probeFails_) error = "AccessDenied";
            return !probeFails_;
        });
        // A managed vault's envelopes go to its bucket (the fake), through the same ManifestStore as any S3 vault's.
        vault::envelopes::setStoreFactoryForTesting([](const uint32_t vaultId) -> std::shared_ptr<sync::manifest::ObjectStore> {
            const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(vaultId));
            if (!s3) throw std::runtime_error("not an S3 vault");
            return std::make_shared<storage::s3::ManifestStore>(buckets.at(s3->bucket),
                                                                sync::manifest::WriteCapability::Conditional);
        });
        reset();
    }

    void TearDown() override {
        if (!IsSkipped()) {
            http::setTransportForTesting(std::nullopt);
            cs::setKeyProbeForTesting(std::nullopt);
            vault::envelopes::setStoreFactoryForTesting({});
            reset();
            auto cfg = config::Registry::get();
            cfg.cloud.endpoint = previousEndpoint_;
            config::Registry::set(cfg);
        }
        Suite::TearDown();
    }

    static void reset() {
        db::Transactions::exec("CloudStorageTest::reset", [&](pqxx::work& txn) {
            txn.exec("DELETE FROM vault_cloud_storage");
            txn.exec("DELETE FROM cloud_storage_account");
            txn.exec("DELETE FROM vault_recovery_grant WHERE account_key_generation IS NOT NULL");
        });
        for (const auto& row : db::query::cloud::RecoveryVaults::list()) (void)db::query::cloud::RecoveryVaults::remove(row.vault_id);
        db::query::cloud::AccountKeys::clear();
        cloud::pin::destroy();
        db::query::cloud::Link::clear();
        cloud::identity::destroy();
        cs::onUnlinked();
    }

    void link() {
        const auto seed = cloud::identity::create();
        db::query::cloud::LinkRow row{.endpoint = "https://api.vaulthalla.test", .status = "pending",
                                      .public_key = cloud::publicKeyOf(seed.bytes()), .name = "test",
                                      .request_id = std::string("0123456789abcdefghjkmnpqrs"), .request_expires_at = 0,
                                      .installation_id = std::nullopt, .account_id = std::nullopt,
                                      .requested_by = "admin", .requested_at = 0, .linked_at = std::nullopt};
        ASSERT_TRUE(db::query::cloud::Link::putPending(row));
        ASSERT_TRUE(db::query::cloud::Link::markLinked("0123456789abcdefghjkmnpqrs", cloud_.installation, 7,
                                                       std::string("d3p1qymnt00000000000000000"), history_.publicId));
    }

    // Linked, the account key pinned, and storage available on the link.
    void linkAndPin() {
        link();
        history_.initial();
        cloud_.keyAnswer = history_.answer();
        ASSERT_EQ(ops::cloud_keys::check("test").state, "pending");
        ASSERT_NO_THROW((void)ops::cloud_keys::confirm(superUser, history_.fingerprint(), ops::vault_keys::Channel::Cli));
        (void)cs::tick(true);   // storage becomes available on this link
        ASSERT_TRUE(DB::account() && DB::account()->enabled_at);
    }

    // Each pass sees the account's state again, and nothing waits on a backoff.
    cs::TickResult tick() {
        for (auto r : DB::list()) {
            r.next_attempt_at.reset();
            DB::update(r);
        }
        return cs::tick(true);
    }

    static EnginePtr newVault(const std::string& prefix = "cs") {
        const auto created = ops::vaults::create(superUser, {.name = prefix + "_" + vh::test::uniqueTag('c'),
                                                             .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(created->id);
    }

    static EnginePtr engineOf(const uint32_t id) { return runtime::Deps::get().storageManager->getEngine(id); }

    static void write(const uint32_t id, const std::string& path, const std::string& text) {
        const auto engine = engineOf(id);
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                          .buffer = bytes(text), .engine = engine, .user = superUser, .overwrite = true});
    }

    static std::string readLocal(const uint32_t id, const std::string& path) {
        const auto engine = engineOf(id);
        const auto reader = engine->openPlaintextReader(db::query::fs::File::getFileByPath(id, path));
        return str(storage::readAll(*reader, 64 << 20));
    }

    static std::string uidOf(const uint32_t id) { return vl::keykit::toBase32(*db::query::vault::Vault::getVault(id)->uid); }

    static sync::Controller& leases() {
        static sync::Controller controller;
        return controller;
    }

    static std::shared_ptr<VersionedBucket> bucketOf(const uint32_t id) {
        const auto row = DB::get(id);
        return row && row->bucket && buckets.contains(*row->bucket) ? buckets.at(*row->bucket) : nullptr;
    }

    // The attach the service started, run inline as RemoteAttachService would (with the fake bucket as the engine's).
    static ra::RunResult runAttach(const uint32_t id) {
        ra::RunDeps d;
        d.tryAcquirePass = [](const uint32_t v) { return leases().tryAcquirePass(v); };
        d.releasePass = [](const uint32_t v) { leases().releasePass(v); };
        d.swapEngine = [id](const uint32_t v) {
            auto& manager = *runtime::Deps::get().storageManager;
            manager.reloadEngine(v);
            useFakeBucket(id);
        };
        d.firstPass = [](const uint32_t, std::time_t) -> std::optional<json> {
            return json{{"status", "success"}, {"started_at", nullptr}, {"finished_at", nullptr}, {"error", nullptr},
                        {"transfers", 0}};
        };
        return ra::run(id, d);
    }

    static void useFakeBucket(const uint32_t id) {
        const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(id));
        if (!cloud) return;
        cloud->setS3ControllerForTesting(bucketOf(id));
        cloud->setRemoteFetchGate([](const storage::CloudEngine&, const storage::RemoteFetchRequest&) {
            return std::unique_ptr<storage::RemoteFetchReservation>{};
        });
    }

    static rd::RunResult runDetach(const uint32_t id) {
        rd::RunDeps d;
        d.tryAcquirePass = [](const uint32_t v) { return leases().tryAcquirePass(v); };
        d.releasePass = [](const uint32_t v) { leases().releasePass(v); };
        d.swapEngine = [](const uint32_t v) { runtime::Deps::get().storageManager->reloadEngine(v); };
        return rd::run(id, d);
    }

    // A vault with a file all the way to active managed storage.
    uint32_t activeVault() {
        const auto e = newVault();
        const auto id = e->vault->id;
        write(id, "/a.txt", "alpha");
        write(id, "/b.txt", std::string(50'000, 'b'));
        for (int i = 0; i < 6 && DB::get(id)->state != "attaching"; ++i) (void)tick();
        EXPECT_EQ(DB::get(id)->state, "attaching") << DB::get(id)->last_error.value_or("");
        const auto result = runAttach(id);
        EXPECT_EQ(result.state, ra::State::Done) << result.error.value_or("");
        (void)tick();
        EXPECT_EQ(DB::get(id)->state, "active") << DB::get(id)->last_error.value_or("");
        useFakeBucket(id);
        return id;
    }

    std::string state(const uint32_t id) const { return DB::get(id) ? DB::get(id)->state : "none"; }

    unsigned callsTo(const std::string& prefix) const {
        return static_cast<unsigned>(std::ranges::count_if(cloud_.calls, [&](const std::string& c) { return c.starts_with(prefix); }));
    }

    template <class Fn>
    static std::string code(Fn&& fn) {
        try {
            (void)fn();
            return "ok";
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::Conflict&) {
            return "conflict";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::NotFound&) {
            return "not_found";
        }
    }

    FakeCloud cloud_;
    KeyHistory history_;
    bool probeFails_ = false;
    std::string previousEndpoint_;
};

TEST_F(CloudStorageTest, NothingRunsUnlinkedAndOnlyTheKeyCheckWithoutAConfirmedKey) {
    const auto e = newVault();
    write(e->vault->id, "/a.txt", "x");
    auto r = cs::tick(true);
    EXPECT_FALSE(r.linked);
    EXPECT_TRUE(cloud_.calls.empty()) << "unlinked: nobody is contacted";

    link();
    history_.initial();
    cloud_.keyAnswer = history_.answer();
    r = cs::tick(true);
    EXPECT_TRUE(r.linked);
    EXPECT_FALSE(r.pinned);
    EXPECT_EQ(callsTo("GET /v1/storage"), 0u) << "no storage call before a person confirmed the account key";
    EXPECT_EQ(callsTo("POST /v1/vaults"), 0u);
    EXPECT_FALSE(DB::get(e->vault->id));
    EXPECT_EQ(cs::status(superUser).account_key, "unconfirmed");
    EXPECT_EQ(cs::status(superUser).next_step.has_value(), true);
}

TEST_F(CloudStorageTest, ANewVaultIsRegisteredAtItsFirstFileKeyedAttachedRetainedAndEnrolled) {
    linkAndPin();
    const auto e = newVault();
    const auto id = e->vault->id;
    const auto uid = uidOf(id);
    (void)tick();
    ASSERT_TRUE(DB::get(id));
    EXPECT_EQ(DB::get(id)->switch_state, "on") << "created after storage became available: on by default";
    EXPECT_EQ(state(id), "unregistered");
    EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>("empty"));
    EXPECT_FALSE(cloud_.vaults.contains(uid) && cloud_.vaults[uid].registered) << "an empty vault isn't registered";

    write(id, "/a.txt", "alpha");
    (void)tick();
    EXPECT_EQ(state(id), "registered");
    ASSERT_TRUE(cloud_.vaults[uid].registered);
    // The label is sealed to the pinned account key: the account key opens it, the cloud can't.
    const auto name = vl::keykit::label::open(cloud_.vaults[uid].label, history_.seeds[0].x25519SecretKey().bytes(),
                                              history_.statements[0], *vl::keykit::fromBase32(uid));
    EXPECT_EQ(name, e->vault->name);

    (void)tick();   // switched on at the cloud with the default retention
    EXPECT_TRUE(cloud_.vaults[uid].enabled);
    EXPECT_EQ(cloud_.vaults[uid].retention, 30u);
    (void)tick();   // the bucket is ready: the sealed key exchange
    EXPECT_EQ(state(id), "keyed") << DB::get(id)->last_error.value_or("");
    const auto row = *DB::get(id);
    ASSERT_TRUE(row.api_key_id);
    EXPECT_EQ(row.key_state, "active");
    EXPECT_EQ(cloud_.keys[*row.key_id].state, "active") << "acknowledged after the probe";
    const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(*row.api_key_id);
    EXPECT_EQ(key->secret_access_key, cloud_.keys[*row.key_id].secret) << "the sealed secret opened for this server";
    EXPECT_EQ(key->origin, "cloud");
    EXPECT_FALSE(key->editable());
    EXPECT_EQ(key->user_id, e->vault->owner_id) << "the vault owner's key";
    // People can't change or remove a cloud key.
    EXPECT_EQ(code([&] { return ops::api_keys::update(superUser, *row.api_key_id, {.name = std::string("x")}); }), "conflict");
    EXPECT_EQ(code([&] { return ops::api_keys::remove(superUser, *row.api_key_id); }), "conflict");

    (void)tick();
    EXPECT_EQ(state(id), "attaching");
    const auto attach = db::query::vault::RemoteAttach::get(id);
    ASSERT_TRUE(attach);
    EXPECT_EQ(attach->origin, "cloud");
    // The account key is the vault's recovery recipient, added by the system on the pin's authority.
    const auto grants = db::query::vault::RecoveryGrants::usable(id);
    ASSERT_EQ(grants.size(), 1u);
    EXPECT_EQ(grants[0].account_key_generation, std::optional<uint32_t>(1));
    EXPECT_TRUE(grants[0].authorized_by.starts_with("system:cloud")) << grants[0].authorized_by;

    ASSERT_EQ(runAttach(id).state, ra::State::Done);
    (void)tick();
    EXPECT_EQ(state(id), "active");
    useFakeBucket(id);
    (void)tick();   // the next step enrolls it
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(id));
    ASSERT_TRUE(s3);
    EXPECT_TRUE(s3->encrypt_upstream);
    EXPECT_EQ(s3->storage_layout, vault::model::StorageLayout::OpaqueV1);
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::Full);
    // Automatic enrollment: only the account key's envelopes, and they are envelopes for this vault.
    ASSERT_TRUE(cloud_.enrollments.contains(uid));
    const auto& sent = cloud_.enrollments[uid]["envelopes"];
    ASSERT_FALSE(sent.empty());
    for (const auto& env : sent) {
        const auto bytes = vl::keykit::base64Decode(env.get<std::string>());
        ASSERT_TRUE(bytes);
        const auto unwrapped = vl::keykit::kev1::unwrap(*bytes, history_.seeds[0].x25519SecretKey().bytes(),
                                                        vl::keykit::kev1::Suite::X25519, *vl::keykit::fromBase32(uid));
        EXPECT_GE(unwrapped.key_version, 1u);
    }
    EXPECT_EQ(db::query::cloud::RecoveryVaults::get(id)->enrolled_by, "system:cloud");
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
    // A later retention change through the vault's recovery policy is sent.
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE upstream_bucket SET noncurrent_retention_days = 90 WHERE vault_id = $1", pqxx::params{id});
    });
    EXPECT_TRUE(cs::status(superUser).vaults.size() > 0);
    (void)tick();
    EXPECT_EQ(cloud_.vaults[uid].retention, 90u);
    EXPECT_EQ(DB::get(id)->retention_sent, std::optional<uint32_t>(90));
}

TEST_F(CloudStorageTest, ExistingVaultsAreOfferedAndNeverUploadedBeforeAPersonAccepts) {
    const auto e = newVault("old");
    const auto id = e->vault->id;
    write(id, "/a.txt", "existing");
    // A vault existing before storage became available: storage becomes available a second later.
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault SET created_at = created_at - interval '1 hour' WHERE id = $1", pqxx::params{id});
    });
    linkAndPin();
    for (int i = 0; i < 3; ++i) (void)tick();
    ASSERT_TRUE(DB::get(id));
    EXPECT_EQ(DB::get(id)->switch_state, "offered");
    EXPECT_EQ(state(id), "unregistered");
    EXPECT_EQ(callsTo("POST /v1/vaults"), 0u) << "an offered vault is never registered before acceptance";
    const auto s = cs::status(superUser);
    EXPECT_TRUE(s.offer_open);
    const auto ours = std::ranges::find_if(s.offered, [&](const cs::VaultEntry& v) { return v.vault_id == id; });
    ASSERT_NE(ours, s.offered.end());
    EXPECT_GT(ours->local_bytes, 0u) << "the offer lists sizes";
    EXPECT_EQ(code([&] { return cs::acceptOffer(superUser, std::nullopt, cs::Channel::Agent); }), "denied");

    const auto r = cs::acceptOffer(superUser, std::vector<unsigned int>{id}, cs::Channel::Cli);
    EXPECT_EQ(r.vaults, std::vector<unsigned int>{id});
    (void)tick();
    EXPECT_EQ(state(id), "registered");
}

// Replicated vaults (the join contract, 6 and 7): the replica set as the cloud lists it, a vault the account holder
// removed from this server stops syncing, and a leave is reported once (then the cloud no longer holds it here).
TEST_F(CloudStorageTest, TheReplicaSetIsReadARemovedVaultStopsSyncingAndALeaveIsReported) {
    const auto parsed = vh::cloud::storage::parseOverview(json{
        {"vaults", json::array({json{{"vault_uid", "0123456789abcdefghjkmnpqrs"},
                                     {"replicas", json::array({{{"deployment_id", "dep-a"}, {"name", "A"}}})},
                                     {"former_replicas", json::array({{{"deployment_id", "dep-b"}, {"name", "B"},
                                                                       {"node_id", "node-b"}, {"reason", "server"},
                                                                       {"removed_at", 1}}})},
                                     {"removed", {{"reason", "owner"}, {"at", 2}}}}})}});
    ASSERT_EQ(parsed.vaults.size(), 1u);
    EXPECT_EQ(parsed.vaults[0].replicas.size(), 1u);
    ASSERT_EQ(parsed.vaults[0].former_replicas.size(), 1u);
    EXPECT_EQ(parsed.vaults[0].former_replicas[0].node_id, std::optional<std::string>("node-b"));
    EXPECT_EQ(parsed.vaults[0].removed_reason, std::optional<std::string>("owner"));

    const auto e = newVault("replica");
    const auto id = e->vault->id;
    linkAndPin();
    const auto uid = uidOf(id);
    auto& v = cloud_.vaults[uid];
    v.registered = true;
    v.replicas = json::array({{{"deployment_id", "dep-a"}, {"name", "A"}}});
    (void)tick();
    EXPECT_TRUE(db::query::sync::Policy::getSync(id)->enabled) << "listed as held: syncs";
    EXPECT_FALSE(cs::removedAtCloud(uid));
    v.removedByOwner = true;
    EXPECT_TRUE(cs::removedAtCloud(uid)) << "asked live: vh vault leave then only changes the copy here";
    (void)tick();
    EXPECT_FALSE(db::query::sync::Policy::getSync(id)->enabled) << "removed by the account holder: stops syncing";
    cloud_.reachable = false;
    EXPECT_TRUE(cs::removedAtCloud(uid)) << "the last poll's word when the cloud can't answer";
    cloud_.reachable = true;

    // Joined again (the drill: the pass between fetches used the overview from before the join and stopped the new
    // copy): a cloud restore or join drops the cached overview, and nothing acts on the vault before a fresh one.
    const auto resume = [&] {
        ops::vaults::SyncPatch on;
        on.enabled = true;
        (void)ops::vaults::updateSync(superUser, id, on);
    };
    v.removedByOwner = false;
    resume();
    (void)cs::tick(false);
    EXPECT_FALSE(db::query::sync::Policy::getSync(id)->enabled) << "the stale overview still says removed";
    resume();
    cs::refreshSoon();
    (void)cs::tick(false);
    EXPECT_TRUE(db::query::sync::Policy::getSync(id)->enabled) << "no pass acts on the cache from before the join";
    (void)tick();
    EXPECT_TRUE(db::query::sync::Policy::getSync(id)->enabled) << "the fresh overview lists it as held";

    std::string error;
    EXPECT_TRUE(cs::reportLeft(uid, error)) << error;
    EXPECT_EQ(callsTo("DELETE /v1/vaults/" + uid + "/replica"), 1u);
    EXPECT_TRUE(cs::reportLeft(uid, error)) << "no longer held there (404): nothing to report";
}

// Contract 7 and 10 (2026-11-15): node ids in both lists; a writer removed here is reported, never removed at the cloud;
// the manifest status says what the cloud lists, so the two sides never disagree silently.
TEST_F(CloudStorageTest, AWriterRemovedHereIsReportedAndTheStatusSaysWhatTheCloudLists) {
    const auto parsed = vh::cloud::storage::parseOverview(json{
        {"vaults", json::array({json{{"vault_uid", "0123456789abcdefghjkmnpqrs"},
                                     {"replicas", json::array({{{"deployment_id", "dep-a"}, {"name", "A"}, {"node_id", "node-a"},
                                                                {"unlisted", nullptr}},
                                                               {{"deployment_id", "dep-c"}, {"name", "C"}, {"node_id", "node-c"},
                                                                {"unlisted", {{"by", {{"deployment_id", "dep-a"}, {"name", "A"}}},
                                                                              {"at", 5}}}}})},
                                     {"replica_limit", 3}}})}});
    ASSERT_EQ(parsed.vaults[0].replicas.size(), 2u);
    EXPECT_FALSE(parsed.vaults[0].replicas[0].unlisted_by.has_value());
    EXPECT_EQ(parsed.vaults[0].replicas[1].unlisted_by, std::optional<std::string>("A"));

    const auto e = newVault("replica");
    const auto id = e->vault->id;
    const auto uid = uidOf(id);
    // Unlinked: nothing is reported, and the status knows nothing of the cloud.
    EXPECT_EQ(cs::reportWriterRemoved(uid, "node-b"), "");
    const json manifest{{"writers", {"node-self", "node-b"}},
                        {"replicas", json::array({{{"node_id", "node-self"}, {"self", true}}, {{"node_id", "node-b"}, {"self", false}}})}};
    auto st = cs::describeReplicas(uid, manifest);
    EXPECT_TRUE(st["replicas"][0]["cloud"].is_null());
    EXPECT_TRUE(st["cloud_only"].empty());

    linkAndPin();
    auto& v = cloud_.vaults[uid];
    v.registered = true;
    v.replicas = json::array({{{"deployment_id", "dep-self"}, {"name", "this server"}, {"node_id", "node-self"}},
                              {{"deployment_id", "dep-b"}, {"name", "B"}, {"node_id", "node-b"}},
                              {{"deployment_id", "dep-d"}, {"name", "D"}, {"node_id", "node-d"}}});
    v.formerReplicas = json::array({{{"deployment_id", "dep-e"}, {"name", "E"}, {"node_id", "node-e"}, {"reason", "owner"}}});
    (void)tick();
    st = cs::describeReplicas(uid, json{{"writers", {"node-self", "node-b", "node-e", "node-x"}},
                                        {"replicas", json::array({{{"node_id", "node-self"}}, {{"node_id", "node-b"}},
                                                                  {{"node_id", "node-e"}}, {{"node_id", "node-x"}}})}});
    EXPECT_EQ(st["replicas"][0]["cloud"], "listed");
    EXPECT_EQ(st["replicas"][1]["cloud"], "listed");
    EXPECT_EQ(st["replicas"][2]["cloud"], "former") << "removed at the cloud: the next publish drops it";
    EXPECT_EQ(st["replicas"][3]["cloud"], "not_listed") << "a writer the cloud doesn't list";
    ASSERT_EQ(st["cloud_only"].size(), 1u) << "a server the cloud lists that the manifest doesn't name";
    EXPECT_EQ(st["cloud_only"][0]["name"], "D");
    EXPECT_TRUE(st["cloud_only"][0]["unlisted_by"].is_null());

    // B removed from the manifest here: reported; the cloud keeps listing B until the account holder removes it.
    const auto said = cs::reportWriterRemoved(uid, "node-b");
    EXPECT_NE(said.find("still lists 'B'"), std::string::npos) << said;
    EXPECT_NE(said.find("the account holder removes it"), std::string::npos) << said;
    EXPECT_EQ(callsTo("POST /v1/vaults/" + uid + "/replicas/unlisted"), 1u);
    EXPECT_FALSE(v.replicas[1]["unlisted"].is_null());
    (void)tick();
    st = cs::describeReplicas(uid, json{{"writers", {"node-self"}}, {"replicas", json::array({{{"node_id", "node-self"}}})}});
    ASSERT_EQ(st["cloud_only"].size(), 2u);
    EXPECT_EQ(st["cloud_only"][0]["unlisted_by"], "this server");
    // A node the cloud lists nowhere, and one it removed already: nothing to report.
    EXPECT_EQ(cs::reportWriterRemoved(uid, "node-x"), "Vaulthalla Cloud doesn't list it as a server of this vault");
    EXPECT_EQ(cs::reportWriterRemoved(uid, "node-e"), "Vaulthalla Cloud no longer lists it either");
    EXPECT_EQ(callsTo("POST /v1/vaults/" + uid + "/replicas/unlisted"), 1u);
}

TEST_F(CloudStorageTest, WaitingReasonsAndASwitchOffBeforeTheBucketStopsWithoutAnAttach) {
    linkAndPin();
    const auto e = newVault();
    const auto id = e->vault->id;
    write(id, "/a.txt", "x");
    for (const auto reason : {"payment_required", "over_quota", "account_key_unconfirmed", "bucket_limit"}) {
        cloud_.waitingReason = reason;
        for (auto& [uid, v] : cloud_.vaults)
            if (v.enabled) v.state = "waiting";
        for (int i = 0; i < 3; ++i) (void)tick();
        EXPECT_EQ(state(id), "waiting");
        EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>(reason));
    }
    cloud_.waitingReason.clear();
    cloud_.holdPending = true;
    cloud_.vaults[uidOf(id)].state = "pending";
    (void)tick();
    EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>("pending"));
    EXPECT_EQ(code([&] { return cs::setSwitch(superUser, id, false, std::nullopt, cs::Channel::Cli); }), "ok")
        << "no confirmation is needed before a bucket exists";
    (void)tick();
    EXPECT_EQ(state(id), "off");
    EXPECT_FALSE(cloud_.vaults[uidOf(id)].enabled) << "the cloud was told";
    EXPECT_FALSE(db::query::vault::RemoteAttach::get(id)) << "no attach without the switch";
    EXPECT_EQ(callsTo("POST /v1/storage/vaults/" + uidOf(id) + "/credentials"), 0u);
}

TEST_F(CloudStorageTest, ALostCredentialResponseIsNeverReplayedAndAFailedProbeIsNeverAcknowledged) {
    linkAndPin();
    const auto e = newVault();
    const auto id = e->vault->id;
    write(id, "/a.txt", "x");
    for (int i = 0; i < 2; ++i) (void)tick();   // registered, switched on: the bucket is ready
    cloud_.loseNextCredential = true;
    (void)tick();
    EXPECT_EQ(state(id), "waiting");
    EXPECT_TRUE(DB::get(id)->last_error.has_value());
    probeFails_ = true;
    (void)tick();
    EXPECT_EQ(state(id), "waiting") << "a key that fails the probe isn't acknowledged";
    EXPECT_EQ(cloud_.keys[*DB::get(id)->key_id].state, "issued");
    probeFails_ = false;
    (void)tick();   // the stored key passes the probe now: acknowledged, not asked for again
    EXPECT_EQ(state(id), "keyed");
    unsigned issued = 0, active = 0, revoked = 0;
    for (const auto& [kid, k] : cloud_.keys) {
        issued += k.state == "issued";
        active += k.state == "active";
        revoked += k.state == "revoked";
    }
    EXPECT_EQ(active, 1u);
    EXPECT_EQ(issued, 0u);
    EXPECT_EQ(revoked, 1u) << "the lost response's key was replaced by a new key pair's, never replayed";
    EXPECT_EQ(callsTo("POST /v1/storage/vaults/" + uidOf(id) + "/credentials"), 2u);
}

TEST_F(CloudStorageTest, TheAccessGateFollowsTheAccountAndASupersededKeyIsAskedForAgain) {
    linkAndPin();
    const auto id = activeVault();
    const auto firstKey = *DB::get(id)->key_id;
    // restricted: the cloud swaps the key to read_delete; the server asks again and the gate is read-only.
    cloud_.state = "restricted";
    cloud_.access = "read_delete";
    cloud_.cause = "restricted";
    cloud_.enforce();
    (void)tick();
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::ReadOnly);
    EXPECT_NE(*DB::get(id)->key_id, firstKey) << "the superseded key was replaced";
    EXPECT_EQ(DB::get(id)->key_access, std::optional<std::string>("read_delete"));
    EXPECT_EQ(db::query::vault::APIKey::getAPIKey(*DB::get(id)->api_key_id)->cloud_access, std::optional<std::string>("read_delete"));
    useFakeBucket(id);
    // suspended: keys revoked, no request at all.
    cloud_.state = "suspended";
    cloud_.access = "none";
    cloud_.cause = "suspended";
    cloud_.enforce();
    (void)tick();
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::None);
    EXPECT_EQ(DB::get(id)->key_state, "none");
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha") << "local copies keep working";
    // active again: a full key, the gate open.
    cloud_.state = "active";
    cloud_.access = "full";
    cloud_.cause = "active";
    // As the cloud does: a revoked key is never reinstated, so the server asks for a new one (the drill's finding:
    // the gate stayed closed after the account paid again).
    const auto requestsBefore = callsTo("POST /v1/storage/vaults/");
    for (int i = 0; i < 3 && storage::remote_access::mode(id) != storage::remote_access::Mode::Full; ++i) (void)tick();
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::Full);
    EXPECT_GT(callsTo("POST /v1/storage/vaults/"), requestsBefore) << "a new bucket key was asked for";
    EXPECT_EQ(DB::get(id)->key_state, "active");
    // An operator can't set a managed vault's access by hand.
    EXPECT_EQ(code([&] {
                  return ops::vault_remote::setAccess(superUser, {.vault_id = id, .mode = storage::remote_access::Mode::Full,
                                                                  .reason = std::nullopt});
              }),
              "managed_storage");
}

TEST_F(CloudStorageTest, UnlinkIsRefusedWhileVaultsAreManagedUnlessForced) {
    linkAndPin();
    const auto id = activeVault();
    EXPECT_EQ(code([&] { return ops::cloud::unlink(superUser, ops::cloud::Channel::Cli, false); }), "managed_vaults");
    EXPECT_TRUE(db::query::cloud::Link::get());
    EXPECT_EQ(code([&] { return ops::cloud::unlink(superUser, ops::cloud::Channel::Cli, true); }), "ok");
    EXPECT_FALSE(db::query::cloud::Link::get());
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::None);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
}

TEST_F(CloudStorageTest, EjectionTurnsTheKeyIntoTheCustomersInPlaceAndMovesNoData) {
    linkAndPin();
    const auto id = activeVault();
    const auto bucket = bucketOf(id);
    const auto objectsBefore = bucket->keys();
    bucket->clearRequests();
    cloud_.vaults[uidOf(id)].state = "ejecting";
    (void)tick();
    EXPECT_EQ(state(id), "ejected");
    const auto key = db::query::vault::APIKey::getAPIKey(*DB::get(id)->api_key_id);
    EXPECT_EQ(key->origin, "customer");
    EXPECT_TRUE(key->editable());
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::Full);
    EXPECT_TRUE(cloud_.vaults[uidOf(id)].convertedAt) << "reported /ejected";
    EXPECT_EQ(bucket->keys(), objectsBefore) << "no data moved";
    EXPECT_TRUE(bucket->requests().empty()) << "no request reached the bucket";
    EXPECT_EQ(db::query::vault::Vault::getVault(id)->type, vault::model::VaultType::S3);
    // Ordinary BYOS from here: the customer may replace the key.
    EXPECT_EQ(code([&] { return ops::api_keys::update(superUser, key->id, {.name = std::string("mine")}); }), "ok");
}

TEST_F(CloudStorageTest, AMovedVaultKeepsItsDataReadOnlyAndIsKeptLocalOnRequest) {
    linkAndPin();
    const auto id = activeVault();
    auto row = *DB::get(id);
    row.active_at = *row.active_at - 10;
    DB::update(row);
    cloud_.vaults[uidOf(id)].hidden = true;   // restored onto another server: no longer this deployment's
    (void)tick();
    EXPECT_EQ(state(id), "moved");
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::None);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
    EXPECT_TRUE(std::ranges::any_of(cs::health(), [](const cs::HealthIssue& h) { return h.code == "vault_cloud_moved"; }));
    EXPECT_EQ(code([&] { return cs::setSwitch(superUser, id, false, std::nullopt, cs::Channel::Cli); }), "invalid")
        << "keeping it local needs the vault's name";
    (void)cs::setSwitch(superUser, id, false, db::query::vault::Vault::getVault(id)->name, cs::Channel::Cli);
    (void)tick();
    EXPECT_EQ(state(id), "detaching");
    ASSERT_EQ(db::query::vault::RemoteDetach::get(id)->mode, rd::Mode::InPlace);
    EXPECT_EQ(runDetach(id).state, rd::State::Done);
    (void)tick();
    EXPECT_EQ(state(id), "off");
    EXPECT_EQ(db::query::vault::Vault::getVault(id)->type, vault::model::VaultType::Local);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
}

TEST_F(CloudStorageTest, AVaultTheCloudListsAsMovedStopsAtOnceAndNamesWhereItWent) {
    linkAndPin();
    const auto id = activeVault();
    cloud_.vaults[uidOf(id)].movedTo = "nas2";   // still listed to this deployment, with where it went
    (void)tick();
    EXPECT_EQ(state(id), "moved");
    EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>("restored on nas2"));
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::None);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
    // The portal page for leaving managed storage is the cloud's address; one that isn't https is refused.
    EXPECT_EQ(cs::status(superUser).ejection.value("portal_url", ""), "https://app.vaulthalla.test/storage/leave");
}

TEST(CloudStorageContract, TheOverviewReadsTheCloudsNamesAndRefusesAnUnsafePortalAddress) {
    const auto base = nlohmann::json{{"entitlement", {{"storage_access", "none"}}}, {"vaults", nlohmann::json::array()}};
    auto body = base;
    body["account_key_confirmed"] = true;   // the old name means nothing now
    EXPECT_FALSE(::vh::cloud::storage::parseOverview(body).offline_copy_confirmed);
    body["account_key_offline_copy_confirmed"] = true;
    EXPECT_TRUE(::vh::cloud::storage::parseOverview(body).offline_copy_confirmed);
    for (const auto* url : {"http://localhost.evil.test/x", "http://portal.test/storage/leave", "javascript:alert(1)"}) {
        body["ejection_portal_url"] = url;
        EXPECT_THROW((void)::vh::cloud::storage::parseOverview(body), std::runtime_error) << url;
    }
    body["ejection_portal_url"] = "http://localhost:3000/storage/leave";
    EXPECT_EQ(::vh::cloud::storage::parseOverview(body).ejection_portal, std::optional<std::string>("http://localhost:3000/storage/leave"));
    body["ejection_portal_url"] = nullptr;
    EXPECT_FALSE(::vh::cloud::storage::parseOverview(body).ejection_portal);
    body["vaults"] = nlohmann::json::array({{{"vault_uid", "x"}, {"moved_to", "somewhere"}}});
    EXPECT_THROW((void)::vh::cloud::storage::parseOverview(body), std::runtime_error) << "moved_to is an object";
    body["vaults"] = nlohmann::json::array({{{"vault_uid", "x"}, {"moved_to", {{"deployment_id", "d1"}, {"name", "nas2"}}}}});
    EXPECT_EQ(::vh::cloud::storage::parseOverview(body).vaults.at(0).moved_to, std::optional<std::string>("nas2"));
}

TEST_F(CloudStorageTest, TheEndOfThePlanConvertsToLocalInPlaceAndListsWhatWasLostWithoutDeletingAnything) {
    linkAndPin();
    const auto id = activeVault();
    // One file is held only in the bucket (smart cache released its local copy).
    const auto f = db::query::fs::File::getFileByPath(id, "/b.txt");
    const auto engine = engineOf(id);
    const auto backing = f->backing_path.is_absolute() ? f->backing_path
                                                       : engine->paths->absPath(f->backing_path, fs::model::PathType::BACKING_ROOT);
    ASSERT_TRUE(std::filesystem::remove(backing));
    const auto bucket = bucketOf(id);
    const auto objectsBefore = bucket->keys();
    cloud_.state = "ended";
    cloud_.access = "none";
    cloud_.cause = "ended";
    cloud_.enforce();
    (void)tick();
    EXPECT_EQ(state(id), "active") << "one report converts nothing";
    (void)cs::confirmEnded(superUser, cs::Channel::Cli);
    (void)tick();
    EXPECT_EQ(state(id), "detaching");
    bucket->clearRequests();
    const auto detached = runDetach(id);
    EXPECT_EQ(detached.state, rd::State::Done) << detached.error.value_or("");
    EXPECT_TRUE(bucket->requests().empty()) << "in place: no request to the bucket";
    (void)tick();
    EXPECT_EQ(state(id), "ended");
    EXPECT_EQ(db::query::vault::Vault::getVault(id)->type, vault::model::VaultType::Local);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha") << "what was held here stays";
    const auto lost = db::query::vault::RemoteDetach::get(id)->lost;
    ASSERT_TRUE(lost);
    ASSERT_EQ((*lost)["files"].size(), 1u);
    EXPECT_EQ((*lost)["files"][0]["path"], "/b.txt");
    EXPECT_EQ(bucket->keys(), objectsBefore) << "nothing in the bucket was deleted";
    // Recovery: the account key's envelopes are held in the database now, for every version.
    for (const auto& e : db::query::vault::RemoteAttach::envelopes(id)) EXPECT_FALSE(e.bytes.empty()) << e.kid;
    EXPECT_FALSE(db::query::vault::RecoveryGrants::usable(id).empty()) << "no grant was dropped";
}

TEST_F(CloudStorageTest, SurfacesAuthorizeAndAgentsOnlyRead) {
    linkAndPin();
    const auto e = newVault();
    const auto id = e->vault->id;
    (void)tick();
    EXPECT_EQ(code([&] { return cs::setSwitch(superUser, id, false, std::nullopt, cs::Channel::Agent); }), "denied");
    EXPECT_EQ(code([&] { return cs::setNewVaultsDefault(superUser, false, cs::Channel::Agent); }), "denied");
    EXPECT_EQ(code([&] { return cs::billingHandoff(superUser, "portal", std::nullopt, cs::Channel::Agent); }), "denied");
    EXPECT_EQ(code([&] { return cs::status(superUser); }), "ok");
    EXPECT_FALSE(cs::setNewVaultsDefault(superUser, false, cs::Channel::Cli));
    const auto h = cs::billingHandoff(superUser, "portal", std::nullopt, cs::Channel::Cli);
    EXPECT_TRUE(h.url.starts_with("https://"));
    const auto j = cs::toJson(cs::status(superUser));
    EXPECT_TRUE(j.at("available").get<bool>());
    EXPECT_FALSE(j.at("new_vaults").get<bool>());
}

TEST_F(CloudStorageTest, AnEndedPlanWaitsForAConfirmationOrTheGracePeriodAndASingleReportChangesNothing) {
    linkAndPin();
    const auto id = activeVault();
    EXPECT_EQ(code([&] { return cs::confirmEnded(superUser, cs::Channel::Cli); }), "conflict") << "nothing to confirm";
    cloud_.state = "ended";
    cloud_.access = "none";
    cloud_.cause = "ended";
    cloud_.enforce();
    (void)tick();
    EXPECT_EQ(state(id), "active");
    EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>("ended_pending_confirmation"));
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::None) << "attached, without access";
    EXPECT_FALSE(db::query::vault::RemoteDetach::get(id));
    EXPECT_TRUE(cs::status(superUser).ended.has_value());
    EXPECT_TRUE(std::ranges::any_of(cs::health(), [](const cs::HealthIssue& h) { return h.code == "cloud_storage_ended_pending"; }));
    // A wrong report: the next answer is active again, and the run of `ended` starts over.
    cloud_.state = "active";
    cloud_.access = "full";
    cloud_.cause = "active";
    for (auto& [kid, k] : cloud_.keys) k.state = "revoked";
    cloud_.keys["Kback000000"] = {.uid = uidOf(id), .state = "active", .access = "full", .secret = "s"};
    (void)tick();
    EXPECT_FALSE(DB::account()->ended_seen_at);
    EXPECT_FALSE(cs::status(superUser).ended.has_value());
    cloud_.state = "ended";
    cloud_.access = "none";
    cloud_.enforce();
    (void)tick();
    EXPECT_EQ(state(id), "active");
    // The grace period passes without interruption: the conversion starts without a person.
    db::Transactions::exec("t", [&](pqxx::work& txn) {
        txn.exec("UPDATE cloud_storage_account SET ended_seen_at = now() - interval '25 hours'");
    });
    (void)tick();
    EXPECT_EQ(state(id), "detaching");
    EXPECT_EQ(db::query::vault::RemoteDetach::get(id)->mode, rd::Mode::InPlace);
}

TEST_F(CloudStorageTest, SwitchingOnAgainRecognisesTheVaultsOwnBucketAndRefusesWithoutDeletingAnything) {
    linkAndPin();
    const auto id = activeVault();
    const auto bucket = bucketOf(id);
    const auto bucketName = *DB::get(id)->bucket;
    (void)cs::setSwitch(superUser, id, false, db::query::vault::Vault::getVault(id)->name, cs::Channel::Cli);
    (void)tick();
    ASSERT_EQ(state(id), "detaching");
    ASSERT_EQ(runDetach(id).state, rd::State::Done);
    (void)tick();
    ASSERT_EQ(state(id), "off");
    EXPECT_TRUE(cloud_.vaults[uidOf(id)].detachedAt) << "reported /detached";
    const auto objects = bucket->keys();
    ASSERT_FALSE(objects.empty());

    (void)cs::setSwitch(superUser, id, true, std::nullopt, cs::Channel::Cli);
    for (int i = 0; i < 6; ++i) (void)tick();
    EXPECT_EQ(state(id), "keyed");
    EXPECT_EQ(DB::get(id)->reason, std::optional<std::string>("bucket_holds_this_vault"));
    EXPECT_FALSE(db::query::vault::RemoteAttach::get(id)) << "no attach over its earlier copy";
    EXPECT_EQ(bucket->keys(), objects) << "nothing in the bucket was deleted";
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");

    // Another vault offered the same bucket isn't told it is its own: an ordinary non-empty bucket.
    const auto other = newVault("other");
    write(other->vault->id, "/x.txt", "x");
    auto key = std::make_shared<vault::model::APIKey>(superUser->id, "cs_other_" + vh::test::uniqueTag('k'),
                                                      vault::model::S3Provider::Other, "AKIATESTACCESSKEY000",
                                                      "secret-value-0000000000000000000000000", "auto",
                                                      "https://s3.fake.test");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
    try {
        (void)ra::requireBucketUsable(other->vault->id, keyId, bucketName, *bucket, std::nullopt);
        ADD_FAILURE() << "a non-empty bucket was accepted";
    } catch (const ra::Refusal& e) {
        EXPECT_EQ(e.code(), "bucket_not_empty");
    }
    EXPECT_EQ(bucket->keys(), objects);
}

TEST_F(CloudStorageTest, TheRootCarriesTheAccountPolicyAndARestoreOffersIt) {
    linkAndPin();
    const auto id = activeVault();
    auto answer = history_.answer();
    answer["policy"] = history_.policy(1);
    cloud_.keyAnswer = answer;
    ASSERT_EQ(ops::cloud_keys::check("test").state, "pinned");
    // The manifest root names the policy's exact bytes for a vault the account key covers.
    const auto content = db::query::sync::Manifest::collect(id);
    ASSERT_TRUE(content.recovery_policy);
    ASSERT_TRUE(content.recovery_policy->account_policy);
    EXPECT_EQ(content.recovery_policy->account_policy->policy, answer["policy"]["policy"].get<std::string>());
    EXPECT_EQ(content.recovery_policy->account_policy->signature, answer["policy"]["signature"].get<std::string>());
    // A newer policy from a root is verified against this server's pin and accepted; the same or an older one isn't.
    const auto newer = history_.policy(2);
    EXPECT_TRUE(ops::cloud_keys::offerPolicy(newer["policy"], newer["signature"], "test root"));
    EXPECT_EQ(ops::cloud_keys::status(superUser).policy->sequence, 2u);
    EXPECT_FALSE(ops::cloud_keys::offerPolicy(newer["policy"], newer["signature"], "test root"));
    EXPECT_FALSE(ops::cloud_keys::offerPolicy(answer["policy"]["policy"], answer["policy"]["signature"], "test root"))
        << "a rollback is refused";
    // A forgery (another key's signature) is refused.
    const auto forged = vl::keykit::base64UrlEncode(std::vector<uint8_t>(64, 7));
    EXPECT_FALSE(ops::cloud_keys::offerPolicy(history_.policy(3)["policy"], forged, "test root"));
    EXPECT_EQ(ops::cloud_keys::status(superUser).policy->sequence, 2u);
}

TEST_F(CloudStorageTest, VerifyComparesTheCloudsAccountKeyEnvelopesWithThisServersRecords) {
    linkAndPin();
    const auto id = activeVault();
    (void)tick();   // enrolled
    ASSERT_TRUE(cloud_.enrollments.contains(uidOf(id)));
    const auto ok = ops::cloud_recovery::status(superUser, id, true);
    ASSERT_EQ(ok.size(), 1u);
    EXPECT_EQ(ok[0].state, "ready") << ok[0].verify.dump();
    EXPECT_TRUE(ok[0].automatic);
    EXPECT_TRUE(ok[0].verify["missing"].empty());
    EXPECT_GE(ok[0].verify["versions_checked"].get<int>(), 1);
    cloud_.dropEnvelopeVersion = 1;
    const auto behind = ops::cloud_recovery::status(superUser, id, true);
    EXPECT_EQ(behind[0].state, "behind");
    EXPECT_FALSE(behind[0].verify["missing"].empty());
    // Without --verify only the coverage report is compared.
    EXPECT_EQ(ops::cloud_recovery::status(superUser, id, false)[0].verify, nullptr);
}


TEST_F(CloudStorageTest, AManagedVaultRestoredHereGetsAKeyOfItsOwnAndIsAdoptedOnlyAfterTheRestore) {
    linkAndPin();
    const auto id = activeVault();
    const auto uid = uidOf(id);
    // As after a restore onto this server: the vault is here, without a managed-storage row yet.
    DB::remove(id);
    EXPECT_EQ(code([&] { return cs::keyForRestore(superUser, uid, superUser->id, cs::Channel::Agent); }), "denied");
    const auto key = cs::keyForRestore(superUser, uid, superUser->id, cs::Channel::Cli);
    EXPECT_EQ(cloud_.keys.at(key.key_id).state, "issued") << "never acknowledged before the restore wrote the vault";
    const auto stored = db::query::vault::APIKey::getAPIKey(key.api_key_id);
    ASSERT_TRUE(stored);
    EXPECT_TRUE(stored->cloudIssued());
    EXPECT_EQ(stored->name, "managed storage " + uid);

    // A restore that stops: the key goes (the cloud revokes the unacknowledged one).
    const auto dropped = cs::keyForRestore(superUser, uid, superUser->id, cs::Channel::Cli);
    cs::discardRestoreKey(dropped);
    EXPECT_FALSE(db::query::vault::APIKey::getAPIKey(dropped.api_key_id));
    EXPECT_EQ(cloud_.keys.at(key.key_id).state, "revoked") << "a new request revoked the earlier unacknowledged key";

    const auto again = cs::keyForRestore(superUser, uid, superUser->id, cs::Channel::Cli);
    cs::adoptRestored(again, id);
    const auto row = DB::get(id);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->state, "active");
    EXPECT_EQ(row->switch_state, "on");
    EXPECT_EQ(row->key_state, "active");
    EXPECT_EQ(row->api_key_id, std::optional<uint32_t>(again.api_key_id));
    EXPECT_EQ(cloud_.keys.at(again.key_id).state, "active") << "acknowledged once adopted";
    EXPECT_EQ(storage::remote_access::mode(id), storage::remote_access::Mode::Full);
    DB::remove(id);   // later tests in the suite share the fake cloud buckets and API key manager
}

TEST_F(CloudStorageTest, NoRestoreKeyWithoutAConfirmedAccountKey) {
    link();
    EXPECT_EQ(code([&] { return cs::keyForRestore(superUser, vl::keykit::toBase32(vl::keykit::newUid()), superUser->id,
                                                  cs::Channel::Cli); }),
              "managed_storage_unavailable");
}


TEST_F(CloudStorageTest, ABucketTheCloudIsDeletingWhileThePlanIsActiveMakesTheVaultLocalInPlace) {
    linkAndPin();
    const auto id = activeVault();
    const auto bucket = bucketOf(id);
    const auto objectsBefore = bucket->keys();
    // Paid again after `ended`: the plan is active, but the end began deleting the vault's bucket.
    cloud_.vaults[uidOf(id)].state = "emptying";
    (void)tick();
    EXPECT_EQ(state(id), "detaching");
    ASSERT_EQ(db::query::vault::RemoteDetach::get(id)->mode, rd::Mode::InPlace);
    EXPECT_EQ(runDetach(id).state, rd::State::Done);
    (void)tick();
    EXPECT_EQ(state(id), "ended");
    EXPECT_EQ(db::query::vault::Vault::getVault(id)->type, vault::model::VaultType::Local);
    EXPECT_EQ(readLocal(id, "/a.txt"), "alpha");
    EXPECT_EQ(bucket->keys(), objectsBefore) << "in place: nothing in the bucket is touched";
}

}
