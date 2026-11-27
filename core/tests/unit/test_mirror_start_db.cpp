// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Starting a mirror (server mirror phase 2 wave 3, piece A; design/peers/mirror.md "Starting a mirror", "As built:
// starting a mirror"; migration 163). One database holds one server, so each side runs against a scripted other
// server (mirror::start::setTransportForTesting): the core's side with a fake mirror that answers what it is told to,
// the mirror's side with a fake core whose attestation key the test holds (a seed of its own, pinned on the peer row as
// pairing would). The two-daemon proof of the whole start is `vhh drill peers` step 7.
//
// Covered: every precondition's refusal; the offer table's lifetime (expiry, sweep); the mirror's checks (uid, name,
// space, history); the key proof (a wrong attestation, a wrong key check, an envelope for another recipient, no
// current version: nothing written); the vault the mirror creates (uid, root uid, remote owner, keys sealed here with
// their origin, no access until the grant); crash points of the start on both sides (each resumed or cleaned up by
// cancel); the grant following every change (link default, per-vault role, the role edited, deleted, link-up);
// cancel at each step on both sides; rotation refused on mirrored vaults; the background contents worker.

#include "../helpers/db_suite.hpp"
#include "audit/Trail.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/Router.hpp"
#include "auth/stepup/StepUp.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "crypto/SecretKey.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/mirror/Start.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "mirror/Contents.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/start/BackgroundContents.hpp"
#include "mirror/start/Start.hpp"
#include "ops/Error.hpp"
#include "ops/Mirrors.hpp"
#include "ops/PeerPolicy.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "peer/Keys.hpp"
#include "mirror/access/Access.hpp"
#include "rbac/Mirrored.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Local.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/uid.hpp>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_mirror_start_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Action = rbac::permission::vault::FilesystemAction;
namespace start = vh::mirror::start;
namespace mq = db::query::mirror;
using mq::MirrorStart;
using mq::MirrorVaults;
using namespace std::chrono_literals;

std::string tag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "s" +
           std::to_string(n.fetch_add(1));
}

std::string b64(const std::span<const uint8_t> bytes) {
    std::string out(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

std::vector<uint8_t> unb64(const std::string& s) {
    std::vector<uint8_t> out(s.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0)
        throw std::runtime_error("bad base64");
    out.resize(len);
    return out;
}

// The other server, as this one sees it over its link.
struct Wire {
    std::mutex mutex;
    std::vector<std::pair<std::string, json>> sent;
    std::function<std::optional<json>(const std::string&, const json&)> answer;
    std::optional<std::time_t> up{1000};

    // What was sent with `command`, optionally only for one offer (offer_uid) or one vault (vault_uid): the database
    // holds the other tests' starts too, and every pass looks at all of them.
    std::vector<json> of(const std::string& command, const std::string& about = {}) {
        std::scoped_lock lock(mutex);
        std::vector<json> out;
        for (const auto& [c, p] : sent)
            if (c == command && (about.empty() || p.value("offer_uid", "") == about || p.value("vault_uid", "") == about))
                out.push_back(p);
        return out;
    }
    void clear() {
        std::scoped_lock lock(mutex);
        sent.clear();
    }
};

struct Tamper {
    bool wrongSeed{false};
    bool wrongCheck{false};
    bool otherRecipient{false};
    bool noCurrent{false};
};

json okAnswer(json data = json::object()) { return {{"status", "OK"}, {"data", std::move(data)}}; }
json refusal(const std::string& code, const std::string& text) {
    return {{"status", "ERROR"}, {"data", {{"code", code}}}, {"error", text}};
}

class MirrorStartDbTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<Wire> wire;
    // The fake mirror's wrap key (the core wraps to it).
    inline static std::array<uint8_t, 32> mirrorWrapSecret{};
    inline static vh::peer::Key32 mirrorWrapPublic{};
    // The fake core's attestation seed (pinned on the peer row, as pairing pins the card's keys).
    inline static std::array<uint8_t, 32> coreSeed{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mirror_start")) return;
        randombytes_buf(mirrorWrapSecret.data(), mirrorWrapSecret.size());
        crypto_scalarmult_base(mirrorWrapPublic.data(), mirrorWrapSecret.data());
        randombytes_buf(coreSeed.data(), coreSeed.size());
        // This server's wrap key, made before any linked server pins it (as the first pairing does).
        (void)vh::peer::keys::wrapPublicKey();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        start::setTransportForTesting({});
        mirror::contents::setSourceFactoryForTesting({});
        rbac::mirrored::resetForTesting();
        vh::mirror::access::resetForTesting();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        wire = std::make_shared<Wire>();
        const auto w = wire;
        start::setTransportForTesting(
            {.request = [w](uint32_t, const std::string& command, const json& payload,
                            std::chrono::milliseconds) -> std::optional<json> {
                 std::function<std::optional<json>(const std::string&, const json&)> answer;
                 std::optional<std::time_t> up;
                 {
                     std::scoped_lock lock(w->mutex);
                     w->sent.emplace_back(command, payload);
                     answer = w->answer;
                     up = w->up;
                 }
                 if (!up) return std::nullopt;
                 return answer ? answer(command, payload) : std::optional<json>(okAnswer());
             },
             .upSince = [w](uint32_t) {
                 std::scoped_lock lock(w->mutex);
                 return w->up;
             }});
        start::Service::instance()->resetForTesting();
    }

    void TearDown() override {
        start::setTransportForTesting({});
        mirror::contents::setSourceFactoryForTesting({});
    }

    static vh::peer::Key32 coreAttestPublic() {
        const auto pub = vh::vault::attestation::publicKeyFromSeed(coreSeed);
        vh::peer::Key32 k{};
        std::ranges::copy(pub, k.begin());
        return k;
    }

    // A linked server as the core sees its mirror (wrap key: the test's), or as a mirror sees its core (attestation
    // key: the test's seed; wrap key: this server's own, which the envelopes are for).
    static vh::peer::Record newPeer(const bool asCore) {
        const auto t = tag();
        db::query::peer::NewPeer p;
        p.node_id = (asCore ? "core-" : "mirror-") + t;
        p.name = (asCore ? "core-" : "mirror-") + t;
        p.spki_sha256 = std::string(48, asCore ? 'c' : 'd') + std::string(16 - std::min<std::size_t>(16, t.size()), '0') +
                        t.substr(0, std::min<std::size_t>(16, t.size()));
        for (auto& ch : p.spki_sha256)
            if (!std::isxdigit(static_cast<unsigned char>(ch))) ch = 'e';
        if (asCore) {
            p.attest_public_keys = {coreAttestPublic()};
            p.wrap_public_key = vh::peer::keys::wrapPublicKey();
        } else {
            vh::peer::Key32 any{};
            any.fill(0x42);
            p.attest_public_keys = {any};
            p.wrap_public_key = mirrorWrapPublic;
        }
        return db::query::peer::Peers::insert(p);
    }

    // A local vault with /doc.txt and /dir.
    static uint32_t coreVault(const std::string& prefix = "ms") {
        const auto id = ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::Local,
                                                        .owner_id = superUser->id})
                            ->id;
        const auto engine = runtime::Deps::get().storageManager->getEngine(id);
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = superUser});
        const std::string text = "mirror start";
        (void)fs::Filesystem::createFile({.path = "/doc.txt", .fuse_path = engine->vaultPathToFusePath("/doc.txt"),
                                          .buffer = std::vector<uint8_t>(text.begin(), text.end()), .engine = engine,
                                          .user = superUser, .overwrite = true});
        return id;
    }

    static void sql(const std::string& statement) {
        db::Transactions::exec("mirror start test", [&](pqxx::work& txn) { txn.exec(statement); });
    }

    static std::string scalar(const std::string& query) {
        return db::Transactions::exec("mirror start test", [&](pqxx::work& txn) {
            const auto r = txn.exec(query);
            return r.empty() || r[0][0].is_null() ? std::string() : r[0][0].as<std::string>();
        });
    }

    static std::string refusalCode(const std::function<void()>& f) {
        try {
            f();
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::NotFound&) {
            return "not_found";
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::Conflict&) {
            return "conflict";
        } catch (const ops::Invalid&) {
            return "invalid";
        }
        return "";
    }

    static void tickUntilQuiet() {
        for (int i = 0; i < 6; ++i) start::Service::instance()->tick();
    }

    // ---- the mirror's side: what a core would send

    struct FakeVersion {
        uint32_t version{};
        bool current{false};
        std::shared_ptr<const crypto::SecretKey> key;
    };

    // Each offer's owner is another account of the core (the remote account here goes with its last vault).
    static uint32_t nextOwner() {
        static std::atomic<uint32_t> n{100};
        return n.fetch_add(1);
    }

    static json offerJson(const std::string& offerUid, const vl::keykit::Uid& vaultUid, const vl::keykit::Uid& rootUid,
                          const std::string& name, const uint64_t size = 1000, const uint64_t coreVaultId = 77) {
        return {{"offer_uid", offerUid}, {"vault_uid", vl::keykit::toBase32(vaultUid)}, {"core_vault_id", coreVaultId},
                {"root_uid", vl::keykit::toBase32(rootUid)}, {"term", 1}, {"name", name}, {"description", "from the core"},
                {"quota", 0}, {"size_bytes", size}, {"file_count", 3}, {"history", false},
                {"owner", {{"node", "core-owner-node"}, {"id", nextOwner()}, {"name", "alice"}}},
                {"role", {{"role_name", "reader"}, {"files", 1}, {"directories", 1}, {"sync", 0}, {"roles", 0}}},
                {"expires_at", 0}};
    }

    static json keysJson(const std::string& offerUid, const vh::peer::Record& core, const vl::keykit::Uid& vaultUid,
                         const std::vector<FakeVersion>& versions, const Tamper tamper = {}, const uint64_t coreVaultId = 77) {
        json list = json::array();
        std::array<uint8_t, 32> otherSeed{};
        randombytes_buf(otherSeed.data(), otherSeed.size());
        std::array<uint8_t, 32> otherWrap{};
        crypto_scalarmult_base(otherWrap.data(), otherSeed.data());
        const auto ownWrap = vh::peer::keys::wrapPublicKey();
        for (const auto& v : versions) {
            const auto recipient = tamper.otherRecipient ? std::span<const uint8_t>(otherWrap)
                                                         : std::span<const uint8_t>(ownWrap);
            const auto envelope = vl::keykit::kev1::wrap(v.key->bytes(), vl::keykit::kev1::Suite::X25519, v.version,
                                                         vaultUid, recipient);
            auto check = vh::vault::keyCheck(v.key->bytes(), static_cast<unsigned>(coreVaultId), v.version);
            const auto message = vh::vault::attestation::message(core.node_id, coreVaultId, v.version, check);
            const auto signature =
                vh::vault::attestation::signWithSeed(tamper.wrongSeed ? std::span<const uint8_t>(otherSeed)
                                                                      : std::span<const uint8_t>(coreSeed),
                                                     message);
            if (tamper.wrongCheck) check = std::string(32, '0');
            list.push_back({{"version", v.version}, {"current", v.current && !tamper.noCurrent},
                            {"envelope", b64(envelope)}, {"key_check", check},
                            {"attestation", {{"key_id", 3}, {"signature", b64(signature)}}}});
        }
        return {{"offer_uid", offerUid}, {"vault_uid", vl::keykit::toBase32(vaultUid)}, {"core_vault_id", coreVaultId},
                {"versions", list}};
    }

    static std::vector<FakeVersion> twoVersions() {
        return {{.version = 1, .current = false, .key = crypto::SecretKey::random()},
                {.version = 2, .current = true, .key = crypto::SecretKey::random()}};
    }

    struct Offered {
        vh::peer::Record core;
        std::string offerUid;
        vl::keykit::Uid vaultUid{}, rootUid{};
        std::string name;
        mq::Offer offer;
    };

    // A fake core offers a vault to this server, which a super admin accepts.
    static Offered offeredAndAccepted(const bool acceptIt = true) {
        Offered o;
        o.core = newPeer(true);
        o.offerUid = crypto::id::toUuid(crypto::id::newObjectUid());
        o.vaultUid = crypto::id::newObjectUid();
        o.rootUid = crypto::id::newObjectUid();
        o.name = "mirrored_" + tag();
        const auto answer = start::offerReceived(o.core, offerJson(o.offerUid, o.vaultUid, o.rootUid, o.name));
        EXPECT_EQ(answer.value("state", ""), "pending");
        o.offer = *MirrorStart::offerByUid(o.offerUid, "mirror");
        if (acceptIt) o.offer = ops::mirrors::accept(superUser, std::to_string(o.offer.id));
        return o;
    }

    // A copy this server holds, its start complete (keys installed, the begin with a reader grant). `finished`: its
    // first copy complete, as piece B's follower records it (mirror_vault.copy_finished, set by the applier once the
    // last baseline page matched the core's digest; MirrorFollowDbTest drives that path, `vhh drill peers` end to end).
    static std::pair<Offered, uint32_t> startedCopy(const bool finished = true) {
        auto o = offeredAndAccepted();
        (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, twoVersions()));
        (void)start::beginReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                            {"term", 1},
                                            {"grant", {{"role_name", "reader"}, {"files", 0xffffffffu},
                                                       {"directories", 0xffffffffu}, {"sync", 0}, {"roles", 0}}}});
        const auto vaultId = *MirrorStart::vaultWithUid(o.vaultUid);
        if (finished) sql("UPDATE mirror_vault SET copy_finished = TRUE WHERE vault_id = " + std::to_string(vaultId));
        return {o, vaultId};
    }

    static json coreEnds(const Offered& o, const std::optional<bool> removeCopy) {
        json p{{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)}, {"reason", "cancelled_by_core"}};
        if (removeCopy) p["remove_copy"] = *removeCopy;
        return start::cancelReceived(o.core, p);
    }

    static bool superAdminMay(const uint32_t vaultId, const Action action, const std::string& path = "/") {
        const rbac::resolver::vault::QuietFilesystemDenials quiet;
        const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        if (!engine) return false;
        return rbac::resolver::Vault::has<Action>(
            {.user = superUser, .permission = action, .vault_id = vaultId, .path = engine->vaultPathToFusePath(path)});
    }
};

// ============================================================================================ the core's preconditions

TEST_F(MirrorStartDbTest, EveryPreconditionRefusesWithItsOwnCode) {
    const auto peer = newPeer(false);
    const auto check = [](const uint32_t v) { return refusalCode([&] { (void)start::checkVault(v); }); };

    EXPECT_EQ(check(coreVault()), "") << "a plain local vault can be mirrored";
    EXPECT_EQ(check(999999), "not_found");

    {   // pending deletion
        const auto v = coreVault();
        sql("UPDATE vault SET deleted_at = now() WHERE id = " + std::to_string(v));
        EXPECT_EQ(check(v), "vault_pending_deletion");
        sql("UPDATE vault SET deleted_at = NULL WHERE id = " + std::to_string(v));
    }
    {   // mirrored already, either role
        const auto v = coreVault();
        (void)MirrorVaults::startCore(v, peer.id);
        EXPECT_EQ(check(v), "mirror_already");
        (void)MirrorVaults::remove(v);
        (void)MirrorVaults::startMirror(v, peer.id);
        EXPECT_EQ(check(v), "mirror_already") << "a vault held here as another server's copy";
        (void)MirrorVaults::remove(v);
    }
    {   // a start running
        const auto v = coreVault();
        (void)start::offerVault(v, peer, superUser->id, superUser->name());
        EXPECT_EQ(check(v), "mirror_start_running");
        EXPECT_TRUE(start::cancelOnCore(v, "test", false, false, superUser->id, superUser->name()));
    }
    {   // bucket-replicated
        const auto v = coreVault();
        sql("INSERT INTO remote_manifest_state (vault_id, manifest_key, writers) VALUES (" + std::to_string(v) +
            ", '.vaulthalla/root', ARRAY['another-node'])");
        EXPECT_EQ(check(v), "vault_replicated");
    }
    {   // a key rotation in progress
        const auto v = coreVault();
        runtime::Deps::get().storageManager->getEngine(v)->encryptionManager->prepare_key_rotation();
        EXPECT_EQ(check(v), "key_rotation_running");
    }
    {   // legacy content: gcm0, and plaintext with bytes
        const auto v = coreVault();
        sql("UPDATE files SET encryption_iv = 'AAAAAAAAAAAAAAAA' FROM fs_entry e WHERE e.id = files.fs_entry_id AND "
            "e.vault_id = " + std::to_string(v));
        EXPECT_EQ(check(v), "legacy_content");
        sql("UPDATE files SET encryption_iv = '' FROM fs_entry e WHERE e.id = files.fs_entry_id AND e.vault_id = " +
            std::to_string(v));
        EXPECT_EQ(check(v), "legacy_content") << "a plaintext file with bytes";
    }
    {   // a trashed file without an object uid (the log can't carry it)
        const auto v = coreVault();
        sql("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias, size_bytes) VALUES (" +
            std::to_string(v) + ", '/old.txt', '/nowhere', '" + std::string(33, 'a') + "', 3)");
        EXPECT_EQ(check(v), "trashed_without_uid");
    }
    {   // a key version not attested by this server
        const auto v = coreVault();
        sql("UPDATE vault_keys SET attestation = NULL WHERE vault_id = " + std::to_string(v));
        EXPECT_EQ(check(v), "key_version_unattested");
    }
    {   // a file whose bytes are not on this server's disk
        const auto v = coreVault();
        const auto file = db::query::fs::File::getFileByPath(v, "/doc.txt");
        std::filesystem::remove(file->backing_path);
        EXPECT_EQ(check(v), "contents_not_held");
    }

    // The linked server: live, and its link up.
    EXPECT_EQ(refusalCode([&] { start::checkLink(peer); }), "");
    wire->up.reset();
    EXPECT_EQ(refusalCode([&] { start::checkLink(peer); }), "peer_link_down");
    wire->up = 1000;
    const auto revoked = *db::query::peer::Peers::revoke(newPeer(false).id);
    EXPECT_EQ(refusalCode([&] { start::checkLink(revoked); }), "peer_not_linked");
}

TEST_F(MirrorStartDbTest, OnlyAPersonWhoMayManageTheVaultStartsAMirrorAndOnlyWithTheSwitchOn) {
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "ms_plain_" + tag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Start-Pass-123")})
            .user->id);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::add(plain, {.vault_id = v, .peer = std::to_string(peer.id)}); }),
              "denied");
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::pending(plain); }), "denied") << "the mirror's side: super admins";
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    EXPECT_EQ(offer.state, "offered");
    EXPECT_TRUE(offer.notify);
    EXPECT_EQ(offer.core_vault_id, v);
    EXPECT_FALSE(offer.history);
}

// ====================================================================================== the core's side of the start

TEST_F(MirrorStartDbTest, TheCoreOffersDeliversProvableKeysToTheMirrorsWrapKeyAndBeginsOnlyAfterTheAcknowledgement) {
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    start::Service::instance()->tick();
    const auto offers = wire->of("peer.mirror.offer", offer.offer_uid);
    ASSERT_EQ(offers.size(), 1u);
    EXPECT_EQ(offers[0].value("offer_uid", ""), offer.offer_uid);
    EXPECT_EQ(offers[0].value("history", true), false);
    EXPECT_EQ(offers[0]["owner"].value("id", 0u), superUser->id);
    EXPECT_FALSE(MirrorStart::offer(offer.id)->notify) << "told";
    start::Service::instance()->tick();
    EXPECT_EQ(wire->of("peer.mirror.offer", offer.offer_uid).size(), 1u) << "told once";
    EXPECT_FALSE(MirrorVaults::get(v)) << "no core row before the mirror holds its keys";

    // The mirror accepts.
    (void)start::answerReceived(peer, {{"offer_uid", offer.offer_uid}, {"decision", "accepted"}});
    EXPECT_EQ(MirrorStart::offer(offer.id)->state, "accepted");
    start::Service::instance()->tick();
    const auto keys = wire->of("peer.mirror.keys", offer.offer_uid);
    ASSERT_EQ(keys.size(), 1u);
    const auto engine = runtime::Deps::get().storageManager->getEngine(v);
    const auto current = engine->encryptionManager->get_key_version();
    bool sawCurrent = false;
    for (const auto& item : keys[0]["versions"]) {
        const auto version = item.at("version").get<uint32_t>();
        const auto opened = vl::keykit::kev1::unwrap(unb64(item.at("envelope").get<std::string>()), mirrorWrapSecret,
                                                     vl::keykit::kev1::Suite::X25519, *engine->vault->uid);
        EXPECT_EQ(opened.key_version, version);
        const auto key = engine->encryptionManager->historicalKeySnapshot(version);
        EXPECT_TRUE(std::ranges::equal(opened.key.bytes(), key->bytes())) << "the vault's key, wrapped to the mirror";
        EXPECT_EQ(item.at("key_check").get<std::string>(), vh::vault::keyCheck(key->bytes(), v, version));
        const vh::vault::attestation::Attestation att{.key_id = item["attestation"].at("key_id").get<unsigned>(),
                                                      .signature = unb64(item["attestation"].at("signature"))};
        EXPECT_EQ(vh::vault::attestation::check(att, v, version, item.at("key_check").get<std::string>()),
                  vh::vault::attestation::Verdict::Valid);
        sawCurrent = sawCurrent || (item.at("current").get<bool>() && version == current);
    }
    EXPECT_TRUE(sawCurrent);
    EXPECT_EQ(keys[0].dump().find(b64(engine->encryptionManager->historicalKeySnapshot(current)->bytes())), std::string::npos)
        << "never the key in the clear";

    // The acknowledgement: then the core row, then the begin with the grant.
    const auto state = MirrorStart::offer(offer.id)->state;
    EXPECT_EQ(state, "started");
    const auto row = MirrorVaults::get(v);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->role, "core");
    EXPECT_EQ(row->peer_id, peer.id);
    const auto begins = wire->of("peer.mirror.begin", offer.offer_uid);
    ASSERT_EQ(begins.size(), 1u);
    EXPECT_TRUE(begins[0]["grant"].is_null()) << "the link grants nothing yet";
}

TEST_F(MirrorStartDbTest, AMirrorThatRefusesTheKeysEndsTheStartWithNoCoreRow) {
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    (void)start::answerReceived(peer, {{"offer_uid", offer.offer_uid}, {"decision", "accepted"}});
    wire->answer = [](const std::string& command, const json&) -> std::optional<json> {
        if (command == "peer.mirror.keys") return refusal("mirror_keys_refused", "key version 1: unverified");
        return okAnswer();
    };
    tickUntilQuiet();
    const auto o = *MirrorStart::offer(offer.id);
    EXPECT_EQ(o.state, "failed");
    EXPECT_EQ(o.reason.value_or(""), "mirror_keys_refused");
    EXPECT_FALSE(MirrorVaults::get(v));
    EXPECT_TRUE(wire->of("peer.mirror.begin", offer.offer_uid).empty());
    // A retry of mirror.add starts over.
    EXPECT_EQ(refusalCode([&] { (void)start::checkVault(v); }), "");
}

TEST_F(MirrorStartDbTest, CrashPointsOfTheCoreAreResumedOrCleanedUp) {
    const auto peer = newPeer(false);
    {   // After the acknowledgement, before startCore: the next pass makes the core row and begins.
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
        EXPECT_FALSE(MirrorVaults::get(v));
        start::Service::instance()->tick();
        EXPECT_TRUE(MirrorVaults::get(v));
        EXPECT_EQ(MirrorStart::offer(offer.id)->state, "started");
    }
    {   // After startCore, before the begin was answered (the link dropped): the core row stays, the begin is sent again
        // once the link is back, and startCore is not called twice.
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
        wire->answer = [](const std::string& command, const json&) -> std::optional<json> {
            if (command == "peer.mirror.begin") return std::nullopt;
            return okAnswer();
        };
        start::Service::instance()->tick();
        EXPECT_TRUE(MirrorVaults::get(v));
        EXPECT_EQ(MirrorStart::offer(offer.id)->state, "keys_acked");
        wire->answer = {};
        start::Service::instance()->resetForTesting();  // the retry delay
        start::Service::instance()->tick();
        EXPECT_EQ(MirrorStart::offer(offer.id)->state, "started");
    }
    {   // The same crash, then a cancel: no core row, and the mirror is told.
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
        (void)MirrorVaults::startCore(v, peer.id);
        wire->clear();
        const auto c = ops::mirrors::cancel(superUser, {.vault_id = v});
        EXPECT_EQ(c.side, "core");
        EXPECT_FALSE(MirrorVaults::get(v));
        EXPECT_EQ(MirrorStart::offer(offer.id)->state, "cancelled");
        start::Service::instance()->tick();
        ASSERT_EQ(wire->of("peer.mirror.cancel", offer.offer_uid).size(), 1u);
        EXPECT_FALSE(MirrorStart::offer(offer.id)->notify);
        EXPECT_TRUE(wire->of("peer.mirror.begin", offer.offer_uid).empty()) << "a cancelled start never begins";
    }
    {   // The offer never reached the mirror (link down): it goes when the link is back, nothing counted meanwhile.
        const auto v = coreVault();
        const auto offer = start::offerVault(v, peer, superUser->id, superUser->name());
        wire->up.reset();
        wire->clear();
        start::Service::instance()->tick();
        EXPECT_TRUE(wire->of("peer.mirror.offer", offer.offer_uid).empty());
        EXPECT_EQ(MirrorStart::offer(offer.id)->attempts, 0u) << "a link that is down is not an attempt";
        wire->up = 2000;
        start::Service::instance()->tick();
        EXPECT_EQ(wire->of("peer.mirror.offer", offer.offer_uid).size(), 1u);
    }
}

TEST_F(MirrorStartDbTest, TheCoreCancelsAtEveryStep) {
    const auto peer = newPeer(false);
    for (const auto* at : {"offered", "accepted", "keys_acked", "started"}) {
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        if (std::string(at) != "offered")
            (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "accepted", .notify = false});
        if (std::string(at) == "keys_acked" || std::string(at) == "started") {
            (void)MirrorStart::transition(offer.id, {"accepted"}, {.to = "keys_acked", .notify = false});
            (void)MirrorVaults::startCore(v, peer.id);
        }
        if (std::string(at) == "started") (void)MirrorStart::transition(offer.id, {"keys_acked"}, {.to = "started"});
        wire->clear();
        (void)ops::mirrors::cancel(superUser, {.vault_id = v});
        EXPECT_FALSE(MirrorVaults::get(v)) << at;
        EXPECT_EQ(MirrorStart::offer(offer.id)->state, "cancelled") << at;
        start::Service::instance()->tick();
        EXPECT_EQ(wire->of("peer.mirror.cancel", offer.offer_uid).size(), 1u) << at;
        EXPECT_EQ(refusalCode([&] { (void)start::checkVault(v); }), "") << at << ": nothing left behind";
    }
    // The mirror cancels: the core drops its row.
    const auto v = coreVault();
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
    (void)MirrorVaults::startCore(v, peer.id);
    const auto vaultUid = *db::query::vault::Vault::getVault(v)->uid;
    EXPECT_TRUE(start::cancelReceived(peer, {{"offer_uid", offer.offer_uid}, {"vault_uid", vl::keykit::toBase32(vaultUid)},
                                             {"reason", "cancelled_by_mirror"}})
                    .value("cancelled", false));
    EXPECT_FALSE(MirrorVaults::get(v));
    EXPECT_EQ(MirrorStart::offer(offer.id)->state, "cancelled");
    EXPECT_FALSE(MirrorStart::offer(offer.id)->notify) << "the mirror knows: it said so";
}

TEST_F(MirrorStartDbTest, TheGrantFollowsEveryChangeAndEveryLinkUp) {
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    (void)start::answerReceived(peer, {{"offer_uid", offer.offer_uid}, {"decision", "accepted"}});
    tickUntilQuiet();
    ASSERT_EQ(MirrorStart::offer(offer.id)->state, "started");
    wire->clear();
    const auto uid = vl::keykit::toBase32(*db::query::vault::Vault::getVault(v)->uid);
    const auto lastGrant = [&]() -> json {
        start::Service::instance()->tick();
        const auto grants = wire->of("peer.mirror.grant", uid);
        return grants.empty() ? json("none sent") : grants.back()["grant"];
    };
    EXPECT_EQ(lastGrant(), json("none sent")) << "the begin carried it";

    (void)ops::peer_policy::set(superUser, std::to_string(peer.id), ops::roles::Ref{std::string("reader")});
    auto g = lastGrant();
    ASSERT_TRUE(g.is_object()) << g.dump();
    EXPECT_EQ(g.value("role_name", ""), "reader") << "the link's default";
    wire->clear();
    EXPECT_EQ(lastGrant(), json("none sent")) << "nothing changed: nothing sent";

    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = v, .subject = {.type = "peer", .id = peer.id}},
                                                  .role = "contributor"});
    EXPECT_EQ(lastGrant().value("role_name", ""), "contributor") << "a per-vault assignment";

    // The role's own permissions edited.
    const auto custom = ops::roles::createVaultRole(superUser, {.name = "ms_role_" + tag()});
    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = v, .subject = {.type = "peer", .id = peer.id}},
                                                  .role = custom->name});
    const auto before = lastGrant();
    EXPECT_EQ(before.value("role_name", ""), custom->name);
    ops::roles::UpdateRole change{.role = custom->id};
    change.permissions.changes.emplace_back("vault.fs.files.download", true);
    (void)ops::roles::updateVaultRole(superUser, change);
    const auto after = lastGrant();
    EXPECT_EQ(after.value("role_name", ""), custom->name);
    EXPECT_NE(after.value("files", uint64_t{0}), before.value("files", uint64_t{0})) << "the actual bits, again";

    // No access, then nothing at all: the grant is cleared.
    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = v, .subject = {.type = "peer", .id = peer.id}},
                                                  .role = "implicit_deny"});
    EXPECT_TRUE(lastGrant().is_null()) << "implicit_deny grants nothing";
    (void)ops::roles::unassignVaultRole(superUser, {.vault_id = v, .subject = {.type = "peer", .id = peer.id}});
    EXPECT_EQ(lastGrant().value("role_name", ""), "reader") << "back to the default";
    (void)ops::peer_policy::set(superUser, std::to_string(peer.id), std::nullopt);
    EXPECT_TRUE(lastGrant().is_null());

    // A link-up sends it again, unchanged.
    wire->clear();
    wire->up = 5000;
    EXPECT_TRUE(lastGrant().is_null());
    EXPECT_EQ(wire->of("peer.mirror.grant", uid).size(), 1u);
}

// ==================================================================================== the mirror's side of the start

TEST_F(MirrorStartDbTest, AnOfferWaitsForASuperAdminOrIsAcceptedByTheLinkAndIsToldBack) {
    auto o = offeredAndAccepted(false);
    EXPECT_EQ(o.offer.state, "pending");
    EXPECT_FALSE(o.offer.notify);
    const auto pending = ops::mirrors::pending(superUser);
    EXPECT_TRUE(std::ranges::any_of(pending, [&](const auto& p) { return p.id == o.offer.id; }));
    const auto again = start::offerReceived(o.core, offerJson(o.offerUid, o.vaultUid, o.rootUid, o.name));
    EXPECT_EQ(again.value("state", ""), "pending") << "the same offer again: the same answer";

    (void)ops::mirrors::accept(superUser, std::to_string(o.offer.id));
    start::Service::instance()->tick();
    const auto answers = wire->of("peer.mirror.answer", o.offerUid);
    ASSERT_EQ(answers.size(), 1u);
    EXPECT_EQ(answers[0].value("decision", ""), "accepted");

    // A link set to accept every vault.
    (void)ops::mirrors::setAcceptAll(superUser, std::to_string(o.core.id), true);
    const auto uid = crypto::id::toUuid(crypto::id::newObjectUid());
    const auto auto1 = start::offerReceived(o.core, offerJson(uid, crypto::id::newObjectUid(), crypto::id::newObjectUid(),
                                                              "auto_" + tag()));
    EXPECT_EQ(auto1.value("state", ""), "accepted");
    (void)ops::mirrors::setAcceptAll(superUser, std::to_string(o.core.id), false);

    // Declined, and told.
    auto d = offeredAndAccepted(false);
    wire->clear();
    (void)ops::mirrors::decline(superUser, d.offerUid);
    start::Service::instance()->tick();
    const auto declined = wire->of("peer.mirror.answer", d.offerUid);
    ASSERT_EQ(declined.size(), 1u);
    EXPECT_EQ(declined[0].value("decision", ""), "declined");
}

TEST_F(MirrorStartDbTest, TheMirrorRefusesAVaultItHoldsANameItHasNoSpaceOrHistory) {
    const auto core = newPeer(true);
    const auto declinedWith = [&](const json& offer) {
        (void)start::offerReceived(core, offer);
        return MirrorStart::offerByUid(offer.at("offer_uid").get<std::string>(), "mirror")->reason.value_or("");
    };
    const auto fresh = [] { return crypto::id::toUuid(crypto::id::newObjectUid()); };

    // A uid this server holds.
    const auto local = coreVault("held");
    const auto heldUid = *db::query::vault::Vault::getVault(local)->uid;
    EXPECT_EQ(declinedWith(offerJson(fresh(), heldUid, crypto::id::newObjectUid(), "other_" + tag())),
              "mirror_vault_exists");
    // A name a vault here has (case and spaces aside).
    const auto localName = db::query::vault::Vault::getVault(local)->name;
    std::string upper = localName;
    for (auto& c : upper) c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    EXPECT_EQ(declinedWith(offerJson(fresh(), crypto::id::newObjectUid(), crypto::id::newObjectUid(), " " + upper + " ")),
              "mirror_name_taken");
    // No room.
    EXPECT_EQ(declinedWith(offerJson(fresh(), crypto::id::newObjectUid(), crypto::id::newObjectUid(), "huge_" + tag(),
                                     uint64_t{1} << 60)),
              "mirror_no_space");
    // History (never offered by this version, refused all the same).
    auto withHistory = offerJson(fresh(), crypto::id::newObjectUid(), crypto::id::newObjectUid(), "hist_" + tag());
    withHistory["history"] = true;
    EXPECT_EQ(declinedWith(withHistory), "history_not_supported");
    // A malformed offer is an error, never a row.
    auto bad = offerJson(fresh(), crypto::id::newObjectUid(), crypto::id::newObjectUid(), "bad_" + tag());
    bad["vault_uid"] = "not-a-uid";
    EXPECT_EQ(refusalCode([&] { (void)start::offerReceived(core, bad); }), "invalid");
    EXPECT_FALSE(MirrorStart::offerByUid(bad.at("offer_uid").get<std::string>(), "mirror"));
    // The declines are told to the core.
    start::Service::instance()->tick();
    EXPECT_GE(wire->of("peer.mirror.answer").size(), 4u);
}

TEST_F(MirrorStartDbTest, ProvenKeysMakeTheVaultWithTheCoresUidRootAndOwnerAndNobodyHasAccessUntilTheGrant) {
    auto o = offeredAndAccepted();
    const auto versions = twoVersions();
    const auto answer = start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, versions));
    EXPECT_TRUE(answer.value("installed", false));
    const auto vaultId = MirrorStart::vaultWithUid(o.vaultUid);
    ASSERT_TRUE(vaultId);
    const auto offer = *MirrorStart::offerByUid(o.offerUid, "mirror");
    EXPECT_EQ(offer.state, "installed");
    EXPECT_EQ(offer.vault_id, vaultId);

    const auto vault = db::query::vault::Vault::getVault(*vaultId);
    EXPECT_EQ(vault->name, o.name);
    EXPECT_EQ(vault->type, vault::model::VaultType::Local);
    EXPECT_EQ(scalar("SELECT d.uid::text FROM fs_entry e JOIN directories d ON d.fs_entry_id = e.id WHERE e.vault_id = " +
                     std::to_string(*vaultId) + " AND e.path = '/'"),
              crypto::id::toUuid(o.rootUid))
        << "the root folder has the core's root uid";
    EXPECT_EQ(scalar("SELECT count(*) FROM fs_entry WHERE vault_id = " + std::to_string(*vaultId)), "1") << "no entries";
    EXPECT_EQ(scalar("SELECT home_node || ':' || home_id || ':' || remote::text FROM users WHERE id = " +
                     std::to_string(vault->owner_id)),
              "core-owner-node:" + std::to_string(o.offer.owner.id) + ":true")
        << "the owner is the core's account, a remote account here";

    // The keys, sealed here: the engine reads exactly the core's keys, with their origin recorded.
    const auto engine = runtime::Deps::get().storageManager->getEngine(*vaultId);
    ASSERT_TRUE(engine);
    EXPECT_EQ(engine->encryptionManager->get_key_version(), 2u);
    for (const auto& v : versions)
        EXPECT_TRUE(std::ranges::equal(engine->encryptionManager->historicalKeySnapshot(v.version)->bytes(), v.key->bytes()));
    EXPECT_EQ(scalar("SELECT count(*) FROM vault_key_origin WHERE anchor = 'peer' AND origin_vault_id = 77 AND "
                     "origin_node_id = '" + o.core.node_id + "' AND vault_id = " + std::to_string(*vaultId)),
              "2");
    EXPECT_EQ(scalar("SELECT count(*) FROM vault_keys WHERE attestation IS NOT NULL AND vault_id = " +
                     std::to_string(*vaultId)),
              "1")
        << "re-attested by this server over its own vault id";

    // The mirror row, and no grant: nobody, super admins included.
    const auto row = MirrorVaults::get(*vaultId);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->role, "mirror");
    EXPECT_EQ(row->peer_id, o.core.id);
    EXPECT_FALSE(row->grant);
    EXPECT_FALSE(superAdminMay(*vaultId, Action::List));

    // The same keys again (the acknowledgement was lost): the same answer, nothing new.
    EXPECT_TRUE(start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, versions)).value("installed", false));
    EXPECT_EQ(scalar("SELECT count(*) FROM vault WHERE uid = '" + crypto::id::toUuid(o.vaultUid) + "'"), "1");

    // The begin, with the core's grant: super admins here get exactly it.
    (void)start::beginReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                        {"term", 1},
                                        {"grant", {{"role_name", "reader"}, {"files", 0xffffffffu},
                                                   {"directories", 0xffffffffu}, {"sync", 0}, {"roles", 0}}}});
    EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "started");
    ASSERT_TRUE(MirrorVaults::get(*vaultId)->grant);
    EXPECT_EQ(MirrorVaults::get(*vaultId)->grant->granted_by_node, o.core.node_id) << "the sender, never the payload";
    EXPECT_TRUE(superAdminMay(*vaultId, Action::List));

    // A grant from a server that is not this vault's core is never kept; the core's null clears it.
    const auto stranger = newPeer(true);
    EXPECT_EQ(refusalCode([&] {
                  (void)start::grantReceived(stranger, {{"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                                        {"grant", {{"role_name", "admin"}, {"files", 1},
                                                                   {"directories", 1}, {"sync", 1}, {"roles", 1}}}});
              }),
              "not_found");
    EXPECT_EQ(MirrorVaults::get(*vaultId)->grant->role_name, "reader");
    (void)start::grantReceived(o.core, {{"vault_uid", vl::keykit::toBase32(o.vaultUid)}, {"grant", nullptr}});
    EXPECT_FALSE(MirrorVaults::get(*vaultId)->grant);
    EXPECT_FALSE(superAdminMay(*vaultId, Action::List));

    // Rotation on the mirror is refused.
    EXPECT_EQ(refusalCode([&] { engine->encryptionManager->prepare_key_rotation(); }), "vault_mirrored");
}

TEST_F(MirrorStartDbTest, OneUnprovableVersionRefusesTheWholeStartAndWritesNothing) {
    const struct {
        const char* name;
        Tamper tamper;
    } cases[] = {{"an attestation by another key", {.wrongSeed = true}},
                 {"a key check that is not the key's", {.wrongCheck = true}},
                 {"an envelope for another recipient", {.otherRecipient = true}},
                 {"no current version", {.noCurrent = true}}};
    for (const auto& c : cases) {
        auto o = offeredAndAccepted();
        auto versions = twoVersions();
        // One good version, one tampered: the whole delivery is refused.
        auto payload = keysJson(o.offerUid, o.core, o.vaultUid, versions, c.tamper);
        if (!c.tamper.noCurrent) {
            const auto good = keysJson(o.offerUid, o.core, o.vaultUid, {versions[0]});
            payload["versions"][0] = good["versions"][0];
        }
        EXPECT_EQ(refusalCode([&] { (void)start::keysReceived(o.core, payload); }), "mirror_keys_refused") << c.name;
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid)) << c.name << ": no vault";
        EXPECT_EQ(scalar("SELECT count(*) FROM vault_key_origin WHERE origin_node_id = '" + o.core.node_id + "'"), "0")
            << c.name << ": no key";
        const auto offer = *MirrorStart::offerByUid(o.offerUid, "mirror");
        EXPECT_EQ(offer.state, "failed") << c.name;
        EXPECT_EQ(offer.reason.value_or(""), "mirror_keys_unproven") << c.name;
        EXPECT_FALSE(offer.detail.value_or("").empty()) << c.name << ": the reason is kept";
    }
    // Self-attested keys (this server's own attestation key pinned for the peer) prove nothing.
    auto o = offeredAndAccepted();
    sql("UPDATE peer SET attest_public_keys = (SELECT jsonb_agg(encode(public_key, 'base64')) FROM key_attestation_keys) "
        "WHERE id = " + std::to_string(o.core.id));
    const auto core = *db::query::peer::Peers::byId(o.core.id);
    EXPECT_EQ(refusalCode([&] { (void)start::keysReceived(core, keysJson(o.offerUid, core, o.vaultUid, twoVersions())); }),
              "mirror_keys_refused");
}

TEST_F(MirrorStartDbTest, TheMirrorCancelsAStartThatHasNotCompletedAndRefusesACompletedOne) {
    {   // pending, accepted: the row goes to cancelled, the core is told
        auto o = offeredAndAccepted(false);
        wire->clear();
        const auto c = ops::mirrors::cancel(superUser, {.offer = o.offerUid});
        EXPECT_EQ(c.side, "mirror");
        EXPECT_EQ(MirrorStart::offer(o.offer.id)->state, "cancelled");
        start::Service::instance()->tick();
        EXPECT_EQ(wire->of("peer.mirror.cancel", o.offerUid).size(), 1u);
    }
    {   // installed: the vault, its keys, its rows and the remote owner go
        auto o = offeredAndAccepted();
        (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, twoVersions()));
        const auto vaultId = *MirrorStart::vaultWithUid(o.vaultUid);
        const auto owner = db::query::vault::Vault::getVault(vaultId)->owner_id;
        const auto c = ops::mirrors::cancel(superUser, {.vault_id = vaultId});
        EXPECT_TRUE(c.removed);
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
        EXPECT_FALSE(MirrorVaults::get(vaultId));
        EXPECT_EQ(scalar("SELECT count(*) FROM vault_keys WHERE vault_id = " + std::to_string(vaultId)), "0");
        EXPECT_EQ(scalar("SELECT count(*) FROM vault_key_origin WHERE vault_id = " + std::to_string(vaultId)), "0");
        EXPECT_EQ(scalar("SELECT count(*) FROM users WHERE id = " + std::to_string(owner)), "0");
        EXPECT_FALSE(runtime::Deps::get().storageManager->getEngine(vaultId));
    }
    {   // started: refused here; the core's cancel with remove_copy removes it
        auto o = offeredAndAccepted();
        (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, twoVersions()));
        (void)start::beginReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                            {"term", 1}, {"grant", nullptr}});
        const auto vaultId = *MirrorStart::vaultWithUid(o.vaultUid);
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = vaultId}); }),
                  "mirror_detach_required");
        EXPECT_TRUE(MirrorVaults::get(vaultId));
        // Another server can't remove it.
        const auto stranger = newPeer(true);
        EXPECT_FALSE(start::cancelReceived(stranger, {{"vault_uid", vl::keykit::toBase32(o.vaultUid)}})
                         .value("cancelled", true));
        EXPECT_TRUE(MirrorVaults::get(vaultId));
        EXPECT_TRUE(start::cancelReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                                   {"reason", "cancelled_by_core"}, {"remove_copy", true}})
                        .value("cancelled", false));
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
        EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "cancelled");
    }
    {   // A crash after the vault was created and before the acknowledgement reached the core: the core sends the keys
        // again, the same answer comes back; or it cancels, and everything goes.
        auto o = offeredAndAccepted();
        const auto versions = twoVersions();
        (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, versions));
        EXPECT_TRUE(start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, versions)).value("installed", false));
        (void)start::cancelReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)}});
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
    }
}

TEST_F(MirrorStartDbTest, OffersExpireAndFinishedOnesAreSweptButAStartedOneStaysWhileItsMirrorDoes) {
    auto o = offeredAndAccepted(false);
    sql("UPDATE mirror_offer SET expires_at = now() - interval '1 second' WHERE id = " + std::to_string(o.offer.id));
    wire->clear();
    start::Service::instance()->tick();
    const auto expired = *MirrorStart::offer(o.offer.id);
    EXPECT_EQ(expired.state, "expired");
    EXPECT_EQ(expired.reason.value_or(""), "offer_expired");
    EXPECT_EQ(wire->of("peer.mirror.cancel", o.offerUid).size(), 1u) << "the core is told";
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::accept(superUser, std::to_string(o.offer.id)); }),
              "mirror_offer_not_pending");

    // On the core, too.
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    sql("UPDATE mirror_offer SET expires_at = now() - interval '1 second' WHERE id = " + std::to_string(offer.id));
    start::Service::instance()->tick();
    EXPECT_EQ(MirrorStart::offer(offer.id)->state, "expired");

    // Swept after 30 days: finished rows with nothing left to tell.
    sql("UPDATE mirror_offer SET finished_at = now() - interval '31 days' WHERE id IN (" + std::to_string(o.offer.id) +
        ", " + std::to_string(offer.id) + ")");
    start::Service::instance()->tick();
    EXPECT_FALSE(MirrorStart::offer(o.offer.id));
    EXPECT_FALSE(MirrorStart::offer(offer.id));

    // A started offer whose mirror row lives is kept (a later cancel tells the other server through it).
    auto s = offeredAndAccepted();
    (void)start::keysReceived(s.core, keysJson(s.offerUid, s.core, s.vaultUid, twoVersions()));
    (void)start::beginReceived(s.core, {{"offer_uid", s.offerUid}, {"vault_uid", vl::keykit::toBase32(s.vaultUid)},
                                        {"term", 1}, {"grant", nullptr}});
    sql("UPDATE mirror_offer SET finished_at = now() - interval '31 days' WHERE id = " + std::to_string(s.offer.id));
    (void)MirrorStart::sweepFinished(std::chrono::duration_cast<std::chrono::seconds>(start::kFinishedKept));
    EXPECT_TRUE(MirrorStart::offer(s.offer.id));
}

TEST_F(MirrorStartDbTest, KeyRotationWaitsForAStartAndOnTheCoreGoesOverTheLinkFirst) {
    const auto peer = newPeer(false);
    const auto v = coreVault();
    const auto em = runtime::Deps::get().storageManager->getEngine(v)->encryptionManager;
    (void)ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
    EXPECT_EQ(refusalCode([&] { em->prepare_key_rotation(); }), "mirror_start_running") << "while the start runs";
    (void)MirrorVaults::startCore(v, peer.id);
    const auto version = em->get_key_version();
    {   // the link down: refused, nothing rotated
        std::scoped_lock lock(wire->mutex);
        wire->up.reset();
    }
    EXPECT_EQ(refusalCode([&] { em->prepare_key_rotation(); }), "mirror_link_down");
    EXPECT_EQ(em->get_key_version(), version);
    {   // up, the mirror refuses the key: refused, nothing rotated
        std::scoped_lock lock(wire->mutex);
        wire->up = 1;
        wire->answer = [](const std::string&, const json&) -> std::optional<json> {
            return refusal("mirror_key_refused", "a test");
        };
    }
    EXPECT_EQ(refusalCode([&] { em->prepare_key_rotation(); }), "mirror_key_refused");
    EXPECT_EQ(em->get_key_version(), version);
    EXPECT_FALSE(db::query::vault::Key::keyRotationInProgress(v));
    {
        std::scoped_lock lock(wire->mutex);
        wire->answer = nullptr;
        wire->sent.clear();
    }
    // The mirror holds it: the rotation goes on, and what went over the link was an envelope, never the key.
    EXPECT_EQ(refusalCode([&] { em->prepare_key_rotation(); }), "");
    EXPECT_EQ(em->get_key_version(), version + 1);
    {
        std::scoped_lock lock(wire->mutex);
        ASSERT_FALSE(wire->sent.empty());
        const auto& [command, payload] = wire->sent.back();
        EXPECT_EQ(command, "peer.mirror.key");
        EXPECT_EQ(payload.value("version", 0u), version + 1);
        EXPECT_FALSE(payload.value("envelope", std::string{}).empty());
        for (const auto* secret : {"key", "encrypted_key", "iv"}) EXPECT_FALSE(payload.contains(secret)) << secret;
    }
    EXPECT_EQ(refusalCode([&] { (void)vh::vault::EncryptionManager::mintSalvageKey(v, 99, true); }), "vault_mirrored")
        << "a key salvage stays refused";
    em->finish_key_rotation();
    (void)ops::mirrors::cancel(superUser, {.vault_id = v});
}

// =============================================================================== ending a mirror (owner, 2026-11-26)

TEST_F(MirrorStartDbTest, TheMirrorRemovesAnUnfinishedCopyWhateverTheFlagOrTheSetting) {
    auto o = offeredAndAccepted();
    (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, twoVersions()));
    const auto vaultId = *MirrorStart::vaultWithUid(o.vaultUid);
    EXPECT_FALSE(start::firstCopyFinished(vaultId)) << "installed: the first copy has not begun";
    (void)ops::mirrors::setKeepRemoved(superUser, std::to_string(o.core.id), true);
    const auto answer = coreEnds(o, false);
    EXPECT_EQ(answer.value("copy", ""), "removed");
    EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid)) << "nothing complete was held: removed";
    EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "cancelled");
}

TEST_F(MirrorStartDbTest, AStartedCopyWhoseFirstCopyIsUnfinishedIsRemovedWhateverWasAskedOrSet) {
    // The begin came, the follower has not finished the first copy: nothing complete is held here.
    auto [o, vaultId] = startedCopy(false);
    EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "started");
    EXPECT_FALSE(start::firstCopyFinished(vaultId)) << "started is not finished: piece B's flag decides";
    (void)ops::mirrors::setKeepRemoved(superUser, std::to_string(o.core.id), true);
    EXPECT_EQ(coreEnds(o, std::nullopt).value("copy", ""), "removed");
    EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
    EXPECT_FALSE(MirrorVaults::get(vaultId));
    EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "cancelled");
}

TEST_F(MirrorStartDbTest, AFinishedCopyIsRemovedOnlyWhenAskedAndTheLinkKeepsNothingAndOtherwiseOrphaned) {
    {   // remove_copy, keep off: removed
        auto [o, vaultId] = startedCopy();
        EXPECT_TRUE(start::firstCopyFinished(vaultId));
        const auto answer = coreEnds(o, true);
        EXPECT_EQ(answer.value("copy", ""), "removed");
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
        EXPECT_FALSE(MirrorVaults::get(vaultId));
    }
    {   // no remove_copy: kept, orphaned, the last grant and the offer's own ending
        auto [o, vaultId] = startedCopy();
        const auto answer = coreEnds(o, std::nullopt);
        EXPECT_EQ(answer.value("copy", ""), "kept");
        const auto row = MirrorVaults::get(vaultId);
        ASSERT_TRUE(row);
        EXPECT_EQ(row->role, "orphaned");
        ASSERT_TRUE(row->grant);
        EXPECT_EQ(row->grant->role_name, "reader") << "the last recorded grant stays";
        EXPECT_TRUE(superAdminMay(vaultId, Action::List)) << "rbac::mirrored treats it like a mirror";
        EXPECT_EQ(MirrorStart::offerByUid(o.offerUid, "mirror")->state, "orphaned");
        // Told again (the core's retry): it stays as it was left.
        EXPECT_EQ(coreEnds(o, true).value("copy", ""), "kept");
        EXPECT_TRUE(MirrorVaults::get(vaultId));
        EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = vaultId}); }), "");
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid)) << "a super admin here removes an orphaned copy";
    }
    {   // remove_copy, keep on: kept
        auto [o, vaultId] = startedCopy();
        (void)ops::mirrors::setKeepRemoved(superUser, std::to_string(o.core.id), true);
        const auto answer = coreEnds(o, true);
        EXPECT_EQ(answer.value("copy", ""), "kept");
        EXPECT_EQ(MirrorVaults::get(vaultId)->role, "orphaned");
        EXPECT_EQ(MirrorStart::keepVaults(o.core.id).set_by, superUser->id);
    }
}

TEST_F(MirrorStartDbTest, TheKeepSettingIsASuperAdminsAndAudited) {
    const auto core = newPeer(true);
    const auto plain = identities::manager().user(
        ops::users::create(superUser, {.name = "ms_keep_" + tag(), .role = "unprivileged",
                                       .password = std::string("Mirror-Start-Pass-123")})
            .user->id);
    EXPECT_EQ(refusalCode([&] { (void)ops::mirrors::setKeepRemoved(plain, std::to_string(core.id), true); }), "denied");
    EXPECT_FALSE(MirrorStart::keepVaults(core.id).enabled) << "off by default";
    EXPECT_TRUE(ops::mirrors::setKeepRemoved(superUser, std::to_string(core.id), true).enabled);
    EXPECT_TRUE(audit::Trail::instance()->flushNow());
    EXPECT_EQ(scalar("SELECT details::jsonb->>'enabled' FROM audit_event WHERE action = 'mirror.keep_removed.set' "
                     "ORDER BY seq DESC LIMIT 1"),
              "true");
    EXPECT_FALSE(ops::mirrors::setKeepRemoved(superUser, std::to_string(core.id), false).enabled);
}

TEST_F(MirrorStartDbTest, TheCoreAsksForRemovalOrNotAndRecordsWhatTheMirrorDid) {
    const auto peer = newPeer(false);
    for (const bool remove : {false, true}) {
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        (void)start::answerReceived(peer, {{"offer_uid", offer.offer_uid}, {"decision", "accepted"}});
        tickUntilQuiet();
        ASSERT_EQ(MirrorStart::offer(offer.id)->state, "started");
        // The mirror unreachable: the core ends its own side at once and the request waits.
        wire->up.reset();
        const auto c = ops::mirrors::cancel(superUser, {.vault_id = v, .remove_copy = remove});
        EXPECT_EQ(c.remove_copy, remove);
        EXPECT_FALSE(MirrorVaults::get(v)) << "the core's side ended at once";
        start::Service::instance()->tick();
        EXPECT_TRUE(MirrorStart::offer(offer.id)->notify) << "queued";
        wire->up = 3000;
        wire->answer = [remove](const std::string& command, const json&) -> std::optional<json> {
            if (command == "peer.mirror.cancel") return okAnswer({{"cancelled", true}, {"copy", remove ? "removed" : "kept"}});
            return okAnswer();
        };
        start::Service::instance()->tick();
        const auto sent = wire->of("peer.mirror.cancel", offer.offer_uid);
        ASSERT_EQ(sent.size(), 1u);
        EXPECT_EQ(sent[0].value("remove_copy", !remove), remove);
        const auto after = *MirrorStart::offer(offer.id);
        EXPECT_FALSE(after.notify);
        EXPECT_EQ(after.remove_copy, remove);
        EXPECT_EQ(after.copy_outcome.value_or(""), remove ? "removed" : "kept");
        EXPECT_EQ(ops::mirrors::toJson(ops::mirrors::get(superUser, v))["start"].value("copy", ""),
                  remove ? "removed" : "kept")
            << "mirror info shows it";
        wire->answer = {};
    }
}

TEST_F(MirrorStartDbTest, UnlinkingBeforeAQueuedRemovalIsDeliveredDropsItAndKeepsTheCopiesOrphaned) {
    {   // The core's side: a queued cancel for a server unlinked meanwhile is dropped.
        const auto peer = newPeer(false);
        const auto v = coreVault();
        const auto offer = ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        wire->up.reset();
        (void)ops::mirrors::cancel(superUser, {.vault_id = v, .remove_copy = true});
        (void)db::query::peer::Peers::revoke(peer.id);
        wire->up = 4000;
        start::Service::instance()->tick();
        EXPECT_FALSE(MirrorStart::offer(offer.id)->notify) << "dropped";
        EXPECT_TRUE(wire->of("peer.mirror.cancel", offer.offer_uid).empty()) << "never delivered";
    }
    {   // The mirror's side: an unlinked core's copies are kept, orphaned.
        auto [o, vaultId] = startedCopy();
        (void)db::query::peer::Peers::revoke(o.core.id);
        EXPECT_GE(start::reconcileUnlinked(), 1u);
        EXPECT_EQ(MirrorVaults::get(vaultId)->role, "orphaned");
        EXPECT_TRUE(MirrorStart::vaultWithUid(o.vaultUid));
    }
}

// Wave 5: on the core the delete takes the choice for the mirror's copy (MirrorLeaveDbTest covers it); without one it is
// refused while a start runs and while mirrored, and the vault is free once the mirror ended.
TEST_F(MirrorStartDbTest, DeletingAMirroredVaultIsRefusedUntilItsMirrorEnded) {
    const auto peer = newPeer(false);
    const auto remove = [](const uint32_t v) {
        return refusalCode([&] { (void)ops::vaults::remove(superUser, {.id = v, .accept_key_loss = true}); });
    };
    {   // The core: while a start runs, while mirrored; free once ended.
        const auto v = coreVault();
        (void)ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)});
        EXPECT_EQ(remove(v), "mirror_copy_choice_required");
        (void)MirrorVaults::startCore(v, peer.id);
        EXPECT_EQ(remove(v), "mirror_copy_choice_required");
        (void)ops::mirrors::cancel(superUser, {.vault_id = v});
        EXPECT_EQ(remove(v), "") << "the mirror ended: an ordinary vault again";
    }
    {   // The mirror: another server's vault; an orphaned copy goes through mirror.cancel.
        auto [o, vaultId] = startedCopy();
        EXPECT_EQ(remove(vaultId), "vault_mirrored");
        (void)coreEnds(o, false);
        EXPECT_EQ(remove(vaultId), "vault_orphaned_copy");
        EXPECT_TRUE(MirrorStart::vaultWithUid(o.vaultUid));
        (void)ops::mirrors::cancel(superUser, {.vault_id = vaultId});
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        EXPECT_EQ(scalar("SELECT count(*) FROM audit_event WHERE action = 'mirror.remove' AND vault_id = " +
                         std::to_string(vaultId)),
                  "1");
    }
}

// ============================================================================ step-up in the console

namespace {
std::shared_ptr<protocols::ws::Session> mirrorConsole(const std::shared_ptr<identities::User>& user) {
    auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = user;
    web->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>();
    web->tokens->refreshToken->jti = "mirror-stepup-jti-" + tag();
    web->tokens->refreshToken->aal = 1;
    web->tokens->refreshToken->amr = {"pwd"};
    web->tokens->refreshToken->authTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    return web;
}

void grantStepUp(const std::shared_ptr<protocols::ws::Session>& web, const auth::stepup::Family family,
                 const std::string& target) {
    web->stepUp().addGrant({.user_id = web->user->id, .refresh_jti = web->tokens->refreshToken->jti, .family = family,
                            .target = target, .method = "test",
                            .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
}

// The step-up a call asks for in the console, or nullopt when it asks none (and ran).
template <class F>
std::optional<std::pair<std::string, std::string>> stepUpAsked(F&& f) {
    try {
        f();
    } catch (const ops::StepUpRequired& e) {
        return std::make_pair(e.family, e.target.value_or(""));
    }
    return std::nullopt;
}
}

TEST_F(MirrorStartDbTest, TheConsoleStepsUpToSendAVaultsKeysToRemoveACopyOrAnOrphanedCopyAndForNothingElse) {
    namespace stepup = auth::stepup;
    const auto peer = newPeer(false);
    const auto web = mirrorConsole(superUser);

    // mirror.add: the keys family, bound to the vault; refused without the grant, runs with it.
    const auto v = coreVault();
    {
        const stepup::Scope scope(web);
        const auto asked = stepUpAsked([&] { (void)ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)}); });
        ASSERT_TRUE(asked);
        EXPECT_EQ(asked->first, "keys");
        EXPECT_EQ(asked->second, "mirror.add:" + std::to_string(v));
        EXPECT_FALSE(MirrorStart::facts(v) && MirrorStart::activeOffer(MirrorStart::facts(v)->vault_uid, "core"))
            << "nothing offered without the step-up";
        grantStepUp(web, stepup::Family::Keys, "mirror.add:" + std::to_string(v));
        EXPECT_FALSE(stepUpAsked([&] {
            EXPECT_EQ(ops::mirrors::add(superUser, {.vault_id = v, .peer = std::to_string(peer.id)}).state, "offered");
        }));
    }

    // mirror.cancel on the core of a mirror that has begun: data.destroy only when it asks to remove the copy.
    const auto begun = coreVault();
    {
        const auto offer = start::offerVault(begun, peer, superUser->id, superUser->name());
        (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
        (void)MirrorVaults::startCore(begun, peer.id);
        const stepup::Scope scope(web);
        const auto asked = stepUpAsked([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = begun, .remove_copy = true}); });
        ASSERT_TRUE(asked);
        EXPECT_EQ(asked->first, "data.destroy");
        EXPECT_EQ(asked->second, "mirror.cancel:" + std::to_string(begun));
        EXPECT_TRUE(MirrorVaults::get(begun)) << "nothing ended without the step-up";
        grantStepUp(web, stepup::Family::DataDestroy, "mirror.cancel:" + std::to_string(begun));
        EXPECT_FALSE(stepUpAsked([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = begun, .remove_copy = true}); }));
        EXPECT_FALSE(MirrorVaults::get(begun));
        EXPECT_TRUE(MirrorStart::latestOffer(*db::query::vault::Vault::getVault(begun)->uid, "core")->remove_copy);
    }
    const auto kept = coreVault();
    {
        const auto offer = start::offerVault(kept, peer, superUser->id, superUser->name());
        (void)MirrorStart::transition(offer.id, {"offered"}, {.to = "keys_acked", .notify = false});
        (void)MirrorVaults::startCore(kept, peer.id);
        const auto plain = mirrorConsole(superUser);
        const stepup::Scope scope(plain);
        EXPECT_FALSE(stepUpAsked([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = kept}); }))
            << "ending a mirror and leaving the copy where it is asks for nothing";
        EXPECT_FALSE(MirrorVaults::get(kept));
    }

    // Removing an orphaned copy on the mirror: data.destroy, bound to the vault.
    auto [o, copyId] = startedCopy();
    (void)coreEnds(o, std::nullopt);
    ASSERT_EQ(MirrorVaults::get(copyId)->role, "orphaned");
    {
        const auto mirrorWeb = mirrorConsole(superUser);
        const stepup::Scope scope(mirrorWeb);
        const auto asked = stepUpAsked([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = copyId}); });
        ASSERT_TRUE(asked);
        EXPECT_EQ(asked->first, "data.destroy");
        EXPECT_EQ(asked->second, "mirror.cancel:" + std::to_string(copyId));
        EXPECT_TRUE(MirrorStart::vaultWithUid(o.vaultUid)) << "the copy stays without the step-up";
        grantStepUp(mirrorWeb, stepup::Family::DataDestroy, "mirror.cancel:" + std::to_string(copyId));
        EXPECT_FALSE(stepUpAsked([&] { (void)ops::mirrors::cancel(superUser, {.vault_id = copyId}); }));
        EXPECT_FALSE(MirrorStart::vaultWithUid(o.vaultUid));
    }
}

// ================================================================================== the join with piece B

namespace {
// The core as the follower reaches it: counts what it is asked, answers nothing.
class CountingCore final : public vh::mirror::follow::Transport {
public:
    std::vector<std::string> asked;
    bool connected(uint32_t) override { return true; }
    std::optional<Answer> request(uint32_t, const std::string& command, const json&) override {
        asked.push_back(command);
        return std::nullopt;
    }
    bool notify(uint32_t, const std::string&, const json&) override { return true; }
};
}

TEST_F(MirrorStartDbTest, TheFollowerAsksForTheTreeOnlyOnceTheCoresBeginArrived) {
    // Found while building the wave 3 drill (by reading the join): the mirror's row exists from the keys on, the core's
    // row only after the keys
    // are answered and its baseline taken; a tree request in between got not_found, which the follower read as "the
    // core is gone" and stopped the vault for good (expired, mirror_core_gone).
    auto o = offeredAndAccepted();
    (void)start::keysReceived(o.core, keysJson(o.offerUid, o.core, o.vaultUid, twoVersions()));
    const auto vaultId = *MirrorStart::vaultWithUid(o.vaultUid);
    EXPECT_TRUE(start::awaitingBegin(vaultId));
    CountingCore core;
    const auto before = vh::mirror::follow::Follower::instance()->step(vaultId, core);
    EXPECT_EQ(before.step, vh::mirror::follow::Step::Waiting) << before.detail;
    EXPECT_TRUE(core.asked.empty()) << "nothing asked before the begin";
    EXPECT_EQ(MirrorVaults::get(vaultId)->state, "live");
    (void)start::beginReceived(o.core, {{"offer_uid", o.offerUid}, {"vault_uid", vl::keykit::toBase32(o.vaultUid)},
                                        {"term", 1}, {"grant", nullptr}});
    EXPECT_FALSE(start::awaitingBegin(vaultId));
    (void)vh::mirror::follow::Follower::instance()->step(vaultId, core);
    ASSERT_FALSE(core.asked.empty());
    EXPECT_EQ(core.asked.front(), "peer.mirror.tree") << "the first copy starts once the core has its row";
}

// ============================================================================ background work on the mirror

TEST_F(MirrorStartDbTest, TheLocalSyncPassLeavesTheTrashOfAMirrorAndOfAnOrphanedCopyAlone) {
    // The design's rule ("Background work on the mirror"), enforced while building the wave 3 drill: the local sync
    // pass runs none of its content-changing jobs (the at-rest repair, the trash purge, rotation) on a vault held here
    // as another server's copy. Shown with the trash (rows the pass would end on a vault whose engine purges).
    const auto core = newPeer(true);
    const auto v = coreVault("trash");
    const auto engine = runtime::Deps::get().storageManager->getEngine(v);
    engine->remove("/doc.txt", superUser->id);
    const auto trashed = [&] {
        return scalar("SELECT count(*) FROM files_trashed WHERE deleted_at IS NULL AND vault_id = " + std::to_string(v));
    };
    ASSERT_EQ(trashed(), "1");
    (void)MirrorVaults::startMirror(v, core.id);
    (*std::make_shared<sync::Local>(engine))();
    EXPECT_EQ(trashed(), "1") << "a mirror's trash changes only by its core's log";
    (void)MirrorVaults::orphan(v);
    (*std::make_shared<sync::Local>(engine))();
    EXPECT_EQ(trashed(), "1") << "an orphaned copy is still another server's vault";
    // (An ordinary vault's pass purges it: SyncPassSchedulingDb runs those, on the sync pools this suite doesn't
    // start.)
    (void)MirrorVaults::remove(v);
}

// ====================================================================================== background contents

namespace {

class ServeBytes final : public mirror::contents::Source {
public:
    explicit ServeBytes(std::vector<uint8_t> bytes, std::shared_ptr<std::atomic<int>> reads)
        : bytes_(std::move(bytes)), reads_(std::move(reads)) {}
    mirror::contents::SourceResult read(const uint64_t offset, uint64_t, const std::function<bool()>&,
                                        const vh::peer::object::Sink& sink) override {
        reads_->fetch_add(1);
        if (bytes_.empty()) return {vh::peer::object::FetchStatus::Refused, "not_held"};
        sink(std::span<const uint8_t>(bytes_.data() + offset, bytes_.size() - offset));
        return {vh::peer::object::FetchStatus::Complete, ""};
    }

private:
    std::vector<uint8_t> bytes_;
    std::shared_ptr<std::atomic<int>> reads_;
};

}

TEST_F(MirrorStartDbTest, BackgroundContentsFetchWhileTheLinkIsUpAndBackOffFromFailures) {
    auto& worker = *start::BackgroundContents::instance();
    worker.resetForTesting();
    const auto core = newPeer(true);
    const auto v = coreVault("bg");
    const auto engine = runtime::Deps::get().storageManager->getEngine(v);
    const auto file = db::query::fs::File::getFileByPath(v, "/doc.txt");
    const auto sealed = vh::fs::ops::readFileToString(file->backing_path);
    std::filesystem::remove(file->backing_path);
    (void)MirrorVaults::startMirror(v, core.id);
    const mq::Expected expected{.vault_id = v, .object_uid = *file->object_uid, .generation = file->encryption_iv,
                                .key_version = file->encrypted_with_key_version, .size_bytes = file->size_bytes,
                                .content_hash = file->content_hash.value_or(""), .mtime_us = 1'700'000'000'000'000LL};
    mq::PendingContents::expect(expected);

    // Link down: nothing runs.
    wire->up.reset();
    EXPECT_EQ(worker.tick(), 0u);

    // A source that refuses: one batch, then the vault backs off.
    wire->up = 1000;
    auto reads = std::make_shared<std::atomic<int>>(0);
    mirror::contents::setSourceFactoryForTesting(
        [reads](const auto&, const auto&) { return std::make_unique<ServeBytes>(std::vector<uint8_t>{}, reads); });
    EXPECT_EQ(worker.tick(), 1u);
    ASSERT_TRUE(worker.waitIdleForTesting(20s));
    EXPECT_GE(reads->load(), 1);
    EXPECT_EQ(worker.tick(), 0u) << "backing off: no busy loop on a failing file";

    // The bytes: received in the background, the row cleared.
    worker.resetForTesting();
    const std::vector<uint8_t> bytes(sealed.begin(), sealed.end());
    mirror::contents::setSourceFactoryForTesting(
        [bytes, reads](const auto&, const auto&) { return std::make_unique<ServeBytes>(bytes, reads); });
    EXPECT_EQ(worker.tick(), 1u);
    ASSERT_TRUE(worker.waitIdleForTesting(20s));
    EXPECT_FALSE(mq::PendingContents::get(v, *file->object_uid)) << "received";
    EXPECT_EQ(vh::fs::ops::readFileToString(file->backing_path), sealed);
    (void)MirrorVaults::remove(v);
}

// ============================================================================ mirror every vault (the core's link)

TEST_F(MirrorStartDbTest, MirrorEveryVaultOffersEachVaultOnceNewOnesTooAndNeverOneTheOtherServerDeclined) {
    namespace stepup = auth::stepup;
    const auto peer = newPeer(false);
    const auto ref = std::to_string(peer.id);
    const auto offers = [&](const uint32_t v, const bool active = false) {
        return std::stoi(scalar("SELECT count(*) FROM mirror_offer WHERE side = 'core' AND vault_id = " +
                                std::to_string(v) + " AND peer_id = " + ref +
                                (active ? " AND finished_at IS NULL" : "")));
    };
    const auto a = coreVault("every"), b = coreVault("every");
    start::Service::instance()->tick();
    EXPECT_EQ(offers(a), 0) << "off by default";
    EXPECT_FALSE(MirrorStart::mirrorVaults(peer.id).enabled);

    // Turning it on sends vaults' keys: the console asks the keys step-up, bound to the server.
    const auto web = mirrorConsole(superUser);
    {
        const stepup::Scope scope(web);
        const auto asked = stepUpAsked([&] { (void)ops::mirrors::setMirrorAll(superUser, ref, true); });
        ASSERT_TRUE(asked);
        EXPECT_EQ(asked->first, "keys");
        EXPECT_EQ(asked->second, "mirror.mirror_all:" + ref);
        EXPECT_FALSE(MirrorStart::mirrorVaults(peer.id).enabled) << "nothing set without the step-up";
        grantStepUp(web, stepup::Family::Keys, "mirror.mirror_all:" + ref);
        EXPECT_TRUE(ops::mirrors::setMirrorAll(superUser, ref, true).enabled);
    }
    start::Service::instance()->tick();
    EXPECT_EQ(offers(a, true), 1) << "every vault that is not mirrored is offered";
    EXPECT_EQ(offers(b, true), 1);
    start::Service::instance()->tick();
    EXPECT_EQ(offers(a), 1) << "once";

    // The other server declines a's offer: never made again. A vault made now is offered.
    const auto offerA = *MirrorStart::activeOffer(MirrorStart::facts(a)->vault_uid, "core");
    (void)start::answerReceived(peer, json{{"offer_uid", offerA.offer_uid}, {"decision", "declined"},
                                           {"reason", "declined"}});
    const auto c = coreVault("every");
    start::Service::instance()->wake();
    start::Service::instance()->tick();
    EXPECT_EQ(offers(c, true), 1) << "a new vault is offered as it is created";
    EXPECT_EQ(offers(a), 1) << "a declined offer is not made again";
    EXPECT_EQ(MirrorStart::latestOffer(offerA.vault_uid, "core")->state, "declined");

    // Off: a new vault waits for mirror.add.
    EXPECT_FALSE(ops::mirrors::setMirrorAll(superUser, ref, false).enabled);
    const auto d = coreVault("every");
    start::Service::instance()->wake();
    start::Service::instance()->tick();
    EXPECT_EQ(offers(d), 0);
    audit::Trail::instance()->flushNow();
    EXPECT_GE(std::stoi(scalar("SELECT count(*) FROM audit_event WHERE action = 'mirror.mirror_all.set'")), 2);

    // Every offer made here ends (the database, and its other tests' vaults, are shared).
    for (const auto& o : MirrorStart::offers("core", true))
        if (o.peer_id == peer.id && o.vault_id)
            (void)start::cancelOnCore(*o.vault_id, "cancelled_by_core", false, false, std::nullopt, "test");
}

}
