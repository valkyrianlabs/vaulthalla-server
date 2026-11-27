// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Key rotation on a mirrored vault, run by its core (design/peers/mirror.md "Key rotation"; mirror/rotate), with the two
// servers of helpers/mirror_pair.hpp. The new version goes over the link first (peer.mirror.key, served by the mirror's
// own handler: proven against the attestation key pinned for the core, held), the rotation then re-seals on the core as
// on any vault, and the mirror makes the version current when the log names it and receives the re-sealed files.
//
// Covered: the rotation ends with equal digests, every file readable on the mirror under the new version, the old one
// still held, the mirror never stopped; refused cleanly (nothing rotated, nothing logged) with the link down or the
// mirror not live; a mirror restarted mid-rotation (before and after the version became current) finishes; a repeated
// delivery is answered and a version in use with another key is refused; a key salvage stays refused.

#include "../helpers/mirror_pair.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/mirror/Keys.hpp"
#include "fs/ops/file.hpp"
#include "mirror/rotate/Rotate.hpp"
#include "peer/Keys.hpp"
#include "sync/rotation/Rotation.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"

#include <vl/keykit/uid.hpp>

#include <sodium.h>

#include <array>
#include <cstring>

namespace vh::test_mirror_rotate {

using namespace vh::test_mirror_pair;   // the fixture and its aliases (json, mq, mf, ap, ms)
namespace start = vh::mirror::start;

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
        throw std::runtime_error("not base64");
    out.resize(len);
    return out;
}

class MirrorRotateDbTest : public MirrorPairDb {
protected:
    // The core's attestation seed, pinned on the mirror's row for its core (as pairing pins the card's keys). In one
    // database the core's own signature is this server's, which a mirror never accepts as proof; the wire re-signs it.
    inline static std::array<uint8_t, 32> coreSeed{};

    static void SetUpTestSuite() {
        setUpPair("test_mirror_rotate");
        if (skipTests) return;
        randombytes_buf(coreSeed.data(), coreSeed.size());
        const auto pub = vh::vault::attestation::publicKeyFromSeed(coreSeed);
        const auto wrap = vh::peer::keys::wrapPublicKey();   // the core wraps to the mirror's key: this server's own
        sql("UPDATE peer SET attest_public_keys = jsonb_build_array('" + b64(pub) + "') WHERE id = " +
            std::to_string(corePeer));
        sql("UPDATE peer SET wrap_public_key = decode('" + hex(wrap) + "', 'hex') WHERE id = " + std::to_string(mirrorPeer));
    }

    void TearDown() override {
        start::setTransportForTesting({});
        MirrorPairDb::TearDown();
    }

    static std::string hex(const std::span<const uint8_t> bytes) {
        static constexpr char digits[] = "0123456789abcdef";
        std::string out;
        for (const auto b : bytes) {
            out += digits[b >> 4];
            out += digits[b & 15];
        }
        return out;
    }

    // This server acts as the mirror again while the core's turn is on (its node id is its own).
    struct AsMirror {
        AsMirror() { sql("UPDATE device_node SET node_id = '" + ownNode + "' WHERE singleton"); }
        ~AsMirror() { sql("UPDATE device_node SET node_id = '" + coreNode + "' WHERE singleton"); }
    };

    struct Link {
        bool up{true};
        std::vector<json> delivered;   // what the mirror was sent
        std::vector<json> answers;
    };

    // The link from the core to its mirror: peer.mirror.key served by the mirror's handler on its turn, re-signed with
    // the pinned core seed on its way.
    static void linkTo(Scenario& s, const std::shared_ptr<Link>& link) {
        start::setTransportForTesting(
            {.request = [&s, link](uint32_t, const std::string& command, const json& payload,
                                   std::chrono::milliseconds) -> std::optional<json> {
                 if (!link->up) return std::nullopt;
                 if (command != "peer.mirror.key") return json{{"status", "OK"}, {"data", json::object()}};
                 link->delivered.push_back(payload);
                 auto signedPayload = payload;
                 const auto uid = vl::keykit::fromBase32(payload.at("vault_uid").get<std::string>());
                 const auto unwrapped =
                     vh::peer::keys::unwrapVaultKey(unb64(payload.at("envelope").get<std::string>()), *uid);
                 const auto coreVault = payload.at("core_vault_id").get<uint32_t>();
                 const auto version = payload.at("version").get<uint32_t>();
                 const auto check = vh::vault::keyCheck(unwrapped.key.bytes(), coreVault, version);
                 EXPECT_EQ(check, payload.at("key_check").get<std::string>()) << "the core's key check over its vault";
                 const auto sig = vh::vault::attestation::signWithSeed(
                     coreSeed, vh::vault::attestation::message(coreNode, coreVault, version, check));
                 signedPayload["attestation"] = {{"key_id", 1}, {"signature", b64(sig)}};
                 const auto core = *db::query::peer::Peers::byId(corePeer);
                 json answer;
                 toMirror(s);
                 {
                     AsMirror as;
                     try {
                         answer = {{"status", "OK"}, {"data", vh::mirror::rotate::keyReceived(core, signedPayload)}};
                     } catch (const ops::Refused& e) {
                         answer = {{"status", "ERROR"}, {"data", {{"code", e.code}}}, {"error", e.what()}};
                     } catch (const std::exception& e) {
                         answer = {{"status", "ERROR"}, {"data", {{"code", "invalid"}}}, {"error", e.what()}};
                     }
                 }
                 toCore(s);
                 link->answers.push_back(answer);
                 return answer;
             },
             .upSince = [link](uint32_t) -> std::optional<std::time_t> {
                 if (!link->up) return std::nullopt;
                 return 1;
             }});
    }

    // On the core's turn: prepare (the delivery), re-seal up to `limit` files, finish when none is left.
    static void rotateOnCore(Scenario& s, const std::size_t limit = SIZE_MAX, const bool prepare = true) {
        toCore(s);
        {
            AsCore as;
            const auto em = s.core->encryptionManager;
            if (prepare) em->prepare_key_rotation();
            const auto deps = vh::sync::rotation::runtimeDeps(s.core);
            std::size_t done = 0;
            for (const auto& f : db::query::fs::File::getFilesOlderThanKeyVersion(s.coreId, em->get_key_version())) {
                if (done++ >= limit) break;
                EXPECT_EQ(vh::sync::rotation::rotateFile(f, deps), vh::sync::rotation::Outcome::Rotated) << f->path;
            }
            if (db::query::fs::File::getFilesOlderThanKeyVersion(s.coreId, em->get_key_version()).empty())
                em->finish_key_rotation();
            captureLog(s);
        }
        toMirror(s);
    }

    static std::string plaintextOnMirror(const Scenario& s, const std::string& path) {
        const auto f = db::query::fs::File::getFileByPath(s.mirrorId, path);
        if (!f) return "<missing>";
        const auto bytes = vh::fs::ops::readFileToVector(f->backing_path);
        const auto plain =
            mirrorEm(s)->decrypt(bytes, f->encryption_iv, f->encrypted_with_key_version);
        return {plain.begin(), plain.end()};
    }

    // The process's engine of a vault (the one the applier reloads; a test's handle can be an earlier one).
    static EnginePtr live(const uint32_t vaultId) { return runtime::Deps::get().storageManager->getEngine(vaultId); }
    static std::shared_ptr<vault::EncryptionManager> mirrorEm(const Scenario& s) {
        return live(s.mirrorId)->encryptionManager;
    }

    static std::string keysDiag(const Scenario& s) {
        const auto m = std::to_string(s.mirrorId), c = std::to_string(s.coreId);
        return db::Transactions::exec("rot diag", [&](pqxx::work& txn) {
            std::string out;
            for (const auto* q : {"SELECT string_agg(version::text, ',') FROM vault_keys WHERE vault_id = $1",
                                  "SELECT string_agg(version::text, ',') FROM vault_keys_trashed WHERE vault_id = $1",
                                  "SELECT string_agg(version::text, ',') FROM vault_key_origin WHERE vault_id = $1"}) {
                const auto r = txn.exec(q, pqxx::params{s.mirrorId});
                out += std::string(" [") + (r[0][0].is_null() ? "" : r[0][0].c_str()) + "]";
            }
            const auto k = txn.exec("SELECT string_agg(seq::text || ':' || COALESCE(state::text, ''), ' | ') FROM "
                                    "vault_replication_log WHERE vault_id = $1 AND op = 'key'",
                                    pqxx::params{s.coreId});
            out += std::string(" log keys: ") + (k[0][0].is_null() ? "none" : k[0][0].c_str());
            out += " mirror at " + std::to_string(mirrorRow(s).last_seq) + " core " + c + " mirror " + m;
            return out;
        });
    }

    static uint32_t keyVersionOf(const uint32_t vaultId, const std::string& path) {
        const auto f = db::query::fs::File::getFileByPath(vaultId, path);
        return f ? f->encrypted_with_key_version : 0;
    }

    static const std::map<std::string, std::string>& files() {
        static const std::map<std::string, std::string> f{{"/a.txt", "alpha, sealed once and re-sealed"},
                                                          {"/docs/b.txt", "bravo in a folder"},
                                                          {"/docs/c.txt", "charlie, the third"}};
        return f;
    }
};

TEST_F(MirrorRotateDbTest, ARotationOnTheCoreEndsWithEqualDigestsAndEveryFileReadableOnTheMirrorUnderTheNewVersion) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        for (const auto& [path, text] : files()) write(e, path, text);
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    const auto link = std::make_shared<Link>();
    linkTo(s, link);
    const auto mirrorBefore = mirrorEm(s)->get_key_version();
    const auto journal = "SELECT count(*) FROM fs_change_log WHERE vault_id = " + std::to_string(s.coreId);
    const auto journaled = coreCount(s, journal);

    rotateOnCore(s);
    EXPECT_EQ(coreCount(s, journal), journaled) << "a re-seal is no change in the core's journal (the same plaintext)";
    ASSERT_EQ(link->delivered.size(), 1u) << "the new version went to the mirror once, before anything was re-sealed";
    ASSERT_EQ(link->answers.front().value("status", ""), "OK") << link->answers.front().dump();
    for (const auto* secret : {"key", "encrypted_key", "iv"})
        EXPECT_FALSE(link->delivered.front().contains(secret)) << "only an envelope travels: " << secret;
    const auto newVersion = link->delivered.front().at("version").get<uint32_t>();
    toCore(s);
    EXPECT_EQ(s.core->encryptionManager->get_key_version(), newVersion);
    for (const auto& [path, text] : files()) {
        // The row records the new generation's sealed-bytes hash: what the mirror checks the bytes it fetches against.
        const auto f = db::query::fs::File::getFileByPath(s.coreId, path);
        ASSERT_TRUE(f);
        EXPECT_EQ(f->content_hash.value_or(""), crypto::hash::blake2b(f->backing_path)) << path;
    }
    EXPECT_FALSE(s.core->encryptionManager->rotation_in_progress()) << "every file was re-sealed on the core";
    toMirror(s);

    followAll(wire, s);
    EXPECT_EQ(mirrorRow(s).state, "live") << "the mirror never stopped: " << mirrorRow(s).stop_detail.dump();
    EXPECT_EQ(mirrorEm(s)->get_key_version(), newVersion)
        << "current once the log named it; " << keysDiag(s);
    receiveAll(s);
    expectSettled(s);
    for (const auto& [path, text] : files()) {
        EXPECT_EQ(keyVersionOf(s.mirrorId, path), newVersion) << path;
        EXPECT_EQ(plaintextOnMirror(s, path), text) << path;
    }
    EXPECT_TRUE(mirrorEm(s)->hasKeyVersion(mirrorBefore)) << "the outgoing version stays held";
    EXPECT_EQ(one<int>("SELECT count(*) FROM vault_key_origin WHERE vault_id = " + std::to_string(s.mirrorId) +
                       " AND version = " + std::to_string(newVersion) + " AND origin_node_id = '" + coreNode + "'"),
              1)
        << "the version records where it came from";
    audit::Trail::instance()->flushNow();
    EXPECT_GE(one<int>("SELECT count(*) FROM audit_event WHERE action = 'mirror.key'"), 2) << "both sides audited";

    // What the console reads of the copy now (mirror.get): nothing pending, the first copy done, the link up, the
    // last acknowledgement's time, its settings.
    const auto row = ops::mirrors::toJson(ops::mirrors::get(superUser, s.mirrorId));
    EXPECT_EQ(row.value("pending_changes", 99), 0) << row.dump();
    EXPECT_TRUE(row.at("first_copy").value("finished", false)) << row.dump();
    EXPECT_TRUE(row.value("link_up", false)) << row.dump();
    EXPECT_TRUE(row.at("confirmed_at").is_number_integer()) << row.dump();
    ASSERT_TRUE(row.at("settings").is_object()) << row.dump();
    EXPECT_FALSE(row.at("settings").at("versions").value("enabled", true)) << "a mirror's versions setting, off";
    EXPECT_FALSE(row.at("settings").value("mirror_all", true));
}

TEST_F(MirrorRotateDbTest, WithTheLinkDownOrTheMirrorNotLiveTheRotationIsRefusedAndNothingChanges) {
    auto s = begin([](const EnginePtr& e) { write(e, "/a.txt", "alpha"); });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const auto link = std::make_shared<Link>();
    link->up = false;
    linkTo(s, link);

    const auto refusal = [&]() -> std::string {
        toCore(s);
        std::string code;
        {
            AsCore as;
            try {
                s.core->encryptionManager->prepare_key_rotation();
            } catch (const ops::Refused& e) {
                code = e.code;
                EXPECT_NE(std::string(e.what()).find("vh mirror cancel"), std::string::npos) << e.what();
            }
        }
        toMirror(s);
        return code;
    };
    toCore(s);
    const auto version = s.core->encryptionManager->get_key_version();
    const auto seq = mq::MirrorVaults::get(s.coreId)->last_seq;
    toMirror(s);

    EXPECT_EQ(refusal(), "mirror_link_down");
    link->up = true;
    ASSERT_TRUE(mq::MirrorVaults::stop(s.coreId, "stopped", "mirror_key_missing", {{"why", "a test"}}));
    EXPECT_EQ(refusal(), "mirror_not_live");
    ASSERT_TRUE(mq::MirrorVaults::setState(s.coreId, "live"));
    EXPECT_TRUE(link->delivered.empty()) << "nothing was sent while the mirror was not live";

    toCore(s);
    EXPECT_EQ(s.core->encryptionManager->get_key_version(), version) << "nothing rotated";
    EXPECT_FALSE(db::query::vault::Key::keyRotationInProgress(s.coreId));
    EXPECT_EQ(mq::MirrorVaults::get(s.coreId)->last_seq, seq) << "nothing logged";
    toMirror(s);
    EXPECT_EQ(mirrorRow(s).state, "live");

    // The mirror refuses a version it holds with another key: refused the same way, nothing rotated.
    toCore(s);
    {
        AsCore as;
        // A version at or below the mirror's current one, with a key the mirror does not hold under it.
        const auto key = crypto::SecretKey::random();
        const db::query::vault::Key::Provenance p{.key_check = vh::vault::keyCheck(key->bytes(), s.coreId, 1),
                                                  .attestation_key_id = 1,
                                                  .attestation = std::vector<uint8_t>(64, 1)};
        try {
            vh::mirror::rotate::deliverBeforeRotation(s.coreId, 1, key->bytes(), p);
            ADD_FAILURE() << "accepted";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "mirror_key_refused") << e.what();
        }
    }
    toMirror(s);
}

TEST_F(MirrorRotateDbTest, AMirrorRestartedMidRotationFinishes) {
    auto s = begin([](const EnginePtr& e) {
        e->mkdir("/docs", superUser);
        for (const auto& [path, text] : files()) write(e, path, text);
    });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const auto link = std::make_shared<Link>();
    linkTo(s, link);

    // Delivered and one file re-sealed; the mirror restarts before following: the version is held, not current.
    rotateOnCore(s, 1);
    const auto newVersion = link->delivered.at(0).at("version").get<uint32_t>();
    const auto before = mirrorEm(s)->get_key_version();
    live(s.mirrorId)->encryptionManager = std::make_shared<vault::EncryptionManager>(s.mirrorId);
    EXPECT_EQ(mirrorEm(s)->get_key_version(), before);
    EXPECT_TRUE(mirrorEm(s)->hasKeyVersion(newVersion)) << "held across the restart";

    // It follows (the version becomes current) and restarts again with files on both versions.
    followAll(wire, s);
    EXPECT_EQ(mirrorEm(s)->get_key_version(), newVersion);
    receiveAll(s);
    live(s.mirrorId)->encryptionManager = std::make_shared<vault::EncryptionManager>(s.mirrorId);
    EXPECT_EQ(mirrorEm(s)->get_key_version(), newVersion);

    // The core finishes; the mirror catches up and ends where the core is.
    rotateOnCore(s, SIZE_MAX, false);
    EXPECT_EQ(link->delivered.size(), 1u) << "the version goes over once per rotation";
    followAll(wire, s);
    receiveAll(s);
    expectSettled(s);
    for (const auto& [path, text] : files()) {
        EXPECT_EQ(keyVersionOf(s.mirrorId, path), newVersion) << path;
        EXPECT_EQ(plaintextOnMirror(s, path), text) << path;
    }
}

TEST_F(MirrorRotateDbTest, ARepeatedDeliveryIsAnsweredAndAKeySalvageStaysRefused) {
    auto s = begin([](const EnginePtr& e) { write(e, "/a.txt", "alpha"); });
    Wire wire(s);
    followAll(wire, s);
    receiveAll(s);
    const auto link = std::make_shared<Link>();
    linkTo(s, link);
    rotateOnCore(s);
    ASSERT_EQ(link->delivered.size(), 1u);
    followAll(wire, s);

    // The same delivery again (an answer that was lost): the same answer, nothing changes.
    const auto again = link->delivered.front();
    toCore(s);
    {
        AsCore as;
        // Re-sent through the link (it re-signs with the pinned seed).
        const auto t = start::transport();
        const auto answer = t.request(mirrorPeer, "peer.mirror.key", again, std::chrono::seconds(5));
        ASSERT_TRUE(answer);
        EXPECT_EQ(answer->value("status", ""), "OK") << answer->dump();
    }
    toMirror(s);
    EXPECT_EQ(mirrorRow(s).state, "live");

    // A key salvage mints a version: refused on both servers of a mirrored vault.
    toCore(s);
    {
        AsCore as;
        EXPECT_THROW((void)vault::EncryptionManager::mintSalvageKey(s.coreId, 9, true), ops::Refused);
    }
    toMirror(s);
    EXPECT_THROW((void)vault::EncryptionManager::mintSalvageKey(s.mirrorId, 9, true), ops::Refused);
    // A copy never rotates on its own.
    EXPECT_THROW(mirrorEm(s)->prepare_key_rotation(), ops::Refused);
}

}
