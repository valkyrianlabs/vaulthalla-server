#include "device/ServerIdentity.hpp"

#include "concurrency/AtomicSharedPtr.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "db/Transactions.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"

#include <pqxx/pqxx>

#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/param_build.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <paths.h>

#include <atomic>
#include <fstream>
#include <memory>
#include <mutex>
#include <sstream>
#include <stdexcept>
#include <utility>
#include <vector>

namespace vh::device {

namespace {

struct BnFree { void operator()(BIGNUM* p) const noexcept { BN_clear_free(p); } };
struct BnCtxFree { void operator()(BN_CTX* p) const noexcept { BN_CTX_free(p); } };
struct GroupFree { void operator()(EC_GROUP* p) const noexcept { EC_GROUP_free(p); } };
struct PointFree { void operator()(EC_POINT* p) const noexcept { EC_POINT_free(p); } };
struct ParamBldFree { void operator()(OSSL_PARAM_BLD* p) const noexcept { OSSL_PARAM_BLD_free(p); } };
struct ParamFree { void operator()(OSSL_PARAM* p) const noexcept { OSSL_PARAM_free(p); } };
struct PkeyCtxFree { void operator()(EVP_PKEY_CTX* p) const noexcept { EVP_PKEY_CTX_free(p); } };
struct BioFree { void operator()(BIO* p) const noexcept { BIO_free(p); } };
struct ExtFree { void operator()(X509_EXTENSION* p) const noexcept { X509_EXTENSION_free(p); } };
struct AsnIntFree { void operator()(ASN1_INTEGER* p) const noexcept { ASN1_INTEGER_free(p); } };

constexpr std::size_t kScalarBytes = 32;
// The pin carries trust, not the dates (spec §2: "long validity, >= 10 years").
constexpr long kValiditySeconds = 20L * 365 * 24 * 60 * 60;
constexpr const char* kCommonName = "Vaulthalla device listener";

[[noreturn]] void fail(const std::string& what) { throw std::runtime_error("device server identity: " + what); }

EVP_PKEY* keyFromScalar(const std::span<const uint8_t> scalar) {
    if (scalar.size() != kScalarBytes) fail("the sealed key is not a 32-byte P-256 scalar");
    const std::unique_ptr<EC_GROUP, GroupFree> group(EC_GROUP_new_by_curve_name(NID_X9_62_prime256v1));
    const std::unique_ptr<BN_CTX, BnCtxFree> bnctx(BN_CTX_new());
    const std::unique_ptr<BIGNUM, BnFree> priv(BN_bin2bn(scalar.data(), static_cast<int>(scalar.size()), nullptr));
    if (!group || !bnctx || !priv) fail("out of memory");
    if (BN_is_zero(priv.get()) || BN_cmp(priv.get(), EC_GROUP_get0_order(group.get())) >= 0)
        fail("the sealed key is not a valid P-256 scalar");

    const std::unique_ptr<EC_POINT, PointFree> pub(EC_POINT_new(group.get()));
    if (!pub || EC_POINT_mul(group.get(), pub.get(), priv.get(), nullptr, nullptr, bnctx.get()) != 1)
        fail("cannot derive the public key");
    unsigned char point[65]{};
    if (EC_POINT_point2oct(group.get(), pub.get(), POINT_CONVERSION_UNCOMPRESSED, point, sizeof(point), bnctx.get()) !=
        sizeof(point))
        fail("cannot encode the public key");

    const std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
    if (!bld || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1 ||
        OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_PRIV_KEY, priv.get()) != 1 ||
        OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point, sizeof(point)) != 1)
        fail("cannot build the key parameters");
    const std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld.get()));
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> ctx(EVP_PKEY_CTX_new_from_name(nullptr, "EC", nullptr));
    EVP_PKEY* key = nullptr;
    if (!params || !ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1 ||
        EVP_PKEY_fromdata(ctx.get(), &key, EVP_PKEY_KEYPAIR, params.get()) != 1 || !key)
        fail("cannot load the key");
    return key;
}

std::vector<uint8_t> scalarOf(const EVP_PKEY* key) {
    BIGNUM* raw = nullptr;
    if (EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_PRIV_KEY, &raw) != 1 || !raw) fail("cannot read the private key");
    const std::unique_ptr<BIGNUM, BnFree> bn(raw);
    std::vector<uint8_t> out(kScalarBytes);
    if (BN_bn2binpad(bn.get(), out.data(), static_cast<int>(out.size())) != static_cast<int>(out.size()))
        fail("cannot encode the private key");
    return out;
}

void addExtension(X509* cert, X509V3_CTX* ctx, const int nid, const char* value) {
    const std::unique_ptr<X509_EXTENSION, ExtFree> ext(X509V3_EXT_conf_nid(nullptr, ctx, nid, value));
    if (!ext || X509_add_ext(cert, ext.get(), -1) != 1) fail("cannot add a certificate extension");
}

X509* issueCertificate(EVP_PKEY* key) {
    X509* cert = X509_new();
    if (!cert) fail("out of memory");
    try {
        if (X509_set_version(cert, X509_VERSION_3) != 1) fail("cannot set the certificate version");

        // 20 random bytes, positive (spec's device profile uses the same).
        unsigned char serial[20]{};
        if (RAND_bytes(serial, sizeof(serial)) != 1) fail("CSPRNG failure");
        serial[0] &= 0x7f;
        serial[0] |= 0x01;
        const std::unique_ptr<BIGNUM, BnFree> serialBn(BN_bin2bn(serial, sizeof(serial), nullptr));
        const std::unique_ptr<ASN1_INTEGER, AsnIntFree> serialAsn(serialBn ? BN_to_ASN1_INTEGER(serialBn.get(), nullptr)
                                                                           : nullptr);
        if (!serialAsn || X509_set_serialNumber(cert, serialAsn.get()) != 1) fail("cannot set the serial number");

        if (!X509_gmtime_adj(X509_getm_notBefore(cert), -60L * 60) ||
            !X509_gmtime_adj(X509_getm_notAfter(cert), kValiditySeconds))
            fail("cannot set the validity");

        X509_NAME* name = X509_get_subject_name(cert);
        if (X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_UTF8, reinterpret_cast<const unsigned char*>(kCommonName),
                                       -1, -1, 0) != 1 ||
            X509_set_issuer_name(cert, name) != 1)
            fail("cannot set the subject");
        if (X509_set_pubkey(cert, key) != 1) fail("cannot set the public key");

        X509V3_CTX ctx;
        X509V3_set_ctx_nodb(&ctx);
        X509V3_set_ctx(&ctx, cert, cert, nullptr, nullptr, 0);
        addExtension(cert, &ctx, NID_basic_constraints, "critical,CA:FALSE");
        addExtension(cert, &ctx, NID_key_usage, "critical,digitalSignature");
        addExtension(cert, &ctx, NID_ext_key_usage, "serverAuth");
        addExtension(cert, &ctx, NID_subject_key_identifier, "hash");

        if (X509_sign(cert, key, EVP_sha256()) <= 0) fail("cannot sign the certificate");
        return cert;
    } catch (...) {
        X509_free(cert);
        throw;
    }
}

X509* parsePem(const std::string_view pem) {
    if (pem.empty()) return nullptr;
    const std::unique_ptr<BIO, BioFree> bio(BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size())));
    return bio ? PEM_read_bio_X509(bio.get(), nullptr, nullptr, nullptr) : nullptr;
}

std::string toPem(X509* cert) {
    const std::unique_ptr<BIO, BioFree> bio(BIO_new(BIO_s_mem()));
    if (!bio || PEM_write_bio_X509(bio.get(), cert) != 1) fail("cannot encode the certificate");
    char* data = nullptr;
    const long len = BIO_get_mem_data(bio.get(), &data);
    return {data, static_cast<std::size_t>(len)};
}

concurrency::AtomicSharedPtr<const ServerIdentity>& current() {
    static concurrency::AtomicSharedPtr<const ServerIdentity> identity;
    return identity;
}

}

ServerIdentity::~ServerIdentity() {
    X509_free(certificate_);
    EVP_PKEY_free(key_);
}

std::shared_ptr<const ServerIdentity> ServerIdentity::generate() {
    EVP_PKEY* key = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-256");
    if (!key) fail("cannot generate a key");
    auto scalar = scalarOf(key);
    EVP_PKEY_free(key);
    auto out = fromPrivateScalar(scalar, {});
    OPENSSL_cleanse(scalar.data(), scalar.size());
    return out;
}

std::shared_ptr<const ServerIdentity> ServerIdentity::fromPrivateScalar(const std::span<const uint8_t> scalar,
                                                                        const std::string_view certificatePem) {
    std::shared_ptr<ServerIdentity> self(new ServerIdentity());
    self->key_ = keyFromScalar(scalar);

    if (X509* existing = parsePem(certificatePem)) {
        if (X509_check_private_key(existing, self->key_) == 1) self->certificate_ = existing;
        else X509_free(existing);
    }
    if (!self->certificate_) {
        self->certificate_ = issueCertificate(self->key_);
        self->certificateIsNew_ = true;
    }
    self->certificatePem_ = toPem(self->certificate_);

    const auto pub = crypto::p256KeyOf(self->certificate_);
    if (!pub) fail("the certificate does not carry a P-256 key");
    self->spki_ = pub->spkiSha256;
    return self;
}

std::vector<uint8_t> ServerIdentity::privateScalar() const { return scalarOf(key_); }

std::filesystem::path serverCertificatePath() { return paths::getBackingPath() / "device_server_certificate.pem"; }

namespace {

std::atomic<void (*)(std::string_view)> rotationHook{nullptr};

void identityCrashPoint(const std::string_view point) {
    if (const auto hook = rotationHook.load()) hook(point);
}

std::string readCertificateFile() {
    const auto path = serverCertificatePath();
    std::string pem;
    if (std::error_code ec; std::filesystem::is_regular_file(path, ec)) {
        std::ifstream in(path, std::ios::binary);
        std::ostringstream buf;
        buf << in.rdbuf();
        pem = buf.str();
    }
    return pem;
}

void writeCertificateFile(const ServerIdentity& identity) {
    const auto& text = identity.certificatePem();
    fs::ops::writeFileAtomic(serverCertificatePath(),
                             std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
}

std::vector<unsigned int> pendingIdentityDiscards() {
    return db::Transactions::exec("device::identity.discards", [](pqxx::work& txn) {
        std::vector<unsigned int> out;
        for (const auto& r : txn.exec("SELECT unnest(discard_versions) FROM master_secret_state WHERE slot = "
                                      "'device_tls'"))
            out.push_back(r[0].as<unsigned int>());
        return out;
    });
}

// Deletes the retired identity keys the state lists (never the current one), then forgets them.
void discardRetiredIdentities(const unsigned int current) {
    for (const auto v : pendingIdentityDiscards()) {
        if (v != current) {
            ::vh::crypto::secrets::KeyProvider(identitySlotName(v)).destroySealed();
            log::Registry::runtime()->info("[device] Deleted the retired device listener key (version {})", v);
        }
        db::Transactions::exec("device::identity.discarded", [&](pqxx::work& txn) {
            txn.exec("UPDATE master_secret_state SET discard_versions = array_remove(discard_versions, $1) "
                     "WHERE slot = 'device_tls'",
                     pqxx::params{v});
        });
    }
}

}

std::string identitySlotName(const unsigned int version) {
    if (version == 0) throw std::invalid_argument("device identity versions start at 1");
    const std::string base = paths::testMode ? "test_device_tls" : "device_tls";
    return version == 1 ? base : base + ".v" + std::to_string(version);
}

unsigned int currentIdentityVersion() {
    return db::Transactions::exec("device::identity.version", [](pqxx::work& txn) {
        return txn.exec("SELECT vh_master_version('device_tls')").one_field_ref().as<unsigned int>();
    });
}

std::shared_ptr<const ServerIdentity> loadOrCreateServerIdentity() {
    const auto version = currentIdentityVersion();
    // init() unseals the stored key when there is one and only seals the candidate when there is none.
    const auto candidate = ServerIdentity::generate();
    auto candidateScalar = candidate->privateScalar();
    ::vh::crypto::secrets::KeyProvider provider(identitySlotName(version));
    try {
        provider.init(candidateScalar);
    } catch (...) {
        OPENSSL_cleanse(candidateScalar.data(), candidateScalar.size());
        throw;
    }
    OPENSSL_cleanse(candidateScalar.data(), candidateScalar.size());

    auto identity = ServerIdentity::fromPrivateScalar(provider.getMasterKey(), readCertificateFile());
    if (identity->certificateIsNew()) {
        writeCertificateFile(*identity);
        log::Registry::runtime()->info("[device] Issued the device listener certificate (SPKI sha256 {})",
                                       identity->spkiHex());
    }
    try {
        discardRetiredIdentities(version);
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[device] Could not delete a retired device listener key: {}", e.what());
    }
    return identity;
}

IdentityRotation rotateServerIdentity() {
    static std::mutex rotationMutex;
    std::scoped_lock lock(rotationMutex);

    IdentityRotation out;
    // The next number is taken first, and listed for deletion until the switch claims it: a crash before the switch
    // never lets a later rotation reuse the number, and the next start deletes the key it may have sealed.
    const auto numbers = db::Transactions::exec("device::identity.next", [](pqxx::work& txn) {
        const auto r = txn.exec("UPDATE master_secret_state SET highest_version = highest_version + 1, "
                                "discard_versions = array_append(discard_versions, highest_version + 1) "
                                "WHERE slot = 'device_tls' RETURNING version, highest_version")
                           .one_row();
        return std::pair{r[0].as<unsigned int>(), r[1].as<unsigned int>()};
    });
    const unsigned int from = numbers.first, target = numbers.second;
    out.from = from;
    out.to = target;
    {
        ::vh::crypto::secrets::KeyProvider current(identitySlotName(from));
        if (current.sealedExists()) {
            current.init();
            out.previous_spki_sha256 = ServerIdentity::fromPrivateScalar(current.getMasterKey(), {})->spkiHex();
        }
    }

    // Seal the new key beside the current one and read it back: only a key that unseals is ever switched to.
    const auto fresh = ServerIdentity::generate();
    {
        auto scalar = fresh->privateScalar();
        try {
            ::vh::crypto::secrets::KeyProvider slot(identitySlotName(target));
            slot.destroySealed();  // a leftover of an interrupted rotation, never switched to
            slot.init(scalar);
        } catch (...) {
            OPENSSL_cleanse(scalar.data(), scalar.size());
            throw;
        }
        OPENSSL_cleanse(scalar.data(), scalar.size());
    }
    ::vh::crypto::secrets::KeyProvider back(identitySlotName(target));
    back.init();
    out.identity = ServerIdentity::fromPrivateScalar(back.getMasterKey(), {});
    if (out.identity->spkiSha256() != fresh->spkiSha256())
        throw std::runtime_error("the new device listener key did not unseal to the key that was sealed; nothing was "
                                 "switched");
    identityCrashPoint("identity_sealed");

    // Switch: every paired device is revoked in the same transaction that records the new key.
    out.devices_revoked = db::Transactions::exec("device::identity.switch", [&](pqxx::work& txn) {
        const auto state = txn.exec("SELECT version FROM master_secret_state WHERE slot = 'device_tls' FOR UPDATE")
                               .one_field_ref()
                               .as<unsigned int>();
        if (state != from) throw std::runtime_error("the device identity changed during the rotation");
        const auto revoked = txn.exec("UPDATE devices SET revoked_at = CURRENT_TIMESTAMP WHERE revoked_at IS NULL")
                                 .affected_rows();
        txn.exec("UPDATE master_secret_state SET version = $1, "
                 "discard_versions = array_append(array_remove(array_remove(discard_versions, $1), $2), $2) "
                 "WHERE slot = 'device_tls'",
                 pqxx::params{target, from});
        return static_cast<std::size_t>(revoked);
    });
    identityCrashPoint("identity_switched");

    writeCertificateFile(*out.identity);
    log::Registry::runtime()->warn("[device] Rotated the device listener identity from version {} to {} (SPKI sha256 "
                                   "{}); {} paired device(s) revoked",
                                   from, target, out.identity->spkiHex(), out.devices_revoked);
    try {
        discardRetiredIdentities(target);
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[device] Could not delete the retired device listener key yet ({}); the next "
                                       "start deletes it",
                                       e.what());
    }
    return out;
}

void setIdentityRotationHookForTesting(void (*hook)(std::string_view point)) { rotationHook.store(hook); }

std::shared_ptr<const ServerIdentity> currentServerIdentity() { return current().load(); }

void setCurrentServerIdentity(std::shared_ptr<const ServerIdentity> identity) { current().store(std::move(identity)); }

}
