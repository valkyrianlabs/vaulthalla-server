#include "device/ServerIdentity.hpp"

#include "concurrency/AtomicSharedPtr.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"

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

#include <fstream>
#include <memory>
#include <sstream>
#include <stdexcept>

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

std::shared_ptr<const ServerIdentity> loadOrCreateServerIdentity() {
    // init() unseals the stored key when there is one and only seals the candidate when there is none.
    const auto candidate = ServerIdentity::generate();
    auto candidateScalar = candidate->privateScalar();
    ::vh::crypto::secrets::KeyProvider provider(paths::testMode ? "test_device_tls" : "device_tls");
    provider.init(std::string(candidateScalar.begin(), candidateScalar.end()));
    OPENSSL_cleanse(candidateScalar.data(), candidateScalar.size());

    const auto path = serverCertificatePath();
    std::string pem;
    if (std::error_code ec; std::filesystem::is_regular_file(path, ec)) {
        std::ifstream in(path, std::ios::binary);
        std::ostringstream buf;
        buf << in.rdbuf();
        pem = buf.str();
    }

    auto identity = ServerIdentity::fromPrivateScalar(provider.getMasterKey(), pem);
    if (identity->certificateIsNew()) {
        const auto& text = identity->certificatePem();
        fs::ops::writeFileAtomic(path, std::span(reinterpret_cast<const uint8_t*>(text.data()), text.size()));
        log::Registry::runtime()->info("[device] Issued the device listener certificate (SPKI sha256 {})",
                                       identity->spkiHex());
    }
    return identity;
}

std::shared_ptr<const ServerIdentity> currentServerIdentity() { return current().load(); }

void setCurrentServerIdentity(std::shared_ptr<const ServerIdentity> identity) { current().store(std::move(identity)); }

}
