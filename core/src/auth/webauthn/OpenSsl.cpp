#include "auth/webauthn/OpenSsl.hpp"

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/param_build.h>
#include <openssl/rsa.h>

#include <cstring>
#include <string>

namespace vh::auth::webauthn::openssl {

namespace {

struct PkeyCtxFree {
    void operator()(EVP_PKEY_CTX* c) const { EVP_PKEY_CTX_free(c); }
};
struct ParamBldFree {
    void operator()(OSSL_PARAM_BLD* b) const { OSSL_PARAM_BLD_free(b); }
};
struct ParamFree {
    void operator()(OSSL_PARAM* p) const { OSSL_PARAM_free(p); }
};
struct BnFree {
    void operator()(BIGNUM* b) const { BN_free(b); }
};
struct MdCtxFree {
    void operator()(EVP_MD_CTX* c) const { EVP_MD_CTX_free(c); }
};

Pkey importPublic(const char* type, OSSL_PARAM_BLD* bld) {
    const std::unique_ptr<OSSL_PARAM, ParamFree> params(OSSL_PARAM_BLD_to_param(bld));
    if (!params) return nullptr;
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> ctx(EVP_PKEY_CTX_new_from_name(nullptr, type, nullptr));
    if (!ctx || EVP_PKEY_fromdata_init(ctx.get()) != 1) return nullptr;
    EVP_PKEY* raw = nullptr;
    if (EVP_PKEY_fromdata(ctx.get(), &raw, EVP_PKEY_PUBLIC_KEY, params.get()) != 1 || !raw) return nullptr;
    Pkey key(raw);
    const std::unique_ptr<EVP_PKEY_CTX, PkeyCtxFree> check(EVP_PKEY_CTX_new_from_pkey(nullptr, key.get(), nullptr));
    if (!check || EVP_PKEY_public_check(check.get()) != 1) return nullptr;
    return key;
}

}

void PkeyDeleter::operator()(evp_pkey_st* key) const { EVP_PKEY_free(key); }

Pkey p256(const ByteView x, const ByteView y) {
    if (x.size() != 32 || y.size() != 32) return nullptr;
    unsigned char point[65];
    point[0] = 0x04;  // uncompressed
    std::memcpy(point + 1, x.data(), 32);
    std::memcpy(point + 33, y.data(), 32);
    const std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
    if (!bld
        || OSSL_PARAM_BLD_push_utf8_string(bld.get(), OSSL_PKEY_PARAM_GROUP_NAME, "prime256v1", 0) != 1
        || OSSL_PARAM_BLD_push_octet_string(bld.get(), OSSL_PKEY_PARAM_PUB_KEY, point, sizeof point) != 1)
        return nullptr;
    return importPublic("EC", bld.get());
}

Pkey rsa(const ByteView n, const ByteView e) {
    if (n.empty() || e.empty()) return nullptr;
    const std::unique_ptr<BIGNUM, BnFree> bn(BN_bin2bn(n.data(), static_cast<int>(n.size()), nullptr));
    const std::unique_ptr<BIGNUM, BnFree> be(BN_bin2bn(e.data(), static_cast<int>(e.size()), nullptr));
    const std::unique_ptr<OSSL_PARAM_BLD, ParamBldFree> bld(OSSL_PARAM_BLD_new());
    if (!bn || !be || !bld
        || OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_N, bn.get()) != 1
        || OSSL_PARAM_BLD_push_BN(bld.get(), OSSL_PKEY_PARAM_RSA_E, be.get()) != 1)
        return nullptr;
    return importPublic("RSA", bld.get());
}

int rsaBits(const Pkey& key) {
    if (!key || EVP_PKEY_get_base_id(key.get()) != EVP_PKEY_RSA) return 0;
    return EVP_PKEY_get_bits(key.get());
}

Kind kind(const evp_pkey_st* key) {
    if (!key) return Kind::Other;
    switch (EVP_PKEY_get_base_id(key)) {
        case EVP_PKEY_RSA: return Kind::Rsa;
        case EVP_PKEY_ED25519: return Kind::Ed25519;
        case EVP_PKEY_EC: {
            char group[64] = {};
            std::size_t len = 0;
            if (EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME, group, sizeof group, &len) != 1)
                return Kind::Other;
            return std::string(group, len) == "prime256v1" ? Kind::P256 : Kind::Other;
        }
        default: return Kind::Other;
    }
}

bool verify(evp_pkey_st* key, const ByteView message, const ByteView signature) {
    const auto k = kind(key);
    if (k == Kind::Other || signature.empty()) return false;
    const std::unique_ptr<EVP_MD_CTX, MdCtxFree> md(EVP_MD_CTX_new());
    if (!md) return false;
    EVP_PKEY_CTX* pctx = nullptr;
    const char* digest = k == Kind::Ed25519 ? nullptr : "SHA256";
    if (EVP_DigestVerifyInit_ex(md.get(), &pctx, digest, nullptr, nullptr, key, nullptr) != 1) return false;
    if (k == Kind::Rsa && EVP_PKEY_CTX_set_rsa_padding(pctx, RSA_PKCS1_PADDING) != 1) return false;
    return EVP_DigestVerify(md.get(), signature.data(), signature.size(), message.data(), message.size()) == 1;
}

}
