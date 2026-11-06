#include "auth/webauthn/Attestation.hpp"

#include "auth/webauthn/OpenSsl.hpp"

#include <openssl/asn1.h>
#include <openssl/objects.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <cstring>
#include <memory>

namespace vh::auth::webauthn::attestation {

namespace {

struct X509Free {
    void operator()(X509* c) const { X509_free(c); }
};
struct OctetFree {
    void operator()(ASN1_OCTET_STRING* s) const { ASN1_OCTET_STRING_free(s); }
};
struct ObjectFree {
    void operator()(ASN1_OBJECT* o) const { ASN1_OBJECT_free(o); }
};
using Certificate = std::unique_ptr<X509, X509Free>;

constexpr std::string_view kAttestationOu = "Authenticator Attestation";
constexpr const char* kAaguidOid = "1.3.6.1.4.1.45724.1.1.4";  // id-fido-gen-ce-aaguid

Parsed refuseObject() { return {std::nullopt, Failure::AttestationMalformed}; }
Verified refuseStatement(const Failure f) { return {AttestationType::None, f}; }

bool isFormatIdentifier(const std::string_view fmt) {
    return !fmt.empty() && fmt.size() <= 32 && std::ranges::all_of(fmt, [](const char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-';
    });
}

Certificate certificate(const ByteView der) {
    if (der.empty()) return nullptr;
    const unsigned char* p = der.data();
    Certificate cert(d2i_X509(nullptr, &p, static_cast<long>(der.size())));
    if (!cert || p != der.data() + der.size()) return nullptr;
    return cert;
}

// Exactly one subject attribute of this kind; its value when `value` is wanted.
bool oneSubject(X509_NAME* name, const int nid, std::string_view* value = nullptr) {
    const int idx = X509_NAME_get_index_by_NID(name, nid, -1);
    if (idx < 0 || X509_NAME_get_index_by_NID(name, nid, idx) >= 0) return false;
    const ASN1_STRING* data = X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, idx));
    if (!data || ASN1_STRING_length(data) <= 0) return false;
    if (value)
        *value = std::string_view(reinterpret_cast<const char*>(ASN1_STRING_get0_data(data)),
                                  static_cast<std::size_t>(ASN1_STRING_length(data)));
    return true;
}

// WebAuthn L3 section 8.2.1, "Certificate Requirements for Packed Attestation Statements".
bool meetsPackedRequirements(X509* cert, const Aaguid& aaguid) {
    if (X509_get_version(cert) != X509_VERSION_3) return false;
    X509_NAME* subject = X509_get_subject_name(cert);
    std::string_view ou;
    if (!subject || !oneSubject(subject, NID_countryName) || !oneSubject(subject, NID_organizationName)
        || !oneSubject(subject, NID_organizationalUnitName, &ou) || ou != kAttestationOu
        || !oneSubject(subject, NID_commonName))
        return false;
    const auto flags = X509_get_extension_flags(cert);
    if (flags & (EXFLAG_INVALID | EXFLAG_CA)) return false;

    const std::unique_ptr<ASN1_OBJECT, ObjectFree> oid(OBJ_txt2obj(kAaguidOid, 1));
    if (!oid) return false;
    const int idx = X509_get_ext_by_OBJ(cert, oid.get(), -1);
    if (idx < 0) return true;
    if (X509_get_ext_by_OBJ(cert, oid.get(), idx) >= 0) return false;  // twice
    X509_EXTENSION* ext = X509_get_ext(cert, idx);
    if (!ext || X509_EXTENSION_get_critical(ext) != 0) return false;
    const ASN1_OCTET_STRING* outer = X509_EXTENSION_get_data(ext);
    const unsigned char* q = ASN1_STRING_get0_data(outer);
    const auto outerLen = ASN1_STRING_length(outer);
    const std::unique_ptr<ASN1_OCTET_STRING, OctetFree> inner(d2i_ASN1_OCTET_STRING(nullptr, &q, outerLen));
    if (!inner || q != ASN1_STRING_get0_data(outer) + outerLen || ASN1_STRING_length(inner.get()) != 16) return false;
    return std::memcmp(ASN1_STRING_get0_data(inner.get()), aaguid.data(), aaguid.size()) == 0;
}

bool keyMatchesAlgorithm(evp_pkey_st* key, const std::int64_t alg) {
    switch (alg) {
        case static_cast<std::int64_t>(Algorithm::ES256): return openssl::kind(key) == openssl::Kind::P256;
        case static_cast<std::int64_t>(Algorithm::EdDSA): return openssl::kind(key) == openssl::Kind::Ed25519;
        case static_cast<std::int64_t>(Algorithm::RS256):
            return openssl::kind(key) == openssl::Kind::Rsa && EVP_PKEY_get_bits(key) >= cose::kMinRsaBits
                && EVP_PKEY_get_bits(key) <= cose::kMaxRsaBits;
        default: return false;
    }
}

Verified verifyPacked(const cbor_item_t* stmt, const cose::PublicKey& credentialKey, const Aaguid& aaguid,
                      const ByteView message) {
    for (std::size_t i = 0; i < cbor::size(stmt); ++i) {
        const auto key = cbor::asText(cbor::mapKeyAt(stmt, i));
        if (!key || (*key != "alg" && *key != "sig" && *key != "x5c"))  // ecdaaKeyId is gone since Level 2
            return refuseStatement(Failure::AttestationMalformed);
    }
    const auto alg = cbor::asInt(cbor::find(stmt, "alg"));
    const auto sig = cbor::asBytes(cbor::find(stmt, "sig"));
    if (!alg || !sig || sig->empty()) return refuseStatement(Failure::AttestationMalformed);

    const auto* x5c = cbor::find(stmt, "x5c");
    if (!x5c) {
        // Self attestation.
        if (*alg != static_cast<std::int64_t>(credentialKey.algorithm))
            return refuseStatement(Failure::AttestationAlgorithmMismatch);
        if (!cose::verify(credentialKey, message, *sig)) return refuseStatement(Failure::AttestationSignatureInvalid);
        return {AttestationType::Self, Failure::None};
    }

    if (!cbor::isArray(x5c) || cbor::size(x5c) == 0 || cbor::size(x5c) > kMaxCertificates)
        return refuseStatement(Failure::AttestationMalformed);
    Certificate leaf;
    for (std::size_t i = 0; i < cbor::size(x5c); ++i) {
        const auto der = cbor::asBytes(cbor::arrayAt(x5c, i));
        if (!der) return refuseStatement(Failure::AttestationMalformed);
        auto cert = certificate(*der);
        if (!cert) return refuseStatement(Failure::AttestationCertificateInvalid);
        if (i == 0) leaf = std::move(cert);
    }
    evp_pkey_st* leafKey = X509_get0_pubkey(leaf.get());
    if (!leafKey || !keyMatchesAlgorithm(leafKey, *alg)) return refuseStatement(Failure::AttestationAlgorithmMismatch);
    if (!meetsPackedRequirements(leaf.get(), aaguid)) return refuseStatement(Failure::AttestationCertificateInvalid);
    if (*alg == static_cast<std::int64_t>(Algorithm::ES256) && (sig->size() < 8 || sig->size() > 72))
        return refuseStatement(Failure::AttestationSignatureInvalid);
    if (!openssl::verify(leafKey, message, *sig)) return refuseStatement(Failure::AttestationSignatureInvalid);
    return {AttestationType::Basic, Failure::None};
}

}

Parsed parse(const ByteView encoded) {
    if (encoded.size() > kMaxBytes) return {std::nullopt, Failure::InputTooLarge};
    auto root = cbor::decode(encoded);
    if (!root || !cbor::isMap(root.get()) || cbor::size(root.get()) != 3) return refuseObject();
    const auto fmt = cbor::asText(cbor::find(root.get(), "fmt"));
    const auto* stmt = cbor::find(root.get(), "attStmt");
    const auto authData = cbor::asBytes(cbor::find(root.get(), "authData"));
    if (!fmt || !isFormatIdentifier(*fmt) || !cbor::isMap(stmt) || !authData) return refuseObject();
    Object o;
    o.fmt = std::string(*fmt);
    o.authData.assign(authData->begin(), authData->end());
    o.statement = stmt;
    o.root = std::move(root);  // the tree stays where it is: `statement` remains valid
    return {std::move(o), Failure::None};
}

Verified verify(const Object& object, const cose::PublicKey& credentialKey, const Aaguid& aaguid,
                const ByteView clientDataHash) {
    if (object.fmt == "none") {
        if (cbor::size(object.statement) != 0) return refuseStatement(Failure::AttestationMalformed);
        return {AttestationType::None, Failure::None};
    }
    if (object.fmt == "packed") {
        Bytes message(object.authData);
        message.insert(message.end(), clientDataHash.begin(), clientDataHash.end());
        return verifyPacked(object.statement, credentialKey, aaguid, message);
    }
    return {AttestationType::Unverified, Failure::None};
}

}
