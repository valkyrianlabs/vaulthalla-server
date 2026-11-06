#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn {

std::string_view toString(const Failure f) {
    switch (f) {
        case Failure::None: return "none";
        case Failure::NotConfigured: return "not_configured";
        case Failure::MalformedResponse: return "malformed_response";
        case Failure::InputTooLarge: return "input_too_large";
        case Failure::ChallengeUnknown: return "challenge_unknown";
        case Failure::ChallengeExpired: return "challenge_expired";
        case Failure::ChallengeSessionMismatch: return "challenge_session_mismatch";
        case Failure::ChallengePurposeMismatch: return "challenge_purpose_mismatch";
        case Failure::ChallengeUserMismatch: return "challenge_user_mismatch";
        case Failure::ChallengeScopeMismatch: return "challenge_scope_mismatch";
        case Failure::ClientDataMalformed: return "client_data_malformed";
        case Failure::ClientDataTypeMismatch: return "client_data_type_mismatch";
        case Failure::ClientDataChallengeMismatch: return "client_data_challenge_mismatch";
        case Failure::OriginMismatch: return "origin_mismatch";
        case Failure::CrossOrigin: return "cross_origin";
        case Failure::TopOrigin: return "top_origin";
        case Failure::AuthenticatorDataMalformed: return "authenticator_data_malformed";
        case Failure::RpIdHashMismatch: return "rp_id_hash_mismatch";
        case Failure::UserNotPresent: return "user_not_present";
        case Failure::UserNotVerified: return "user_not_verified";
        case Failure::BackupStateWithoutEligibility: return "backup_state_without_eligibility";
        case Failure::AttestedCredentialMissing: return "attested_credential_missing";
        case Failure::AttestedCredentialUnexpected: return "attested_credential_unexpected";
        case Failure::CredentialIdLength: return "credential_id_length";
        case Failure::CredentialIdMismatch: return "credential_id_mismatch";
        case Failure::CredentialAlreadyRegistered: return "credential_already_registered";
        case Failure::CoseKeyMalformed: return "cose_key_malformed";
        case Failure::UnsupportedAlgorithm: return "unsupported_algorithm";
        case Failure::KeyParametersMismatch: return "key_parameters_mismatch";
        case Failure::InvalidPublicKey: return "invalid_public_key";
        case Failure::RsaKeySize: return "rsa_key_size";
        case Failure::AttestationMalformed: return "attestation_malformed";
        case Failure::AttestationAlgorithmMismatch: return "attestation_algorithm_mismatch";
        case Failure::AttestationSignatureInvalid: return "attestation_signature_invalid";
        case Failure::AttestationCertificateInvalid: return "attestation_certificate_invalid";
        case Failure::CredentialUnknown: return "credential_unknown";
        case Failure::CredentialDisabled: return "credential_disabled";
        case Failure::CredentialSuspended: return "credential_suspended";
        case Failure::CredentialRpIdMismatch: return "credential_rp_id_mismatch";
        case Failure::CredentialOwnerMismatch: return "credential_owner_mismatch";
        case Failure::UserHandleMissing: return "user_handle_missing";
        case Failure::UserHandleMismatch: return "user_handle_mismatch";
        case Failure::SignatureInvalid: return "signature_invalid";
        case Failure::BackupEligibilityChanged: return "backup_eligibility_changed";
        case Failure::SignCountRegression: return "sign_count_regression";
    }
    return "unknown";
}

std::string_view toString(const Purpose p) {
    switch (p) {
        case Purpose::Register: return "register";
        case Purpose::Login: return "login";
        case Purpose::Mfa: return "mfa";
        case Purpose::StepUp: return "stepup";
        case Purpose::Approval: return "approval";
    }
    return "unknown";
}

std::string_view toString(const Algorithm a) {
    switch (a) {
        case Algorithm::EdDSA: return "EdDSA";
        case Algorithm::ES256: return "ES256";
        case Algorithm::RS256: return "RS256";
    }
    return "unknown";
}

std::string_view toString(const AttestationType t) {
    switch (t) {
        case AttestationType::None: return "none";
        case AttestationType::Self: return "self";
        case AttestationType::Basic: return "basic";
        case AttestationType::Unverified: return "unverified";
    }
    return "unknown";
}

}
