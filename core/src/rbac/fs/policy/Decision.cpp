#include "rbac/fs/policy/Decision.hpp"
#include "rbac/permission/Override.hpp"

namespace vh::rbac::fs::policy {
    std::string Decision::toString() const {
        std::ostringstream out;
        out << "Decision: " << (allowed ? "Allowed" : "Denied") << "\n";
        out << "Reason: " << reasonToString(reason) << "\n";
        if (evaluated_path) out << "Path: " << *evaluated_path << "\n";
        if (matched_override) out << "Matched: " << *matched_override << "\n";
        if (override_effect) out << "Override: " << permission::to_string(*override_effect) << "\n";
        return out.str();
    }

    std::string reasonToString(const Decision::Reason &reason) {
        switch (reason) {
            case Decision::Reason::Allowed: return "Allowed";
            case Decision::Reason::MissingPath: return "MissingPath";
            case Decision::Reason::MissingEntry: return "MissingEntry";
            case Decision::Reason::MissingPathAndEntry: return "MissingPathAndEntry";
            case Decision::Reason::MissingUser: return "MissingUser";
            case Decision::Reason::InvalidActionForEntryType: return "InvalidActionForEntryType";
            case Decision::Reason::DeniedByOverride: return "DeniedByOverride";
            case Decision::Reason::AllowedByOverride: return "AllowedByOverride";
            case Decision::Reason::DeniedByBasePermissions: return "DeniedByBasePermissions";
            case Decision::Reason::AllowedByBasePermissions: return "AllowedByBasePermissions";
            case Decision::Reason::StorageEngineNotFound: return "StorageEngineNotFound";
            case Decision::Reason::UnableToResolvePaths: return "UnableToResolvePaths";
            case Decision::Reason::LowRiskOpRequiredForOverrideTraversal: return "LowRiskOpRequiredForOverrideTraversal";
            case Decision::Reason::EntryVaultMismatch: return "EntryVaultMismatch";
            case Decision::Reason::NotGrantedOnMirror: return "NotGrantedOnMirror";
        }
        return "unknown reason";
    }
}
