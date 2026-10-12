#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include "rbac/Fwd.hpp"
#include "rbac/permission/Override.hpp"  // complete type: the `= {}` default arguments instantiate std::vector<Override>

namespace vh::db::query::share {

struct VaultRole {
    struct AssignmentInput {
        std::string share_id;
        uint32_t vault_id{};
        uint32_t vault_role_id{};
        std::string subject_type;
        uint32_t subject_id{};
        std::vector<vh::rbac::permission::Override> overrides;
    };

    struct RecipientAssignmentInput {
        std::vector<uint8_t> email_hash;
        uint32_t vault_role_id{};
        std::vector<vh::rbac::permission::Override> overrides;
    };

    static uint32_t upsertForShare(
        const std::string& shareId,
        uint32_t vaultId,
        const std::shared_ptr<vh::rbac::role::Vault>& role
    );

    static uint32_t upsertAssignment(const AssignmentInput& input);
    static uint32_t upsertPublicAssignment(
        const std::string& shareId,
        uint32_t vaultId,
        uint32_t vaultRoleId,
        const std::vector<vh::rbac::permission::Override>& overrides = {}
    );
    static uint32_t upsertRecipient(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    );
    static uint32_t upsertRecipientAssignment(
        const std::string& shareId,
        uint32_t vaultId,
        uint32_t recipientId,
        uint32_t vaultRoleId,
        const std::vector<vh::rbac::permission::Override>& overrides = {}
    );
    static void replaceRecipientAssignments(
        const std::string& shareId,
        uint32_t vaultId,
        const std::vector<RecipientAssignmentInput>& assignments
    );

    static std::shared_ptr<vh::rbac::role::Vault> getForShare(const std::string& shareId);
    static std::shared_ptr<vh::rbac::role::Vault> getPublicAssignment(const std::string& shareId);
    static std::shared_ptr<vh::rbac::role::Vault> getRecipientAssignment(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    );

    static void removeForShare(const std::string& shareId);
};

}
