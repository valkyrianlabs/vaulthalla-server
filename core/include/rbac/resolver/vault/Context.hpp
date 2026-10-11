#pragma once

#include "identities/User.hpp"
#include "fs/model/Entry.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <type_traits>
#include <ostream>
#include <sstream>

namespace vh::rbac::resolver::vault {
    template<typename EnumT>
    struct Context {
        static_assert(std::is_enum_v<EnumT>, "vh::rbac::vault::Context<EnumT>: EnumT must be an enum type");

        std::shared_ptr<identities::User> user;
        std::optional<EnumT> permission{std::nullopt};
        std::vector<EnumT> permissions{};
        std::optional<std::string> target_subject_type{std::nullopt};
        std::optional<uint32_t> target_subject_id{std::nullopt};
        std::optional<uint32_t> vault_id{std::nullopt};
        std::optional<std::filesystem::path> path{std::nullopt};
        std::shared_ptr<::vh::fs::model::Entry> entry{nullptr};

        [[nodiscard]] bool isValid() const {
            return !!user && (permission || !permissions.empty());
        }

        [[nodiscard]] std::string dump() const {
            std::ostringstream oss;
            const std::string in(2, ' ');
            oss << in << "User: " << user->name() << "\n";
            oss << in << "Vault ID: " << (vault_id ? std::to_string(*vault_id) : "nullopt") << "\n";
            oss << in << "Path: " << (path ? path->string() : "nullopt") << "\n";
            oss << in << "Entry: " << (entry ? entry->name : "nullopt") << ", Entry Path: " << (entry ? entry->path : "nullopt") << "\n";
            return oss.str();
        }
    };
}
