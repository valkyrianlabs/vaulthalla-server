#pragma once

#include <cstdint>
#include <ctime>
#include <string>
#include <vector>
#include <memory>
#include <bitset>
#include <typeindex>
#include <optional>
#include <nlohmann/json_fwd.hpp>
#include "db/Fwd.hpp"
#include <typeindex>

namespace vh::rbac::permission {

struct Permission {
    uint32_t id{}, bit_position{};
    std::string qualified_name, description, slug;
    std::time_t created_at{}, updated_at{};
    std::vector<std::string> flags;
    uint64_t rawValue{};
    std::type_index enumType = typeid(void);
    std::optional<bool> value{std::nullopt};

    Permission() = default;
    explicit Permission(pqxx::row_ref row);
    explicit Permission(const nlohmann::json& j);
    Permission(uint32_t bitPos, std::string name, std::string description, const std::vector<std::string>& flags = {}, uint64_t rawValue = 0, std::type_index enumType = typeid(void));
};
    
void to_json(nlohmann::json& j, const Permission& p);
void from_json(const nlohmann::json& j, Permission& p);

void to_json(nlohmann::json& j, const std::vector<std::shared_ptr<Permission>>& permissions);

}
