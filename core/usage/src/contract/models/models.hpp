#pragma once

// The model registry (internal to core/usage/src/contract/models/*.cpp): every named model the ws book refers to,
// declared next to its siblings by area. Field builders are the book's (../ws/fields.hpp). Each model's description
// names its serializer; core/tests/unit/contract/models_*.cpp check each serializer against its declaration.

#include "../ws/fields.hpp"

#include <string>
#include <utility>
#include <vector>

namespace vh::contract::ws::detail {

inline WsModel model(std::string name, std::string description, std::vector<WsField> fields) {
    return {.name = std::move(name), .description = std::move(description), .fields = std::move(fields)};
}

std::vector<WsModel> identityModels();
std::vector<WsModel> vaultModels();
std::vector<WsModel> fsModels();
std::vector<WsModel> shareModels();
std::vector<WsModel> syncModels();
std::vector<WsModel> statsModels();
std::vector<WsModel> s3GatewayModels();
std::vector<WsModel> adminModels();
std::vector<WsModel> recoveryModels();
std::vector<WsModel> upstreamModels();
std::vector<WsModel> deviceModels();
std::vector<WsModel> vaultKeyModels();

}
