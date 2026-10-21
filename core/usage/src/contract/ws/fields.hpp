#pragma once

// Builders for the ws command book (internal to core/usage/src/contract/ws/*.cpp).

#include "Contract.hpp"

#include <chrono>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::contract::ws::detail {

inline WsField str(std::string name) { return {.name = std::move(name), .types = {"string"}}; }

inline WsField uinteger(std::string name) { return {.name = std::move(name), .types = {"integer"}, .minimum = 0}; }

inline WsField boolean(std::string name) { return {.name = std::move(name), .types = {"boolean"}}; }

inline WsField object(std::string name, std::string model = {}, std::vector<WsField> fields = {}) {
    return {.name = std::move(name), .types = {"object"}, .fields = std::move(fields), .model = std::move(model)};
}

inline WsField objectArray(std::string name, std::string model, std::vector<WsField> fields = {}) {
    return {.name = std::move(name), .types = {"array"}, .items = "object", .fields = std::move(fields),
            .model = std::move(model)};
}

inline WsField strArray(std::string name, std::vector<std::string> itemEnum = {}) {
    return {.name = std::move(name), .types = {"array"}, .items = "string", .item_enum = std::move(itemEnum)};
}

inline WsField anyOf(std::string name, std::vector<std::string> types) {
    return {.name = std::move(name), .types = std::move(types)};
}

// Common shapes.
inline WsField vaultId() { return uinteger("vault_id").gen(gen::ref("vault", {"id"})).desc("Vault id."); }

inline WsField vaultPath(std::string name) {
    return str(std::move(name)).gen(gen::path("/{a}{a}{a}{9}")).desc("Vault-relative path (\"/docs/a.txt\").");
}

inline constexpr std::chrono::milliseconds kDefaultTimeout{15'000};

// The refusal kinds every ops::-backed handler can produce through handler_templates.hpp.
inline std::vector<std::string> opsRefusals() { return {"denied", "invalid", "not_found", "conflict", "unauthorized"}; }

std::vector<WsCommandUsage> authCommands();
std::vector<WsCommandUsage> fsCommands();
std::vector<WsCommandUsage> groupCommands();
std::vector<WsCommandUsage> roleCommands();
std::vector<WsCommandUsage> vaultCommands();
std::vector<WsCommandUsage> shareCommands();
std::vector<WsCommandUsage> metaCommands();
std::vector<WsCommandUsage> upstreamCommands();
std::vector<WsCommandUsage> recoveryCommands();
std::vector<WsCommandUsage> deviceCommands();
std::vector<WsCommandUsage> vaultKeyCommands();

}
