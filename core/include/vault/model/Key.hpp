#pragma once

#include <vector>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <nlohmann/json_fwd.hpp>
#include "db/Fwd.hpp"

namespace vh::vault::model {

struct Key {
    unsigned int vaultId{}, version{};
    std::vector<uint8_t> key, encrypted_key, iv;
    std::time_t created_at{}, updated_at{};
    // The key check the daemon recorded for this version (vault/KeyCheck.hpp; migration 113), or nullopt for a row
    // it hasn't unsealed since the column was added.
    std::optional<std::string> key_check{};
    // This node's signature over the version's key check (vault/KeyAttestation.hpp), by attestation key
    // attestation_key_id; nullopt when none is recorded.
    std::optional<unsigned int> attestation_key_id{};
    std::vector<uint8_t> attestation{};

    Key() = default;
    explicit Key(pqxx::row_ref row);
};

void to_json(nlohmann::json &j, const Key &vk);
void from_json(const nlohmann::json &j, Key &vk);

}
