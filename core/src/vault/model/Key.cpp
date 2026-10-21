#include "vault/model/Key.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/bytea.hpp"

#include <pqxx/row>
#include <nlohmann/json.hpp>

using namespace vh::vault::model;
using namespace vh::db::encoding;

Key::Key(pqxx::row_ref row)
    : vaultId(row["vault_id"].as<unsigned int>()),
      version(row["version"].as<unsigned int>()),
      encrypted_key(from_hex_bytea(row["encrypted_key"].as<std::string>())),
      iv(from_hex_bytea(row["iv"].as<std::string>())),
      created_at(parsePostgresTimestamp(row["created_at"].as<std::string>())),
      updated_at(parsePostgresTimestamp(row["updated_at"].as<std::string>())) {
    if (const auto check = row["key_check"]; !check.is_null()) key_check = check.as<std::string>();
    if (const auto id = row["attestation_key_id"]; !id.is_null()) attestation_key_id = id.as<unsigned int>();
    if (const auto sig = row["attestation"]; !sig.is_null()) attestation = from_hex_bytea(sig.as<std::string>());
}

void vh::vault::model::to_json(nlohmann::json &j, const Key &vk) {
    j = nlohmann::json{
        {"vault_id", vk.vaultId},
        {"key", vk.key},
        {"created_at", timestampToString(vk.created_at)},
        {"updated_at", timestampToString(vk.updated_at)}
    };
}

void vh::vault::model::from_json(const nlohmann::json &j, Key &vk) {
    j.at("vault_id").get_to(vk.vaultId);
    j.at("key").get_to(vk.key);
}
