#include "db/query/vault/APIKey.hpp"
#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "vault/model/APIKey.hpp"
#include "db/encoding/bytea.hpp"
#include "identities/User.hpp"

namespace vh::db::query::vault {

    using vh::db::encoding::to_hex_bytea;
    using vh::db::model::ListQueryParams;

    unsigned int APIKey::upsertAPIKey(const std::shared_ptr<vh::vault::model::APIKey>& key) {
        return Transactions::exec("APIKey::addAPIKey", [&](pqxx::work& txn) {
            pqxx::params p{
                key->user_id,
                key->name,
                to_string(key->provider),
                key->access_key,
                to_hex_bytea(key->encrypted_secret_access_key),
                to_hex_bytea(key->iv),
                key->region,
                key->endpoint
            };
            return txn.exec(pqxx::prepped{"upsert_api_key"}, p).one_field_ref().as<unsigned int>();
        });
    }

    void APIKey::updateAPIKey(const std::shared_ptr<vh::vault::model::APIKey>& key) {
        Transactions::exec("APIKey::updateAPIKey", [&](pqxx::work& txn) {
            pqxx::params p{
                key->id,
                key->name,
                to_string(key->provider),
                key->access_key,
                to_hex_bytea(key->encrypted_secret_access_key),
                to_hex_bytea(key->iv),
                key->region,
                key->endpoint
            };
            txn.exec(pqxx::prepped{"update_api_key"}, p);
        });
    }

    std::vector<std::pair<unsigned int, std::string>> APIKey::listVaultsUsingKey(const unsigned int keyId) {
        return Transactions::exec("APIKey::listVaultsUsingKey", [&](pqxx::work& txn) {
            std::vector<std::pair<unsigned int, std::string>> out;
            for (const auto& row : txn.exec(pqxx::prepped{"list_api_key_vaults"}, keyId))
                out.emplace_back(row["id"].as<unsigned int>(), row["name"].as<std::string>());
            return out;
        });
    }

    void APIKey::removeAPIKey(const unsigned int keyId) {
        Transactions::exec("APIKey::removeAPIKey", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"remove_api_key"}, keyId);
        });
    }

    std::vector<std::shared_ptr<vh::vault::model::APIKey>> APIKey::listAPIKeys(const unsigned int userId, const ListQueryParams& params) {
        return Transactions::exec("APIKey::listAPIKeys", [&](pqxx::work& txn) {
            const auto sql = appendPaginationAndFilter(
                "SELECT * FROM api_keys WHERE user_id = " + txn.quote(userId),
                params, "id", "name"
            );
            return db::sharedRows<vh::vault::model::APIKey>(txn.exec(sql));
        });
    }

    std::vector<std::shared_ptr<vh::vault::model::APIKey>> APIKey::listAPIKeys(const ListQueryParams& params) {
        return Transactions::exec("APIKey::listAPIKeys", [&](pqxx::work& txn) {
            const auto sql = appendPaginationAndFilter(
                "SELECT * FROM api_keys",
                params, "id", "name"
            );
            return db::sharedRows<vh::vault::model::APIKey>(txn.exec(sql));
        });
    }

    std::shared_ptr<vh::vault::model::APIKey> APIKey::getAPIKey(const unsigned int keyId) {
        return Transactions::exec("APIKey::getAPIKey", [&](pqxx::work& txn) -> std::shared_ptr<vh::vault::model::APIKey> {
            const auto res = txn.exec(pqxx::prepped{"get_api_key"}, keyId);
            if (res.empty()) return nullptr;
            return std::make_shared<AK>(res.one_row_ref());
        });
    }

    std::shared_ptr<vh::vault::model::APIKey> APIKey::getAPIKey(const std::string& keyName) {
        if (keyName.empty()) return nullptr;

        return Transactions::exec("APIKey::getAPIKeyByName", [&](pqxx::work& txn) -> std::shared_ptr<vh::vault::model::APIKey> {
            const auto res = txn.exec(pqxx::prepped{"get_api_key_by_name"}, keyName);
            if (res.empty()) return nullptr;
            return std::make_shared<AK>(res.one_row_ref());
        });
    }

    std::optional<unsigned int> APIKey::getAPIKeyOwnerId(unsigned int keyId) {
        return Transactions::exec("APIKey::getAPIKeyOwnerId", [&](pqxx::work& txn) -> std::optional<unsigned int> {
            const auto res = txn.exec(pqxx::prepped{"get_api_key_owner"}, keyId);
            if (res.empty()) return std::nullopt;
            return res.one_row_ref()["id"].as<unsigned int>();
        });
    }

    void APIKey::setAdmin(const unsigned int keyId, const bool enabled, const std::optional<std::string>& accountRef,
                          const std::optional<std::string>& capabilitiesJson, const std::optional<std::time_t> validatedAt) {
        const std::optional<double> at = validatedAt ? std::make_optional(static_cast<double>(*validatedAt)) : std::nullopt;
        Transactions::exec("APIKey::setAdmin", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"api_key_set_admin"}, pqxx::params{keyId, enabled, accountRef, capabilitiesJson, at});
        });
    }

    void APIKey::setProviderToken(const unsigned int keyId, const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& iv) {
        Transactions::exec("APIKey::setProviderToken", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"api_key_set_provider_token"},
                     pqxx::params{keyId, to_hex_bytea(ciphertext), to_hex_bytea(iv)});
        });
    }

    void APIKey::clearProviderToken(const unsigned int keyId) {
        Transactions::exec("APIKey::clearProviderToken", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"api_key_clear_provider_token"}, pqxx::params{keyId});
        });
    }

    void APIKey::resetAdmin(const unsigned int keyId) {
        Transactions::exec("APIKey::resetAdmin", [&](pqxx::work& txn) {
            txn.exec("UPDATE api_keys SET admin_enabled = FALSE, admin_capabilities = NULL, admin_validated_at = NULL, "
                     "encrypted_provider_token = NULL, provider_token_iv = NULL, provider_account_id = NULL WHERE id = $1",
                     pqxx::params{keyId});
        });
    }

    void APIKey::setAccountRef(const unsigned int keyId, const std::optional<std::string>& accountRef) {
        Transactions::exec("APIKey::setAccountRef", [&](pqxx::work& txn) {
            txn.exec(pqxx::prepped{"api_key_set_account_ref"}, pqxx::params{keyId, accountRef});
        });
    }

}
