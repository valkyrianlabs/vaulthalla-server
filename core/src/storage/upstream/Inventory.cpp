#include "storage/upstream/Inventory.hpp"

#include "db/query/vault/APIKey.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"

#include <stdexcept>

namespace vh::storage::upstream {

std::string resolveAccount(const std::shared_ptr<vault::model::APIKey>& key) {
    if (!key) throw std::invalid_argument("no API key");
    if (const auto known = s3::provider::admin::staticAccountRef(*key)) return *known;
    if (!s3::provider::admin::supportsAdmin(*key))
        throw std::runtime_error("the account of API key '" + key->name + "' cannot be determined");
    const auto admin = s3::provider::admin::adminFor(key);
    if (!admin) throw std::runtime_error("provider administration is not available for API key '" + key->name + "'");
    const auto identity = admin->identity();
    if (identity.account_ref.empty())
        throw std::runtime_error("the provider did not report an account for API key '" + key->name + "'");
    key->provider_account_id = identity.account_ref;
    if (key->id != 0)
        if (const auto& manager = runtime::Deps::get().apiKeyManager) manager->setAccountRef(key->id, identity.account_ref);
    return identity.account_ref;
}

BucketIdentity resolvedIdentity(const std::shared_ptr<vault::model::APIKey>& key, const std::string& bucket) {
    auto id = identityFor(*key, bucket);
    if (!id.account_ref) id.account_ref = resolveAccount(key);
    return id;
}

std::vector<db::query::upstream::VaultBinding> bindingsFor(const BucketIdentity& id) {
    std::vector<db::query::upstream::VaultBinding> out;
    for (const auto& binding : db::query::upstream::Binding::forBucketName(id.bucket)) {
        const auto key = db::query::vault::APIKey::getAPIKey(binding.api_key_id);
        if (!key) {
            out.push_back(binding);   // a binding whose key vanished: count it, never assume it is someone else's
            continue;
        }
        if (s3::provider::admin::providerIdentity(*key) != id.provider) continue;
        const auto account = s3::provider::admin::staticAccountRef(*key);
        if (account && id.account_ref && *account != *id.account_ref) continue;
        out.push_back(binding);
    }
    return out;
}

}
