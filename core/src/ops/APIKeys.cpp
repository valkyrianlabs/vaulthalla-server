#include "ops/APIKeys.hpp"

#include "db/query/identities/User.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/vault/APIKey.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/APIKeyManager.hpp"

#include <paths.h>
#include <pqxx/except>

#include <algorithm>
#include <utility>

namespace vh::ops::api_keys {

namespace {

using KeyPerm = rbac::permission::admin::keys::APIPermissions;

bool canOnKey(const Actor& actor, const KeyPerm permission, const unsigned int keyId) {
    return rbac::resolver::Admin::has<KeyPerm>({.user = actor, .permission = permission, .api_key_id = keyId});
}

std::string describe(const Ref& ref) {
    if (const auto* id = std::get_if<unsigned int>(&ref)) return std::to_string(*id);
    return std::get<std::string>(ref);
}

APIKeyPtr requireKey(const Ref& ref) {
    APIKeyPtr key;
    if (const auto* id = std::get_if<unsigned int>(&ref)) {
        if (*id == 0) throw Invalid("API key ID must be a positive integer");
        key = db::query::vault::APIKey::getAPIKey(*id);
    } else {
        key = db::query::vault::APIKey::getAPIKey(std::get<std::string>(ref));
    }
    if (!key) throw NotFound("API key not found: " + describe(ref));
    return key;
}

std::shared_ptr<identities::User> requireOwner(const Actor& actor, const std::optional<Ref>& ref) {
    if (!ref) return actor;
    std::shared_ptr<identities::User> user;
    if (const auto* id = std::get_if<unsigned int>(&*ref)) user = vh::identities::manager().user(*id);
    else user = vh::identities::manager().userByName(std::get<std::string>(*ref));
    if (!user) throw NotFound("owner not found: " + describe(*ref));
    return user;
}

}

APIKeyPtr create(const Actor& actor, const Create& req) {
    requireActor(actor);
    const auto owner = requireOwner(actor, req.owner);
    if (!rbac::resolver::Admin::has<KeyPerm>({.user = actor, .permission = KeyPerm::Create, .target_user_id = owner->id}))
        throw Denied("you do not have permission to create API keys for this owner");

    std::vector<std::string> missing;
    if (req.name.empty()) missing.emplace_back("name");
    if (req.access_key.empty()) missing.emplace_back("access key");
    if (req.secret_access_key.empty()) missing.emplace_back("secret key");
    if (req.endpoint.empty()) missing.emplace_back("endpoint");
    if (!missing.empty()) {
        std::string msg = "missing required";
        for (const auto& m : missing) msg += " " + m + (m == missing.back() ? "" : ",");
        throw Invalid(msg);
    }

    auto key = std::make_shared<vault::model::APIKey>(owner->id, req.name, req.provider, req.access_key,
                                                      req.secret_access_key, req.region.empty() ? "auto" : req.region,
                                                      req.endpoint);
    if (!paths::testMode) {
        const auto [valid, errors] = storage::s3::Controller(key, "").validateAPICredentials();
        if (!valid) throw Invalid("API key validation failed:\n" + errors);
    }

    key->id = runtime::Deps::get().apiKeyManager->addAPIKey(key);
    return requireKey(key->id);
}

APIKeyPtr update(const Actor& actor, const Ref& ref, const Update& req) {
    requireActor(actor);
    auto key = requireKey(ref);
    if (!canOnKey(actor, KeyPerm::Edit, key->id)) throw Denied("you do not have permission to edit this API key");
    const auto previousProvider = key->provider;
    const auto previousEndpoint = key->endpoint;
    const auto previousAccessKey = key->access_key;

    if (req.name) key->name = *req.name;
    if (req.provider) key->provider = *req.provider;
    if (req.access_key) key->access_key = *req.access_key;
    if (req.endpoint) key->endpoint = *req.endpoint;
    if (req.region) key->region = req.region->empty() ? "auto" : *req.region;

    std::vector<std::string> missing;
    if (key->name.empty()) missing.emplace_back("name");
    if (key->access_key.empty()) missing.emplace_back("access key");
    if (key->endpoint.empty()) missing.emplace_back("endpoint");
    if (!missing.empty()) {
        std::string msg = "missing required";
        for (const auto& m : missing) msg += " " + m + (m == missing.back() ? "" : ",");
        throw Invalid(msg);
    }

    // An administrative key repointed at another account (#237) must not stay "administrative" there on authority
    // nobody with admin.upstream.configure granted for it; while event channels run on it, it can't move at all.
    const bool repointed = key->provider != previousProvider || key->endpoint != previousEndpoint ||
                           key->access_key != previousAccessKey;
    if (repointed && key->admin_enabled)
        if (const auto n = db::query::upstream::Subscription::countActiveUsingKey(key->id); n > 0)
            throw Conflict("API key '" + key->name + "' operates " + std::to_string(n) + " active event subscription" +
                           (n == 1 ? "" : "s") + "; turn them off (vh upstream events disable) before changing its "
                           "provider, endpoint or access key");

    const bool newSecret = req.secret_access_key && !req.secret_access_key->empty();
    if (!paths::testMode) {
        auto probe = std::make_shared<vault::model::APIKey>(*key);
        probe->secret_access_key = newSecret
            ? *req.secret_access_key
            : runtime::Deps::get().apiKeyManager->getAPIKey(key->id)->secret_access_key;
        const auto [valid, errors] = storage::s3::Controller(probe, "").validateAPICredentials();
        if (!valid) throw Invalid("API key validation failed:\n" + errors);
    }
    if (newSecret) key->secret_access_key = *req.secret_access_key;

    try {
        runtime::Deps::get().apiKeyManager->updateAPIKey(key);
    } catch (const pqxx::unique_violation&) {
        throw Conflict("another API key of this owner already has this name and access key");
    }

    // The account a key belongs to (#237: bucket identity, protection locks) follows its provider, endpoint and access
    // key; a change means it must be resolved again.
    if (repointed) {
        if (key->admin_enabled) {
            db::query::vault::APIKey::resetAdmin(key->id);
            log::Registry::audit()->warn("[ops::api_keys] {} repointed administrative API key {} ('{}'): provider "
                                         "administration turned off until it is enabled again", actor->name(), key->id,
                                         key->name);
        } else {
            runtime::Deps::get().apiKeyManager->setAccountRef(key->id, std::nullopt);
        }
    }

    // Vaults bound to the key keep their binding (same id); their live engines pick up the new credentials.
    if (const auto& storage = runtime::Deps::get().storageManager) {
        for (const auto& [vaultId, vaultName] : db::query::vault::APIKey::listVaultsUsingKey(key->id)) {
            try {
                storage->reloadEngine(vaultId);
            } catch (const std::exception& e) {
                log::Registry::storage()->warn("[ops::api_keys] API key {} updated, but reloading vault {} ({}) failed: {}",
                                               key->id, vaultName, vaultId, e.what());
            }
        }
    }
    return requireKey(key->id);
}

APIKeyPtr remove(const Actor& actor, const Ref& ref) {
    requireActor(actor);
    auto key = requireKey(ref);
    if (!canOnKey(actor, KeyPerm::Remove, key->id)) throw Denied("you do not have permission to remove this API key");

    // Removing a key used to cascade into every vault's s3 row (bucket binding gone, silently). Refuse instead;
    // the s3.api_key_id foreign key is ON DELETE RESTRICT (migration 099) for anything racing this check.
    const auto refuseInUse = [&](const std::vector<std::pair<unsigned int, std::string>>& vaults) {
        std::string names;
        for (const auto& [id, name] : vaults) names += (names.empty() ? "" : ", ") + name;
        throw Invalid("API key '" + key->name + "' is in use by " + std::to_string(vaults.size()) +
                      (vaults.size() == 1 ? " vault: " : " vaults: ") + names +
                      ". Move or remove those vaults first.");
    };
    if (const auto vaults = db::query::vault::APIKey::listVaultsUsingKey(key->id); !vaults.empty()) refuseInUse(vaults);
    // An event channel (#96) polls its queue with this key.
    if (const auto n = db::query::upstream::Subscription::countActiveUsingKey(key->id); n > 0)
        throw Conflict("API key '" + key->name + "' operates " + std::to_string(n) +
                       " event subscription(s); turn event-driven sync off for those vaults first");

    try {
        runtime::Deps::get().apiKeyManager->removeAPIKey(key->id);
    } catch (const pqxx::foreign_key_violation&) {
        refuseInUse(db::query::vault::APIKey::listVaultsUsingKey(key->id));
        throw;
    }
    return key;
}

APIKeyPtr get(const Actor& actor, const Ref& ref) {
    requireActor(actor);
    auto key = requireKey(ref);
    if (!canOnKey(actor, KeyPerm::View, key->id)) throw Denied("you do not have permission to view this API key");
    return key;
}

std::vector<APIKeyPtr> list(const Actor& actor, db::model::ListQueryParams params) {
    requireActor(actor);
    const auto& perms = actor->apiKeysPerms();
    auto keys = perms.self.canView() && !(perms.admin.canView() || perms.user.canView())
        ? runtime::Deps::get().apiKeyManager->listUserAPIKeys(actor->id)
        : runtime::Deps::get().apiKeyManager->listAPIKeys();
    std::erase_if(keys, [&](const APIKeyPtr& key) { return !key || !canOnKey(actor, KeyPerm::View, key->id); });

    // The visibility filter runs per key, so --filter/--sort/--limit/--page apply here, after it.
    if (params.filter)
        std::erase_if(keys, [&](const APIKeyPtr& key) { return key->name.find(*params.filter) == std::string::npos; });
    if (params.sort && *params.sort != "name" && *params.sort != "id")
        throw Invalid("API keys can be sorted by 'name' or 'id'");
    const bool byName = params.sort && *params.sort == "name";
    const bool desc = params.direction && *params.direction == db::model::SortDirection::DESC;
    std::ranges::sort(keys, [&](const APIKeyPtr& a, const APIKeyPtr& b) {
        const bool less = byName ? a->name < b->name : a->id < b->id;
        const bool greater = byName ? b->name < a->name : b->id < a->id;
        return desc ? greater : less;
    });
    if (params.limit) {
        const auto page = params.page.value_or(1);
        const auto start = std::min<std::size_t>(keys.size(), (page > 0 ? page - 1 : 0) * *params.limit);
        const auto end = std::min<std::size_t>(keys.size(), start + *params.limit);
        keys = std::vector<APIKeyPtr>(keys.begin() + static_cast<std::ptrdiff_t>(start),
                                      keys.begin() + static_cast<std::ptrdiff_t>(end));
    }
    return keys;
}

}
