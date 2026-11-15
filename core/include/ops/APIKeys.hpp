#pragma once

#include "ops/Actor.hpp"
#include "db/model/ListQueryParams.hpp"
#include "vault/model/APIKey.hpp"

#include <memory>
#include <optional>
#include <string>
#include <variant>
#include <vector>

// Upstream S3 API keys, shared by `vh api-key ...` and the ws storage.apiKey.* commands. Authorization is the
// resolver's admin keys.api self/user/admin permissions, checked here once; vault::APIKeyManager underneath is a
// trusted primitive.
namespace vh::ops::api_keys {

using APIKeyPtr = std::shared_ptr<vault::model::APIKey>;

// A key or user as the caller named it: by id, or by name.
using Ref = std::variant<unsigned int, std::string>;

struct Create {
    std::string name;
    vault::model::S3Provider provider{vault::model::S3Provider::AWS};
    std::string access_key;
    std::string secret_access_key;
    std::string endpoint;
    std::string region{"auto"};
    std::optional<Ref> owner{};       // defaults to the actor
};

// An in-place edit: the key keeps its id, so every vault bound to it keeps its S3 binding (the web used to delete
// and re-create, which cascaded into the vaults' s3 rows). Unset fields keep their value; an unset or empty secret
// keeps the sealed secret.
struct Update {
    std::optional<std::string> name{};
    std::optional<vault::model::S3Provider> provider{};
    std::optional<std::string> access_key{};
    std::optional<std::string> secret_access_key{};
    std::optional<std::string> endpoint{};
    std::optional<std::string> region{};
};

// Creates the key after checking the credentials against the provider (skipped in test mode). Never returns the
// secret.
[[nodiscard]] APIKeyPtr create(const Actor& actor, const Create& req);
// Edits the key in place (admin keys.api edit) and re-checks the resulting credentials against the provider like
// create (skipped in test mode). Live engines of the vaults using the key are rebuilt with the new credentials.
[[nodiscard]] APIKeyPtr update(const Actor& actor, const Ref& key, const Update& req);
// update and remove refuse a key managed storage issued (origin "cloud": Conflict); people never change it.
// Returns the removed key's metadata. Refused (Invalid, naming the vaults) while any vault is bound to the key.
APIKeyPtr remove(const Actor& actor, const Ref& key);
// Metadata only; the secret stays sealed.
[[nodiscard]] APIKeyPtr get(const Actor& actor, const Ref& key);
// The keys the actor may view.
[[nodiscard]] std::vector<APIKeyPtr> list(const Actor& actor, db::model::ListQueryParams params = {});

}
