#pragma once

#include "db/query/upstream/Binding.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/Fwd.hpp"

#include <memory>
#include <string>
#include <vector>

// Bucket identity resolution and vault bindings for the upstream control plane (#237). Trusted primitives: ops::upstream
// authorizes.
namespace vh::storage::upstream {

// The key's account: static when the provider encodes it (R2 endpoint, other providers' endpoint host) or cached,
// else asked once (AWS STS through the admin adapter) and cached on the key row. Throws when it can't be resolved.
[[nodiscard]] std::string resolveAccount(const std::shared_ptr<vault::model::APIKey>& key);

// identityFor with the account resolved (never nullopt).
[[nodiscard]] BucketIdentity resolvedIdentity(const std::shared_ptr<vault::model::APIKey>& key, const std::string& bucket);

// Vaults (live and pending deletion) bound to this bucket through any key of the same provider account. A key whose
// account is unknown counts when the provider and name match (fail safe: it may be the same bucket).
[[nodiscard]] std::vector<db::query::upstream::VaultBinding> bindingsFor(const BucketIdentity& id);

}
