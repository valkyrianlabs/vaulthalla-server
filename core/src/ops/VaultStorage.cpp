#include "ops/VaultStorage.hpp"

#include "audit/Trail.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/BucketCapability.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/BucketCapability.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

namespace vh::ops::vault_storage {

namespace vault_storage_detail {

using VaultPerm = rbac::permission::admin::VaultPermissions;
using storage::s3::WriteCapability;

bool publishable(const vault::model::StorageLayout layout, const WriteCapability capability) {
    // opaque_v1 needs conditional writes until spec 06 §5 exists; the path_v0 / transparent index is PUT plainly on
    // a bucket without them (one writer, rebuilt from a listing).
    if (layout == vault::model::StorageLayout::OpaqueV1) return storage::s3::sendsPreconditions(capability);
    return true;
}

}

ProbeAnswer probe(const Actor& actor, const unsigned int vaultId) {
    namespace d = vault_storage_detail;
    requireActor(actor);
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    // The vault as stored (its owner from the row): the probe also serves a vault whose engine doesn't run.
    if (!rbac::resolver::Admin::has<d::VaultPerm>({.user = actor, .permission = d::VaultPerm::Edit, .vault = vault}))
        throw Denied("you do not have permission to edit vault " + vault->name);
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (!s3) throw Invalid("vault '" + vault->name + "' is a local vault: it has no bucket to probe");
    if (const auto key = db::query::vault::APIKey::getAPIKey(s3->api_key_id);
        key && storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, s3->bucket)))
        throw Denied("bucket '" + s3->bucket + "' is protected: Vaulthalla sends it no request until it is unprotected");

    ProbeAnswer answer{.vault_id = vaultId, .vault_name = vault->name,
                       .layout = std::string(vault::model::to_string(s3->storage_layout)), .previous = {},
                       .previously_changed = false, .probe = {}, .manifest_publishable = false};
    const auto before = db::query::vault::BucketCapability::get(vaultId);
    answer.previous = before.capability;
    answer.previously_changed = before.changed_at.has_value();

    try {
        // The live engine's controller when the vault runs (metered, budgeted, the opaque_v1 request rules), else one
        // for the vault's binding.
        const auto& manager = runtime::Deps::get().storageManager;
        const auto engine = manager ? std::dynamic_pointer_cast<storage::CloudEngine>(manager->getEngine(vaultId))
                                    : nullptr;
        if (engine && engine->s3Controller()) {
            answer.probe = storage::bucket_capability::probeAndRecord(vaultId, *engine->s3Controller());
        } else if (auto probed = storage::bucket_capability::probeVault(vaultId)) {
            answer.probe = std::move(*probed);
        } else {
            throw storage::s3::ProbeFailed("no controller for the vault's bucket (test mode)");
        }
    } catch (const storage::s3::ProbeFailed& e) {
        throw Refused("bucket_probe_failed", std::string("the bucket could not be probed: ") + e.what());
    }
    answer.manifest_publishable = d::publishable(s3->storage_layout, answer.probe.capability);

    vh::audit::record({.action = "vault.storage.probe", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vaultId,
                       .details = {{"capability", std::string(storage::s3::to_string(answer.probe.capability))},
                                   {"previous", std::string(storage::s3::to_string(answer.previous))},
                                   {"previously_changed", answer.previously_changed},
                                   {"conditional_put", answer.probe.conditional_put},
                                   {"versioning", answer.probe.versioning},
                                   {"get_if_match", answer.probe.get_if_match}}},
                      fmt::format("[ops::vault_storage] {} probed the bucket of vault {}: {} ({})", actor->name(),
                                  vaultId, storage::s3::to_string(answer.probe.capability), answer.probe.reason));
    return answer;
}

nlohmann::json toJson(const ProbeAnswer& a) {
    auto probe = storage::s3::toJson(a.probe);
    probe.erase("v");
    return {{"vault_id", a.vault_id},
            {"vault_name", a.vault_name},
            {"layout", a.layout},
            {"previous", std::string(storage::s3::to_string(a.previous))},
            {"previously_changed", a.previously_changed},
            {"manifest_publishable", a.manifest_publishable},
            {"probe", std::move(probe)}};
}

}
