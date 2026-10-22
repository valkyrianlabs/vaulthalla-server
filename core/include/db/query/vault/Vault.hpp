#pragma once

#include "db/model/ListQueryParams.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <memory>
#include <vector>
#include <string>
#include <optional>

namespace vh::db::query::vault {

class Vault {
    using V = vh::vault::model::Vault;
    using P = vh::sync::model::Policy;
    using VaultPtr = std::shared_ptr<V>;
    using PolicyPtr = std::shared_ptr<P>;
    using VaultT = vh::vault::model::VaultType;

public:
    Vault() = default;

    static unsigned int upsertVault(const VaultPtr& vault,
                                 const PolicyPtr& sync = nullptr);
    static void removeVault(unsigned int vaultId);
    static VaultPtr getVault(unsigned int vaultID);
    static VaultPtr getVault(const std::string& name, unsigned int ownerId);
    // One page (100 rows unless params.limit says otherwise): list surfaces only.
    static std::vector<VaultPtr> listVaults(const std::optional<VaultT>& type = std::nullopt, model::ListQueryParams&& params = {});
    // Every vault not deleted, by id, unpaginated: what needs all of them (the storage engines, accessible vaults).
    static std::vector<VaultPtr> listLiveVaults();
    static std::vector<VaultPtr> listUserVaults(unsigned int userId, const std::optional<VaultT>& type = std::nullopt, model::ListQueryParams&& params = {});

    static void updateVaultSync(const PolicyPtr& sync, const VaultT& type);

    // Counts deleted vaults pending purge too: their names stay reserved (#162).
    [[nodiscard]] static bool vaultExists(const std::string& name, unsigned int ownerId);

    // The vault (live or deleted) bound to this API key and bucket, if any.
    struct BucketOwner {
        unsigned int vault_id{};
        std::string vault_name;
        bool deleted{};
    };
    [[nodiscard]] static std::optional<BucketOwner> bucketOwner(unsigned int apiKeyId, const std::string& bucket);

    [[nodiscard]] static bool vaultRootExists(unsigned int vaultId);

    [[nodiscard]] static unsigned int maxVaultId();

    static bool localDiskVaultExists();

    [[nodiscard]] static std::string getVaultMountPoint(unsigned int vaultId);

    static std::string getVaultOwnersName(unsigned int vaultId);
    [[nodiscard]] static unsigned int getVaultOwnerId(unsigned int vaultId);
};

}
