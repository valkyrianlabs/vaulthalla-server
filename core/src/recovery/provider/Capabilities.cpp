#include "recovery/provider/Capabilities.hpp"

#include "storage/s3/provider/admin/Admin.hpp"
#include "vault/model/S3Vault.hpp"

#include <vl/vaultfmt/ObjectKeys.hpp>

namespace vh::recovery::provider {

ProviderCapabilities capabilitiesOf(const std::string& providerIdentity) {
    ProviderCapabilities c;
    if (providerIdentity == "aws-s3") {
        c.enable = c.suspend = true;
        c.retention_days = c.retention_indefinite = true;
        c.list_versions = c.restore_copy = c.restore_transfer = true;
        c.propagation_minutes = 15;
        c.unsupported = {"history off: mode off doesn't change an AWS bucket; a bucket Vaulthalla created stays "
                         "unversioned until provider versioning is turned on, and versioning that is on is suspended "
                         "with vh vault recovery suspend"};
        return c;
    }
    if (providerIdentity == "backblaze-b2") {
        c.always_versioned = true;
        c.retention_days = c.retention_indefinite = c.history_off = true;
        c.list_versions = c.restore_transfer = true;
        c.unsupported = {std::string("enable: ") + "every Backblaze B2 bucket is versioned already",
                         std::string("suspend: ") + kB2SuspendUnsupported,
                         std::string("restore by copy: ") + kB2CopyFromVersionUnsupported};
        return c;
    }
    c.unsupported = {unsupportedReason(providerIdentity)};
    return c;
}

std::string unsupportedReason(const std::string& providerIdentity) {
    if (providerIdentity == "aws-s3" || providerIdentity == "backblaze-b2") return {};
    if (providerIdentity == "cloudflare-r2") return storage::s3::provider::admin::kR2VersioningUnsupported;
    return "provider versioning is supported on AWS S3 and Backblaze B2 buckets only";
}

std::string dataPrefixFor(const vault::model::StorageLayout layout) {
    return layout == vault::model::StorageLayout::OpaqueV1 ? std::string(vl::vaultfmt::keys::kContentPrefix) : std::string{};
}

RuleScope ruleScopeFor(const std::string& providerIdentity, const vault::model::StorageLayout layout) {
    if (providerIdentity != "backblaze-b2") return {};
    if (layout == vault::model::StorageLayout::OpaqueV1) return {.prefix = dataPrefixFor(layout), .manifest_rule = false};
    return {.prefix = std::string{}, .manifest_rule = true};
}

}
