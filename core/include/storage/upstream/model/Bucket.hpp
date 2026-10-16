#pragma once

#include "db/Fwd.hpp"
#include "storage/upstream/Guard.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// What Vaulthalla knows about one upstream bucket (upstream_bucket, migration 110), keyed by its identity
// (provider, account_ref, bucket), never by API key: a lock or an ownership record survives the key being deleted
// and re-created.
namespace vh::storage::upstream::model {

enum class Ownership { Managed, Adopted, Unmanaged };
enum class ProvisioningState { None, Creating, Configuring, Ready, Failed, Detached, Deleting, Deleted };

[[nodiscard]] std::string to_string(Ownership o);
[[nodiscard]] Ownership ownershipFromString(const std::string& s);              // throws std::invalid_argument
[[nodiscard]] std::string to_string(ProvisioningState s);
[[nodiscard]] ProvisioningState provisioningStateFromString(const std::string& s);   // throws std::invalid_argument

struct Bucket {
    int64_t id{};
    std::string provider;
    std::string account_ref;
    std::string bucket;
    std::optional<std::string> region;
    Ownership ownership{Ownership::Unmanaged};
    ProvisioningState provisioning_state{ProvisioningState::None};
    // Set only once CreateBucket succeeded for this row and the bucket listed empty (cleanup trusts it).
    bool created_by_vaulthalla{false};
    // A create-new attempt claimed this row (whether or not it created anything).
    bool provision_attempted{false};
    std::optional<std::string> operation_token;
    std::optional<uint32_t> vault_id;
    bool is_protected{false};
    std::optional<std::time_t> protected_at;
    std::optional<uint32_t> protected_by;
    std::optional<std::string> protected_by_name;
    std::optional<std::string> protection_reason;
    std::optional<uint32_t> last_seen_api_key_id;
    std::optional<std::time_t> discovered_at;
    std::optional<std::time_t> last_seen_at;
    std::optional<std::string> last_error;
    std::time_t created_at{};
    std::time_t updated_at{};

    Bucket() = default;
    explicit Bucket(pqxx::row_ref row);

    [[nodiscard]] BucketIdentity identity() const { return {.provider = provider, .account_ref = account_ref, .bucket = bucket}; }
};

}
