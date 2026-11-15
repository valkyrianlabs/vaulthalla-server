#pragma once

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Managed storage's rows (migration 142; design/cloud/managed-remotes.md, "Data model"): vault_cloud_storage (one per
// vault the managed-storage service considered), cloud_storage_account (the account's entitlement as last fetched and
// this server's settings) and the origin of the bucket keys it holds (api_keys.origin, .cloud_access). Trusted
// primitives: nothing here authorizes.
namespace vh::db::query::cloud {

struct VaultStorageRow {
    uint32_t vault_id{};
    std::string vault_uid;
    std::string switch_state{"off"};   // on | off | offered | declined
    std::string switch_by;
    std::time_t switch_at{};
    // unregistered | registered | waiting | keyed | attaching | active | detaching | off | moved | ejected | ended |
    // failed
    std::string state{"unregistered"};
    std::optional<std::string> reason{};
    std::optional<std::string> bucket{}, bucket_id{}, s3_endpoint{}, region{};
    std::optional<uint32_t> api_key_id{};
    std::optional<std::string> key_id{};
    std::string key_state{"none"};     // none | issued | active | superseded
    std::optional<std::string> key_access{};
    std::optional<uint32_t> retention_days{}, retention_sent{}, label_generation{}, enrolled_version{};
    std::optional<std::time_t> enroll_behind_since{};
    uint32_t attempts{};
    std::optional<std::time_t> next_attempt_at{};
    std::optional<std::string> last_error{};
    std::optional<std::time_t> registered_at{}, ready_at{}, active_at{}, moved_at{}, ejected_at{}, ended_at{};
    std::time_t updated_at{};
};

struct StorageAccountRow {
    std::optional<std::string> state{};            // active | past_due | restricted | suspended | ended | null
    std::optional<std::string> plan{};
    std::optional<uint64_t> quota_bytes{};
    std::optional<std::string> storage_access{};   // full | read_delete | none
    std::optional<std::string> cause{};
    std::optional<uint64_t> used_bytes{};
    std::optional<std::string> usage_day{};
    std::optional<bool> account_key_confirmed{};
    std::optional<std::string> provider{};
    nlohmann::json ejection = nullptr;
    nlohmann::json billing = nullptr;
    std::optional<std::time_t> fetched_at{};
    std::optional<std::string> fetch_error{};
    bool new_vaults{true};
    std::optional<std::time_t> enabled_at{};
    bool offer_open{false};
    std::optional<std::time_t> fast_until{};
    std::optional<std::time_t> ended_seen_at{}, ended_confirmed_at{};   // migration 143
    std::optional<std::string> ended_confirmed_by{};
};

// What a successful fetch writes (the settings stay as they are).
struct FetchedAccount {
    std::optional<std::string> state;
    std::string plan;
    uint64_t quota_bytes{};
    std::string storage_access;
    std::string cause;
    std::optional<uint64_t> used_bytes;
    std::optional<std::string> usage_day;
    bool account_key_confirmed{};
    std::string provider;
    nlohmann::json ejection = nullptr;
    nlohmann::json billing = nullptr;
};

struct CloudStorage {
    // ---- the account ---------------------------------------------------------------------------------------------------
    [[nodiscard]] static std::optional<StorageAccountRow> account();
    static void saveFetched(const FetchedAccount& fetched);
    static void saveFetchError(const std::string& error);
    static void setNewVaults(bool on);
    // The first time storage is seen available on this link (true when this call set it).
    static bool markEnabled();
    static void setOfferOpen(bool open);
    static void setFastUntil(std::time_t until);
    // An admin confirmed the current run of `ended` answers (false: the service isn't reporting `ended`).
    static bool confirmEnded(const std::string& by);
    // The link is gone: the cached entitlement and the settings go with it.
    static void clearAccount();

    // ---- vaults --------------------------------------------------------------------------------------------------------
    [[nodiscard]] static std::vector<VaultStorageRow> list();
    [[nodiscard]] static std::optional<VaultStorageRow> get(uint32_t vaultId);
    // A new row (nothing when the vault has one already): true when inserted.
    static bool insert(const VaultStorageRow& row);
    // Writes every column but vault_id and vault_uid.
    static void update(const VaultStorageRow& row);
    static void remove(uint32_t vaultId);

    // Live vaults (not deleted) without a row, with their type and created_at: the sweep's candidates.
    struct Candidate {
        uint32_t vault_id{};
        std::string vault_uid;
        std::string type;            // local | s3
        std::time_t created_at{};
    };
    [[nodiscard]] static std::vector<Candidate> candidates();
    // Whether the vault holds a file with content (a vault is registered only once it does).
    [[nodiscard]] static bool hasContent(uint32_t vaultId);
    // The sealed bytes of its live files with content (the quota courtesy check, the offer's sizes).
    [[nodiscard]] static uint64_t contentBytes(uint32_t vaultId);
    // Vaults that are managed now (a row past registration that isn't off, moved, ejected, ended or failed).
    [[nodiscard]] static bool anyManaged();
    [[nodiscard]] static bool managed(uint32_t vaultId);

    // ---- keys ----------------------------------------------------------------------------------------------------------
    // Marks a key as the cloud's (origin cloud, with its access).
    static void markKeyCloud(uint32_t apiKeyId, const std::string& access);
    // Ejection in place, in one transaction: the vault's key becomes a customer key (origin customer, no cloud
    // access), the row `ejected`. False when the row was already ejected (or has no key).
    static bool eject(uint32_t vaultId);
    // An attached managed vault's recovery setup (design/cloud/managed-remotes.md, "Noncurrent retention"): the bucket
    // bound to the vault in upstream_bucket (versioning enabled, as the provider always versions; the noncurrent
    // retention in days unless already set), and the vault's recovery mode provider_versioning. Idempotent.
    static void bindManagedBucket(uint32_t vaultId, const std::string& provider, const std::string& accountRef,
                                  const std::string& bucket, const std::optional<std::string>& region,
                                  uint32_t apiKeyId, uint32_t retentionDays);
    // The retention the vault's recovery policy asks for now (its bound bucket's noncurrent retention): days, 36500 for
    // indefinite (the service's largest value), nullopt when unset or unbound.
    [[nodiscard]] static std::optional<uint32_t> desiredRetention(uint32_t vaultId);
    // A key's owner: the vault's owner (a cloud key belongs to it).
    [[nodiscard]] static std::optional<uint32_t> ownerOf(uint32_t vaultId);
};

}
