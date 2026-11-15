#pragma once

#include <array>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// The Vaulthalla Cloud link row (migrations 134, 141): at most one, pending or linked.
namespace vh::db::query::cloud {

struct LinkRow {
    std::string endpoint;
    std::string status;  // pending | linked
    std::array<uint8_t, 32> public_key{};
    std::string name;
    std::optional<std::string> request_id;
    std::optional<std::time_t> request_expires_at;
    std::optional<std::string> installation_id;
    std::optional<int64_t> account_id;
    std::string requested_by;
    std::time_t requested_at = 0;
    std::optional<std::time_t> linked_at;
    // What the claim and GET /v1/installation report (migration 141): the deployment this server is and the account's
    // public id (canonical UUID text), which every key statement and recovery policy names.
    std::optional<std::string> deployment_id;
    std::optional<std::string> account_public_id;
    // The last check of the account recovery key (GET /v1/keys/account): when, ok | none | unreachable | refused |
    // rejected | tampered, and why; the date the cloud records for an offline copy of the current generation.
    std::optional<std::time_t> key_checked_at;
    std::optional<std::string> key_check;
    std::optional<std::string> key_check_detail;
    std::optional<std::time_t> offline_copy_at;
};

struct Link {
    [[nodiscard]] static std::optional<LinkRow> get();
    // A new pending row, replacing a pending one (never a linked one: returns false then).
    static bool putPending(const LinkRow& row);
    // pending → linked, for the request it names. False when it isn't that pending request any more.
    static bool markLinked(const std::string& requestId, const std::string& installationId, int64_t accountId,
                           const std::optional<std::string>& deploymentId,
                           const std::optional<std::string>& accountPublicId);
    // Fills the deployment and account public id of a linked row that has none yet (a link made before migration
    // 141). Never changes a value already recorded: false then, or when the row isn't linked.
    static bool fillAccount(const std::optional<std::string>& deploymentId, const std::string& accountPublicId);
    // Records the outcome of a key check on a linked row.
    static void recordKeyCheck(const std::string& outcome, const std::optional<std::string>& detail,
                               std::optional<std::time_t> offlineCopyAt);
    static void clear();
};

}
