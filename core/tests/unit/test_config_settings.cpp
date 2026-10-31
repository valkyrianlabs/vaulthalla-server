// config.yaml / settings JSON for the keys #164 renamed, moved or wired up: sharing.*, vaults.s3.* and the two
// max_connections caps. Upgraded hosts keep their config.yaml (the package never rewrites it), so the old spellings
// must keep their values, the new ones must win when both are present, and the console's JSON must round-trip.

#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "config/config_yaml.hpp"
#include "fuse/Service.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "platform/Mount.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <unistd.h>
#include <yaml-cpp/yaml.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace vh::test_config_settings {

namespace fs = std::filesystem;
using json = nlohmann::json;

class ConfigSettingsTest : public ::testing::Test {
protected:
    config::Config load(const std::string& yaml, std::vector<std::string>* deprecations = nullptr) {
        path_ = fs::temp_directory_path() / ("vh-config-settings-" + std::to_string(::getpid()) + ".yaml");
        std::ofstream(path_) << yaml;
        return config::loadConfig(path_.string(), deprecations);
    }
    void TearDown() override {
        if (!path_.empty()) fs::remove(path_);
    }
    fs::path path_;
};

bool mentions(const std::vector<std::string>& messages, const std::string& needle) {
    return std::ranges::any_of(messages, [&](const std::string& m) { return m.find(needle) != std::string::npos; });
}

TEST_F(ConfigSettingsTest, MissingSectionsKeepTheDefaults) {
    std::vector<std::string> deprecations;
    const auto cfg = load("dev:\n  enabled: false\n", &deprecations);
    EXPECT_TRUE(cfg.sharing.enabled);
    EXPECT_TRUE(cfg.sharing.enable_anonymous);
    EXPECT_TRUE(cfg.sharing.enable_email_validated);
    EXPECT_EQ(cfg.vaults.s3.default_remote_sync_strategy, "cache");
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "ask");
    EXPECT_EQ(cfg.websocket.max_connections, 1024u);
    EXPECT_EQ(cfg.http_preview.max_connections, 512u);
    EXPECT_TRUE(deprecations.empty());
}

TEST_F(ConfigSettingsTest, NewKeysParse) {
    std::vector<std::string> deprecations;
    const auto cfg = load(R"(
sharing:
  enabled: true
  enable_anonymous: false
  enable_email_validated: true
vaults:
  s3:
    default_remote_sync_strategy: mirror
    default_remote_conflict_policy: keep_newest
websocket_server:
  max_connections: 64
)", &deprecations);
    EXPECT_FALSE(cfg.sharing.enable_anonymous);
    EXPECT_TRUE(cfg.sharing.enable_email_validated);
    EXPECT_EQ(cfg.vaults.s3.default_remote_sync_strategy, "mirror");
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "keep_newest");
    EXPECT_EQ(cfg.websocket.max_connections, 64u);
    EXPECT_TRUE(deprecations.empty());
}

// An upgraded host's config.yaml: the old names still carry the operator's values, and each one is reported.
TEST_F(ConfigSettingsTest, LegacyKeysKeepTheirValuesAndAreReported) {
    std::vector<std::string> deprecations;
    const auto cfg = load(R"(
s3_gateway:
  enabled: false
  default_remote_sync_strategy: sync
  default_remote_conflict_policy: keep_remote
sharing:
  enabled: true
  enable_public_links: false
)", &deprecations);
    EXPECT_FALSE(cfg.sharing.enable_email_validated);
    EXPECT_TRUE(cfg.sharing.enable_anonymous);
    EXPECT_EQ(cfg.vaults.s3.default_remote_sync_strategy, "sync");
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "keep_remote");
    ASSERT_EQ(deprecations.size(), 3u);
    EXPECT_TRUE(mentions(deprecations, "sharing.enable_public_links is deprecated: rename it to sharing.enable_email_validated"));
    EXPECT_TRUE(mentions(deprecations, "s3_gateway.default_remote_sync_strategy is deprecated: move it to vaults.s3"));
    EXPECT_TRUE(mentions(deprecations, "s3_gateway.default_remote_conflict_policy is deprecated: move it to vaults.s3"));
}

TEST_F(ConfigSettingsTest, NewKeysWinOverLegacyOnes) {
    std::vector<std::string> deprecations;
    const auto cfg = load(R"(
s3_gateway:
  default_remote_sync_strategy: sync
  default_remote_conflict_policy: keep_remote
vaults:
  s3:
    default_remote_sync_strategy: cache
    default_remote_conflict_policy: keep_local
sharing:
  enable_public_links: false
  enable_email_validated: true
)", &deprecations);
    EXPECT_TRUE(cfg.sharing.enable_email_validated);
    EXPECT_EQ(cfg.vaults.s3.default_remote_sync_strategy, "cache");
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "keep_local");
    ASSERT_EQ(deprecations.size(), 3u);
    for (const auto& message : deprecations) EXPECT_NE(message.find("ignored"), std::string::npos) << message;
}

// Nothing read the old gateway keys before #164, so they may hold anything; that must not stop the daemon.
TEST_F(ConfigSettingsTest, InvalidLegacyValueIsReportedNotFatal) {
    std::vector<std::string> deprecations;
    config::Config cfg;
    ASSERT_NO_THROW(cfg = load("s3_gateway:\n  default_remote_conflict_policy: keep_both\n", &deprecations));
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "ask");
    ASSERT_EQ(deprecations.size(), 1u);
    EXPECT_TRUE(mentions(deprecations, "'keep_both' is not valid"));
}

TEST_F(ConfigSettingsTest, InvalidNewValueRefusesToLoad) {
    EXPECT_THROW((void)load("vaults:\n  s3:\n    default_remote_sync_strategy: smart\n"), std::invalid_argument);
    EXPECT_THROW((void)load("vaults:\n  s3:\n    default_remote_conflict_policy: overwrite\n"), std::invalid_argument);
}

// mount.mode (#262). A typo refuses to start on every platform. A platform with no FUSE runtime (macOS) never mounts:
// a mode an earlier build accepted there is read as disabled with a warning, never a reason to refuse to start. Where
// FUSE exists (Linux) every known mode is kept as written, and fuse::mountStatus() reports what can't be mounted.
TEST_F(ConfigSettingsTest, MountModeTypoRefusesToLoad) {
    EXPECT_THROW((void)load("mount:\n  mode: multi-user\n"), std::invalid_argument);
}

TEST_F(ConfigSettingsTest, MountModeThisPlatformNeverMountsRunsDisabled) {
    for (const std::string mode : {"service_private", "multiuser"}) {
        SCOPED_TRACE(mode);
        std::vector<std::string> deprecations;
        config::Config cfg;
        ASSERT_NO_THROW(cfg = load("mount:\n  mode: " + mode + "\n", &deprecations));
        if (platform::mount::fuseRuntimeAvailable()) {
            EXPECT_EQ(cfg.mount.mode, mode);
            EXPECT_TRUE(deprecations.empty());
        } else {
            EXPECT_EQ(cfg.mount.mode, "disabled");
            ASSERT_EQ(deprecations.size(), 1u);
            EXPECT_TRUE(mentions(deprecations, "mount.mode '" + mode + "' is not available"));
            EXPECT_TRUE(mentions(deprecations, "Vaulthalla Desktop"));
        }
    }
    std::vector<std::string> deprecations;
    EXPECT_EQ(load("mount:\n  mode: disabled\n", &deprecations).mount.mode, "disabled");
    EXPECT_TRUE(deprecations.empty());
}

// The platform seam: macOS provides only disabled, Linux only multiuser (as it always has), neither service_private.
TEST(MountPlatform, ModesMatchTheFuseRuntime) {
    EXPECT_TRUE(platform::mount::supportsMode(platform::mount::defaultMode()));
    EXPECT_FALSE(platform::mount::supportsMode("service_private"));
    if (platform::mount::fuseRuntimeAvailable()) {
        EXPECT_EQ(platform::mount::defaultMode(), "multiuser");
    } else {
        EXPECT_EQ(platform::mount::defaultMode(), "disabled");
        EXPECT_FALSE(platform::mount::supportsMode("multiuser"));
    }
}

// Health and `vh status` where the server never mounts (macOS): disabled, saying where Finder access comes from,
// whatever config.yaml asked for. Linux mounts; its status is proven by make itest.
TEST_F(ConfigSettingsTest, MountStatusWhereTheServerNeverMounts) {
    if (platform::mount::fuseRuntimeAvailable()) GTEST_SKIP() << "this platform mounts; make itest proves its status";
    EXPECT_FALSE(fuse::kernelBridgeBuilt());
    EXPECT_EQ(fuse::makeService(), nullptr);
    struct Restore {
        config::Config saved;
        ~Restore() { config::Registry::set(saved); }
    } restore{config::Registry::get()};
    for (const std::string yaml : {"dev:\n  enabled: false\n", "mount:\n  mode: disabled\n",
                                   "mount:\n  mode: service_private\n", "mount:\n  mode: multiuser\n"}) {
        SCOPED_TRACE(yaml);
        config::Registry::set(load(yaml));
        const auto status = fuse::mountStatus();
        EXPECT_EQ(status.configuredMode, "disabled");
        EXPECT_EQ(status.state, "disabled");
        EXPECT_EQ(status.backend, "none");
        EXPECT_EQ(status.isolation, "not_applicable");
        EXPECT_NE(status.detail.find("Finder access is provided by Vaulthalla Desktop"), std::string::npos)
            << status.detail;
    }
}

// What the console edits and Config::save writes back: the new keys only, so a save migrates an old file.
TEST(ConfigSettingsSerialization, YamlRoundTripWritesOnlyTheNewKeys) {
    config::Config cfg;
    cfg.sharing.enable_anonymous = false;
    cfg.vaults.s3.default_remote_sync_strategy = "mirror";
    cfg.vaults.s3.default_remote_conflict_policy = "ask";

    const auto sharing = YAML::convert<config::SharingConfig>::encode(cfg.sharing);
    const auto vaults = YAML::convert<config::VaultsConfig>::encode(cfg.vaults);
    const auto gateway = YAML::convert<config::S3GatewayConfig>::encode(cfg.s3_gateway);
    EXPECT_FALSE(sharing["enable_public_links"]);
    EXPECT_FALSE(gateway["default_remote_sync_strategy"]);
    EXPECT_FALSE(gateway["default_remote_conflict_policy"]);

    config::SharingConfig sharingBack;
    config::VaultsConfig vaultsBack;
    ASSERT_TRUE(YAML::convert<config::SharingConfig>::decode(YAML::Load(YAML::Dump(sharing)), sharingBack));
    ASSERT_TRUE(YAML::convert<config::VaultsConfig>::decode(YAML::Load(YAML::Dump(vaults)), vaultsBack));
    EXPECT_EQ(json(sharingBack), json(cfg.sharing));
    EXPECT_EQ(json(vaultsBack), json(cfg.vaults));
}

TEST(ConfigSettingsSerialization, JsonRoundTripAndLegacyAliases) {
    config::Config cfg;
    cfg.sharing.enable_email_validated = false;
    cfg.vaults.s3.default_remote_conflict_policy = "keep_newest";
    cfg.websocket.max_connections = 77;

    const json doc = cfg;
    EXPECT_TRUE(doc.at("vaults").at("s3").contains("default_remote_sync_strategy"));
    EXPECT_FALSE(doc.at("s3_gateway").contains("default_remote_sync_strategy"));
    EXPECT_FALSE(doc.at("sharing").contains("enable_public_links"));
    const config::Config back(doc);
    EXPECT_EQ(json(back), doc);

    // A pre-#164 API client: old spellings apply when the new ones are absent...
    json legacy = doc;
    legacy.erase("vaults");
    legacy["s3_gateway"]["default_remote_sync_strategy"] = "sync";
    legacy["sharing"].erase("enable_email_validated");
    legacy["sharing"]["enable_public_links"] = false;
    const config::Config fromLegacy(legacy);
    EXPECT_EQ(fromLegacy.vaults.s3.default_remote_sync_strategy, "sync");
    EXPECT_FALSE(fromLegacy.sharing.enable_email_validated);

    // ...and lose to them when both are sent.
    json both = doc;
    both["s3_gateway"]["default_remote_sync_strategy"] = "sync";
    both["sharing"]["enable_public_links"] = true;
    const config::Config fromBoth(both);
    EXPECT_EQ(fromBoth.vaults.s3.default_remote_sync_strategy, "cache");
    EXPECT_FALSE(fromBoth.sharing.enable_email_validated);
}

// settings.update and the CLI share ops::config's validation.
TEST(ConfigSettingsValidation, RefusesUnknownVaultDefaultsAndZeroCaps) {
    const json current = config::Registry::get();

    auto doc = current;
    doc["vaults"]["s3"]["default_remote_conflict_policy"] = "keep_both";
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);

    doc = current;
    doc["vaults"]["s3"]["default_remote_sync_strategy"] = "smart";
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);

    doc = current;
    doc["websocket_server"]["max_connections"] = 0;
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);

    doc = current;
    doc["http_preview_server"]["max_connections"] = 0;
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);

    doc = current;
    doc["vaults"]["s3"]["default_remote_conflict_policy"] = "ask";
    doc["sharing"]["enable_anonymous"] = false;
    EXPECT_NO_THROW(ops::config::validateSettings(doc));
}

// Rollup retention used to be a hard-coded 365 days for both tiers, so the 5-minute tier (read only for windows up to
// 7 days) grew to most of the database. Each tier now has its own key; old configs get the defaults.
TEST_F(ConfigSettingsTest, StatsRollupRetentionDefaultsAndClamps) {
    const auto old = load("stats_snapshots:\n  enabled: true\n  retention_days: 14\n");
    EXPECT_EQ(old.stats_snapshots.retention_days, 14u);
    EXPECT_EQ(old.stats_snapshots.rollup_5m_retention_days, 30u);
    EXPECT_EQ(old.stats_snapshots.rollup_1h_retention_days, 365u);

    const auto set = load("stats_snapshots:\n  rollup_5m_retention_days: 10\n  rollup_1h_retention_days: 90\n");
    EXPECT_EQ(set.stats_snapshots.retention_days, 30u);
    EXPECT_EQ(set.stats_snapshots.rollup_5m_retention_days, 10u);
    EXPECT_EQ(set.stats_snapshots.rollup_1h_retention_days, 90u);

    // At least a day each, and the coarser tier is never dropped before the finer one.
    const auto clamped = load("stats_snapshots:\n  rollup_5m_retention_days: 0\n  rollup_1h_retention_days: 0\n");
    EXPECT_EQ(clamped.stats_snapshots.rollup_5m_retention_days, 1u);
    EXPECT_EQ(clamped.stats_snapshots.rollup_1h_retention_days, 1u);
    const auto inverted = load("stats_snapshots:\n  rollup_5m_retention_days: 60\n  rollup_1h_retention_days: 7\n");
    EXPECT_EQ(inverted.stats_snapshots.rollup_5m_retention_days, 60u);
    EXPECT_EQ(inverted.stats_snapshots.rollup_1h_retention_days, 60u);
}

TEST(ConfigSettingsSerialization, StatsRollupRetentionRoundTripsThroughYamlAndJson) {
    config::StatsSnapshotsConfig cfg;
    cfg.retention_days = 21;
    cfg.rollup_5m_retention_days = 9;
    cfg.rollup_1h_retention_days = 120;

    config::StatsSnapshotsConfig fromYaml;
    ASSERT_TRUE(YAML::convert<config::StatsSnapshotsConfig>::decode(
        YAML::Load(YAML::Dump(YAML::convert<config::StatsSnapshotsConfig>::encode(cfg))), fromYaml));
    EXPECT_EQ(json(fromYaml), json(cfg));

    const json doc = cfg;
    EXPECT_EQ(doc.at("rollup_5m_retention_days"), 9);
    EXPECT_EQ(doc.at("rollup_1h_retention_days"), 120);
    EXPECT_EQ(json(doc.get<config::StatsSnapshotsConfig>()), doc);

    // An older console that doesn't know the keys keeps the defaults; the settings JSON clamps like YAML.
    json legacy = doc;
    legacy.erase("rollup_5m_retention_days");
    legacy.erase("rollup_1h_retention_days");
    const auto fromLegacy = legacy.get<config::StatsSnapshotsConfig>();
    EXPECT_EQ(fromLegacy.rollup_5m_retention_days, 30u);
    EXPECT_EQ(fromLegacy.rollup_1h_retention_days, 365u);
    json inverted = doc;
    inverted["rollup_5m_retention_days"] = 0;
    inverted["rollup_1h_retention_days"] = 0;
    const auto fromInverted = inverted.get<config::StatsSnapshotsConfig>();
    EXPECT_EQ(fromInverted.rollup_5m_retention_days, 1u);
    EXPECT_EQ(fromInverted.rollup_1h_retention_days, 1u);
}

// The shipped default config uses the new keys only (an install never starts with a deprecation warning).
TEST(ShippedConfig, UsesTheNewKeysWithTheirDefaults) {
    // This tree's deploy/config/config.yaml (VH_PATH_TO_CONFIG may point at another checkout's).
    const auto path = fs::path(VH_TEST_ASSETS_DIR).parent_path().parent_path() / "deploy" / "config" / "config.yaml";
    ASSERT_TRUE(fs::exists(path)) << path;
    std::vector<std::string> deprecations;
    const auto cfg = config::loadConfig(path.string(), &deprecations);
    EXPECT_TRUE(deprecations.empty()) << deprecations.front();
    EXPECT_TRUE(cfg.sharing.enabled);
    EXPECT_TRUE(cfg.sharing.enable_anonymous);
    EXPECT_TRUE(cfg.sharing.enable_email_validated);
    EXPECT_EQ(cfg.vaults.s3.default_remote_sync_strategy, "cache");
    EXPECT_EQ(cfg.vaults.s3.default_remote_conflict_policy, "ask");
    EXPECT_EQ(cfg.websocket.max_connections, 1024u);
    EXPECT_EQ(cfg.http_preview.max_connections, 512u);
    EXPECT_EQ(cfg.stats_snapshots.retention_days, 30u);
    EXPECT_EQ(cfg.stats_snapshots.rollup_5m_retention_days, 30u);
    EXPECT_EQ(cfg.stats_snapshots.rollup_1h_retention_days, 365u);
    EXPECT_EQ(json(cfg.transfer), json(config::TransferConfig{})) << "the shipped transfer section is the defaults";
}


// transfer.* (resumable uploads): every key optional, out-of-range values refused (never clamped), and the same keys
// round-trip through YAML and JSON.
TEST_F(ConfigSettingsTest, TransferDefaultsParseAndRefuseOutOfRange) {
    const auto defaults = load("dev:\n  enabled: false\n");
    EXPECT_EQ(defaults.transfer.part_default_bytes, 64ull << 20);
    EXPECT_EQ(defaults.transfer.part_min_bytes, 1ull << 20);
    EXPECT_EQ(defaults.transfer.max_part_bytes, 512ull << 20);
    EXPECT_EQ(defaults.transfer.http.max_part_bytes, 64ull << 20);
    EXPECT_EQ(defaults.transfer.max_parts_in_flight, 4u);
    EXPECT_EQ(defaults.transfer.commit_workers, 2u);
    EXPECT_EQ(defaults.transfer.session_idle_ttl_hours, 24u);
    EXPECT_EQ(defaults.transfer.session_max_age_hours, 168u);

    const auto set = load("transfer:\n  max_parts_in_flight: 8\n  http:\n    max_part_bytes: 95000000\n");
    EXPECT_EQ(set.transfer.max_parts_in_flight, 8u);
    EXPECT_EQ(set.transfer.http.max_part_bytes, 95000000u);
    EXPECT_EQ(set.transfer.max_part_bytes, 512ull << 20) << "a key left out keeps its default";

    for (const auto* bad : {"transfer:\n  max_parts_in_flight: 0\n", "transfer:\n  max_parts_in_flight: 17\n",
                            "transfer:\n  commit_workers: 9\n", "transfer:\n  max_part_bytes: 4294967297\n",
                            "transfer:\n  part_min_bytes: 0\n", "transfer:\n  part_default_bytes: 1024\n",
                            "transfer:\n  http:\n    max_part_bytes: 1073741824\n",
                            "transfer:\n  http:\n    max_part_bytes: 1024\n",
                            "transfer:\n  session_idle_ttl_hours: 0\n"})
        EXPECT_THROW((void)load(bad), std::invalid_argument) << bad;
}

TEST(ConfigSettingsSerialization, TransferRoundTripsAndSettingsUpdateRefusesOutOfRange) {
    config::Config cfg;
    cfg.transfer.max_parts_in_flight = 6;
    cfg.transfer.http.max_part_bytes = 32ull << 20;
    const auto node = YAML::convert<config::TransferConfig>::encode(cfg.transfer);
    config::TransferConfig back;
    ASSERT_TRUE(YAML::convert<config::TransferConfig>::decode(node, back));
    EXPECT_EQ(json(back), json(cfg.transfer));
    EXPECT_EQ(json(cfg).at("transfer").get<config::TransferConfig>().max_parts_in_flight, 6u);

    const json current = config::Registry::get();
    auto doc = current;
    doc["transfer"]["commit_workers"] = 0;
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);
    doc = current;
    doc["transfer"]["http"]["max_part_bytes"] = (1ull << 30);
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);
    doc = current;
    doc["transfer"]["max_parts_in_flight"] = 8;
    EXPECT_NO_THROW(ops::config::validateSettings(doc));
}

}
