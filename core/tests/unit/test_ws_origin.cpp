// #324: cross-site websocket hijacking. A page on another site opening wss://<vaulthalla>/ws would ride the
// visitor's refresh cookie; the handshake now refuses a browser Origin that doesn't match the requested host (or
// websocket_server.allowed_origins). Also: listeners default to loopback when config.yaml has no host.

#include "config/Config.hpp"
#include "config/config_yaml.hpp"
#include "protocols/ws/OriginPolicy.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include <string>
#include <vector>

namespace vh::test_ws_origin {

using protocols::ws::origin::allowed;

TEST(WsOrigin, SameHostIsAllowedWhateverThePort) {
    EXPECT_TRUE(allowed("https://vault.example.com", "vault.example.com", "", {}));
    EXPECT_TRUE(allowed("https://vault.example.com:8443", "vault.example.com", "", {})) << "proxy port vs Host without port";
    EXPECT_TRUE(allowed("http://127.0.0.1:3000", "127.0.0.1:36969", "", {})) << "console dev server against the daemon";
    EXPECT_TRUE(allowed("https://VAULT.Example.com", "vault.example.com.", "", {}));
    EXPECT_TRUE(allowed("https://[::1]:8443", "[::1]", "", {}));
    EXPECT_TRUE(allowed("https://vault.example.com", "127.0.0.1:36969", "vault.example.com", {})) << "behind a proxy";
}

TEST(WsOrigin, NonBrowserClientsSendNoOriginAndAreAllowed) {
    EXPECT_TRUE(allowed("", "vault.example.com", "", {}));
}

TEST(WsOrigin, OtherSitesAreRefused) {
    EXPECT_FALSE(allowed("https://evil.example.net", "vault.example.com", "", {}));
    EXPECT_FALSE(allowed("https://vault.example.com.evil.net", "vault.example.com", "", {}));
    EXPECT_FALSE(allowed("null", "vault.example.com", "", {})) << "sandboxed iframes and file:// pages";
    EXPECT_FALSE(allowed("chrome-extension://abcdef", "vault.example.com", "", {}));
    EXPECT_FALSE(allowed("https://evil.example.net", "", "", {}));
}

TEST(WsOrigin, ConfiguredOriginsAreAllowed) {
    const std::vector<std::string> list{"https://console.example.org/", "http://10.0.0.5:3000"};
    EXPECT_TRUE(allowed("https://console.example.org", "vault.example.com", "", list));
    EXPECT_TRUE(allowed("http://10.0.0.5:3000", "vault.example.com", "", list));
    EXPECT_FALSE(allowed("http://10.0.0.5:3001", "vault.example.com", "", list)) << "listed origins match exactly";
}

TEST(WsOrigin, AllowedOriginsRoundTripThroughYamlAndJson) {
    config::WebsocketConfig ws;
    ws.allowed_origins = {"https://console.example.org"};
    const auto node = YAML::convert<config::WebsocketConfig>::encode(ws);
    config::WebsocketConfig back;
    ASSERT_TRUE(YAML::convert<config::WebsocketConfig>::decode(YAML::Load(YAML::Dump(node)), back));
    EXPECT_EQ(back.allowed_origins, ws.allowed_origins);
    const nlohmann::json j = ws;
    EXPECT_EQ(j.at("allowed_origins").get<std::vector<std::string>>(), ws.allowed_origins);
    EXPECT_EQ(j.get<config::WebsocketConfig>().allowed_origins, ws.allowed_origins);
}

TEST(ListenerDefaults, AMissingHostMeansLoopback) {
    EXPECT_EQ(config::WebsocketConfig{}.host, "127.0.0.1");
    EXPECT_EQ(config::HttpPreviewConfig{}.host, "127.0.0.1");
    EXPECT_EQ(config::S3GatewayConfig{}.host, "127.0.0.1");
    config::S3GatewayConfig s3;
    ASSERT_TRUE(YAML::convert<config::S3GatewayConfig>::decode(YAML::Load("enabled: true\n"), s3));
    EXPECT_EQ(s3.host, "127.0.0.1");
}

}
