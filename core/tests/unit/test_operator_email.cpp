#include "config/Config.hpp"
#include "config/config_yaml.hpp"
#include "crypto/secrets/Manager.hpp"
#include "email/Message.hpp"
#include "email/Transport.hpp"
#include "email/providers/ResendProvider.hpp"
#include "email/providers/SesProvider.hpp"
#include "email/templates/OperatorTemplates.hpp"
#include "CommandUsage.hpp"
#include "usage/include/UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>
#include <vl/sigv4/verifier.hpp>

#include <algorithm>
#include <chrono>
#include <ctime>
#include <memory>
#include <optional>
#include <string_view>
#include <tuple>
#include <vector>

namespace {

vh::email::Message testMessage() {
    return {
        .from = {.email = "ops@example.com", .name = "Vaulthalla"},
        .to = {{.email = "admin@example.com", .name = std::nullopt}},
        .replyTo = vh::email::Address{.email = "reply@example.com", .name = std::nullopt},
        .subject = "[Vaulthalla] Test operator email",
        .html = "<strong>Hello</strong>",
        .text = "Hello",
        .idempotencyKey = "operator-test:unit",
        .tags = {}
    };
}

bool hasHeader(const vh::email::HttpRequest& request, const std::string& header) {
    return std::ranges::find(request.headers, header) != request.headers.end();
}

void expectRenderedEmail(
    const vh::email::RenderedEmail& rendered,
    const std::string_view subjectFragment,
    const std::string_view htmlFragment,
    const std::string_view textFragment
) {
    EXPECT_FALSE(rendered.subject.empty());
    EXPECT_FALSE(rendered.html.empty());
    EXPECT_FALSE(rendered.text.empty());
    EXPECT_NE(rendered.subject.find(subjectFragment), std::string::npos);
    EXPECT_NE(rendered.html.find(htmlFragment), std::string::npos);
    EXPECT_NE(rendered.text.find(textFragment), std::string::npos);
}

}

TEST(OperatorEmailConfigTest, JsonRoundTripUsesProviderStringsAndNoSecrets) {
    vh::config::Config cfg;
    cfg.email.enabled = true;
    cfg.email.provider = vh::config::EmailProviderKind::Resend;
    cfg.email.from = "Vaulthalla <ops@example.com>";
    cfg.email.reply_to = "ops@example.com";
    cfg.email.base_url = "https://vault.example.com";
    cfg.operator_emails.recipients.alerts = {"ops@example.com"};

    nlohmann::json encoded = cfg;

    EXPECT_EQ(encoded["email"]["provider"], "resend");
    EXPECT_EQ(encoded["email"]["reply_to"], "ops@example.com");
    EXPECT_FALSE(encoded.dump().contains("api_key"));
    EXPECT_FALSE(encoded.dump().contains("secret"));

    const auto decoded = encoded.get<vh::config::Config>();
    EXPECT_TRUE(decoded.email.enabled);
    EXPECT_EQ(decoded.email.provider, vh::config::EmailProviderKind::Resend);
    ASSERT_TRUE(decoded.email.base_url);
    EXPECT_EQ(*decoded.email.base_url, "https://vault.example.com");
    ASSERT_EQ(decoded.operator_emails.recipients.alerts.size(), 1u);
}

TEST(OperatorEmailConfigTest, YamlDecodeAcceptsNullOptionalFields) {
    const auto node = YAML::Load(R"yaml(
enabled: true
provider: resend
from: "Vaulthalla <ops@example.com>"
reply_to: null
base_url: null
resend:
  endpoint: "https://api.resend.test/emails"
)yaml");

    const auto cfg = node.as<vh::config::EmailConfig>();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(cfg.provider, vh::config::EmailProviderKind::Resend);
    EXPECT_FALSE(cfg.reply_to);
    EXPECT_FALSE(cfg.base_url);
    EXPECT_EQ(cfg.resend.endpoint, "https://api.resend.test/emails");
}

TEST(OperatorEmailUsageTest, ResolvesPhaseOneCommandTree) {
    vh::protocols::shell::UsageManager manager;

    EXPECT_EQ(manager.resolve(std::vector<std::string>{"email"})->primary(), "email");
    EXPECT_EQ(manager.resolve(std::vector<std::string>{"email", "provider", "resend", "set"})->primary(), "set");
    EXPECT_EQ(manager.resolve(std::vector<std::string>{"email", "doctor"})->primary(), "doctor");
    EXPECT_EQ(manager.resolve(std::vector<std::string>{"email", "test", "--dry-run"})->primary(), "test");
}

TEST(OperatorEmailMessageTest, ParsesAndValidatesDisplayAddresses) {
    const auto address = vh::email::parseAddress("Vaulthalla <ops@example.com>");

    ASSERT_TRUE(address.name);
    EXPECT_EQ(*address.name, "Vaulthalla");
    EXPECT_EQ(address.email, "ops@example.com");
    EXPECT_EQ(vh::email::formatAddress(address), "Vaulthalla <ops@example.com>");
    EXPECT_NO_THROW(vh::email::validateMessage(testMessage()));
    EXPECT_THROW((void)vh::email::parseAddress("not-an-email"), std::invalid_argument);
}

TEST(OperatorEmailTemplateTest, RendersHtmlAndTextWithoutRawHtmlInjection) {
    const auto rendered = vh::email::templates::renderTestEmail({
        .provider = "resend",
        .instance = "host<prod>",
        .from = "Vaulthalla <ops@example.com>",
        .recipient = "admin+ops@example.com",
        .dryRun = true,
        .baseUrl = "https://vault.example.com"
    });

    EXPECT_EQ(rendered.subject, "[Vaulthalla] Test operator email");
    EXPECT_NE(rendered.html.find("host&lt;prod&gt;"), std::string::npos);
    EXPECT_EQ(rendered.html.find("host<prod>"), std::string::npos);
    EXPECT_NE(rendered.text.find("Provider: resend"), std::string::npos);
    EXPECT_FALSE(rendered.html.empty());
    EXPECT_FALSE(rendered.text.empty());
}

TEST(OperatorEmailTemplateTest, RendersRepresentativeWatchdogAlertAndRecovery) {
    const vh::email::templates::WatchdogEmailContext alertCtx{
        .instance = "prod<primary>",
        .status = "critical",
        .severity = "critical",
        .fingerprint = "critical|services:fuse<mount>",
        .checkedAt = 1'735'689'600,
        .servicesReady = 5,
        .servicesTotal = 7,
        .depsReady = 8,
        .depsTotal = 10,
        .protocolsReady = 1,
        .protocolsTotal = 2,
        .failedServices = {"fuse<mount>", "sync controller"},
        .missingDependencies = {"secrets manager"},
        .protocolIssues = {"websocket endpoint is not ready"},
        .baseUrl = "https://vault.example.com"
    };

    const auto alert = vh::email::templates::renderWatchdogAlertEmail(alertCtx);
    expectRenderedEmail(alert, "Runtime critical", "prod&lt;primary&gt;", "fuse<mount>");
    EXPECT_EQ(alert.html.find("prod<primary>"), std::string::npos);
    EXPECT_NE(alert.html.find("fuse&lt;mount&gt;"), std::string::npos);

    auto recoveryCtx = alertCtx;
    recoveryCtx.status = "healthy";
    recoveryCtx.severity = "info";
    recoveryCtx.failedServices.clear();
    recoveryCtx.missingDependencies.clear();
    recoveryCtx.protocolIssues.clear();

    const auto recovery = vh::email::templates::renderWatchdogRecoveryEmail(recoveryCtx);
    expectRenderedEmail(recovery, "Runtime recovered", "Runtime recovered", "Runtime recovered");
}

TEST(OperatorEmailTemplateTest, RendersRepresentativeWeeklyDigestAndSecurityAlert) {
    const vh::email::templates::WeeklyDigestEmailContext digestCtx{
        .instance = "prod<primary>",
        .weekStart = "2026-05-11",
        .weekEnd = "2026-05-17",
        .scheduledWeekday = "monday",
        .scheduledHourUtc = 8,
        .timezone = "UTC",
        .checkedAt = 1'768'608'000,
        .systemStatus = "warning",
        .dashboardStatus = "warning",
        .warningCount = 4,
        .errorCount = 1,
        .servicesReady = 12,
        .servicesTotal = 13,
        .depsReady = 9,
        .depsTotal = 10,
        .protocolsReady = 3,
        .protocolsTotal = 3,
        .dashboardAvailable = true,
        .dashboardUnavailableReason = std::nullopt,
        .sections = {
            {.title = "Runtime", .severity = "warning", .summary = "One service restarted during the window.", .warningCount = 1, .errorCount = 0},
            {.title = "Vaults", .severity = "healthy", .summary = "All vault sync loops are current.", .warningCount = 0, .errorCount = 0},
            {.title = "Shares", .severity = "critical", .summary = "Expired challenge cleanup needs review.", .warningCount = 1, .errorCount = 1}
        },
        .attention = {
            {.title = "Filesystem latency", .severity = "warning", .message = "p95 metadata latency crossed 250ms."},
            {.title = "Share challenge backlog", .severity = "critical", .message = "Email challenge retries are elevated."}
        },
        .baseUrl = "https://vault.example.com"
    };

    const auto digest = vh::email::templates::renderWeeklyDigestEmail(digestCtx);
    expectRenderedEmail(digest, "Weekly digest", "Share challenge backlog", "Share challenge backlog");

    const vh::email::templates::SecurityAlertEmailContext securityCtx{
        .instance = "prod<primary>",
        .action = "updated",
        .severity = "warning",
        .occurredAt = 1'768'608'000,
        .roleId = 42,
        .roleName = "security<admin>",
        .roleDescription = "Privileged role for incident response <review>",
        .actor = "alice (user id 7)",
        .source = "websocket",
        .permissionFlags = {"admin.roles.edit", "admin.keys.view", "admin.audit.full"},
        .baseUrl = "https://vault.example.com"
    };

    const auto security = vh::email::templates::renderSecurityAlertEmail(securityCtx);
    expectRenderedEmail(security, "Security alert", "security&lt;admin&gt;", "security<admin>");
    EXPECT_EQ(security.html.find("security<admin>"), std::string::npos);
    EXPECT_NE(security.html.find("incident response &lt;review&gt;"), std::string::npos);
}

TEST(ResendProviderTest, SendsExpectedRequestThroughFakeTransport) {
    auto fake = std::make_unique<vh::email::FakeTransport>();
    fake->response = {.status = 202, .body = R"json({"id":"email_123"})json", .headers = ""};
    auto* fakePtr = fake.get();

    vh::email::providers::ResendProvider provider(
        {.endpoint = "https://api.resend.test/emails"},
        [] { return std::optional<std::string>{"re_unit_test_key"}; },
        std::move(fake)
    );

    const auto result = provider.send(testMessage());

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.providerMessageId);
    EXPECT_EQ(*result.providerMessageId, "email_123");
    ASSERT_EQ(fakePtr->requests.size(), 1u);

    const auto& request = fakePtr->requests.front();
    EXPECT_EQ(request.method, "POST");
    EXPECT_EQ(request.url, "https://api.resend.test/emails");
    EXPECT_TRUE(hasHeader(request, "Authorization: Bearer re_unit_test_key"));
    EXPECT_TRUE(hasHeader(request, "Content-Type: application/json"));
    EXPECT_TRUE(hasHeader(request, "Idempotency-Key: operator-test:unit"));

    const auto body = nlohmann::json::parse(request.body);
    EXPECT_EQ(body["from"], "Vaulthalla <ops@example.com>");
    EXPECT_EQ(body["to"][0], "admin@example.com");
    EXPECT_EQ(body["reply_to"], "reply@example.com");
    EXPECT_EQ(body["subject"], "[Vaulthalla] Test operator email");
    EXPECT_FALSE(request.body.contains("re_unit_test_key"));
}

TEST(ResendProviderTest, MissingSecretDoesNotCallTransport) {
    auto fake = std::make_unique<vh::email::FakeTransport>();
    auto* fakePtr = fake.get();

    vh::email::providers::ResendProvider provider(
        {},
        [] { return std::optional<std::string>{}; },
        std::move(fake)
    );

    const auto result = provider.send(testMessage());

    EXPECT_FALSE(result.ok);
    ASSERT_TRUE(result.errorSummary);
    EXPECT_EQ(*result.errorSummary, "missing Resend API key secret");
    EXPECT_TRUE(fakePtr->requests.empty());
}

// An endpoint with a path prefix (an SES proxy at https://host/aws) sends to <origin><prefix>/v2/... and must sign that
// same path: signing only /v2/... while the URL carries the prefix is a SignatureDoesNotMatch at the proxy or SES.
TEST(SesProviderTest, EndpointPathPrefixIsSentAndSigned) {
    for (const auto& [endpoint, origin, host, path] : std::vector<std::tuple<std::string, std::string, std::string, std::string>>{
             {"https://ses-proxy.example.test/aws/", "https://ses-proxy.example.test", "ses-proxy.example.test",
              "/aws/v2/email/outbound-emails"},
             {"http://127.0.0.1:8443/relay/ses", "http://127.0.0.1:8443", "127.0.0.1:8443",
              "/relay/ses/v2/email/outbound-emails"},
             {"https://email.eu-west-1.amazonaws.test", "https://email.eu-west-1.amazonaws.test",
              "email.eu-west-1.amazonaws.test", "/v2/email/outbound-emails"},
         }) {
        SCOPED_TRACE(endpoint);
        auto fake = std::make_unique<vh::email::FakeTransport>();
        fake->response = {.status = 200, .body = R"json({"MessageId":"m"})json", .headers = ""};
        auto* fakePtr = fake.get();
        vh::email::providers::SesProvider provider(
            {.region = "eu-west-1", .endpoint = endpoint},
            vh::crypto::secrets::Manager::createForTesting({
                {vh::email::providers::SesProvider::kAccessKeySecret, "AKIA_UNIT_TEST"},
                {vh::email::providers::SesProvider::kSecretKeySecret, "ses_unit_test_secret"}
            }),
            std::move(fake)
        );

        ASSERT_TRUE(provider.send(testMessage()).ok);
        ASSERT_EQ(fakePtr->requests.size(), 1u);
        const auto& request = fakePtr->requests.front();
        EXPECT_EQ(request.url, origin + path);
        EXPECT_TRUE(hasHeader(request, "Host: " + host));

        vl::sigv4::VerificationInput input{.method = request.method, .target = path, .host = host, .body = request.body};
        for (const auto& header : request.headers) {
            const auto colon = header.find(": ");
            ASSERT_NE(colon, std::string::npos) << header;
            input.headers.emplace_back(header.substr(0, colon), header.substr(colon + 2));
        }
        const auto verified = vl::sigv4::verify(input, "ses_unit_test_secret", vl::sigv4::Clock::now(),
                                                {.service = "ses", .region = "eu-west-1"});
        EXPECT_TRUE(verified.ok()) << verified.message << "\n" << verified.canonical_request;
    }
}

TEST(SesProviderTest, SendsExpectedRequestThroughFakeTransport) {
    auto fake = std::make_unique<vh::email::FakeTransport>();
    fake->response = {.status = 200, .body = R"json({"MessageId":"ses-message-123"})json", .headers = ""};
    auto* fakePtr = fake.get();

    vh::email::providers::SesProvider provider(
        {
            .region = "us-east-1",
            .endpoint = "https://email.us-east-1.amazonaws.test"
        },
        vh::crypto::secrets::Manager::createForTesting({
            {vh::email::providers::SesProvider::kAccessKeySecret, "AKIA_UNIT_TEST"},
            {vh::email::providers::SesProvider::kSecretKeySecret, "ses_unit_test_secret"}
        }),
        std::move(fake)
    );

    const auto result = provider.send(testMessage());

    ASSERT_TRUE(result.ok);
    ASSERT_TRUE(result.providerMessageId);
    EXPECT_EQ(*result.providerMessageId, "ses-message-123");
    ASSERT_EQ(fakePtr->requests.size(), 1u);

    const auto& request = fakePtr->requests.front();
    EXPECT_EQ(request.method, "POST");
    EXPECT_EQ(request.url, "https://email.us-east-1.amazonaws.test/v2/email/outbound-emails");
    EXPECT_TRUE(hasHeader(request, "Content-Type: application/json"));
    EXPECT_TRUE(hasHeader(request, "Host: email.us-east-1.amazonaws.test"));
    EXPECT_TRUE(std::ranges::any_of(request.headers, [](const std::string& header) {
        return header.starts_with("X-Amz-Date: ");
    }));
    EXPECT_TRUE(std::ranges::any_of(request.headers, [](const std::string& header) {
        return header.starts_with("X-Amz-Content-Sha256: ");
    }));
    EXPECT_TRUE(std::ranges::any_of(request.headers, [](const std::string& header) {
        return header.starts_with("Authorization: AWS4-HMAC-SHA256 Credential=AKIA_UNIT_TEST/");
    }));

    const auto body = nlohmann::json::parse(request.body);
    EXPECT_EQ(body["FromEmailAddress"], "Vaulthalla <ops@example.com>");
    EXPECT_EQ(body["Destination"]["ToAddresses"][0], "admin@example.com");
    EXPECT_EQ(body["ReplyToAddresses"][0], "reply@example.com");
    EXPECT_EQ(body["Content"]["Simple"]["Subject"]["Data"], "[Vaulthalla] Test operator email");
    EXPECT_EQ(body["Content"]["Simple"]["Body"]["Html"]["Data"], "<strong>Hello</strong>");
    EXPECT_FALSE(request.body.contains("AKIA_UNIT_TEST"));
    EXPECT_FALSE(request.body.contains("ses_unit_test_secret"));
}
