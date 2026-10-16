// The shell router's debug log never carries credential option values (`vh api-key create … --secret <value>`).

#include "protocols/shell/Router.hpp"

#include <gtest/gtest.h>

using vh::protocols::shell::redactLineForLog;

TEST(ShellLogRedaction, CredentialOptionValuesAreRedacted) {
    const auto line = redactLineForLog(
        "api-key create k --access AKIAEXAMPLE --secret wJalrXUtnFEMI/K7MDENG --provider aws --region us-east-1");
    EXPECT_EQ(line.find("wJalrXUtnFEMI"), std::string::npos) << line;
    EXPECT_NE(line.find("--secret [REDACTED]"), std::string::npos) << line;
    EXPECT_NE(line.find("--region us-east-1"), std::string::npos) << "other options stay readable";
}

TEST(ShellLogRedaction, EqualsFormQuotedValuesAndPasswords) {
    EXPECT_EQ(redactLineForLog("user create bob --password='a b c' --role admin"),
              "user create bob --password=[REDACTED] --role admin");
    EXPECT_EQ(redactLineForLog("x --secret-key \"two words\" y"), "x --secret-key [REDACTED] y");
    EXPECT_EQ(redactLineForLog("x --token=abc"), "x --token=[REDACTED]");
}

TEST(ShellLogRedaction, FlagsWithoutValuesAndOddTokensAreSafe) {
    // A prompting flag followed by another option redacts nothing; bare dashes don't throw.
    EXPECT_EQ(redactLineForLog("upstream admin enable 3 --provider-token --json"),
              "upstream admin enable 3 --provider-token --json");
    EXPECT_EQ(redactLineForLog("fs get /a -- - --"), "fs get /a -- - --");
    EXPECT_EQ(redactLineForLog(""), "");
}
