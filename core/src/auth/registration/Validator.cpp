#include "auth/registration/Validator.hpp"
#include "crypto/password/Strength.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"

#include <paths.h>
#include <ranges>
#include <algorithm>
#include <cctype>
#include <vector>

namespace vh::auth::registration {

namespace {
constexpr std::size_t kMinPasswordLength = 8;
constexpr std::size_t kMaxPasswordLength = 128;
constexpr std::size_t kPassphraseLength = 20;
constexpr unsigned short kMinPasswordStrength = 50;
}

void Validator::validateRegistration(const identities::UserState& user, const std::string& password) {
    std::vector<std::string> errors;

    if (!isValidName(user.name)) errors.emplace_back("Name must be between 3 and 50 characters.");

    if (user.email && !isValidEmail(*user.email)) errors.emplace_back("Email must be valid and contain '@' and '.'.");

    if (const auto violation = passwordPolicyViolation(password)) errors.push_back(*violation);

    if (!errors.empty()) {
        std::ostringstream oss;
        oss << "Registration failed due to the following issues:\n";
        for (const auto& err : errors) oss << "- " << err << std::endl;
        log::Registry::auth()->error("[AuthManager] Registration validation failed: {}", oss.str());
        throw std::runtime_error(oss.str());
    }
}

bool Validator::isValidName(const std::string& name) {
    return !name.empty() && name.size() > 2 && name.size() <= 50;
}

bool Validator::isValidEmail(const std::string& email) {
    return !email.empty() && email.find('@') != std::string::npos && email.find('.') != std::string::npos;
}

bool Validator::isValidPassword(const std::string& password) {
    return !passwordPolicyViolation(password);
}

std::optional<std::string> Validator::passwordPolicyViolation(const std::string& password) {
    if (paths::testMode) return std::nullopt;
    if (auto violation = localPasswordPolicyViolation(password)) return violation;
    if (crypto::password::Strength::isPwnedPassword(password))
        return "Password has been found in public breaches; choose a different one.";
    return std::nullopt;
}

std::optional<std::string> Validator::localPasswordPolicyViolation(const std::string& password) {
    using crypto::password::Strength;

    if (password.size() < kMinPasswordLength)
        return "Password must be at least " + std::to_string(kMinPasswordLength) + " characters.";
    if (password.size() > kMaxPasswordLength)
        return "Password must be at most " + std::to_string(kMaxPasswordLength) + " characters.";

    // Long passwords and passphrases carry their strength in length; only shorter ones need a letter and a digit.
    const auto isDigit = [](const unsigned char c) { return std::isdigit(c) != 0; };
    const auto isLetter = [](const unsigned char c) { return std::isalpha(c) != 0; };
    if (password.size() < kPassphraseLength &&
        !(std::ranges::any_of(password, isDigit) && std::ranges::any_of(password, isLetter)))
        return "Passwords shorter than " + std::to_string(kPassphraseLength) +
               " characters need at least one letter and one digit.";

    if (const auto strength = Strength::passwordStrengthCheck(password); strength < kMinPasswordStrength)
        return "Password is too weak (strength " + std::to_string(strength) +
               "/100). Use a longer password, or mix upper/lowercase, digits, and symbols.";

    if (Strength::isDictionaryWord(password)) return "Password is a dictionary word.";
    if (Strength::isCommonWeakPassword(password)) return "Password is a commonly used password.";
    return std::nullopt;
}

bool Validator::isValidGroup(const std::string& group) {
    return !group.empty() && group.size() >= 3 && group.size() <= 50;
}

}
