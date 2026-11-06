#include "crypto/secrets/KeyProvider.hpp"
#include "platform/Sealer.hpp"
#include "config/Registry.hpp"

#include <paths.h>
#include <algorithm>
#include <atomic>
#include <stdexcept>
#include <utility>

namespace vh::crypto::secrets {

namespace {

std::atomic<KeyProvider::UnsealHook> unsealHook{nullptr};
std::atomic<const char*> postureOverride{nullptr};

std::filesystem::path resolveSealedDir(const std::string& key) {
    return paths::getBackingPath() / (".sealed_" + key + ".blob");
}

}

KeyProvider::KeyProvider(const std::string& name)
    : name_(name), sealedDir_(resolveSealedDir(name)) {
}

void KeyProvider::init(const std::span<const uint8_t> initial) {
    requirePosture();
    platform::sealer::recover(sealedDir_, name_);  // an interrupted reseal (#351)
    if (platform::sealer::present(sealedDir_, name_)) {
        unsealStored();
        return;
    }
    sealAndKeep(initial.empty() ? SecretBytes{} : SecretBytes(initial));
}

void KeyProvider::initGuarded(const DependentsCheck& dependents) {
    requirePosture();
    platform::sealer::recover(sealedDir_, name_);  // an interrupted reseal (#351)
    if (platform::sealer::present(sealedDir_, name_)) {
        unsealStored();
        return;
    }
    if (dependents) {
        if (const auto what = dependents())
            throw MasterSecretLost(
                "The sealed master secret '" + name_ + "' is missing (" + sealedDir_.string() + "), but " + *what +
                " in the database are encrypted with it. Refusing to create a new one: that would make them "
                "permanently undecryptable. Restore the state directory from backup (with the same TPM or Secure "
                "Enclave), or restore the vault keys from their backups (`vh vault keys import`) and the internal "
                "secrets with `vh secret` (docs: vaults/secrets-and-key-export).");
    }
    sealAndKeep({});
}

void KeyProvider::updateMasterKey(const std::span<const uint8_t> newMasterKey) {
    sealAndKeep(newMasterKey.empty() ? SecretBytes{} : SecretBytes(newMasterKey));
}

void KeyProvider::setUnsealHookForTesting(const UnsealHook hook) noexcept { unsealHook.store(hook); }

bool KeyProvider::sealedExists() const {
    return platform::sealer::complete(sealedDir_, name_);
}

void KeyProvider::destroySealed() {
    std::error_code ec;
    std::filesystem::remove_all(sealedDir_, ec);
    if (ec) throw std::filesystem::filesystem_error("deleting the sealed secret '" + name_ + "'", sealedDir_, ec);
    master_ = SecretBytes{};
}

std::string_view KeyProvider::backend() noexcept { return platform::sealer::backend(); }

std::string_view KeyProvider::posture() noexcept {
    if (const auto* forced = postureOverride.load()) return forced;
    return platform::sealer::posture();
}

void KeyProvider::setPostureForTesting(const char* posture) noexcept { postureOverride.store(posture); }

platform::sealer::Policy KeyProvider::policy() const {
    if (!platform::sealer::complete(sealedDir_, name_)) return platform::sealer::Policy::None;
    return platform::sealer::policyOf(sealedDir_, name_);
}

platform::sealer::ResealResult KeyProvider::reseal(const platform::sealer::Policy to) {
    requirePosture();
    return platform::sealer::reseal(sealedDir_, name_, to);
}

platform::sealer::Policy KeyProvider::configuredPolicy() {
    if (!platform::sealer::policySupported()) return platform::sealer::Policy::None;
    return platform::sealer::parsePolicy(config::Registry::get().secrets.tpm_pcr_policy)
        .value_or(platform::sealer::Policy::None);
}

std::vector<std::string> KeyProvider::sealedNames() {
    std::vector<std::string> out;
    std::error_code ec;
    constexpr std::string_view prefix = ".sealed_", suffix = ".blob";
    for (const auto& entry : std::filesystem::directory_iterator(paths::getBackingPath(), ec)) {
        const auto file = entry.path().filename().string();
        if (!entry.is_directory(ec) || file.size() <= prefix.size() + suffix.size() || !file.starts_with(prefix) ||
            !file.ends_with(suffix))
            continue;
        out.push_back(file.substr(prefix.size(), file.size() - prefix.size() - suffix.size()));
    }
    std::ranges::sort(out);
    return out;
}

void KeyProvider::requirePosture() {
    if (!config::Registry::get().secrets.require_hardware) return;
    if (const auto p = posture(); p != "hardware")
        throw std::runtime_error("secrets.require_hardware is set, but sealed secrets on this host are protected by '" +
                                 std::string(p) + "' sealing (" + std::string(backend()) +
                                 "), not hardware. Use a host with a hardware TPM (Linux) or the Secure Enclave "
                                 "(macOS), or turn the setting off.");
}

SecretBytes KeyProvider::generateMasterSecret(const std::size_t bytes) {
    if (bytes == 0) throw std::invalid_argument("master secret size must be > 0");
    return SecretBytes::random(bytes);
}

void KeyProvider::unsealStored() {
    // The sealer hands the secret back in a plain vector: it is wiped here on every path, a throw included, and
    // only the locked copy is kept.
    const WipedKeyCopy unsealed(platform::sealer::unseal(sealedDir_, name_));
    if (const auto hook = unsealHook.load()) hook(unsealed.bytes);
    master_ = SecretBytes(unsealed.bytes);
}

void KeyProvider::sealAndKeep(SecretBytes candidate) {
    if (candidate.empty()) candidate = generateMasterSecret();
    platform::sealer::seal(sealedDir_, name_, candidate.bytes(), configuredPolicy());
    master_ = std::move(candidate);
}

} // namespace vh::crypto::secrets
