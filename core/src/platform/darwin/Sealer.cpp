#include "platform/Sealer.hpp"
#include "platform/darwin/SealerBackends.hpp"
#include "log/Registry.hpp"
#include "config/Registry.hpp"

#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <paths.h>
#include <sodium/utils.h>

// macOS: the Secure Enclave by default (-Ddarwin_sealer=secure-enclave), the development "file" backend when the
// build asks for it or no Secure Enclave key can be used here. One backend per process, reported by
// backend(). Reads follow the format on disk, not the backend: a slot holding <name>.key (every macOS install before
// the Secure Enclave backend) is unsealed from the file and, under the Secure Enclave, resealed there and the
// plaintext file removed. When both formats are present (a crash between writing one and removing the other), the
// active backend's file is the newer one and wins. One operation at a time per process: DB pool connections open
// together and each unseals (on a first start, seals; after an upgrade, migrates) the same slot, and two writers of
// one slot would race on its temporary file. A Secure Enclave unwrap takes about 7 ms.
namespace vh::platform::sealer {

namespace {

enum class DarwinSealer { SecureEnclave, File, Unavailable };

DarwinSealer chooseDarwinSealer();

DarwinSealer activeDarwinSealer() {
    static const DarwinSealer chosen = chooseDarwinSealer();
    return chosen;
}

// Fails closed (#326): without a usable Secure Enclave the daemon refuses to seal or unseal, unless the plain-file
// development backend was chosen explicitly, by the build (-Ddarwin_sealer=file) or by config.yaml
// (secrets.allow_development_file_backend). It used to fall back to files silently, presenting an unprotected
// install as a sealed one.
DarwinSealer chooseDarwinSealer() {
    if (std::string_view(VH_DARWIN_SEALER) == "file") {
        log::Registry::crypto()->warn("[Sealer] Using the development 'file' secret backend (-Ddarwin_sealer=file): "
                                      "sealed secrets are plain 0600 files with no hardware binding");
        return DarwinSealer::File;
    }
    if (secure_enclave::available()) return DarwinSealer::SecureEnclave;
    if (config::Registry::get().secrets.allow_development_file_backend) {
        log::Registry::crypto()->error("[Sealer] The Secure Enclave can't be used here ({}); secrets."
                                       "allow_development_file_backend is set, so secrets are sealed as plain 0600 "
                                       "files with no hardware binding (development only)",
                                       secure_enclave::unavailableReason());
        return DarwinSealer::File;
    }
    log::Registry::crypto()->critical("[Sealer] The Secure Enclave can't be used here ({}). Refusing to keep secrets "
                                      "in plain files. Run the daemon under launchd on a Mac with a Secure Enclave "
                                      "(Apple silicon or T2), or, for development only, set "
                                      "secrets.allow_development_file_backend: true in config.yaml",
                                      secure_enclave::unavailableReason());
    return DarwinSealer::Unavailable;
}

void requireUsable() {
    if (activeDarwinSealer() == DarwinSealer::Unavailable)
        throw std::runtime_error("no secure secret backend: the Secure Enclave can't be used here (" +
                                 secure_enclave::unavailableReason() +
                                 "); see secrets.allow_development_file_backend for development hosts");
}


bool underSecureEnclave() { return activeDarwinSealer() == DarwinSealer::SecureEnclave; }

std::mutex& darwinSealerMutex() {
    static std::mutex m;
    return m;
}

void sealLocked(const std::filesystem::path& dir, const std::string& name, const std::span<const uint8_t> secret) {
    if (underSecureEnclave()) {
        secure_enclave::seal(dir, name, secret);
        removeDurably(file::path(dir, name));
    } else {
        file::seal(dir, name, secret);
        removeDurably(secure_enclave::path(dir, name));
    }
}

}

std::string_view backend() noexcept {
    try {
        switch (activeDarwinSealer()) {
            case DarwinSealer::SecureEnclave: return "secure-enclave";
            case DarwinSealer::File: return "file";
            case DarwinSealer::Unavailable: return "unavailable";
        }
    } catch (...) {}
    return "unavailable";
}

std::string_view posture() noexcept {
    try {
        switch (activeDarwinSealer()) {
            case DarwinSealer::SecureEnclave: return "hardware";
            case DarwinSealer::File: return "development";
            case DarwinSealer::Unavailable: return "unknown";
        }
    } catch (...) {}
    return "unknown";
}

void seal(const std::filesystem::path& dir, const std::string& name, const std::span<const uint8_t> secret) {
    const std::scoped_lock lock(darwinSealerMutex());
    requireUsable();
    sealLocked(dir, name, secret);
}

std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name) {
    const std::scoped_lock lock(darwinSealerMutex());
    requireUsable();
    const auto sePath = secure_enclave::path(dir, name);
    const auto filePath = file::path(dir, name);
    const bool hasSe = std::filesystem::exists(sePath);
    const bool hasFile = std::filesystem::exists(filePath);

    if (hasSe && (underSecureEnclave() || !hasFile)) {
        auto secret = secure_enclave::unseal(dir, name);
        try {
            if (hasFile && underSecureEnclave()) removeDurably(filePath);
        } catch (...) {
            sodium_memzero(secret.data(), secret.size());
            throw;
        }
        return secret;
    }
    if (!hasFile) throw std::runtime_error("no sealed secret '" + name + "' under " + dir.string());

    auto secret = file::unseal(dir, name);
    if (underSecureEnclave()) {
        // seal() reads the new blob back before writing it and removes the plaintext file only after.
        try {
            sealLocked(dir, name, secret);
        } catch (...) {
            sodium_memzero(secret.data(), secret.size());
            throw;
        }
        log::Registry::crypto()->info("[Sealer] Moved sealed secret '{}' from the file backend to the Secure Enclave",
                                      name);
    }
    return secret;
}

bool present(const std::filesystem::path& dir, const std::string& name) {
    return std::filesystem::exists(secure_enclave::path(dir, name)) || std::filesystem::exists(file::path(dir, name));
}

bool complete(const std::filesystem::path& dir, const std::string& name) {
    return present(dir, name);
}

}
