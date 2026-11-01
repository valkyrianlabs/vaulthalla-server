#include "platform/Sealer.hpp"
#include "platform/darwin/SealerBackends.hpp"
#include "log/Registry.hpp"

#include <filesystem>
#include <mutex>
#include <stdexcept>
#include <string>
#include <paths.h>

// macOS: the Secure Enclave by default (-Ddarwin_sealer=secure-enclave), the development "file" backend when the
// build asks for it or the Mac has no Secure Enclave (a virtual machine). One backend per process, reported by
// backend(). Reads follow the format on disk, not the backend: a slot holding <name>.key (every macOS install before
// the Secure Enclave backend) is unsealed from the file and, under the Secure Enclave, resealed there and the
// plaintext file removed. When both formats are present (a crash between writing one and removing the other), the
// active backend's file is the newer one and wins. One operation at a time per process: DB pool connections open
// together and each unseals (on a first start, seals; after an upgrade, migrates) the same slot, and two writers of
// one slot would race on its temporary file. A Secure Enclave unwrap takes about 7 ms.
namespace vh::platform::sealer {

namespace {

enum class DarwinSealer { SecureEnclave, File };

DarwinSealer chooseDarwinSealer() {
    if (std::string_view(VH_DARWIN_SEALER) == "file") {
        log::Registry::crypto()->warn("[Sealer] Using the development 'file' secret backend (-Ddarwin_sealer=file): "
                                      "sealed secrets are plain 0600 files with no hardware binding");
        return DarwinSealer::File;
    }
    if (secure_enclave::available()) return DarwinSealer::SecureEnclave;
    log::Registry::crypto()->error("[Sealer] This Mac has no Secure Enclave (a virtual machine?): sealing with the "
                                   "development 'file' backend instead, plain 0600 files with no hardware binding. "
                                   "Health reports the secrets backend as 'file'");
    return DarwinSealer::File;
}

DarwinSealer activeDarwinSealer() {
    static const DarwinSealer chosen = chooseDarwinSealer();
    return chosen;
}

bool underSecureEnclave() { return activeDarwinSealer() == DarwinSealer::SecureEnclave; }

std::mutex& darwinSealerMutex() {
    static std::mutex m;
    return m;
}

void sealLocked(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret) {
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
        return underSecureEnclave() ? "secure-enclave" : "file";
    } catch (...) {
        return "file";
    }
}

void seal(const std::filesystem::path& dir, const std::string& name, const std::vector<uint8_t>& secret) {
    const std::scoped_lock lock(darwinSealerMutex());
    sealLocked(dir, name, secret);
}

std::vector<uint8_t> unseal(const std::filesystem::path& dir, const std::string& name) {
    const std::scoped_lock lock(darwinSealerMutex());
    const auto sePath = secure_enclave::path(dir, name);
    const auto filePath = file::path(dir, name);
    const bool hasSe = std::filesystem::exists(sePath);
    const bool hasFile = std::filesystem::exists(filePath);

    if (hasSe && (underSecureEnclave() || !hasFile)) {
        auto secret = secure_enclave::unseal(dir, name);
        if (hasFile && underSecureEnclave()) removeDurably(filePath);
        return secret;
    }
    if (!hasFile) throw std::runtime_error("no sealed secret '" + name + "' under " + dir.string());

    auto secret = file::unseal(dir, name);
    if (underSecureEnclave()) {
        // seal() reads the new blob back before writing it and removes the plaintext file only after.
        sealLocked(dir, name, secret);
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
