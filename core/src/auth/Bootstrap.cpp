#include "auth/Bootstrap.hpp"

#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"

#include <paths.h>
#include <pqxx/pqxx>
#include <sodium.h>

#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/stat.h>
#include <stdexcept>
#include <system_error>
#include <unistd.h>

namespace vh::auth::bootstrap {

namespace {

// Seeded by every install before 1.8.0. Kept only to recognise and replace it.
constexpr const char* kRetiredDefaultPassword = "vh!adm1n";

// Digest of the last admin password hash verified not to be the retired default. The Argon2 verify costs ~0.3 s and
// ran on every start; it now runs again only when admin's hash changed (any new password is a new hash).
constexpr const char* kLegacyCheckMarkerName = ".legacy_default_password_checked";

std::filesystem::path legacyCheckMarker() { return paths::getBackingPath() / kLegacyCheckMarkerName; }

std::string readLegacyCheckMarker() {
    std::ifstream in(legacyCheckMarker());
    std::string line;
    std::getline(in, line);
    return line;
}

[[noreturn]] void throwErrno(const std::string& what) {
    throw std::system_error(errno, std::generic_category(), what);
}

void writeAll(const int fd, const std::string& content, const std::filesystem::path& path) {
    std::size_t written = 0;
    while (written < content.size()) {
        const auto n = ::write(fd, content.data() + written, content.size() - written);
        if (n < 0) {
            if (errno == EINTR) continue;
            throwErrno("writing " + path.string());
        }
        written += static_cast<std::size_t>(n);
    }
}

// Temp file in the same directory (O_EXCL, O_NOFOLLOW, 0600), fsync, rename over the target, fsync the directory:
// a crash leaves either no file or the whole password, never a partial one.
void writePrivateFileAtomically(const std::filesystem::path& path, const std::string& content) {
    const auto dir = path.parent_path();
    std::filesystem::create_directories(dir);
    const auto tmp = dir / ("." + path.filename().string() + ".tmp." + std::to_string(::getpid()));
    (void)::unlink(tmp.c_str());

    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) throwErrno("creating " + tmp.string());
    try {
        if (::fchmod(fd, 0600) != 0) throwErrno("chmod " + tmp.string());
        writeAll(fd, content, tmp);
        if (platform::durable::sync(fd) != 0) throwErrno("fsync " + tmp.string());
    } catch (...) {
        ::close(fd);
        (void)::unlink(tmp.c_str());
        throw;
    }
    if (::close(fd) != 0) {
        (void)::unlink(tmp.c_str());
        throwErrno("closing " + tmp.string());
    }
    if (::rename(tmp.c_str(), path.c_str()) != 0) {
        const int err = errno;
        (void)::unlink(tmp.c_str());
        errno = err;
        throwErrno("renaming " + tmp.string() + " to " + path.string());
    }
    if (const int dfd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC); dfd >= 0) {
        (void)platform::durable::sync(dfd);
        ::close(dfd);
    }
}

void setGenerated(const bool generated) {
    db::Transactions::exec("auth::bootstrap::setGenerated", [&](pqxx::work& txn) {
        txn.exec(generated
                     ? "INSERT INTO auth_bootstrap_state (id, super_admin_password_generated, generated_at, rotated_at) "
                       "VALUES (1, TRUE, NOW(), NULL) ON CONFLICT (id) DO UPDATE SET "
                       "super_admin_password_generated = TRUE, generated_at = NOW(), rotated_at = NULL"
                     : "INSERT INTO auth_bootstrap_state (id, super_admin_password_generated, rotated_at) "
                       "VALUES (1, FALSE, NOW()) ON CONFLICT (id) DO UPDATE SET "
                       "super_admin_password_generated = FALSE, rotated_at = NOW()");
    });
}

}

std::filesystem::path initialPasswordFile() {
    return paths::getBackingPath() / kInitialPasswordFileName;
}

bool initialPasswordFileExists() noexcept {
    std::error_code ec;
    return std::filesystem::exists(initialPasswordFile(), ec);
}

std::string generatePassword() {
    std::array<unsigned char, 16> bytes{};
    randombytes_buf(bytes.data(), bytes.size());
    std::array<char, bytes.size() * 2 + 1> hex{};
    sodium_bin2hex(hex.data(), hex.size(), bytes.data(), bytes.size());
    sodium_memzero(bytes.data(), bytes.size());
    return {hex.data(), bytes.size() * 2};
}

std::string issueInitialCredential() {
    auto password = generatePassword();
    auto hash = crypto::hash::password(password);
    if (hash.empty()) throw std::runtime_error("failed to hash the initial super-admin password");

    writePrivateFileAtomically(initialPasswordFile(), password + "\n");
    sodium_memzero(password.data(), password.size());
    setGenerated(true);

    log::Registry::audit()->info("[bootstrap] Generated the initial password of the '{}' account", kSuperAdminName);
    log::Registry::vaulthalla()->warn(
        "[bootstrap] Initial web console password for '{}' written to {} (readable by root). Change it with "
        "'vh setup set-super-admin-password', or keep it and delete that file.",
        kSuperAdminName, initialPasswordFile().string());
    return hash;
}

bool superAdminPasswordIsGenerated() {
    return db::Transactions::exec("auth::bootstrap::isGenerated", [](pqxx::work& txn) {
        const auto res = txn.exec("SELECT super_admin_password_generated FROM auth_bootstrap_state WHERE id = 1");
        return !res.empty() && res.one_field_ref().as<bool>();
    });
}

bool initialPasswordExposed() {
    return initialPasswordFileExists() && superAdminPasswordIsGenerated();
}

std::optional<std::string> removeInitialPasswordFile() {
    std::error_code ec;
    std::filesystem::remove(initialPasswordFile(), ec);
    if (!ec) return std::nullopt;
    return "could not remove " + initialPasswordFile().string() + ": " + ec.message();
}

std::optional<std::string> onSuperAdminPasswordChanged() {
    setGenerated(false);
    auto error = removeInitialPasswordFile();
    if (error)
        log::Registry::vaulthalla()->error(
            "[bootstrap] The '{}' password was changed, but its initial plaintext copy is still on disk: {}. "
            "Remove it manually: sudo rm -f {}",
            kSuperAdminName, *error, initialPasswordFile().string());
    return error;
}

bool retireLegacyDefaultPassword() {
    const auto admin = db::Transactions::exec("auth::bootstrap::legacyCheck", [](pqxx::work& txn) {
        const auto res = txn.exec("SELECT id, password_hash FROM users WHERE name = $1", pqxx::params{std::string{kSuperAdminName}});
        return res.empty() ? std::optional<std::pair<unsigned int, std::string>>{}
                           : std::make_optional(std::make_pair(res[0][0].as<unsigned int>(), res[0][1].as<std::string>()));
    });
    if (!admin) return false;

    const auto fingerprint = crypto::hash::tokenDigest(admin->second);
    if (readLegacyCheckMarker() == fingerprint) return false;
    if (!crypto::hash::verifyPassword(kRetiredDefaultPassword, admin->second)) {
        try {
            writePrivateFileAtomically(legacyCheckMarker(), fingerprint + "\n");
        } catch (const std::exception& e) {
            // Best effort: without the marker the next start just verifies again.
            log::Registry::vaulthalla()->debug("[bootstrap] Could not record the legacy password check: {}", e.what());
        }
        return false;
    }

    const auto hash = issueInitialCredential();
    db::Transactions::exec("auth::bootstrap::retireLegacy", [&](pqxx::work& txn) {
        txn.exec("UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2",
                 pqxx::params{hash, admin->first});
    });
    db::query::auth::RefreshToken::revokeAll(admin->first);

    log::Registry::audit()->warn("[bootstrap] Replaced the retired universal default password of '{}'", kSuperAdminName);
    log::Registry::vaulthalla()->warn(
        "[bootstrap] '{}' still used the retired universal default password. It was replaced with a generated one, "
        "written to {}; its existing web sessions were ended.",
        kSuperAdminName, initialPasswordFile().string());
    return true;
}

}
