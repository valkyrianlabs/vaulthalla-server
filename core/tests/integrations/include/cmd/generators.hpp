#pragma once

#include "ArgsGenerator.hpp"
#include "types/Type.hpp"
#include "permsUtil.hpp"
#include "seed/Stream.hpp"

#include <atomic>
#include <string>
#include <string_view>
#include <memory>
#include <stdexcept>
#include <cstdlib>
#include <cstdint>

namespace vh::test::integration {

// Every draw comes from the seeded stream of the test (or stage) running on this thread (seed/Stream.hpp).
inline uint64_t generateRandomIndex(const uint64_t max) {
    if (max == 0) throw std::runtime_error("CLITestContext: cannot generate index for empty collection");
    return seed::current().uniform_int<uint64_t>(0, max - 1);
}

inline bool coin(const uintmax_t outOf = 10000, const uintmax_t p = 5000) { return generateRandomIndex(outOf) < p; }

inline std::string generateNow(args::Gen g,
                           const std::string_view token = "default",
                           const std::string_view usage = "example") {
    args::Rng rng{seed::current().engine()()};
    const args::GenContext ctx{std::string(token), std::string(usage)};
    return args::to_string_value(g->generate(rng, ctx));
}

inline std::string generateName(const std::string& usage) {
    const auto it = std::views::split(usage, '/').front();
    const std::string entity(it.begin(), it.end());
    return generateNow(args::ArgGenerator::Join({
        args::ArgGenerator::Constant(std::string(entity + "_")),
        args::ArgGenerator::RandomString(6, 10, "abcdefghijklmnopqrstuvwxyz0123456789")
    }, ""), "name", usage);
}

inline std::string generateEmail(const std::string& usage) {
    return generateNow(args::ArgGenerator::Join({
        args::ArgGenerator::RandomString(6, 10, "abcdefghijklmnopqrstuvwxyz0123456789"),
        args::ArgGenerator::Constant(std::string("@example.org"))
    }, ""), "email", usage);
}

inline std::string generateVaultName(const std::string& usage, const bool prefix = true) {
    if (prefix) {
        return generateNow(args::ArgGenerator::Join({
            args::ArgGenerator::Constant(std::string("vault_")),
            args::ArgGenerator::RandomString(6, 18, "abcdefghijklmnopqrstuvwxyz0123456789")
        }, ""), "vault_name", usage);
    }
    return generateNow(args::ArgGenerator::RandomString(8, 22, "abcdefghijklmnopqrstuvwxyz0123456789"),
                           "vault_name", usage);
}

inline std::string generateRoleName(const EntityType& type, const std::string& usage) {
    if (type == EntityType::ADMIN_ROLE) {
        return generateNow(args::ArgGenerator::Join({
            args::ArgGenerator::Constant(std::string("role_")),
            args::ArgGenerator::RandomString(6, 10, "abcdefghijklmnopqrstuvwxyz0123456789")
        }, ""), "role_name", usage);
    }
    if (type == EntityType::VAULT_ROLE) {
        return generateNow(args::ArgGenerator::Join({
            args::ArgGenerator::Constant(std::string("vrole_")),
            args::ArgGenerator::RandomString(6, 10, "abcdefghijklmnopqrstuvwxyz0123456789")
        }, ""), "role_name", usage);
    }
    throw std::runtime_error("EntityFactory: unsupported entity type for role name generation");
}

inline uint16_t generateBitmask(const std::size_t numBits) {
    if (numBits == 0 || numBits > 16) throw std::runtime_error("EntityFactory: invalid bitmask size");
    uint16_t mask = 0;
    for (std::size_t i = 0; i < numBits; ++i) if (coin()) mask |= (1 << i);
    do {
        mask = 0;
        for (std::size_t i = 0; i < numBits; ++i)
            if (coin()) mask |= (1 << i);

        mask |= (1 << (1 + generateRandomIndex(numBits - 1))); // force at least one nonzero
        mask &= ~0b0000000000000011;
    } while (mask == 0 || mask == 0b0000001111111111); // forbid super_admin
    return mask;
}

inline std::string generateQuotaStr(const std::string& usage) {
    return generateNow(args::ArgGenerator::Join({
        args::ArgGenerator::OneOf({"unlimited", "100MB", "1G", "10G", "100G", "1T"})
    }, ""), "quota", usage);
}

inline std::string randomAlias(const std::vector<std::string>& aliases) {
    if (aliases.empty()) throw std::runtime_error("AliasHandler: no aliases provided");
    return aliases[generateRandomIndex(aliases.size())];
}

inline std::string randomFlagAlias(const std::vector<std::string>& flags) {
    if (flags.empty()) throw std::runtime_error("AliasHandler: no flag aliases provided");
    const auto a = flags[generateRandomIndex(flags.size())];
    if (a.size() == 1) return "-" + a;
    return "--" + a;
}

inline std::string randomAllowDenyOrNoOptMakeFlag(const std::string& flag) {
    const auto choice = generateRandomIndex(3);
    if (choice == 0) return "--allow-" + flag;
    if (choice == 1) return "--deny-" + flag;
    return "--" + flag;
}

inline std::string generateDescription(const std::string& usage) {
    return generateNow(args::ArgGenerator::Join({
        args::ArgGenerator::Constant(std::string("Auto-generated description ")),
        args::ArgGenerator::RandomString(10, 100, "abcdefghijklmnopqrstuvwxyz0123456789 ")
    }, ""), "description", usage);
}

// Test Linux UIDs/GIDs come from one reserved range (VH_TEST_UID_BASE, default kDefaultLinuxIdBase) and are unique
// within a run: never a real account's id (1000+), never the invoking admin's, never one handed out twice
// (users.linux_uid and groups.linux_gid are UNIQUE).
//
// The default sits below 2^31: users.linux_uid and groups.linux_gid are signed INTEGER columns
// (deploy/psql/010_auth.sql), so the daemon can't store a uid >= 2147483648 at all (an insert fails with "value ...
// is out of range for type integer"). 2100000000 is above SSSD's default id range (up to 2000200000) and below
// systemd's container range at 0x7FFE0000.
inline constexpr uint32_t kDefaultLinuxIdBase = 2100000000u;
inline constexpr uint32_t kLinuxIdSpan = 1000000u;
inline constexpr uint32_t kLargestStorableLinuxId = 2147483647u;

namespace detail {
inline std::atomic<uint32_t> g_linuxIdBase{kDefaultLinuxIdBase};
inline std::atomic<uint32_t> g_linuxIdNext{0};
}

inline void setLinuxIdBase(const uint32_t base) {
    if (base < 65536u || base > UINT32_MAX - 2u - kLinuxIdSpan)
        throw std::invalid_argument("VH_TEST_UID_BASE must leave room for " + std::to_string(kLinuxIdSpan) +
                                    " ids between 65536 and 4294967293");
    detail::g_linuxIdBase.store(base);
}

[[nodiscard]] inline uint32_t linuxIdBase() { return detail::g_linuxIdBase.load(); }

[[nodiscard]] inline uint32_t allocateLinuxId() {
    const auto n = detail::g_linuxIdNext.fetch_add(1);
    if (n >= kLinuxIdSpan) throw std::runtime_error("integration harness: reserved Linux id range exhausted");
    return linuxIdBase() + n;
}

}
