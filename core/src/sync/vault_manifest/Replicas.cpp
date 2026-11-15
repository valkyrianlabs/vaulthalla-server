#include "sync/vault_manifest/Replicas.hpp"

#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "ops/Error.hpp"

#include <fmt/format.h>

#include <algorithm>

namespace vh::sync::replicas {

bool experimental() { return config::Registry::get().sync.replicas.experimental; }

void requireExperimental(const std::string_view what) {
    if (!experimental())
        throw ops::Refused("replicas_experimental",
                           fmt::format("{}: replicated vaults are experimental and off; set sync.replicas.experimental: "
                                       "true in the configuration to use them",
                                       what));
}

std::vector<std::string> writers(const uint32_t vaultId) { return db::query::sync::Manifest::state(vaultId).writers; }

bool replicated(const uint32_t vaultId) {
    const auto self = db::query::device::Devices::nodeId();
    const auto w = writers(vaultId);
    return std::ranges::any_of(w, [&](const std::string& n) { return n != self; });
}

void refuseIfReplicated(const uint32_t vaultId, const std::string_view what, const std::string_view how) {
    if (!replicated(vaultId)) return;
    throw ops::Refused("vault_replicated",
                       fmt::format("vault {} is replicated (its manifest names {} writers): {} is refused on a "
                                   "replicated vault; {}",
                                   vaultId, writers(vaultId).size(), what, how));
}

}
