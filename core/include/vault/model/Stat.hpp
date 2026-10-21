#pragma once

#include "sync/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <nlohmann/json_fwd.hpp>

namespace vh::vault::model {

struct Capacity;

struct Stat {
    uint32_t vault_id;
    std::shared_ptr<Capacity> capacity;

    explicit Stat(unsigned int vaultId);
};

void to_json(nlohmann::json& j, const std::shared_ptr<Stat>& s);

// What to_json sends for a vault: its capacity and its engine's latest sync run (null before the first one).
nlohmann::json statJson(const std::shared_ptr<Capacity>& capacity,
                        const std::shared_ptr<sync::model::Event>& latestSyncEvent);

}
