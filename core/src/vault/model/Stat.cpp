#include "vault/model/Stat.hpp"
#include "vault/model/Capacity.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/Engine.hpp"
#include "sync/model/Event.hpp"

#include <nlohmann/json.hpp>

using namespace vh::vault::model;

Stat::Stat(unsigned int vaultId)
    : vault_id(vaultId),
      capacity(std::make_shared<Capacity>(vaultId)) {}

nlohmann::json vh::vault::model::statJson(const std::shared_ptr<Capacity>& capacity,
                                          const std::shared_ptr<sync::model::Event>& latestSyncEvent) {
    nlohmann::json j;
    j["capacity"] = capacity;
    j["latest_sync_event"] = latestSyncEvent;
    return j;
}

void vh::vault::model::to_json(nlohmann::json& j, const std::shared_ptr<Stat>& s) {
    j = statJson(s->capacity, runtime::Deps::get().storageManager->getEngine(s->vault_id)->latestSyncEvent);
}
