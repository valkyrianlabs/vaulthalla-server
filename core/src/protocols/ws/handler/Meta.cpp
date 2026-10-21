#include "protocols/ws/handler/Meta.hpp"
#include "Contract.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

json Meta::contract() {
    const auto& id = vh::contract::identity();
    return {{"contract_version", id.version}, {"contract_hash", id.contract_hash}, {"ws_hash", id.ws_hash},
            {"models_hash", id.models_hash}};
}

}
