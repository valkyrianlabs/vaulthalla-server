#pragma once

#include <nlohmann/json_fwd.hpp>

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

// Facts about the daemon itself, for clients that must adapt to it.
struct Meta {
    // meta.contract.get: the identity of the contract this daemon was built from (core/usage, vh_usage --json):
    // {contract_version, contract_hash, ws_hash}. The web console compares ws_hash with the one it was generated
    // against and tells the user to reload when they differ. Read-only, no secrets, allowed without a signed-in user.
    static json contract();
};

}
