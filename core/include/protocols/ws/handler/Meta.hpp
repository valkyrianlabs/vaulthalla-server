#pragma once

#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <memory>
#include <string>
#include <vector>

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

// Facts about the daemon itself, for clients that must adapt to it.
struct Meta {
    // meta.contract.get: the identity of the contract this daemon was built from (core/usage, vh_usage --json):
    // {contract_version, contract_hash, ws_hash, models_hash}. The web console compares ws_hash with the one it was
    // generated against and tells the user to reload when they differ. Read-only, no secrets; a signed-in session
    // (web or device) or a pairing-only one, never an unauthenticated web socket (bc342115).
    static json contract();

    // meta.hello: the protocol handshake (core/usage WsProtocol.hpp, docs/reference/ws-protocol.md). Negotiates the
    // session's protocol version from the client's range, keeps what the client said it is on the session (and a
    // paired device's app_version), and answers {server, protocol, capabilities, commands, contract}. `commands` is
    // what the daemon's router registers. No overlap throws a refusal with data.code protocol_unsupported and the
    // server's range; malformed members are `invalid`. Any session may send it.
    static json hello(const json& payload, const std::shared_ptr<Session>& session,
                      const std::vector<std::string>& commands);
};

}
