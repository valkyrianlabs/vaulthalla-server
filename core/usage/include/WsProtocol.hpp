#pragma once

#include <optional>
#include <string>
#include <vector>

// The ws protocol's compatibility contract: which protocol versions this daemon speaks and which client-detectable
// features it has. A ws client says `meta.hello` with the range it speaks; the daemon picks the newest version both
// speak and the session keeps it (ws::Session::protocolVersion), so a handler can answer an older client in the shape
// it knows. Published by `vh_usage --json` (`protocol`, `capabilities`, both covered by contract_hash) and answered by
// meta.hello. Policy: docs/reference/ws-protocol.md. tools/contracts/protocol_compat.py fails the build when the ws
// surface changes incompatibly with the frozen baseline of kProtocolVersion (core/usage/protocol/v<N>.json).
namespace vh::contract {

// The newest protocol version this daemon speaks. Bump it for a breaking change to the ws surface (the compat check
// lists what counts), add its baseline (protocol_compat.py --write), and decide kProtocolMin.
inline constexpr int kProtocolVersion = 1;

// The oldest protocol version this daemon still answers in that version's shapes. Raise it only when the older
// shapes are dropped: a client whose range ends below it gets protocol_unsupported.
inline constexpr int kProtocolMin = 1;

static_assert(kProtocolMin >= 1 && kProtocolMin <= kProtocolVersion);

// A feature a client must detect that the command list can't show (a new member in an existing answer, an HTTP lane,
// a behavior). Command presence is not a capability: meta.hello's `commands` says which commands exist. Names are
// stable dotted lower-case identifiers ("fs.entry.metadata_version"): never renamed, reused or removed while the
// protocol lasts.
struct Capability {
    std::string name{};
    std::string since{};  // the first release that has it ("1.17.0")
    std::string description{};
};

// Every capability, sorted by name.
std::vector<Capability> capabilities();

// The capability names alone, sorted (what meta.hello answers).
std::vector<std::string> capabilityNames();

// The protocol version a session speaks, from what the client said in meta.hello: the newest both sides speak,
// min(kProtocolVersion, client max), unless that is below max(kProtocolMin, client min) (nullopt: no overlap). A
// missing bound is the server's; a client that sends neither gets kProtocolMin (what a session that never says hello
// speaks).
std::optional<int> negotiateProtocol(std::optional<int> clientMin, std::optional<int> clientMax);

}
