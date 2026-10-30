// The ws protocol's capability registry and version negotiation (WsProtocol.hpp). Append-only: a capability, once
// released, keeps its name and stays listed while the protocol lasts (tools/contracts/protocol_compat.py refuses a
// removal against the frozen baseline).

#include "WsProtocol.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::contract {

std::vector<Capability> capabilities() {
    std::vector<Capability> out{
        {.name = "device.lanes.download",
         .since = "1.16.0",
         .description = "The device listener serves GET/HEAD /download/content (Range, conditional requests) as the "
                        "device's user."},
        {.name = "device.lanes.preview",
         .since = "1.16.0",
         .description = "The device listener serves /preview (thumbnails and rich previews) as the device's user."},
        {.name = "device.lanes.upload",
         .since = "1.16.0",
         .description = "The device listener serves the /upload session lane (create, PUT, finish) as the device's "
                        "user."},
        {.name = "device.mcp",
         .since = "1.16.0",
         .description = "The device listener serves remote MCP (JSON-RPC over POST /mcp) as the device's user."},
        {.name = "device.server.identity",
         .since = "1.16.0",
         .description = "A paired device can read the server key's pin (SPKI SHA-256) over its own session "
                        "(device.server.identity)."},
        {.name = "errors.unknown_command_code",
         .since = "1.19.0",
         .description = "An unknown command on a web or device session answers ERROR with data.code "
                        "\"unknown_command\" (the text stays \"Unknown command\")."},
        {.name = "fs.entry.content_version",
         .since = "1.17.0",
         .description = "fs.metadata and fs.dir.list entries carry content_version, equal to the /download/content "
                        "ETag."},
        {.name = "fs.entry.metadata_version",
         .since = "1.17.0",
         .description = "fs.metadata and fs.dir.list entries carry metadata_version, which changes on rename and "
                        "move."},
        {.name = "fs.entry.stable_id",
         .since = "1.17.0",
         .description = "An entry keeps its id across rename and move (ws, FUSE), children of a moved folder "
                        "included."},
        {.name = "http.upload.content",
         .since = "1.17.0",
         .description = "PUT /upload/content: a streaming conditional create (If-None-Match) or replace (If-Match) "
                        "on the web and device listeners."},
        {.name = "ws.envelope.optional_payload",
         .since = "1.16.0",
         .description = "A request frame without `payload` reads as {} (daemons before 1.16 refused it)."},
    };
    std::ranges::sort(out, {}, &Capability::name);
    if (const auto dup = std::ranges::adjacent_find(out, {}, &Capability::name); dup != out.end())
        throw std::logic_error("capability " + dup->name + " is declared twice");
    return out;
}

std::vector<std::string> capabilityNames() {
    std::vector<std::string> out;
    for (auto& c : capabilities()) out.push_back(std::move(c.name));
    return out;
}

std::optional<int> negotiateProtocol(const std::optional<int> clientMin, const std::optional<int> clientMax) {
    if (!clientMin && !clientMax) return kProtocolMin;
    const int version = std::min(kProtocolVersion, clientMax.value_or(kProtocolVersion));
    if (version < std::max(kProtocolMin, clientMin.value_or(kProtocolMin))) return std::nullopt;
    return version;
}

}
