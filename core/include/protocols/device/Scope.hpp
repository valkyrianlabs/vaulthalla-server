#pragma once

#include <boost/beast/http/verb.hpp>

#include <span>
#include <string_view>

// Scoped devices (design/core/mcp-remote-signin.md, "Scoped devices"; migration 152): a paired device's scope
// ("read" | "write" | "destructive") bounds everything its sessions run. The ws router holds commands to it by their
// contract effect (Router::scopedDeviceMayRun), /mcp through the MCP catalog's ceiling, and the HTTP lanes by
// laneEffect below.
namespace vh::protocols::device::scope {

// read < write < destructive; 0 for anything else.
[[nodiscard]] int rank(std::string_view scopeOrEffect) noexcept;
// Whether a device of `scope` may do something of `effect` (an unknown either way: no).
[[nodiscard]] bool allows(std::string_view scope, std::string_view effect) noexcept;

// What a request on the device listener does, by the CLI leaves' effect rule:
//   read   GET/HEAD /preview*, /download* (thumbnails, previews, original bytes, conflict sides, folder ZIPs);
//          POST /preview/batch (readiness: it may queue derived previews, a cache, never a file);
//          /transfer* (calibration: sink bytes are read and discarded, source bytes generated; nothing touches disk);
//          /mcp (each tool call is held to the device's scope by the MCP ceiling).
//   write  every /upload* request (creating or replacing a file's content, or cancelling one's own upload), and
//          anything else (fail closed).
// No lane deletes anything, so none is destructive.
[[nodiscard]] std::string_view laneEffect(boost::beast::http::verb method, std::string_view target) noexcept;

// The same classification as a table, for people (`vh device scopes`): each row's sample request is classified by
// laneEffect exactly as the row says (DeviceScope.TheLaneTableIsWhatLaneEffectDoes), so the two never disagree.
struct LaneClass {
    std::string_view methods;
    std::string_view lanes;
    std::string_view effect;
    boost::beast::http::verb sample_method;
    std::string_view sample_target;
};
[[nodiscard]] std::span<const LaneClass> laneClasses() noexcept;

}
