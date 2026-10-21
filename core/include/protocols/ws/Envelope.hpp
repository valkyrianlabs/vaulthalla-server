#pragma once

#include <nlohmann/json.hpp>

#include <optional>
#include <string>
#include <string_view>

// The ws envelope rules the session, the router and the handler templates share. The contract publishes the same
// rules for clients (vh_usage --json `envelope`, core/usage/src/contract/ws/envelope.cpp).
//
// Request: {command, payload?, requestId?, token?}. Answer: {command: "<command>.response", status: "OK" | "ERROR" |
// "UNAUTHORIZED", requestId?, data?, error?}; `data` is omitted when the result is empty. A frame that can't be
// routed is answered {command: "error", status: "parse_error", error, message, requestId?}.
namespace vh::protocols::ws::envelope {

using json = nlohmann::json;

// The frame's requestId as answers echo it: a string or an integer; anything else (or none) is null, not echoed.
[[nodiscard]] json requestId(const json& frame);

// Why a parsed frame can't be routed (not an object, no non-empty string `command`, a `token` that is not a string),
// or nullopt when it can.
[[nodiscard]] std::optional<std::string> problem(const json& frame);

// The answer to a frame that can't be routed. `error` carries the text; `message` repeats it for clients written
// before 1.16 (it goes away in a later release).
[[nodiscard]] json parseError(std::string_view text, const json& requestId = nullptr);

// The answer to a binary (upload) frame the daemon failed to process.
[[nodiscard]] json internalError();

// What a payload command's handler reads: the frame's `payload`, or {} when the frame has none.
[[nodiscard]] const json& payloadOf(const json& frame);

}
