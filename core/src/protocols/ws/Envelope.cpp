#include "protocols/ws/Envelope.hpp"

namespace vh::protocols::ws::envelope {

json requestId(const json& frame) {
    if (!frame.is_object()) return nullptr;
    const auto it = frame.find("requestId");
    if (it == frame.end() || !(it->is_string() || it->is_number_integer())) return nullptr;
    return *it;
}

std::optional<std::string> problem(const json& frame) {
    if (!frame.is_object()) return "A message must be a JSON object";
    const auto command = frame.find("command");
    if (command == frame.end() || !command->is_string() || command->get_ref<const std::string&>().empty())
        return "A message needs a non-empty string 'command'";
    if (const auto token = frame.find("token"); token != frame.end() && !token->is_string() && !token->is_null())
        return "A message's 'token' must be a string";
    return std::nullopt;
}

json parseError(const std::string_view text, const json& requestId) {
    json frame{{"command", "error"}, {"status", "parse_error"}, {"error", text}, {"message", text}};
    if (!requestId.is_null()) frame["requestId"] = requestId;
    return frame;
}

json internalError() {
    constexpr std::string_view text = "An internal error occurred while processing your request.";
    return {{"command", "error"}, {"status", "internal_error"}, {"error", text}, {"message", text}};
}

const json& payloadOf(const json& frame) {
    static const json kEmpty = json::object();
    if (!frame.is_object()) return kEmpty;
    const auto it = frame.find("payload");
    return it == frame.end() ? kEmpty : *it;
}

}
