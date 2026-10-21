#pragma once

#include <nlohmann/json.hpp>
#include "protocols/ws/Fwd.hpp"

namespace vh::protocols::ws::model {

using json = nlohmann::json;

// The answer's `status`. A fault (anything that is not a typed refusal) is an ERROR without data.code.
enum class Status { OK, ERROR, UNAUTHORIZED };

struct Response {
    std::string cmd;
    json req, data{};
    Status status = Status::OK;
    std::optional<std::string> error{};

    Response(std::string&& cmd, json&& req, const Status& status, json&& data = json{}, std::optional<std::string>&& error = std::nullopt);

    // {command: "<cmd>.response", status, requestId? (echoed from req), data? (omitted when empty), error?}.
    [[nodiscard]] json frame() const;

    void operator()(const std::shared_ptr<Session>& session);

    static Response SUCCESS(std::string&& cmd, json&& req, json&& data);

    static Response ERROR(std::string&& cmd, json&& req, std::string&& error);

    static Response UNAUTHORIZED(std::string&& cmd, json&& req);

    // A fault while routing `cmd`: an ERROR answer to that command (no data.code) that says what failed.
    static Response INTERNAL_ERROR(std::string&& cmd, json&& req, std::string&& error = "Unknown");
};

std::string to_string(const Status& status);

}
