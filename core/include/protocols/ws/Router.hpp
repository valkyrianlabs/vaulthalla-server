#pragma once

#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>
#include "protocols/ws/Fwd.hpp"
#include "protocols/ws/RefusalLogThrottle.hpp"

namespace vh::protocols::ws {

using json = nlohmann::json;

class Router {
  public:
    enum class CommandAuthDecision { Allow, RequireHumanAuth, Deny };

    using SessionPtr = std::shared_ptr<Session>;
    using Handler = std::function<void(json&&, const SessionPtr&)>;

    using RawWsHandler = std::function<json(const json&, const SessionPtr&)>;
    using RawPayloadHandler = std::function<json(const json&, const SessionPtr&)>;
    using RawPayloadHandlerOnly = std::function<json(const json&)>;
    using RawHandlerWithToken = std::function<json(const std::string&, const SessionPtr&)>;
    using RawSessionOnly = std::function<json(const SessionPtr&)>;
    using RawEmpty = std::function<json()>;

    void registerWs(const std::string& cmd, RawWsHandler fn);
    void registerPayload(const std::string& cmd, RawPayloadHandler fn);
    void registerPayloadOnly(const std::string& cmd, RawPayloadHandlerOnly fn);
    void registerHandlerWithToken(const std::string& cmd, RawHandlerWithToken fn);
    void registerSessionOnlyHandler(const std::string& cmd, RawSessionOnly fn);
    void registerEmptyHandler(const std::string& cmd, RawEmpty fn);

    void registerHandler(const std::string& cmd, Handler h);

    void routeMessage(json&& msg, const SessionPtr& session);

    // Whether a handler is registered for `command` (the ws contract test checks the usage book against it).
    [[nodiscard]] bool hasHandler(const std::string& command) const { return handlers_.contains(command); }

    // Every registered command name, sorted (the ws contract test checks each one has a usage book entry).
    [[nodiscard]] std::vector<std::string> commands() const;

    [[nodiscard]] static bool isPublicShareCommand(std::string_view command);
    [[nodiscard]] static bool isShareFilesystemCommand(std::string_view command);
    [[nodiscard]] static bool isShareDownloadCommand(std::string_view command);
    [[nodiscard]] static bool isSharePreviewCommand(std::string_view command);
    [[nodiscard]] static bool isShareUploadCommand(std::string_view command);
    [[nodiscard]] static bool isShareModeCommand(std::string_view command);
    [[nodiscard]] static bool isAuthenticatedShareManagementCommand(std::string_view command);
    [[nodiscard]] static CommandAuthDecision classifyCommand(std::string_view command, const Session& session);

    // ---------------------------
    // Member-function-pointer overloads
    // ---------------------------

    // Payload: json Obj::method(const json&, const SessionPtr&)
    template <class Obj>
    void registerPayload(std::string cmd, Obj* obj, json (Obj::*mf)(const json&, const SessionPtr&)) {
        registerPayload(
            std::move(cmd),
            [obj, mf](const json& payload, const SessionPtr& session) {
                return (obj->*mf)(payload, session);
            });
    }

    // Payload: json Obj::method(const json&, const SessionPtr&) const
    template <class Obj>
    void registerPayload(std::string cmd, const Obj* obj, json (Obj::*mf)(const json&, const SessionPtr&) const) {
        registerPayload(
            std::move(cmd),
            [obj, mf](const json& payload, const SessionPtr& session) {
                return (obj->*mf)(payload, session);
            });
    }

    template <class Obj>
    void registerPayloadOnly(std::string cmd, Obj* obj, json (Obj::*mf)(const json&)) {
        registerPayloadOnly(
            std::move(cmd),
            [obj, mf](const json& payload) {
                return (obj->*mf)(payload);
            });
    }

    template <class Obj>
    void registerPayloadOnly(std::string cmd, const Obj* obj, json (Obj::*mf)(const json&) const) {
        registerPayloadOnly(
            std::move(cmd),
            [obj, mf](const json& payload) {
                return (obj->*mf)(payload);
            });
    }

    // Token: json Obj::method(const std::string&, const SessionPtr&)
    template <class Obj>
    void registerHandlerWithToken(std::string cmd, Obj* obj, json (Obj::*mf)(const std::string&, const SessionPtr&)) {
        registerHandlerWithToken(
            std::move(cmd),
            [obj, mf](const std::string& token, const SessionPtr& session) {
                return (obj->*mf)(token, session);
            });
    }

    // Token: json Obj::method(const std::string&, const SessionPtr&) const
    template <class Obj>
    void registerHandlerWithToken(std::string cmd, const Obj* obj, json (Obj::*mf)(const std::string&, const SessionPtr&) const) {
        registerHandlerWithToken(
            std::move(cmd),
            [obj, mf](const std::string& token, const SessionPtr& session) {
                return (obj->*mf)(token, session);
            });
    }

    // Session-only: json Obj::method(const SessionPtr&)
    template <class Obj>
    void registerSessionOnlyHandler(std::string cmd, Obj* obj, json (Obj::*mf)(const SessionPtr&)) {
        registerSessionOnlyHandler(
            std::move(cmd),
            [obj, mf](const SessionPtr& session) {
                return (obj->*mf)(session);
            });
    }

    // Session-only: json Obj::method(const SessionPtr&) const
    template <class Obj>
    void registerSessionOnlyHandler(std::string cmd, const Obj* obj, json (Obj::*mf)(const SessionPtr&) const) {
        registerSessionOnlyHandler(
            std::move(cmd),
            [obj, mf](const SessionPtr& session) {
                return (obj->*mf)(session);
            });
    }

    // Empty: json Obj::method()
    template <class Obj>
    void registerEmptyHandler(std::string cmd, Obj* obj, json (Obj::*mf)()) {
        registerEmptyHandler(
            std::move(cmd),
            [obj, mf]() {
                return (obj->*mf)();
            });
    }

    // Empty: json Obj::method() const
    template <class Obj>
    void registerEmptyHandler(std::string cmd, const Obj* obj, json (Obj::*mf)() const) {
        registerEmptyHandler(
            std::move(cmd),
            [obj, mf]() {
                return (obj->*mf)();
            });
    }

    // ---------------------------
    // Static / free-function overloads
    // ---------------------------

    void registerWs(const std::string& cmd, json (*fn)(const json&, const SessionPtr&)) {
        registerWs(cmd, RawWsHandler{
            [fn](const json& req, const SessionPtr& session) {
                return fn(req, session);
            }});
    }

    void registerPayload(const std::string& cmd, json (*fn)(const json&, const SessionPtr&)) {
        registerPayload(cmd, RawPayloadHandler{
            [fn](const json& payload, const SessionPtr& session) {
                return fn(payload, session);
            }});
    }

    void registerPayloadOnly(const std::string& cmd, json (*fn)(const json&)) {
        registerPayloadOnly(cmd, RawPayloadHandlerOnly{
            [fn](const json& payload) {
                return fn(payload);
            }});
    }

    void registerHandlerWithToken(const std::string& cmd, json (*fn)(const std::string&, const SessionPtr&)) {
        registerHandlerWithToken(cmd, RawHandlerWithToken{
            [fn](const std::string& token, const SessionPtr& session) {
                return fn(token, session);
            }});
    }

    void registerSessionOnlyHandler(const std::string& cmd, json (*fn)(const SessionPtr&)) {
        registerSessionOnlyHandler(cmd, RawSessionOnly{
            [fn](const SessionPtr& session) {
                return fn(session);
            }});
    }

    void registerEmptyHandler(const std::string& cmd, json (*fn)()) {
        registerEmptyHandler(cmd, RawEmpty{
            [fn]() {
                return fn();
            }});
    }

  private:
    // Refusals (unauthorized, rate limited) log at debug per request, and at warning once per client/command
    // window with a suppressed-count summary (#135). `detail` (client-supplied text) only reaches the debug line.
    void logRefusal(const std::string& label, std::string_view suffix, std::string_view detail);
    [[nodiscard]] std::string commandForLog(std::string_view command) const;

    std::unordered_map<std::string, Handler> handlers_;
    RefusalLogThrottle refusalLog_;
};

}
