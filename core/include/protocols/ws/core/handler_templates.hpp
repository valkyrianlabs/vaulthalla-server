#pragma once

#include "protocols/ws/Router.hpp"
#include "protocols/ws/model/Response.hpp"
#include "protocols/ws/Envelope.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Fwd.hpp"

#include <functional>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>
#include <type_traits>
#include <utility>

using json = nlohmann::json;

namespace vh::protocols::ws::core {
    inline void respondWithCurrentError(std::string &&cmd, json &&msg, const std::shared_ptr<Session> &session) {
        auto reply = describeCurrentError();
        model::Response(std::move(cmd), std::move(msg), model::Status::ERROR, std::move(reply.data),
                        std::move(reply.message))(session);
    }

    template<class Fn>
    Router::Handler makeWsHandler(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                json data = std::invoke(fn, msg, session);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    template<class Fn>
    Router::Handler makePayloadHandler(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                const json &payload = envelope::payloadOf(msg);  // no payload reads as {}
                json data = std::invoke(fn, payload, session);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    template<class Fn>
    Router::Handler makePayloadOnlyHandler(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                const json& payload = envelope::payloadOf(msg);  // no payload reads as {}
                json data = std::invoke(fn, payload);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    template<class Fn>
    Router::Handler makeHandlerWithToken(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                const auto &token = msg.at("token").get_ref<const std::string &>();
                json data = std::invoke(fn, token, session);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    template<class Fn>
    Router::Handler makeSessionOnlyHandler(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                json data = std::invoke(fn, session);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    template<class Fn>
    Router::Handler makeEmptyHandler(std::string cmd, Fn &&fn) {
        return [cmd = std::move(cmd), fn = std::forward<Fn>(fn)]
        (json &&msg, const std::shared_ptr<Session> &session) mutable {
            try {
                json data = std::invoke(fn);
                model::Response::SUCCESS(std::string(cmd), std::move(msg), std::move(data))(session);
            } catch (...) {
                respondWithCurrentError(std::string(cmd), std::move(msg), session);
            }
        };
    }

    // ---------------------------
    // helpers to bind member functions cleanly
    // ---------------------------

    template<class Obj>
    auto bindWsMember(Obj *obj, json (Obj::*mf)(const json &, const std::shared_ptr<Session> &)) {
        return [obj, mf](const json &msg, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(msg, session);
        };
    }

    template<class Obj>
    auto bindWsMember(const Obj *obj, json (Obj::*mf)(const json &, const std::shared_ptr<Session> &) const) {
        return [obj, mf](const json &msg, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(msg, session);
        };
    }

    template<class Obj>
    auto bindPayloadMember(Obj *obj, json (Obj::*mf)(const json &, const std::shared_ptr<Session> &)) {
        return [obj, mf](const json &payload, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(payload, session);
        };
    }

    template<class Obj>
    auto bindPayloadMember(const Obj *obj, json (Obj::*mf)(const json &, const std::shared_ptr<Session> &) const) {
        return [obj, mf](const json &payload, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(payload, session);
        };
    }

    template<class Obj>
    auto bindTokenMember(Obj *obj, json (Obj::*mf)(const std::string &, const std::shared_ptr<Session> &)) {
        return [obj, mf](const std::string &token, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(token, session);
        };
    }

    template<class Obj>
    auto bindTokenMember(const Obj *obj, json (Obj::*mf)(const std::string &, const std::shared_ptr<Session> &) const) {
        return [obj, mf](const std::string &token, const std::shared_ptr<Session> &session) {
            return (obj->*mf)(token, session);
        };
    }

    template<class Obj>
    auto bindSessionOnlyMember(Obj *obj, json (Obj::*mf)(const std::shared_ptr<Session> &)) {
        return [obj, mf](const std::shared_ptr<Session> &session) {
            return (obj->*mf)(session);
        };
    }

    template<class Obj>
    auto bindSessionOnlyMember(const Obj *obj, json (Obj::*mf)(const std::shared_ptr<Session> &) const) {
        return [obj, mf](const std::shared_ptr<Session> &session) {
            return (obj->*mf)(session);
        };
    }

    template<class Obj>
    auto bindEmptyMember(Obj *obj, json (Obj::*mf)()) {
        return [obj, mf]() {
            return (obj->*mf)();
        };
    }

    template<class Obj>
    auto bindEmptyMember(const Obj *obj, json (Obj::*mf)() const) {
        return [obj, mf]() {
            return (obj->*mf)();
        };
    }
}
