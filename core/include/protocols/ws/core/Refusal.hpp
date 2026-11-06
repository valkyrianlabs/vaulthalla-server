#pragma once

#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <string>
#include <utility>

namespace vh::protocols::ws::core {
    // What an ERROR response carries for the exception being handled (call only inside a catch block). An ops
    // refusal gets a stable machine-readable `data.code` so clients can render a typed state instead of matching
    // message text: Denied "denied", NotFound "not_found", Invalid "invalid", Conflict "conflict", and
    // NeedsConfirmation its own code (the client asks, then resends with the acceptance set), Refused its own code
    // (device pairing: no_pairing_window, rate_limited, device_unknown). Anything that is not
    // an ops::Error is a fault: the message, no code.
    struct ErrorReply {
        std::string message;
        nlohmann::json data{};
    };

    // A typed refusal whose answer carries more than its code: data is `details` plus {code} (meta.hello's
    // protocol_unsupported names the server's range and version; auth.login's mfa_required carries the pending
    // sign-in). ws handlers and the ws sign-in flow only; ops:: never raise it.
    struct DetailedRefusal : ops::Refused {
        nlohmann::json details;
        DetailedRefusal(std::string code_, const std::string &text, nlohmann::json details_)
            : Refused(std::move(code_), text), details(std::move(details_)) {}
    };

    inline ErrorReply describeCurrentError() {
        try {
            throw;
        } catch (const ops::NeedsConfirmation &e) {
            return {e.what(), nlohmann::json{{"code", e.code}}};
        } catch (const ops::StepUpRequired &e) {
            return {e.what(), nlohmann::json{{"code", e.code},
                                             {"family", e.family},
                                             {"target", e.target ? nlohmann::json(*e.target) : nlohmann::json(nullptr)},
                                             {"methods", e.methods},
                                             {"max_age_seconds", e.max_age_seconds}}};
        } catch (const DetailedRefusal &e) {
            nlohmann::json data = e.details.is_object() ? e.details : nlohmann::json::object();
            data["code"] = e.code;
            return {e.what(), std::move(data)};
        } catch (const ops::Refused &e) {
            return {e.what(), nlohmann::json{{"code", e.code}}};
        } catch (const ops::Denied &e) {
            return {e.what(), nlohmann::json{{"code", "denied"}}};
        } catch (const ops::NotFound &e) {
            return {e.what(), nlohmann::json{{"code", "not_found"}}};
        } catch (const ops::Invalid &e) {
            return {e.what(), nlohmann::json{{"code", "invalid"}}};
        } catch (const ops::Conflict &e) {
            return {e.what(), nlohmann::json{{"code", "conflict"}}};
        } catch (const std::exception &e) {
            return {e.what()};
        } catch (...) {
            return {"Unknown error"};
        }
    }
}
