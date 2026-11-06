#pragma once

#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <memory>

// Device approvals (#361; auth/approval/Approvals.hpp, MFA design note sections 6.2-6.3): the device's side
// (device.approval.challenge|submit with its approval key, device.approval.request|status for a console approval;
// a paired device's own session only) and the person's side in the web console (auth.approval.list|approve|deny,
// web sessions only, a passkey with user verification only).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Approvals {
    static json challenge(const json& payload, const std::shared_ptr<Session>& session);
    static json submit(const json& payload, const std::shared_ptr<Session>& session);
    static json request(const json& payload, const std::shared_ptr<Session>& session);
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json keyRegister(const json& payload, const std::shared_ptr<Session>& session);

    static json list(const std::shared_ptr<Session>& session);
    static json approve(const json& payload, const std::shared_ptr<Session>& session);
    static json deny(const json& payload, const std::shared_ptr<Session>& session);
};

}
