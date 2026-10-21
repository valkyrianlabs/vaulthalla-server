#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"
#include "email/DeliveryHistory.hpp"

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Email {
    static json config(const std::shared_ptr<Session>& session);
    static json updateConfig(const json& payload, const std::shared_ptr<Session>& session);
    static json setProviderSecret(const json& payload, const std::shared_ptr<Session>& session);
    static json testSend(const json& payload, const std::shared_ptr<Session>& session);
    static json history(const json& payload, const std::shared_ptr<Session>& session);

    // One email.history row (the ws contract's EmailDeliveryRecord model).
    static json deliveryRecordJson(const ::vh::email::DeliveryRecord& row);
};

}
