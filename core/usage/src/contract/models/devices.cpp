// ws models: paired devices (Vaulthalla Desktop). device::to_json(Device) (core/src/device/Device.cpp). Checked
// against its serializer by core/tests/unit/contract/models_devices.cpp.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField deviceSpki(std::string name) {
    return str(std::move(name)).desc("SHA-256 of the device certificate's SubjectPublicKeyInfo (64 lowercase hex).");
}

WsField deviceTime(std::string name) { return integer(std::move(name)).desc("Unix seconds."); }

}

std::vector<WsModel> deviceModels() {
    std::vector<WsModel> out;

    out.push_back(model("Device",
        "A paired device (a devices row, migration 112): device::to_json(Device), core/src/device/Device.cpp.",
        {uinteger("id").desc("The row id: stable across key rotations."),
         deviceSpki("device_id").desc("The device id: the SHA-256 of its current certificate's SubjectPublicKeyInfo "
                                      "(64 lowercase hex digits)."),
         uinteger("user_id").desc("The account the device acts as."),
         str("user_name").desc("That account's name (empty when unknown)."),
         str("name"),
         str("platform").desc("\"macOS\"."),
         str("app_version").desc("Empty when the device didn't say."),
         deviceSpki("previous_device_id").nullable().desc(
             "The key before the last rotation, until the device first connects with the new one."),
         uinteger("approved_by").nullable().desc("The user who approved the pairing; null once that account is gone."),
         deviceTime("created_at"),
         deviceTime("last_seen_at").nullable(),
         str("last_ip").nullable().desc("The address of the device's last connection."),
         deviceTime("revoked_at").nullable(),
         boolean("revoked").desc("Revoked devices stay listed; their key never pairs again.")}));

    return out;
}

}
