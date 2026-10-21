// ws book: dashboard.preferences.* (core/src/protocols/ws/handler/dashboard/Preferences.cpp → db::query::dashboard).
// Per-user dashboard layouts; every signed-in user manages only their own.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField dashboardPreferenceKey() {
    return str("preference_key")
        .opt()
        .desc("Default \"dashboard.home\" (also for \"\"); at most 64 characters.");
}

// An invalid key, payload or layout answers data.code "invalid" (the handler types the validation's refusals).
std::vector<std::string> dashboardRefusals() { return {"unauthorized", "invalid"}; }

}

std::vector<WsCommandUsage> dashboardCommands() {
    std::vector<WsCommandUsage> out;

    out.push_back({
        .command = "dashboard.preferences.get",
        .description = "The caller's saved dashboard layout for a key; exists is false (empty layout) when none is "
                       "saved. A non-object payload reads the default key.",
        .payload = {dashboardPreferenceKey()},
        .response = {object("preferences", "DashboardPreference")},
        .refusal_codes = dashboardRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "dashboard.preferences.update",
        .description = "Save the caller's dashboard layout for a key (insert or replace). The layout is validated "
                       "(at most 64 KiB and 64 cards) and otherwise stored as sent.",
        .payload = {dashboardPreferenceKey(),
                    object("layout", "",
                           {objectArray("cards", "",
                                        {str("id").desc("1..128 characters."),
                                         str("size").opt().nullable(),
                                         str("variant").opt().nullable(),
                                         boolean("visible").opt().nullable(),
                                         uinteger("order").opt().nullable().desc("0..100000.")})
                                .opt()
                                .desc("Other members of each card are stored as sent.")})
                        .gen(gen::constant("{\"cards\":[]}"))
                        .desc("Other members of the layout are stored as sent.")},
        .response = {object("preferences", "DashboardPreference")},
        .refusal_codes = dashboardRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "dashboard.preferences.reset",
        .description = "Delete the caller's saved layout for a key; deleted says whether one existed. A non-object "
                       "payload resets the default key.",
        .payload = {dashboardPreferenceKey()},
        .response = {boolean("reset").desc("Always true."), boolean("deleted")},
        .refusal_codes = dashboardRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
