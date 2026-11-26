// Models: health findings (core/src/health/Findings.cpp and Catalog.cpp to_json; ops::health::list).

#include "models.hpp"

namespace vh::contract::ws::detail {

std::vector<WsModel> healthModels() {
    std::vector<WsModel> out;

    out.push_back(model("HealthRemedy",
        "Something a person can do about a finding (core/src/health/Catalog.cpp to_json). It only names a place or an "
        "existing command: running it goes through that command's own permission check and confirmation.",
        {str("id").desc("Stable within its class."), str("label"),
         str("kind").oneOf({"open", "command"}),
         str("href").nullable().desc("kind open: the console's route (\"/cost#budget-alerts\")."),
         str("command").nullable().desc("kind command: an existing ws command."),
         anyOf("payload", {"object", "null"}).desc("kind command: its payload."),
         str("effect").oneOf({"read", "write", "destructive"}).nullable().desc("kind command: the command's effect.")}));

    out.push_back(model("HealthFindingMark",
        "What an operator said about a finding class (core/src/health/Findings.cpp to_json; health_finding_state).",
        {str("class"), str("subject").desc("\"\" for the whole server."),
         str("state").oneOf({"acknowledged", "silenced"}),
         str("severity").oneOf({"warning", "error"}).desc("The highest severity the mark covers."),
         uinteger("set_by").nullable().desc("The account's id; null once the account is gone."),
         str("set_by_name"), uinteger("set_at").desc("Epoch seconds."),
         uinteger("expires_at").nullable().desc("Epoch seconds; null: until the finding clears (acknowledged) or "
                                                "until turned back on (silenced)."),
         str("note").nullable()}));

    out.push_back(model("HealthFinding",
        "An active health finding with its state (core/src/health/Findings.cpp to_json).",
        {str("class"), str("subject"), str("card_id"), str("severity").oneOf({"warning", "error"}),
         str("title").desc("The card's title."), str("class_title").desc("What this class of finding means."),
         str("message"), str("href").nullable(), str("metric_key").nullable(),
         boolean("notifies").desc("Whether the class is worth interrupting someone for."),
         str("state").oneOf({"active", "acknowledged", "silenced"}),
         object("mark", "HealthFindingMark").nullable().desc("The mark behind the state; null while active."),
         objectArray("remedies", "HealthRemedy")}));

    out.push_back(model("HealthFindingClass",
        "A class of health finding (core/src/health/Catalog.cpp to_json).",
        {str("class"), str("card_id"), str("title"), str("max_severity").oneOf({"warning", "error"}),
         boolean("notifies"), objectArray("remedies", "HealthRemedy")}));

    out.push_back(model("HealthFindings",
        "The health answer (ops::health::list): the dashboard's status and counts as they are, the counts without "
        "acknowledged and silenced findings, the findings and the silences that are set for classes not active now.",
        {str("overall_status"), uinteger("error_count"), uinteger("warning_count"),
         uinteger("unattended_error_count").desc("Errors no mark covers: what still asks for a person."),
         uinteger("unattended_warning_count"),
         uinteger("checked_at").desc("When the figures were taken (epoch seconds)."),
         objectArray("findings", "HealthFinding"), objectArray("silences", "HealthFindingMark"),
         boolean("can_manage").desc("Whether this account may acknowledge and silence (admin.stats.manage)."),
         objectArray("catalog", "HealthFindingClass").opt().desc("With include_catalog: every class.")}));

    return out;
}

}
