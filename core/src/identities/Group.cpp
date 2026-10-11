#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "db/encoding/timestamp.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "rbac/role/Vault.hpp"

#include <pqxx/result>
#include <nlohmann/json.hpp>

#include <stdexcept>

using namespace vh::protocols::shell;
using namespace vh::db::encoding;

namespace vh::identities {

Group::Group(const unsigned int id, std::shared_ptr<const GroupState> initial, const bool detached)
    : id(id), state_(std::move(initial)), detached_(detached) {}

std::shared_ptr<Group> Group::detached(const unsigned int id, GroupState state) {
    return std::shared_ptr<Group>(new Group(id, std::make_shared<const GroupState>(std::move(state)), true));
}

void Group::replaceDetachedState(GroupState next) {
    if (!detached_) throw std::logic_error("canonical groups change only through identities::Manager");
    publish(std::make_shared<const GroupState>(std::move(next)));
}

std::string Group::name() const { return state()->name; }
std::optional<unsigned int> Group::linuxGid() const { return state()->linux_gid; }
std::optional<std::string> Group::description() const { return state()->description; }
bool Group::deleted() const { return state()->deleted; }

GroupState groupStateFromRow(pqxx::row_ref gr) {
    GroupState s;
    s.linux_gid = gr["linux_gid"].as<std::optional<unsigned int>>();
    s.name = gr["name"].as<std::string>();
    s.description = gr["description"].is_null() ? std::nullopt : std::make_optional(gr["description"].as<std::string>());
    s.created_at = parsePostgresTimestamp(gr["created_at"].as<std::string>());
    s.updated_at = gr["updated_at"].is_null()
                       ? std::nullopt
                       : std::make_optional(parsePostgresTimestamp(gr["updated_at"].as<std::string>()));
    return s;
}

nlohmann::json to_json(const Group& g, const std::vector<GroupMember>* members) {
    const auto s = g.state();
    nlohmann::json list = nlohmann::json::array();
    if (members)
        for (const auto& member : *members) list.push_back(member);

    nlohmann::json j = {
        {"id", g.id},
        {"name", s->name},
        {"description", s->description},
        {"created_at", timestampToString(s->created_at)},
        {"members", list}
    };

    if (s->linux_gid) j["gid"] = *s->linux_gid;
    if (s->updated_at.has_value()) j["updated_at"] = timestampToString(*s->updated_at);
    return j;
}

nlohmann::json to_json(const std::shared_ptr<Group>& g) {
    if (!g) return nullptr;
    const auto members = manager().members(g->id);
    return to_json(*g, &members);
}

nlohmann::json to_json(const std::vector<std::shared_ptr<Group>>& groups) {
    auto j = nlohmann::json::array();
    for (const auto& group : groups)
        if (group) j.push_back(to_json(group));
    return j;
}

void to_json(nlohmann::json& j, const GroupMember& gm) {
    j = {
        {"user", to_public_json(gm.user)},
        {"joined_at", timestampToString(gm.joined_at)}
    };
}

nlohmann::json to_json(const std::vector<GroupMember>& members) {
    auto j = nlohmann::json::array();
    for (const auto& member : members) j.push_back(member);
    return j;
}

std::string to_string(const std::shared_ptr<Group>& g, const std::vector<GroupMember>* members) {
    const auto s = g->state();
    std::string out;
    out += "Group Name: " + s->name + "\n";
    out += "Group ID: " + std::to_string(g->id) + "\n";
    if (s->description) out += "\nDescription: " + *s->description;
    out += "\nCreated at: " + timestampToString(s->created_at);
    if (s->updated_at) out += "\nUpdated at: " + timestampToString(*s->updated_at);

    const auto list = members ? *members : manager().members(g->id);
    out += "\nMembers:\n";
    for (const auto& member : list)
        out += "  - " + member.user->name() + " (ID: " + std::to_string(member.user->id) + "), Joined at: " +
               timestampToString(member.joined_at) + "\n";

    return out;
}

std::string to_string(const std::vector<std::shared_ptr<Group>>& groups) {
    if (groups.empty()) return "No groups found";

    Table tbl({
        {"ID", Align::Left, 4, 8, false, false},
        {"Name", Align::Left, 8, 30, true, true},
        {"Description", Align::Left, 30, 50, true, true},
        {"Created At", Align::Left, 20, 30, true, true},
        {"Members", Align::Left, 4, 10, false, false}
    }, term_width());

    for (const auto& g : groups) {
        const auto s = g->state();
        tbl.add_row({
            std::to_string(g->id),
            s->name,
            s->description.value_or(""),
            timestampToString(s->created_at),
            std::to_string(manager().memberCount(g->id))
        });
    }

    return tbl.render();
}

std::string to_string(const GroupMember& gm) {
    return "Member: " + gm.user->name() + " (ID: " + std::to_string(gm.user->id) + "), Joined at: " +
           timestampToString(gm.joined_at);
}

std::string to_string(const std::vector<GroupMember>& members) {
    if (members.empty()) return "No members found";

    std::string out = "Group Members:\n";
    for (const auto& member : members) out += "  - " + to_string(member) + "\n";
    return out;
}

}
