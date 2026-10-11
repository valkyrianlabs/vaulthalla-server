#include "db/query/identities/Group.hpp"
#include "db/Transactions.hpp"
#include "identities/Group.hpp"
#include "db/query/identities/helpers.hpp"

#include <stdexcept>

namespace vh::db::query::identities {

uint32_t Group::createGroup(const vh::identities::GroupState& draft) {
    return Transactions::exec("Group::createGroup", [&](pqxx::work& txn) {
        const pqxx::params p{draft.name, draft.description, draft.linux_gid};

        const auto res = txn.exec(pqxx::prepped{"create_group"}, p);
        if (res.empty()) throw std::runtime_error("Failed to create group: " + draft.name);
        const auto id = res.one_row_ref()["id"].as<uint32_t>();

        upsertVaultRoles(txn, draft.roles.vaults, "group", id);
        return id;
    });
}

void Group::updateGroup(const uint32_t id, const vh::identities::GroupState& next) {
    Transactions::exec("Group::updateGroup", [&](pqxx::work& txn) {
        const pqxx::params p{id, next.name, next.description, next.linux_gid};
        txn.exec(pqxx::prepped{"update_group"}, p);
        upsertVaultRoles(txn, next.roles.vaults, "group", id);
    });
}

void Group::deleteGroup(const uint32_t groupId) {
    Transactions::exec("Group::deleteGroup", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"delete_group"}, groupId);
    });
}

void Group::addMembersToGroup(const uint32_t group, const std::vector<uint32_t>& members) {
    Transactions::exec("Group::addMembersToGroup", [&](pqxx::work& txn) {
        for (const auto& member : members)
            txn.exec(pqxx::prepped{"save_group_member"}, pqxx::params{group, member});
    });
}

void Group::removeMembersFromGroup(const uint32_t group, const std::vector<uint32_t>& members) {
    Transactions::exec("Group::removeMembersFromGroup", [&](pqxx::work& txn) {
        for (const auto& member : members)
            txn.exec(pqxx::prepped{"remove_group_member"}, pqxx::params{group, member});
    });
}

bool Group::groupExists(const std::string& name) {
    return Transactions::exec("Group::groupExists", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"group_exists_by_name"}, name);
        if (res.empty()) return false;
        return res.one_field_ref().as<bool>();
    });
}

}
