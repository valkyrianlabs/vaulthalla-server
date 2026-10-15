#include "db/query/rbac/role/Admin.hpp"
#include "db/Transactions.hpp"
#include "db/template/Paginate.hpp"
#include "rbac/role/Admin.hpp"

#include <pqxx/pqxx>
#include <stdexcept>

namespace vh::db::query::rbac::role {

using AdminRole = vh::rbac::role::Admin;
using AdminRolePtr = std::shared_ptr<AdminRole>;

unsigned int Admin::insert(const AdminRolePtr& role) {
    if (!role) throw std::invalid_argument("role::Admin::insert received null role");

    return Transactions::exec("role::Admin::insert", [&](pqxx::work& txn) {
        return txn.exec(
            pqxx::prepped{"admin_role_insert"},
            pqxx::params{
                role->name,
                role->description,
                role->identities.toBitString(),
                role->audits.toBitString(),
                role->settings.toBitString(),
                role->roles.toBitString(),
                role->vaults.toBitString(),
                role->keys.toBitString(),
                role->s3Gateway.toBitString(),
                role->stats.toBitString(),
                role->upstream.toBitString()
            }
        ).one_row_ref()["id"].as<unsigned int>();
    });
}

unsigned int Admin::upsert(const AdminRolePtr& role) {
    if (!role) throw std::invalid_argument("role::Admin::upsert received null role");

    return Transactions::exec("role::Admin::upsert", [&](pqxx::work& txn) -> unsigned int {
        // If the role already has an id, update/upsert by id.
        if (role->id != 0) {
            txn.exec(
                pqxx::prepped{"admin_role_upsert"},
                pqxx::params{
                    role->id,
                    role->name,
                    role->description,
                    role->identities.toBitString(),
                    role->audits.toBitString(),
                    role->settings.toBitString(),
                    role->roles.toBitString(),
                    role->vaults.toBitString(),
                    role->keys.toBitString(),
                    role->s3Gateway.toBitString(),
                    role->stats.toBitString(),
                    role->upstream.toBitString()
                }
            );

            return role->id;
        }

        // Otherwise upsert by unique name and return the generated/resolved id.
        const auto res = txn.exec(
            pqxx::prepped{"admin_role_upsert_by_name"},
            pqxx::params{
                role->name,
                role->description,
                role->identities.toBitString(),
                role->audits.toBitString(),
                role->settings.toBitString(),
                role->roles.toBitString(),
                role->vaults.toBitString(),
                role->keys.toBitString(),
                role->s3Gateway.toBitString(),
                role->stats.toBitString(),
                role->upstream.toBitString()
            }
        );

        if (res.empty()) throw std::runtime_error("role::Admin::upsert failed to return row");
        return res.one_row_ref()["id"].as<unsigned int>();
    });
}

void Admin::remove(unsigned int id) {
    Transactions::exec("role::Admin::remove(id)", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"admin_role_delete"}, pqxx::params{id});
    });
}

void Admin::remove(const AdminRolePtr& role) {
    if (!role) return;
    remove(role->id);
}

AdminRolePtr Admin::get(unsigned int id) {
    return Transactions::exec("role::Admin::get(id)", [&](pqxx::work& txn) -> AdminRolePtr {
        const auto res = txn.exec(pqxx::prepped{"admin_role_get_by_id"}, pqxx::params{id});
        if (res.empty()) return nullptr;
        return std::make_shared<AdminRole>(res.one_row_ref());
    });
}

AdminRolePtr Admin::get(const std::string& name) {
    return Transactions::exec("role::Admin::get(name)", [&](pqxx::work& txn) -> AdminRolePtr {
        const auto res = txn.exec(pqxx::prepped{"admin_role_get_by_name"}, pqxx::params{name});
        if (res.empty()) return nullptr;
        return std::make_shared<AdminRole>(res.one_row_ref());
    });
}

bool Admin::exists(unsigned int id) {
    return Transactions::exec("role::Admin::exists(id)", [&](pqxx::work& txn) -> bool {
        const auto res = txn.exec(pqxx::prepped{"admin_role_exists_by_id"}, pqxx::params{id});
        if (res.empty()) return false;
        return res.one_row_ref()[0].as<bool>();
    });
}

bool Admin::exists(const std::string& name) {
    return Transactions::exec("role::Admin::exists(name)", [&](pqxx::work& txn) -> bool {
        const auto res = txn.exec(pqxx::prepped{"admin_role_exists_by_name"}, pqxx::params{name});
        if (res.empty()) return false;
        return res.one_row_ref()[0].as<bool>();
    });
}

std::vector<AdminRolePtr> Admin::list(model::ListQueryParams&& params) {
    return Transactions::exec("role::Admin::list", [&](pqxx::work& txn) -> std::vector<AdminRolePtr> {
        std::vector<AdminRolePtr> roles;

        const auto res = txn.exec(pqxx::prepped{"admin_role_list_all"});

        roles.reserve(res.size());
        for (const auto& row : res) roles.emplace_back(std::make_shared<AdminRole>(row));

        return template_::paginate(std::move(roles), params);
    });
}

}
