#include "cmd/Router.hpp"
#include "TestCase.hpp"
#include "entity/Registrar.hpp"
#include "cli/Context.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "vault/model/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "seed/Stream.hpp"

#include <chrono>
#include <stdexcept>

using namespace vh::protocols::shell;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;
using namespace vh::vault::model;

namespace vh::test::integration::cmd {
    Router::Router(const std::shared_ptr<cli::Context>& ctx)
        : registrar_(std::make_shared<entity::Registrar>(ctx)) {
        registerAll();
    }

    void Router::registerRoute(const std::string& path, const CallType& handler) {
        if (routes_.contains(path)) throw std::runtime_error("cmd::Router: route already registered for path: " + path);
        routes_[path] = handler;
    }

    // Each test runs under its own seeded stream (h64(root, stream, index)), whatever thread runs it, and a harness
    // exception fails that test instead of the whole run.
    std::shared_ptr<TestCase> Router::route(const std::shared_ptr<TestCase>& test) const {
        const auto start = std::chrono::steady_clock::now();
        try {
            if (test->stream.empty()) throw std::logic_error("test has no seed stream label: " + test->name);
            const seed::Scope scope(test->stream, test->streamIndex);
            dispatch(test);
        } catch (const std::exception& e) {
            test->result.exit_code = -1;
            if (!test->result.stderr_text.empty()) test->result.stderr_text += '\n';
            test->result.stderr_text += std::string("harness exception: ") + e.what();
            test->fail(std::string("harness exception: ") + e.what());
        }
        test->duration_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();
        return test;
    }

    void Router::dispatch(const std::shared_ptr<TestCase>& test) const {
        const auto apply = [&](EntityResult&& r) {
            test->result = std::move(r.result);
            test->entity = std::move(r.entity);
            test->command = std::move(r.command);
        };

        if (!routes_.contains(test->path)) throw std::runtime_error("cmd::Router: no route registered for path: " + test->path);

        if (test->subject && test->subjectType) {
            if (!std::holds_alternative<tripleArgWithSubjTypeFunc>(routes_.at(test->path)))
                throw std::runtime_error("cmd::Router: route does not support subject type for path: " + test->path);

            const auto func = std::get<tripleArgWithSubjTypeFunc>(routes_.at(test->path));
            apply(func(test->entity, test->target, *test->subjectType, test->subject));
            return;
        }

        if (test->subject) {
            if (!std::holds_alternative<tripleArgFunc>(routes_.at(test->path)))
                throw std::runtime_error("cmd::Router: route does not support subject for path: " + test->path);

            const auto func = std::get<tripleArgFunc>(routes_.at(test->path));
            apply(func(test->entity, test->target, test->subject));
            return;
        }

        if (test->target) {
            if (!std::holds_alternative<dualArgFunc>(routes_.at(test->path)))
                throw std::runtime_error("cmd::Router: route does not support target entity for path: " + test->path);

            const auto func = std::get<dualArgFunc>(routes_.at(test->path));
            apply(func(test->entity, test->target));
            return;
        }

        if (!std::holds_alternative<singleArgFunc>(routes_.at(test->path)))
            throw std::runtime_error("cmd::Router: route requires target entity for path: " + test->path);

        const auto func = std::get<singleArgFunc>(routes_.at(test->path));
        apply(func(test->entity));
        return;
    }

    std::vector<std::shared_ptr<TestCase>> Router::route(const std::vector<std::shared_ptr<TestCase>>& tests) const {
        std::vector<std::shared_ptr<TestCase>> results;
        for (auto& t : tests) results.push_back(route(t));
        return results;
    }

    void Router::registerAll() {
        registerRoute("user/create", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->create(EntityType::USER);
        });

        registerRoute("group/create", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->create(EntityType::GROUP);
        });

        registerRoute("vault/create", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->create(EntityType::VAULT);
        });

        registerRoute("role/create/admin", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->create(EntityType::ADMIN_ROLE);
        });

        registerRoute("role/create/vault", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->create(EntityType::VAULT_ROLE);
        });

        registerRoute("user/update", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no user entity provided for update");
            const auto user = std::static_pointer_cast<User>(entity);
            return registrar_->update(EntityType::USER, user);
        });

        registerRoute("vault/update", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault entity provided for update");
            const auto vault = std::static_pointer_cast<Vault>(entity);
            return registrar_->update(EntityType::VAULT, vault);
        });

        registerRoute("group/update", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no group entity provided for update");
            const auto group = std::static_pointer_cast<Group>(entity);
            return registrar_->update(EntityType::GROUP, group);
        });

        registerRoute("role/update/admin", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no admin role entity provided for update");
            const auto role = std::static_pointer_cast<User>(entity);
            return registrar_->update(EntityType::ADMIN_ROLE, role);
        });

        registerRoute("role/update/vault", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault role entity provided for update");
            const auto role = std::static_pointer_cast<Vault>(entity);
            return registrar_->update(EntityType::VAULT_ROLE, role);
        });

        registerRoute("user/list", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->list(EntityType::USER);
        });

        registerRoute("group/list", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->list(EntityType::GROUP);
        });

        registerRoute("vault/list", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->list(EntityType::VAULT);
        });

        registerRoute("role/list/admin", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->list(EntityType::ADMIN_ROLE);
        });

        registerRoute("role/list/vault", [&](const std::shared_ptr<void>&) -> EntityResult {
            return registrar_->list(EntityType::VAULT_ROLE);
        });

        registerRoute("user/info", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no user entity provided for info");
            const auto user = std::static_pointer_cast<User>(entity);
            return registrar_->info(EntityType::USER, user);
        });

        registerRoute("group/info", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no group entity provided for info");
            const auto group = std::static_pointer_cast<Group>(entity);
            return registrar_->info(EntityType::GROUP, group);
        });

        registerRoute("vault/info", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault entity provided for info");
            const auto vault = std::static_pointer_cast<Vault>(entity);
            return registrar_->info(EntityType::VAULT, vault);
        });

        registerRoute("role/info/admin", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no admin role entity provided for info");
            const auto role = std::static_pointer_cast<User>(entity);
            return registrar_->info(EntityType::ADMIN_ROLE, role);
        });

        registerRoute("role/info/vault", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault role entity provided for info");
            const auto role = std::static_pointer_cast<Vault>(entity);
            return registrar_->info(EntityType::VAULT_ROLE, role);
        });

        registerRoute("user/delete", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no user entity provided for deletion");
            const auto user = std::static_pointer_cast<User>(entity);
            return registrar_->remove(EntityType::USER, user);
        });

        registerRoute("group/delete", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no group entity provided for deletion");
            const auto group = std::static_pointer_cast<Group>(entity);
            return registrar_->remove(EntityType::GROUP, group);
        });

        registerRoute("vault/delete", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault entity provided for deletion");
            const auto vault = std::static_pointer_cast<Vault>(entity);
            return registrar_->remove(EntityType::VAULT, vault);
        });

        registerRoute("role/delete/admin", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no admin role entity provided for deletion");
            const auto role = std::static_pointer_cast<User>(entity);
            return registrar_->remove(EntityType::ADMIN_ROLE, role);
        });

        registerRoute("role/delete/vault", [&](const std::shared_ptr<void>& entity) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault role entity provided for deletion");
            const auto role = std::static_pointer_cast<Vault>(entity);
            return registrar_->remove(EntityType::VAULT_ROLE, role);
        });

        registerRoute("group/user/add", [&](const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no group-user entity pair provided for addition");
            const auto group = std::static_pointer_cast<Group>(entity);
            const auto user = std::static_pointer_cast<User>(target);
            return registrar_->manageGroup(EntityType::USER, ActionType::ADD, group, user);
        });

        registerRoute("group/user/remove", [&](const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no group-user entity pair provided for removal");
            const auto group = std::static_pointer_cast<Group>(entity);
            const auto user = std::static_pointer_cast<User>(target);
            return registrar_->manageGroup(EntityType::USER, ActionType::REMOVE, group, user);
        });

        registerRoute("vault/role/assign", [&](const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target, const EntityType& subjectType, const std::shared_ptr<void>& subject) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for assignment");
            if (!target) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for assignment");
            if (!subject) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for assignment");
            const auto vault = std::static_pointer_cast<Vault>(entity);
            const auto role = std::static_pointer_cast<role::Vault>(target);

            if (subjectType == EntityType::USER)
                return registrar_->manageVaultRoleAssignments(EntityType::USER, CommandType::ASSIGN, vault, role, subject);
            if (subjectType == EntityType::GROUP)
                return registrar_->manageVaultRoleAssignments(EntityType::GROUP, CommandType::ASSIGN, vault, role, subject);

            throw std::runtime_error("cmd::Router: unsupported subject type for vault role assignment");
        });

        registerRoute("vault/role/unassign", [&](const std::shared_ptr<void>& entity, const std::shared_ptr<void>& target, const EntityType& subjectType, const std::shared_ptr<void>& subject) -> EntityResult {
            if (!entity) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for unassignment");
            if (!target) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for unassignment");
            if (!subject) throw std::runtime_error("cmd::Router: no vault-role entity-subject triplet provided for unassignment");
            const auto vault = std::static_pointer_cast<Vault>(entity);
            const auto role = std::static_pointer_cast<role::Vault>(target);

            if (subjectType == EntityType::USER)
                return registrar_->manageVaultRoleAssignments(EntityType::USER, CommandType::UNASSIGN, vault, role, subject);
            if (subjectType == EntityType::GROUP)
                return registrar_->manageVaultRoleAssignments(EntityType::GROUP, CommandType::UNASSIGN, vault, role, subject);

            throw std::runtime_error("cmd::Router: unsupported subject type for vault role unassignment");
        });
    }
}
