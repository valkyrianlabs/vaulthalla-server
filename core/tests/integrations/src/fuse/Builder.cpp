#include "fuse/Builder.hpp"
#include "cmd/generators.hpp"
#include "types/Type.hpp"
#include "fuse/helpers.hpp"

#include "identities/User.hpp"
#include "identities/Group.hpp"

#include "vault/model/Vault.hpp"

#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/identities/Group.hpp"
#include "db/query/rbac/Permission.hpp"
#include "db/query/rbac/permission/Override.hpp"

#include "sync/model/LocalPolicy.hpp"
#include "runtime/Deps.hpp"

#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "fs/model/Path.hpp"

#include "rbac/role/Vault.hpp"
#include "rbac/fs/glob/Tokenizer.hpp"
#include "identities/Manager.hpp"

using namespace vh;
using namespace vh::test::integration::fuse;
using vh::identities::User;
using vh::identities::Group;

// Scenario users and groups take ids from the run's reserved range (cmd/generators.hpp allocateLinuxId): never a
// real account's uid on this host, never one another test already holds.

Builder Builder::make(BuilderSpec&& spec) {
    const auto admin = vh::identities::manager().userByName("admin");
    if (!admin || !admin->state()->meta.linux_uid) throw std::runtime_error("Admin user/uid not found");

    const auto engine = makeVault();
    if (!engine) throw std::runtime_error("Failed to create vault");

    const auto root = std::filesystem::path(engine->paths->fuseRoot / engine->vault->effectiveFuseName());
    if (!admin->state()->meta.linux_uid) throw std::runtime_error("Admin Linux UID not found");
    seed_vault_tree(*admin->state()->meta.linux_uid, root, spec.baseDir);

    return Builder{FuseScenarioContext{ "FUSE: " + spec.name, admin, engine, root, spec.baseDir }};
}

std::shared_ptr<storage::Engine> Builder::makeVault() {
    auto vault = std::make_shared<vault::model::Vault>();
    vault->name = generateVaultName("vault/create");
    vault->description = "Test Vault";
    vault->owner_id = vh::identities::manager().userByName("admin")->id;

    if (vault->name.empty()) throw std::runtime_error("Vault name cannot be empty");

    const auto sync = std::make_shared<sync::model::LocalPolicy>();
    sync->interval = std::chrono::minutes(15);
    sync->conflict_policy = sync::model::LocalPolicy::ConflictPolicy::Overwrite;

    vault = runtime::Deps::get().storageManager->addVault(vault, sync);
    return runtime::Deps::get().storageManager->getEngine(vault->id);
}

void Builder::seed_vault_tree(const uid_t admin_uid, const std::filesystem::path &root, const std::string &base) {
    (void)mkdir_as(admin_uid, root / base / "docs");
    (void)write_as(admin_uid, root / base / "docs" / "secret.txt", "TOP SECRET\n");
    (void)write_as(admin_uid, root / base / "note.txt", "hello\n");
}

void Builder::buildAssignVRole(VaultRoleSpec&& spec) {
    const auto role = db::query::rbac::role::Vault::get(spec.templateName);
    if (!role) throw std::runtime_error("Builder::buildVaultRole(): template role not found: " + spec.templateName);

    role->id = 0;
    role->name = spec.roleNameSeed;
    role->description = spec.description;

    db::query::rbac::role::Vault::upsert(role);

    role->fs.overrides = spec.overrides;

    vh::identities::Touched touched;
    switch (spec.subjectType) {
        case TargetSubject::User:
            role->assign(subject_.user->id, spec.getSubjectType(), ctx_.engine->vault->id);
            subject_.userVaultRole = role;
            touched.users = {subject_.user->id};
            break;
        case TargetSubject::Group:
            role->assign(subject_.group->id, spec.getSubjectType(), ctx_.engine->vault->id);
            subject_.groupVaultRole = role;
            touched.groups = {subject_.group->id};
            break;
        default:
            throw std::runtime_error("Builder::buildVaultRole(): invalid subject kind");
    }

    // Through the identity manager, like every product write: the canonical subject (and FUSE) see it at once.
    vh::identities::manager().mutate(std::move(touched), [&] { db::query::rbac::role::vault::Assignments::assign(role); });
}

void Builder::makeUser(UserSpec&& userSpec) {
    vh::identities::UserState draft;
    draft.name = generateName(userSpec.userNameSeed);
    draft.roles.admin = db::query::rbac::role::Admin::get(userSpec.adminRoleTemplateName);
    if (!draft.roles.admin) throw std::runtime_error("Failed to create admin role: " + userSpec.adminRoleTemplateName);

    draft.meta.linux_uid = test::integration::allocateLinuxId();
    subject_.uid = *draft.meta.linux_uid;
    uids_.push_back(*draft.meta.linux_uid);

    for (;;) {
        try {
            subject_.user = vh::identities::manager().createUser(draft, "x");
            return;
        } catch (const std::exception& e) {
            if (!std::string(e.what()).contains("Key (name)=() already exists"))
                throw std::runtime_error("Failed to create user: " + std::string(e.what()));
            draft.name = generateName("user/create");
        }
    }
}

void Builder::makeGroup(std::string&& nameSeed) {
    vh::identities::GroupState draft;
    draft.name = generateName(nameSeed);
    draft.linux_gid = test::integration::allocateLinuxId();
    gids_.push_back(*draft.linux_gid);
    subject_.gid = *draft.linux_gid;

    for (;;) {
        try {
            subject_.group = vh::identities::manager().createGroup(draft);
            return;
        } catch (const std::exception& e) {
            if (!std::string(e.what()).contains("Key (name)=() already exists"))
                throw std::runtime_error("Failed to create group: " + std::string(e.what()));
            draft.name = generateName("group/create");
        }
    }
}

void Builder::makeOverride(OverrideSpec &&spec) const {
    const auto perm = db::query::rbac::Permission::getPermissionByName(spec.permName);
    if (!perm) throw std::runtime_error("Permission not found: " + spec.permName);

    rbac::permission::Override ov;
    ov.permission = *perm;
    ov.assignment_id = spec.subjectType == TargetSubject::User ?
        subject_.userVaultRole->assignment_id : subject_.groupVaultRole->assignment_id;
    ov.effect = spec.effect;
    ov.enabled = spec.enabled;
    ov.pattern = rbac::fs::glob::Tokenizer::parse(spec.pattern);

    if (spec.subjectType == TargetSubject::User) {
        ov.assignment_id = subject_.userVaultRole->assignment_id;
        subject_.userVaultRole->fs.overrides.push_back(ov);
    } else {
        ov.assignment_id = subject_.groupVaultRole->assignment_id;
        subject_.groupVaultRole->fs.overrides.push_back(ov);
    }

    // Through the identity manager, like every product write: FUSE sees the override at once.
    vh::identities::Touched touched;
    if (spec.subjectType == TargetSubject::User) touched.users = {subject_.user->id};
    else touched.groups = {subject_.group->id};
    vh::identities::manager().mutate(std::move(touched), [&] {
        db::query::rbac::permission::Override::upsert(std::make_shared<rbac::permission::Override>(ov));
    });
}

void Builder::makeTestCase(FuseTestCaseSpec &&spec) {
    auto tc = std::make_shared<TestCase>();
    tc->name = std::move(spec.name);
    tc->path = std::move(spec.path);         // e.g. "fuse/mkdir"
    tc->expect_exit = spec.expect_exit;      // 0 or EACCES, etc.
    tc->must_contain = std::move(spec.must_contain);
    tc->must_not_contain = std::move(spec.must_not_contain);
    ctx_.steps.emplace_back(std::move(tc), std::move(spec.fn));
}

test::integration::TestStage Builder::exec() const {
    const auto results = runSteps();

    const auto vId = ctx_.engine->vault->id;
    vh::identities::Touched touched;
    if (subject_.user) touched.users = {subject_.user->id};
    if (subject_.group) touched.groups = {subject_.group->id};
    vh::identities::manager().mutate(std::move(touched), [&] {
        if (subject_.user) db::query::rbac::role::vault::Assignments::unassign(vId, "user", subject_.user->id);
        if (subject_.group) db::query::rbac::role::vault::Assignments::unassign(vId, "group", subject_.group->id);
    });

    return {
        .name = ctx_.name,
        .tests = results,
        .uids = uids_,
        .gids = gids_
    };
}

std::vector<std::shared_ptr<test::integration::TestCase>> Builder::runSteps() const {
    std::vector<std::shared_ptr<TestCase>> out;
    out.reserve(ctx_.steps.size());

    for (const auto& s : ctx_.steps) {
        if (!s.tc || !s.fn) continue;
        const auto start = std::chrono::steady_clock::now();
        ExecResult exec;
        try {
            exec = s.fn();
        } catch (const std::exception& e) {
            // One step's harness failure is that step's failure, not the scenario's or the run's.
            exec.exit_code = -1;
            exec.stderr_text = std::string("harness exception: ") + e.what();
        }
        s.tc->duration_ms = std::chrono::duration<double, std::milli>(std::chrono::steady_clock::now() - start).count();

        // Map into TestCase::result
        s.tc->result.exit_code  = exec.exit_code;
        s.tc->result.stdout_text = exec.stdout_text;
        s.tc->result.stderr_text = exec.stderr_text;
        s.tc->command = exec.command;
        s.tc->wedge = exec.wedge;
        s.tc->stream = std::string("fuse:") + ctx_.name;

        // Pre-evaluate expectation (validateStage re-checks and adds the details)
        bool ok = !exec.wedge && s.tc->expect_exit == exec.exit_code;
        if (ok && !s.tc->must_contain.empty())
            for (const auto& needle : s.tc->must_contain)
                if (s.tc->result.stdout_text.find(needle) == std::string::npos) { ok = false; break; }

        if (ok && !s.tc->must_not_contain.empty())
            for (const auto& bad : s.tc->must_not_contain)
                if (s.tc->result.stdout_text.find(bad) != std::string::npos) { ok = false; break; }

        if (exec.wedge) s.tc->assertion = AssertionResult::Fail("FUSE: " + exec.stderr_text);
        else if (!ok)
            s.tc->assertion = AssertionResult::Fail("FUSE: expected exit " + std::to_string(s.tc->expect_exit) + ", got " +
                                                    std::to_string(exec.exit_code) +
                                                    (exec.stderr_text.empty() ? "" : " (" + exec.stderr_text + ")") +
                                                    " or an output expectation failed");
        else s.tc->assertion = AssertionResult::Pass();

        out.push_back(s.tc);
    }
    return out;
}

void Builder::addUserToGroup() {
    if (!subject_.user || !subject_.group) throw std::runtime_error("Builder::addUserToGroup(): subject user/group not set");
    // The canonical user and group the builder holds see the membership as soon as this returns.
    vh::identities::manager().addMembers(subject_.group->id, {subject_.user->id});
}
