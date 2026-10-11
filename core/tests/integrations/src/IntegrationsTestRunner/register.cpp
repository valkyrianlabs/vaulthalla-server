#include "IntegrationsTestRunner.hpp"
#include "cli/Context.hpp"

namespace vh::test::integration {
    void IntegrationsTestRunner::registerStdoutContains(const std::string& path, std::string needle) {
        expectations_by_path_[path].must_have.push_back(std::move(needle));
    }
    void IntegrationsTestRunner::registerStdoutNotContains(const std::string& path, std::string needle) {
        expectations_by_path_[path].must_not_have.push_back(std::move(needle));
    }
    void IntegrationsTestRunner::registerStdoutContains(const std::string& path, std::vector<std::string> needles) {
        auto& e = expectations_by_path_[path].must_have;
        e.insert(e.end(),
                 std::make_move_iterator(needles.begin()),
                 std::make_move_iterator(needles.end()));
    }
    void IntegrationsTestRunner::registerStdoutNotContains(const std::string& path, std::vector<std::string> needles) {
        auto& e = expectations_by_path_[path].must_not_have;
        e.insert(e.end(),
                 std::make_move_iterator(needles.begin()),
                 std::make_move_iterator(needles.end()));
    }

    void IntegrationsTestRunner::registerAllContainsAssertions() {
        const std::vector<std::string> user_info_fields = {"User ID", "User", "Email", "Role"};
        const std::vector<std::string> vault_info_fields = {"ID", "Name", "Owner ID", "Quota"};
        const std::vector<std::string> vault_list_fields = {"ID", "NAME", "OWNER", "QUOTA", "DESCRIPTION"};
        const std::vector<std::string> group_info_fields = {"Group ID", "Name"};
        // What `role info` / `role list` print today (rbac/role to_string). These were keyed role/<action> and never
        // applied; the "Type" / "Permissions" fields they named are not part of the output.
        const std::vector<std::string> role_fields = {"Role ID:", "Name:", "Created At:", "Updated At:"};
        const auto role_kind_field = [](const std::string& path) {
            return path.ends_with("/admin") ? std::string("Identities:") : std::string("Vault Permissions:");
        };

        for (const auto& entity : cli::Context::ENTITIES) {
            for (const auto& action : cli::Context::ACTIONS) {
                // Role test cases run under role/<action>/admin and role/<action>/vault (TestCase::Generate), so
                // their expectations are keyed the same way; keyed role/<action> they never applied.
                std::vector<std::string> paths;
                if (entity == "role") {
                    paths = {"role/" + std::string(action) + "/admin", "role/" + std::string(action) + "/vault"};
                } else {
                    paths = {std::string(entity) + "/" + std::string(action)};
                }

                for (const auto& path : paths) {
                    registerStdoutNotContains(path, {"Traceback", "Exception", "Error", "invalid", "not found", "failed", "unrecognized"});
                    if (action == "info") {
                        if (entity == "user") registerStdoutContains(path, user_info_fields);
                        else if (entity == "vault") registerStdoutContains(path, vault_info_fields);
                        else if (entity == "group") registerStdoutContains(path, group_info_fields);
                        else if (entity == "role") {
                            registerStdoutContains(path, role_fields);
                            registerStdoutContains(path, role_kind_field(path));
                        }
                    } else if (action == "list") {
                        if (entity == "user") registerStdoutContains(path, {"ID", "Name", "Email", "Role"});
                        else if (entity == "vault") registerStdoutContains(path, vault_list_fields);
                        else if (entity == "group") registerStdoutContains(path, {std::string("ID"), "Name"});
                        else if (entity == "role") {
                            registerStdoutContains(path, role_fields);
                            registerStdoutContains(path, role_kind_field(path));
                        }
                    }
                }
            }
        }
    }
}
