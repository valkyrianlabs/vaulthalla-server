#pragma once

#include "protocols/shell/types.hpp"
#include "rbac/permission/Override.hpp"
#include "db/model/ListQueryParams.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "identities/Fwd.hpp"
#include "rbac/Fwd.hpp"

#include <optional>
#include <string>
#include <vector>
#include <string_view>
#include <utility>
#include <memory>
#include <regex>

namespace vh::protocols::shell {
    template<typename T>
    struct Lookup {
        std::shared_ptr<T> ptr;
        std::string error;
        explicit operator bool() const { return static_cast<bool>(ptr); }
    };

    struct PatternParse {
        bool ok = false;
        std::optional<rbac::fs::glob::model::Pattern> pattern{};
        std::string error;
    };

    struct EnableParse {
        bool ok = false;
        std::optional<bool> value;
        std::string error;
    };

    struct EffectParse {
        bool ok = false;
        std::optional<rbac::permission::OverrideOpt> value;
        std::string error;
    };

    struct Subject {
        std::string type; // "user", "group" or "peer" (a linked server: `vh vault role assign|remove --peer`)
        unsigned int id = 0;
    };

    CommandResult invalid(std::string msg);

    CommandResult invalid(const std::vector<std::string> &args, std::string msg);

    CommandResult ok(std::string out);

    // "yes"/"no" for CLI status output.
    [[nodiscard]] std::string yesNo(bool value);

    CommandResult usage(const std::vector<std::string> &args = {});

    std::optional<std::string> optVal(const CommandCall &c, const std::vector<std::string> &args);

    std::optional<std::string> optVal(const CommandCall &c, const std::string &key);

    std::optional<unsigned int> parseUInt(const std::string &sv);

    uintmax_t parseSize(const std::string &s);

    [[nodiscard]] bool hasFlag(const CommandCall &c, const std::string &key);

    [[nodiscard]] bool hasFlag(const CommandCall &c, const std::vector<std::string> &keys);

    [[nodiscard]] bool hasKey(const CommandCall &c, const std::string &key);

    bool isCommandMatch(const std::vector<std::string> &path, std::string_view subcmd);

    Lookup<Subject> parseSubject(const CommandCall &call, const std::string &errPrefix);

    Lookup<rbac::role::Vault> resolveVaultRole(const std::string &roleArg, const std::string &errPrefix);

    Lookup<rbac::role::Admin> resolveAdminRole(const std::string &roleArg, const std::string &errPrefix);

    Lookup<identities::User> resolveUser(const std::string &userArg, const std::string &errPrefix);

    std::pair<std::string_view, CommandCall> descend(const CommandCall &call);

    db::model::ListQueryParams parseListQuery(const CommandCall &call);
}
