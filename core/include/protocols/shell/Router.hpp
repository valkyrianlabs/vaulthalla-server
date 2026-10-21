#pragma once

#include <protocols/shell/types.hpp>
#include "protocols/shell/SocketIO.hpp"
#include "identities/Fwd.hpp"
#include "protocols/shell/Fwd.hpp"

#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>

namespace vh::protocols::shell {

// The line as the debug log may show it: values of credential options (--secret, --password, --token, … per
// ws::isSensitiveLogKey, in "--opt value" and "--opt=value" form) replaced by [REDACTED].
[[nodiscard]] std::string redactLineForLog(const std::string& line);


class Router {
public:
    void registerCommand(const std::shared_ptr<CommandUsage>& usage, CommandHandler handler);

    CommandResult executeLine(const std::string& line,
        const std::shared_ptr<identities::User>& user,
        SocketIO* io = nullptr,
        std::optional<TransferPeer> transfer = std::nullopt,
        std::optional<std::string> input = std::nullopt) const;

    // The option-validation verdict executeLine would reach for `line`, without running the handler: an error
    // message for an undeclared option, or nullopt. Lets tests check definitions against documented examples.
    [[nodiscard]] std::optional<std::string> optionError(const std::string& line) const;

private:

    std::unordered_map<std::string, CommandInfo> commands_;
    std::unordered_map<std::string, std::string> aliasMap_; // alias -> canonical
    std::unordered_map<std::string, std::string> pluralMap_; // plural -> singular

    std::string canonicalFor(const std::string& nameOrAlias) const;

    static std::string normalize(const std::string& s);
    static std::string normalize_alias(const std::string& s);
    static std::string joinAliases(const std::unordered_set<std::string>& aliases);
    static std::string strip_leading_dashes(const std::string& s);
    static std::string pretty_alias(const std::string& a);
};

} // namespace vh::shell
