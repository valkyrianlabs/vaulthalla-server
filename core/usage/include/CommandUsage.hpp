#pragma once

#include "ColorTheme.hpp"
#include "types.hpp"

#include <string>
#include <vector>
#include <optional>
#include <cstddef>
#include <memory>

namespace vh::protocols::shell {

class CommandUsage : public std::enable_shared_from_this<CommandUsage> {
public:
    std::vector<std::string> aliases;
    std::string description;
    std::optional<std::string> synopsis;  // if empty, synthesized
    std::weak_ptr<CommandUsage> parent;
    std::vector<std::shared_ptr<CommandUsage>> subcommands;
    std::vector<Positional> positionals;
    std::vector<Flag> optional_flags, required_flags;
    std::vector<Optional> optional;
    std::vector<Option> required;
    std::vector<GroupedOptions> groups;
    std::vector<Example> examples;
    TestUsage test_usage;
    bool pluralAliasImpliesList = false;
    // Option families the command accepts beyond its declared options and validates itself, e.g. the generated
    // permission flags {"allow-", "deny-"} of role commands. Every other undeclared option is rejected.
    std::vector<std::string> option_prefixes;
    // Leaves only: what running the command does (see CommandEffect).
    CommandEffect effect = CommandEffect::Unset;

    int term_width = 100;  // target width for str()
    std::size_t max_key_col = 30; // cap left column width
    bool show_aliases = true;
    ColorTheme theme{};

    CommandUsage() = default;

    [[nodiscard]] std::string primary() const;

    [[nodiscard]] std::string str() const;
    [[nodiscard]] std::string basicStr() const;
    [[nodiscard]] std::string markdown() const;
    // The plain one-line synopsis ("vh user delete <user> [--yes] ..."), without colors.
    [[nodiscard]] std::string synopsisLine() const { return buildSynopsis_(); }

    [[nodiscard]] bool matches(const std::string& alias) const;

    [[nodiscard]] std::shared_ptr<CommandUsage> findSubcommand(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<Positional> resolvePositional(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<Flag> resolveFlag(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<Optional> resolveOptional(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<Option> resolveRequired(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<GroupedOptions> resolveGroup(const std::string& alias) const;
    [[nodiscard]] std::shared_ptr<Optional> resolveGroupOptional(const std::string& groupAlias, const std::string& optionalAlias) const;

private:
    static constexpr std::string_view binName_ = "vh";

    [[nodiscard]] std::string buildSynopsis_() const;
    [[nodiscard]] static std::string normalizePositional_(const std::string& s);
    [[nodiscard]] std::string constructCmdString() const;
    [[nodiscard]] std::string joinAliasesInline_(const std::string& sep = " | ") const;
    [[nodiscard]] std::string joinAliasesCode_();
    void emitCommand(std::ostringstream& out,
        const std::shared_ptr<CommandUsage>& command = nullptr,
        bool spaceLines = false) const;

    [[nodiscard]] std::vector<const CommandUsage*> lineage_() const;
    [[nodiscard]] std::string tokenFor_(const CommandUsage* node) const;
    static bool sameAliases_(const CommandUsage* a, const CommandUsage* b);
    [[nodiscard]] static std::string join_(const std::vector<std::string>& v, std::string_view sep);
    [[nodiscard]] static std::string renderEntryPrimary_(const Entry& e, bool squareIfOptional);
    static void appendWrapped_(std::ostringstream& out,
                               const std::string& text,
                               size_t width,
                               size_t indentAfterFirst = 0);
};

}
