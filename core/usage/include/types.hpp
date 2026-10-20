#pragma once

#include "FieldGen.hpp"

#include <map>
#include <string>
#include <string_view>
#include <vector>
#include <optional>
#include <utility>
#include <variant>
#include <memory>

namespace vh::protocols::shell {

// What running a command does, declared on every leaf of the usage book (a unit test refuses a leaf without one):
// Read changes nothing; Write changes state that can be changed back; Destructive deletes, purges, revokes, rotates
// keys or does something else that can't be undone. Exported by vh_usage --json; the MCP catalog derives tool
// annotations (readOnlyHint, destructiveHint) from it.
enum class CommandEffect { Unset, Read, Write, Destructive };

[[nodiscard]] constexpr std::string_view effectName(const CommandEffect e) {
    switch (e) {
        case CommandEffect::Read: return "read";
        case CommandEffect::Write: return "write";
        case CommandEffect::Destructive: return "destructive";
        case CommandEffect::Unset: break;
    }
    return "";
}

struct Entry {
    std::string label;
    std::string desc;

    Entry(std::string label_, std::string desc_)
        : label(std::move(label_)), desc(std::move(desc_)) {}

    Entry() = default;
};

struct Positional final : Entry {
    std::vector<std::string> aliases;
    // How a test renderer produces a value for this positional (see FieldGen.hpp); exported by vh_usage --json.
    contract::FieldGenPtr generator = nullptr;

    Positional(std::string label_, std::string desc_)
        : Entry(std::move(label_), std::move(desc_)) {}

    Positional(std::string label_, std::string desc_, std::vector<std::string> aliases_,
               contract::FieldGenPtr generator_ = nullptr)
        : Entry(std::move(label_), std::move(desc_)), aliases(std::move(aliases_)), generator(std::move(generator_)) {}

    Positional() = default;

    [[nodiscard]] Positional withGen(contract::FieldGenPtr g) const {
        Positional p = *this;
        p.generator = std::move(g);
        return p;
    }

    // 🏗️ Factory Methods

    static Positional Same(const std::string& label, std::string desc, contract::FieldGenPtr generator_ = nullptr) {
        return {label, std::move(desc), {label}, std::move(generator_)};
    }

    // With aliases
    static Positional WithAliases(std::string label, std::string desc, std::vector<std::string> aliases, contract::FieldGenPtr generator_ = nullptr) {
        Positional p;
        p.label = std::move(label);
        p.desc = std::move(desc);
        p.aliases = std::move(aliases);
        p.generator = std::move(generator_);
        return p;
    }

    // Shortcut for one alias
    static Positional Alias(std::string label, std::string desc, std::string alias, contract::FieldGenPtr generator_ = nullptr) {
        return Positional(std::move(label), std::move(desc), {std::move(alias)}, std::move(generator_));
    }
};

struct Flag : Entry {
    std::vector<std::string> aliases;
    bool default_state = false;

    Flag(std::string label_, std::string desc_)
        : Entry(std::move(label_), std::move(desc_)) {}

    Flag(std::string label_, std::string desc_, std::string alias_, const bool default_state_ = false)
        : Entry(std::move(label_), std::move(desc_)), aliases({std::move(alias_)}), default_state(default_state_) {}

    Flag(std::string label_, std::string desc_, std::vector<std::string> aliases_, const bool default_state_)
        : Entry(std::move(label_), std::move(desc_)), aliases(std::move(aliases_)), default_state(default_state_) {}

    Flag() = default;

    // 🏗️ Factory Methods

    static Flag On(std::string label, std::string desc, std::vector<std::string> aliases = {}) {
        return {std::move(label), std::move(desc), std::move(aliases), true};
    }

    static Flag Off(std::string label, std::string desc, std::vector<std::string> aliases = {}) {
        return {std::move(label), std::move(desc), std::move(aliases), false};
    }

    static Flag Alias(std::string label, std::string desc, std::string alias, const bool default_state = false) {
        return Flag(std::move(label), std::move(desc), std::vector{std::move(alias)}, default_state);
    }

    static Flag WithAliases(std::string label, std::string desc, std::vector<std::string> aliases, const bool default_state = false) {
        Flag f;
        f.label = std::move(label);
        f.desc = std::move(desc);
        f.aliases = std::move(aliases);
        f.default_state = default_state;
        return f;
    }

    static Flag Toggle(std::string label, std::string desc, bool default_state) {
        return Flag{std::move(label), std::move(desc), std::vector<std::string>{}, default_state};
    }
};

struct Option : Entry {
    std::vector<std::string> option_tokens, value_tokens;
    // One generator per value token (e.g. "name" -> a role name, "id" -> a role id). A value token without one is a
    // literal choice (sync strategies, "unlimited") or not yet covered. Exported by vh_usage --json.
    std::map<std::string, contract::FieldGenPtr> generators;

    template<class Self>
    [[nodiscard]] Self withGen(this const Self& self, std::string valueToken, contract::FieldGenPtr g) {
        Self copy = self;
        copy.generators[std::move(valueToken)] = std::move(g);
        return copy;
    }

    // Every value token is itself the value (an enum-like option).
    template<class Self>
    [[nodiscard]] Self withLiteralValues(this const Self& self) {
        Self copy = self;
        for (const auto& token : copy.value_tokens) copy.generators[token] = contract::gen::constant(token);
        return copy;
    }

    Option(std::string label_, std::string desc_,
           std::vector<std::string> option_tokens_,
           std::vector<std::string> value_tokens_)
        : Entry(std::move(label_), std::move(desc_)),
          option_tokens(std::move(option_tokens_)),
          value_tokens(std::move(value_tokens_)) {}

    Option(std::string label_, std::string desc_)
        : Entry(std::move(label_), std::move(desc_)) {}

    Option() = default;

    static Option Single(std::string label,
                         std::string desc,
                         std::string option,
                         std::string value_token) {
        return Option(std::move(label), std::move(desc),
                      {std::move(option)}, {std::move(value_token)});
    }

    static Option Multi(std::string label,
                        std::string desc,
                        std::vector<std::string> options,
                        std::vector<std::string> value_tokens) {
        return {std::move(label), std::move(desc),
                      std::move(options), std::move(value_tokens)};
    }

    static Option Mirrored(std::string label,
                           std::string desc,
                        const std::string& token) {
        return Option(std::move(label), std::move(desc),
                      {token}, {token});
    }

    static Option OneToMany(std::string label,
                             std::string desc,
                             std::string option,
                             std::vector<std::string> value_tokens) {
        return Option(std::move(label), std::move(desc),
                      {std::move(option)}, std::move(value_tokens));
    }

    static Option Same(const std::string& token,
                           std::string desc) {
        return Option(token, std::move(desc), {token}, {token});
    }
};

struct Optional : Option {
    std::optional<std::string> default_value;

    Optional(std::string label_,
             std::string desc_,
             std::vector<std::string> option_tokens_,
             std::vector<std::string> value_tokens_,
             std::optional<std::string> default_value_)
        : Option(std::move(label_), std::move(desc_),
                 std::move(option_tokens_), std::move(value_tokens_)),
          default_value(std::move(default_value_)) {}

    explicit Optional(const Option& o) : Option(o) {}

    Optional() = default;

    static Optional Single(std::string label,
                           std::string desc,
                           std::string option,
                           std::string value_token,
                           std::optional<std::string> def = std::nullopt) {
        Optional o;
        o.label = std::move(label);
        o.desc = std::move(desc);
        o.option_tokens = {std::move(option)};
        o.value_tokens = {std::move(value_token)};
        o.default_value = std::move(def);
        return o;
    }

    static Optional Multi(std::string label,
                          std::string desc,
                          std::vector<std::string> options,
                          std::vector<std::string> value_tokens,
                          std::optional<std::string> def = std::nullopt) {
        return {std::move(label), std::move(desc),
                        std::move(options), std::move(value_tokens),
                        std::move(def)};
    }

    static Optional OneToMany(std::string label,
                                 std::string desc,
                                 std::string option,
                                 std::vector<std::string> value_tokens,
                                 std::optional<std::string> def = std::nullopt) {
        return Optional(std::move(label), std::move(desc),
                        {std::move(option)}, std::move(value_tokens),
                        std::move(def));
    }

    static Optional ManyToOne(std::string label,
                             std::string desc,
                             std::vector<std::string> options,
                             std::string value_token,
                             std::optional<std::string> def = std::nullopt) {
        return Optional(std::move(label), std::move(desc),
                        std::move(options), {std::move(value_token)},
                        std::move(def));
    }

    static Optional Mirrored(std::string label,
                             std::string desc,
                             const std::string& token,
                             std::optional<std::string> def = std::nullopt) {
        return Optional(std::move(label), std::move(desc),
                        {token}, {token}, std::move(def));
    }

    // 🆕 new factory
    static Optional Same(const std::string& token,
                         std::string desc,
                         std::optional<std::string> def = std::nullopt) {
        return Optional(token, std::move(desc), {token}, {token}, std::move(def));
    }
};

struct GroupedOptions {
    std::string title;
    std::vector<std::variant<Optional, Flag>> items;

    GroupedOptions(std::string t, std::vector<std::variant<Optional, Flag>> i)
        : title(std::move(t)), items(std::move(i)) {}

    GroupedOptions() = default;
};

struct Example {
    std::string cmd;
    std::string note;
};

class CommandUsage;

struct TestCommandUsage {
    std::weak_ptr<CommandUsage> command;
    unsigned int minIter = 1, max_iter = 1;

    TestCommandUsage() = default;

    explicit TestCommandUsage(const std::shared_ptr<CommandUsage>& cmd,
                 const unsigned int min_iter = 1,
                 const unsigned int max_iter = 1)
        : command(cmd), minIter(min_iter), max_iter(max_iter) {}

    static TestCommandUsage Single(const std::shared_ptr<CommandUsage>& cmd) {
        return TestCommandUsage(cmd, 1, 1);
    }

    static TestCommandUsage Optional(const std::shared_ptr<CommandUsage>& cmd) {
        return TestCommandUsage(cmd, 0, 1);
    }

    static TestCommandUsage Multiple(const std::shared_ptr<CommandUsage>& cmd,
                                      const unsigned int min_iter = 1,
                                      const unsigned int max_iter = 3) {
        return TestCommandUsage(cmd, min_iter, max_iter);
    }

    static TestCommandUsage Robust(const std::shared_ptr<CommandUsage>& cmd) {
        return TestCommandUsage(cmd, 1, 5);
    }

    static TestCommandUsage Stress(const std::shared_ptr<CommandUsage>& cmd) {
        TestCommandUsage t;
        t.command = cmd;
        t.minIter = 5;
        t.max_iter = 10;
        return t;
    }
};

struct TestUsage {
    std::vector<TestCommandUsage> setup, lifecycle, teardown;
};

}
