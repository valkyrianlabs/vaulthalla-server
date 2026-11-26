#include "usages.hpp"
#include "ArgsGenerator.hpp"

// `vh health [list] | ack | silence | unsilence` (design/health/findings.md): health findings and what operators said
// about them. Handler: core/src/protocols/shell/commands/health.cpp (ops::health, the same checks as ws health.*:
// admin.stats.view to read, admin.stats.manage to change). The three that change state are never offered to agents
// (mcp::exclusions).
namespace vh::protocols::shell::health_book {

namespace {

std::shared_ptr<CommandUsage> node(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto jsonOut = Flag::Alias("json_output", "Print the result as JSON (the ws shapes)", "json");
const auto classPos = Positional::Alias("class", "The finding's class, as `vh health` prints it "
                                        "(system.fuse.error_rate_high)", "class",
                                        contract::gen::pattern("system.db.warning"));
const auto note = Optional::Single("note", "A note shown with the mark (up to 500 characters)", "note", "text")
                      .withGen("text", contract::gen::pattern("seen"));

std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"list", "ls", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "The health findings that are active now, each with its state (active, acknowledged, "
                       "silenced), and the silences that are set. Needs admin.stats.view. Exit status: 0 when "
                       "nothing asks for a person, 1 when an unattended warning does, 2 when an unattended error does.";
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh health", "What needs attention now."},
                     {"vh health list --json", "The same as JSON."},
                     {"vh health >/dev/null || echo attention", "Use the exit status in scripts."}};
    return cmd;
}

std::shared_ptr<CommandUsage> ack(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"ack", "acknowledge"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "\"I have seen this\": mark an active finding acknowledged. The mark ends when the finding "
                       "clears or gets worse. Needs admin.stats.manage; recorded in the audit trail.";
    cmd->positionals = {classPos};
    cmd->optional = {note};
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh health ack system.db.warning", "Acknowledge the database warning."},
                     {"vh health ack system.fuse.error_rate_high --note \"replacing the disk\"", "With a note."}};
    return cmd;
}

std::shared_ptr<CommandUsage> silence(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"silence", "mute"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "\"Do not tell me about this\": silence a class of finding, active or not, for a time or "
                       "until it is turned back on. A silence does not cover the finding getting worse. Needs "
                       "admin.stats.manage; recorded in the audit trail.";
    cmd->positionals = {classPos};
    cmd->optional = {Optional::Single("for", "How long: a number with m, h or d (30m, 24h, 7d). Without it: until "
                                      "turned back on", "for", "duration")
                         .withGen("duration", contract::gen::pattern("24h")),
                     Optional::Single("severity", "The worst severity it covers: warning or error (default: what "
                                      "the class has now, or the worst it can have)", "severity", "level")
                         .withGen("level", contract::gen::pattern("warning")),
                     note};
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh health silence system.operations.active_work", "Never mention queued work again."},
                     {"vh health silence system.retention.warning --for 7d", "Quiet for a week."}};
    return cmd;
}

std::shared_ptr<CommandUsage> unsilence(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"unsilence", "unmute"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Turn a class of finding back on: remove its silence or acknowledgement. Needs "
                       "admin.stats.manage; recorded in the audit trail.";
    cmd->positionals = {classPos};
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh health unsilence system.retention.warning", "Hear about it again."}};
    return cmd;
}

std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"health"};
    cmd->description = "Health findings: what the server reports as wrong, and what was said about it "
                       "(acknowledged, silenced). `vh health` alone lists them.";
    cmd->examples = {{"vh health", "What needs attention now."},
                     {"vh health silence system.operations.active_work", "Stop hearing about queued work."}};
    cmd->subcommands = {list(cmd->weak_from_this()), ack(cmd->weak_from_this()), silence(cmd->weak_from_this()),
                        unsilence(cmd->weak_from_this())};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Health Commands";
    book->root = base(parent);
    return book;
}

}
