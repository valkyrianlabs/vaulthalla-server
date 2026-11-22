#include "usages.hpp"
#include "ArgsGenerator.hpp"

// `vh audit list|verify|export` (#323): the tamper-evident audit trail. Handler: core/src/protocols/shell/commands/
// audit.cpp (ops::audit, the same checks as ws audit.*: admin.audits.view).
namespace vh::protocols::shell::audit_book {

namespace {

std::shared_ptr<CommandUsage> node(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

const auto jsonOut = Flag::Alias("json_output", "Print the result as JSON (the ws shapes)", "json");
const auto since = Optional::Single("since", "From this time: YYYY-MM-DD (UTC) or Unix seconds", "since", "time")
                       .withGen("time", contract::gen::pattern("2026-01-0{1}"));
const auto until = Optional::Single("until", "Before this time: YYYY-MM-DD (UTC) or Unix seconds", "until", "time")
                       .withGen("time", contract::gen::pattern("2026-12-1{1}"));

std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"list", "ls", "show"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Recent audit events, newest first. Needs admin.audits.view; viewing is itself recorded.";
    cmd->optional = {Optional::Single("action", "Only actions starting with this (\"auth.\", \"rbac.\")", "action",
                                      "prefix").withGen("prefix", contract::gen::pattern("auth.")),
                     Optional::Single("limit", "How many events (1..1000, default 50)", "limit", "n")
                         .withGen("n", contract::gen::intRange(1, 50)),
                     Optional::Single("device", "Only one paired device: what it did (under whatever scope) and what "
                                      "was done to it; its number from `vh device list --all`", "device", "number"),
                     Optional::Single("grant", "Only one connector grant: its tool calls and its own events; its id",
                                      "grant", "id"),
                     since, until};
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh audit list", "The 50 newest events."},
                     {"vh audit list --action auth. --since 2026-11-01", "Sign-ins and sign-outs since November 1."},
                     {"vh audit list --device 7", "Everything device 7 did, and every change to it."},
                     {"vh audit list --device 7 --action device.scope.refused",
                      "What device 7's scope refused it."}};
    return cmd;
}

std::shared_ptr<CommandUsage> verify(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"verify", "check"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Recompute the audit hash chain and check every signed head. Exit status 0 when intact, 1 "
                       "when the trail was altered (the output names the first bad event).";
    cmd->optional_flags = {jsonOut};
    cmd->examples = {{"vh audit verify", "Check the whole retained trail."}};
    return cmd;
}

std::shared_ptr<CommandUsage> exportCmd(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"export"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Write events as NDJSON (vh-audit-export-v1) to stdout, with their hashes and the signed "
                       "heads that cover them, so the file verifies offline (tools/audit/verify_export.py).";
    cmd->optional = {since, until};
    cmd->examples = {{"vh audit export --since 2026-01-01 > audit-2026.ndjson", "Export this year's events."}};
    return cmd;
}

std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = node(parent);
    cmd->aliases = {"audit"};
    cmd->description = "The tamper-evident audit trail: who did what, hash-chained and signed (see "
                       "docs/admin/audit-trail).";
    cmd->examples = {{"vh audit list", "Recent events."}, {"vh audit verify", "Check the chain."}};
    cmd->subcommands = {list(cmd->weak_from_this()), verify(cmd->weak_from_this()), exportCmd(cmd->weak_from_this())};
    return cmd;
}

}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Audit Commands";
    book->root = base(parent);
    return book;
}

}
