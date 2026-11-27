#include "protocols/shell/commands/all.hpp"

#include "mirror/copy/Copy.hpp"
#include "ops/Error.hpp"
#include "ops/MirrorLeave.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Peers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/Transfer.hpp"
#include "storage/PlaintextReader.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <ctime>
#include <functional>
#include <optional>

// `vh mirror ...` (design/peers/mirror.md): parsing and rendering only. Who may, and what changes, is ops::mirrors.
// Minimal by design (wave 3): the polished CLI, the console and Desktop come later.
namespace vh::protocols::shell::commands {

// Named, not anonymous: the unity build joins this file with the other command files of this namespace.
namespace mirror_cli {
namespace {

namespace mirrors = ::vh::ops::mirrors;

std::string mirrorPretty(const nlohmann::json& j) {
    auto out = j.dump(4);
    out.push_back('\n');
    return out;
}

// Like runOp, with a refusal's stable code in front of its sentence ("mirror add: legacy_content: ...").
template <class Op, class Format>
CommandResult runMirrorOp(const std::string& prefix, Op&& op, Format&& format) {
    try {
        return ok(std::invoke(std::forward<Format>(format), std::invoke(std::forward<Op>(op))));
    } catch (const ops::Refused& e) {
        return invalid(prefix + ": " + e.code + ": " + e.what());
    } catch (const ops::Error& e) {
        return invalid(prefix + ": " + e.what());
    }
}

std::string offerLine(const mirrors::Offer& o) {
    return fmt::format("offer {}  vault \"{}\" ({} file(s), {} bytes) from linked server {}  {} ({}){}\n", o.id, o.name,
                       o.file_count, o.size_bytes, o.peer_id, o.state, mirrors::toJson(o).value("step", ""),
                       o.reason ? " " + *o.reason : std::string());
}

std::string mirroredText(const mirrors::Mirrored& m) {
    const auto j = mirrors::toJson(m);
    std::string out = fmt::format("vault {} \"{}\": {}", m.vault_id, m.vault_name, m.role);
    if (m.peer) out += fmt::format(" with linked server {} (\"{}\", node {})", m.peer->id, m.peer->name, m.peer->node_id);
    out += "\n";
    if (m.row) {
        out += fmt::format("  term {}, last seq {}, state {}\n", m.row->term, m.row->last_seq, m.row->state);
        if (m.row->role != "core")
            out += m.row->grant ? fmt::format("  granted: '{}' by {}\n", m.row->grant->role_name, m.row->grant->granted_by_node)
                                : std::string("  granted: nothing yet (nobody here has access)\n");
    }
    if (m.start)
        out += fmt::format("  start: offer {} {} ({}){}\n", m.start->id, m.start->state, j["start"].value("step", ""),
                           m.start->reason ? ", " + *m.start->reason : std::string());
    if (m.start && m.start->side == "core" && m.start->state == "cancelled")
        out += fmt::format("  ended here{}; the linked server's copy: {}\n",
                           m.start->remove_copy ? " (its removal asked)" : "",
                           m.start->copy_outcome.value_or(m.start->notify ? "not told yet" : "unknown"));
    if (const auto deleting = j.value("deleting", nlohmann::json(nullptr)); deleting.is_object()) {
        const auto at = static_cast<std::time_t>(deleting.value("purge_after", int64_t{0}));
        char when[32] = {};
        std::tm tm{};
        if (gmtime_r(&at, &tm)) (void)std::strftime(when, sizeof when, "%Y-%m-%d %H:%M UTC", &tm);
        const auto copy = deleting.value("copy", std::string("leave"));
        out += m.row && m.row->role == "core"
                   ? fmt::format("  being deleted: purged {}; then the linked server's copy is {} (vh vault restore {} "
                                 "keeps the mirror)\n",
                                 when, copy == "remove" ? "removed (unless it keeps removed vaults)" : "left, orphaned",
                                 m.vault_id)
                   : fmt::format("  its core is deleting it: read-only here until {}, then {} (unless the core restores "
                                 "it; vh mirror detach keeps it as this server's)\n",
                                 when, deleting.value("here", copy == "remove" ? std::string("removed")
                                                                               : std::string("kept as an orphaned copy")));
    }
    if (m.row && m.row->role == "orphaned")
        out += fmt::format("  an orphaned copy: its core ended the mirror and this server kept the copy, read-only. Two "
                           "things can be done with it: keep it as this server's own vault (vh mirror detach {}), or "
                           "remove it with its keys (vh mirror cancel {})\n",
                           m.vault_id, m.vault_id);
    if (m.detached && m.detached->side == "mirror")
        out += fmt::format("  detached here at ({}, {}){}: a standalone vault now. It still shares its uid and keys with "
                           "the original on linked server {}; the re-key pass is recommended\n",
                           m.detached->fork.term, m.detached->fork.seq,
                           m.detached->missing ? fmt::format(", {} file(s) whose contents never arrived", m.detached->missing)
                                               : std::string(),
                           m.detached->peer_id);
    else if (m.detached)
        out += fmt::format("  linked server {} detached its copy of this vault at ({}, {}); the mirror ended here. Both "
                           "servers hold its keys: a key rotation here is recommended\n",
                           m.detached->peer_id, m.detached->fork.term, m.detached->fork.seq);
    return out;
}

CommandResult handleAdd(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "add"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault) return invalid("mirror add: the vault is its number (vh vault list)");
    const auto to = optVal(call, "to");
    if (!to) return invalid("mirror add: --to <linked server> is required");
    return runMirrorOp("mirror add",
                       [&] { return mirrors::add(call.user, {.vault_id = static_cast<uint32_t>(*vault), .peer = *to}); },
                       [&](const mirrors::Offer& o) {
                           return json ? mirrorPretty(mirrors::toJson(o))
                                       : fmt::format("Offered vault {} to linked server {} (offer {}). It starts once "
                                                     "that server accepts (vh mirror info {}).\n",
                                                     *vault, o.peer_id, o.id, *vault);
                       });
}

CommandResult handlePending(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "pending"}));
    const auto json = hasFlag(call, "json");
    return runMirrorOp("mirror pending", [&] { return mirrors::pending(call.user); },
                       [&](const std::vector<mirrors::Offer>& list) {
                           if (json) {
                               nlohmann::json offers = nlohmann::json::array();
                               for (const auto& o : list) offers.push_back(mirrors::toJson(o));
                               return mirrorPretty({{"offers", std::move(offers)}});
                           }
                           if (list.empty()) return std::string("No offers wait here.\n");
                           std::string out;
                           for (const auto& o : list) out += offerLine(o);
                           return out;
                       });
}

CommandResult handleDecision(const CommandCall& call, const bool acceptIt) {
    const auto* name = acceptIt ? "accept" : "decline";
    validatePositionals(call, resolveUsage({"mirror", name}));
    const auto json = hasFlag(call, "json");
    const auto& ref = call.positionals.at(0);
    return runMirrorOp(std::string("mirror ") + name,
                       [&] { return acceptIt ? mirrors::accept(call.user, ref) : mirrors::decline(call.user, ref); },
                       [&](const mirrors::Offer& o) {
                           return json ? mirrorPretty(mirrors::toJson(o))
                                       : fmt::format("Offer {} {}.\n", o.id, acceptIt ? "accepted: the keys come next"
                                                                                      : "declined");
                       });
}

CommandResult handleCancel(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "cancel"}));
    const auto json = hasFlag(call, "json");
    mirrors::CancelRequest req;
    if (const auto v = parseUInt(call.positionals.at(0)); v && *v > 0) req.vault_id = static_cast<uint32_t>(*v);
    req.offer = optVal(call, "offer");
    req.remove_copy = hasFlag(call, "remove-copy");
    return runMirrorOp("mirror cancel", [&] { return mirrors::cancel(call.user, req); },
                       [&](const mirrors::Cancelled& c) {
                           if (json) return mirrorPretty(mirrors::toJson(c));
                           if (c.side == "core")
                               return fmt::format("Ended the mirror of vault {} here. The linked server is told (when "
                                                  "it is reachable){}; vh mirror info {} shows what it did.\n",
                                                  c.vault_id.value_or(0),
                                                  c.remove_copy ? " and asked to remove its copy"
                                                                : " and keeps its copy, orphaned",
                                                  c.vault_id.value_or(0));
                           return std::string(c.removed ? "Cancelled: the vault and its keys were removed here; the core "
                                                          "is told.\n"
                                                        : "Cancelled; the core is told.\n");
                       });
}

CommandResult handleList(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "list"}));
    const auto json = hasFlag(call, "json");
    return runMirrorOp("mirror list", [&] { return mirrors::list(call.user); },
                       [&](const std::vector<mirrors::Mirrored>& list) {
                           if (json) {
                               nlohmann::json vaults = nlohmann::json::array();
                               for (const auto& m : list) vaults.push_back(mirrors::toJson(m));
                               return mirrorPretty({{"vaults", std::move(vaults)}});
                           }
                           if (list.empty()) return std::string("No mirrored vaults and no starts here.\n");
                           std::string out;
                           for (const auto& m : list) out += mirroredText(m);
                           return out;
                       });
}

CommandResult handleInfo(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "info"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault) return invalid("mirror info: the vault is its number (vh vault list)");
    return runMirrorOp("mirror info", [&] { return mirrors::get(call.user, static_cast<uint32_t>(*vault)); },
                       [&](const mirrors::Mirrored& m) {
                           return json ? mirrorPretty({{"vault", mirrors::toJson(m)}}) : mirroredText(m);
                       });
}

CommandResult handleAcceptAll(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "accept-all"}));
    const auto json = hasFlag(call, "json");
    const auto& peerRef = call.positionals.at(0);
    const auto& state = call.positionals.at(1);
    if (state != "on" && state != "off") return invalid("mirror accept-all: the state is on or off");
    return runMirrorOp("mirror accept-all", [&] { return mirrors::setAcceptAll(call.user, peerRef, state == "on"); },
                       [&](const ::vh::db::query::mirror::AcceptVaults& a) {
                           if (json) return mirrorPretty(mirrors::toJson(a, ::vh::ops::peers::resolveRef(peerRef)));
                           return std::string(a.enabled ? "Every vault that server offers is accepted here now.\n"
                                                        : "Offers from that server wait for a super admin here.\n");
                       });
}

CommandResult handleKeep(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "keep-removed"}));
    const auto json = hasFlag(call, "json");
    const auto& peerRef = call.positionals.at(0);
    const auto& state = call.positionals.at(1);
    if (state != "on" && state != "off") return invalid("mirror keep-removed: the state is on or off");
    return runMirrorOp("mirror keep-removed", [&] { return mirrors::setKeepRemoved(call.user, peerRef, state == "on"); },
                       [&](const ::vh::db::query::mirror::AcceptVaults& a) {
                           if (json) return mirrorPretty(mirrors::toJson(a, ::vh::ops::peers::resolveRef(peerRef)));
                           return std::string(a.enabled ? "Vaults that server removes are kept here, orphaned.\n"
                                                        : "Vaults that server removes are removed here when it asks.\n");
                       });
}

std::string heldLine(const ::vh::db::query::mirror::HeldChange& h) {
    return fmt::format("{} {}  vault {}  {} {}{}  {} ({}: {}){}\n", h.kind == "conflict" ? "conflict" : "held", h.id,
                       h.vault_id, h.op, h.path.value_or("?"), h.copy_name ? " -> " + *h.copy_name : std::string(),
                       h.state, h.reason_code, h.reason, h.kind == "held" && h.state == "open"
                                                             ? fmt::format("  (vh mirror retry|discard {})", h.id)
                                                             : std::string());
}

CommandResult handleHeld(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "held"}));
    const auto json = hasFlag(call, "json");
    std::optional<uint32_t> vault;
    if (const auto v = optVal(call, "vault")) {
        const auto n = parseUInt(*v);
        if (!n || *n == 0) return invalid("mirror held: --vault is the vault's number (vh vault list)");
        vault = static_cast<uint32_t>(*n);
    }
    return runMirrorOp("mirror held", [&] { return mirrors::held(call.user, vault, hasFlag(call, "all")); },
                       [&](const std::vector<::vh::db::query::mirror::HeldChange>& list) {
                           if (json) {
                               nlohmann::json out = nlohmann::json::array();
                               for (const auto& h : list) out.push_back(mirrors::toJson(h));
                               return mirrorPretty({{"held", std::move(out)}});
                           }
                           if (list.empty()) return std::string("No held changes and no conflict copies.\n");
                           std::string out;
                           for (const auto& h : list) out += heldLine(h);
                           return out;
                       });
}

CommandResult handleHeldDecision(const CommandCall& call, const bool retryIt) {
    const char* name = retryIt ? "retry" : "discard";
    validatePositionals(call, resolveUsage({"mirror", name}));
    const auto json = hasFlag(call, "json");
    const auto id = parseUInt(call.positionals.at(0));
    if (!id || *id == 0) return invalid(std::string("mirror ") + name + ": the held change is its number (vh mirror held)");
    return runMirrorOp(std::string("mirror ") + name,
                       [&] {
                           return retryIt ? mirrors::retryHeld(call.user, *id) : mirrors::discardHeld(call.user, *id);
                       },
                       [&](const ::vh::db::query::mirror::HeldChange& h) {
                           if (json) return mirrorPretty({{"held", mirrors::toJson(h)}});
                           return std::string(retryIt ? "Sent to the core again.\n" : "Discarded.\n");
                       });
}

// ---- leaving a mirror (wave 5 piece A; ops/MirrorLeave.hpp)

std::string detachPreviewText(const ::vh::mirror::leave::Preview& p) {
    std::string out = fmt::format("vault {} \"{}\": {} copy of linked server {}, {}{}\n", p.vault_id, p.vault_name, p.role,
                                  p.peer ? p.peer->node_id : std::string("?"), p.state,
                                  p.stop_reason ? " (" + *p.stop_reason + ")" : std::string());
    out += fmt::format("  applied through ({}, {}); confirmed by the core: {}; digest there: {}\n", p.applied.term,
                       p.applied.seq,
                       p.confirmed ? fmt::format("({}, {})", p.confirmed->term, p.confirmed->seq) : std::string("nothing yet"),
                       !p.digest_matched ? std::string("not compared yet") : *p.digest_matched ? "matched" : "differed");
    if (!p.copy_finished)
        out += fmt::format("  the first copy is not finished: {} of the core's {} entries are here\n", p.copy_cursor,
                           p.baseline_rows);
    out += fmt::format("  {} pending change(s) become ordinary changes here; {} held change(s) stay listed\n",
                       p.pending_changes, p.held_changes);
    if (p.missing.empty()) out += "  every file's contents are here\n";
    else {
        out += fmt::format("  {} file(s) whose contents are not here (they stay listed, marked missing; opening one "
                           "fails):\n", p.missing.size());
        for (const auto& m : p.missing) out += fmt::format("    {}  ({} bytes)\n", m.path, m.size_bytes);
    }
    return out;
}

std::string copyText(const ::vh::mirror::copy::Job& j) {
    std::string out = fmt::format("copy {} of vault {} into \"{}\"{}: {}, {} of {} entries, {} of {} bytes{}\n", j.id,
                                  j.source_vault_id ? std::to_string(*j.source_vault_id) : std::string("(removed)"),
                                  j.name, j.vault_id ? fmt::format(" (vault {})", *j.vault_id) : std::string(), j.state,
                                  j.entries_done, j.entries_total, j.bytes_done, j.bytes_total,
                                  j.error ? ": " + *j.error : std::string());
    if (!j.skipped.empty()) {
        out += fmt::format("  {} file(s) left out:\n", j.skipped.size());
        for (const auto& s : j.skipped) out += fmt::format("    {}  ({} bytes, {})\n", s.path, s.size_bytes, s.reason);
    }
    return out;
}

CommandResult handleDetachCopy(const CommandCall& call, const uint32_t vaultId, const bool json) {
    const auto render = [json](const char* key, const std::optional<::vh::mirror::copy::Job>& j, const std::string& lead) {
        if (json) return mirrorPretty({{key, j ? ::vh::mirror::copy::toJson(*j) : nlohmann::json(nullptr)}});
        return j ? lead + copyText(*j) : std::string("No copy of this vault was written here.\n");
    };
    if (hasFlag(call, "status"))
        return runMirrorOp("mirror detach", [&] { return mirrors::copyStatus(call.user, vaultId); },
                           [&](const std::optional<::vh::mirror::copy::Job>& j) { return render("copy", j, ""); });
    if (hasFlag(call, "cancel"))
        return runMirrorOp("mirror detach", [&] { return mirrors::cancelCopy(call.user, vaultId); },
                           [&](const ::vh::mirror::copy::Job& j) {
                               return render("copy", j, "Cancel asked: the partial vault is removed.\n");
                           });
    return runMirrorOp("mirror detach",
                       [&] {
                           return mirrors::detachCopy(call.user, {.vault_id = vaultId, .name = optVal(call, "name"),
                                                                  .owner = optVal(call, "owner")});
                       },
                       [&](const ::vh::mirror::copy::Job& j) {
                           return render("copy", j, fmt::format("Copying vault {} into a new vault in the background (vh "
                                                                "mirror detach {} --copy --status shows how far it is); "
                                                                "the held copy stays as it is.\n", vaultId, vaultId));
                       });
}

CommandResult handleDetach(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "detach"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault || *vault == 0) return invalid("mirror detach: the vault is its number (vh vault list)");
    const auto vaultId = static_cast<uint32_t>(*vault);
    const bool copy = hasFlag(call, "copy");
    if (!copy && (hasFlag(call, "status") || hasFlag(call, "cancel") || optVal(call, "name")))
        return invalid("mirror detach: --name, --status and --cancel go with --copy");
    if (copy && hasFlag(call, "status") && hasFlag(call, "cancel"))
        return invalid("mirror detach: --status or --cancel, not both");
    if (copy && !hasFlag(call, "dry-run")) return handleDetachCopy(call, vaultId, json);
    if (hasFlag(call, "dry-run"))
        return runMirrorOp("mirror detach", [&] { return mirrors::detachPreview(call.user, vaultId); },
                           [&](const ::vh::mirror::leave::Preview& p) {
                               return json ? mirrorPretty({{"preview", ::vh::mirror::leave::toJson(p)}})
                                           : detachPreviewText(p) + "Nothing changed (--dry-run).\n";
                           });
    return runMirrorOp("mirror detach",
                       [&] { return mirrors::detach(call.user, {.vault_id = vaultId, .owner = optVal(call, "owner")}); },
                       [&](const ::vh::mirror::leave::Detached& d) {
                           if (json) return mirrorPretty({{"detached", ::vh::mirror::leave::toJson(d)}});
                           return fmt::format("Detached vault {}: it is a standalone vault on this server now, owned by "
                                              "account {}{}. {}It still shares its uid and keys with the original: the "
                                              "re-key pass is recommended.\n",
                                              vaultId, d.owner_id,
                                              d.missing ? fmt::format(" ({} file(s) whose contents never arrived are "
                                                                      "marked missing)", d.missing)
                                                        : std::string(),
                                              d.core_told_later ? "The core is told when it is reachable. " : "");
                       });
}

CommandResult handleVersions(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "versions"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault || *vault == 0) return invalid("mirror versions: the vault is its number (vh vault list)");
    const auto& state = call.positionals.at(1);
    if (state != "on" && state != "off") return invalid("mirror versions: the state is on or off");
    mirrors::VersionsRequest req{.vault_id = static_cast<uint32_t>(*vault), .enabled = state == "on"};
    const auto number = [&](const char* flag) -> std::optional<uint64_t> {
        const auto v = optVal(call, flag);
        if (!v) return std::nullopt;
        const auto n = parseUInt(*v);
        if (!n) throw ops::Invalid(std::string("--") + flag + " is a number (0: no limit of that kind)");
        return static_cast<uint64_t>(*n);
    };
    try {
        if (const auto n = number("keep-last")) req.keep_last = static_cast<unsigned int>(std::min<uint64_t>(*n, 100000));
        if (const auto n = number("max-age-days")) req.max_age_days = static_cast<unsigned int>(std::min<uint64_t>(*n, 100000));
        req.quota_bytes = number("quota-bytes");
    } catch (const ops::Error& e) {
        return invalid(std::string("mirror versions: ") + e.what());
    }
    return runMirrorOp("mirror versions", [&] { return mirrors::setVersions(call.user, req); },
                       [&](const ::vh::mirror::versions::Setting& s) {
                           if (json) return mirrorPretty({{"versions", mirrors::toJson(s)}});
                           if (!s.policy.enabled) return std::string("This server keeps no versions of what the core "
                                                                     "replaces or deletes in that vault.\n");
                           return fmt::format("This server keeps versions of what the core replaces or deletes in vault "
                                              "{}: {}{}{}.\n", *vault,
                                              s.policy.keep_last ? fmt::format("the last {} per file", *s.policy.keep_last)
                                                                 : std::string("no count limit"),
                                              s.policy.max_age_days ? fmt::format(", for {} days", *s.policy.max_age_days)
                                                                    : std::string(),
                                              s.policy.quota_bytes ? fmt::format(", at most {} bytes", *s.policy.quota_bytes)
                                                                   : std::string());
                       });
}

// `vh mirror save <id> <dest>`: the person's version of a held write, streamed to the client's file (the
// transfer frames of `vh fs get`; the client writes <dest>, "-" is stdout). Nothing in the vault changes.
CommandResult heldGetFail(const int code, const std::string& msg) { return {code, "", "mirror save: " + msg}; }

CommandResult handleHeldGet(const CommandCall& call) {
    namespace tx = ::vh::protocols::shell::transfer;
    const auto usage = resolveUsage({"mirror", "save"});
    if (call.positionals.size() != usage->positionals.size())
        return heldGetFail(tx::exitcode::kUsage, "usage: vh mirror save <id> <dest|->");
    if (!call.transfer)
        return heldGetFail(tx::exitcode::kUsage, "this vh client can't receive files; use the vh that came with the daemon");
    const auto id = parseUInt(call.positionals.at(0));
    if (!id || *id == 0) return heldGetFail(tx::exitcode::kUsage, "the held change is its number (vh mirror held)");
    mirrors::HeldContent content;
    try {
        content = mirrors::heldContent(call.user, *id);
    } catch (const ops::Denied& e) {
        return heldGetFail(tx::exitcode::kNoPerm, e.what());
    } catch (const ops::NotFound& e) {
        return heldGetFail(tx::exitcode::kNoInput, e.what());
    } catch (const ops::Refused& e) {
        return heldGetFail(1, e.code + ": " + e.what());
    } catch (const ops::Error& e) {
        return heldGetFail(1, e.what());
    }
    const int fd = call.transfer->fd;
    if (!SocketIO::send_json(fd, {{"type", "transfer"}, {"size", content.size}}))
        return heldGetFail(tx::exitcode::kTempFail, "the client went away");
    std::vector<std::uint8_t> chunk(tx::kChunkBytes);
    std::uint64_t offset = 0, seq = 0;
    while (offset < content.size) {
        const auto want = static_cast<std::size_t>(std::min<std::uint64_t>(chunk.size(), content.size - offset));
        const auto n = content.reader->read(offset, std::span(chunk.data(), want));
        if (n == 0) return heldGetFail(1, "the held version is shorter than its recorded size");
        if (!SocketIO::send_json(fd, {{"type", "data"}, {"seq", seq}, {"b64", tx::encode(std::span(chunk.data(), n))}}))
            return heldGetFail(tx::exitcode::kTempFail, "the client stopped reading");
        offset += n;
        ++seq;
    }
    try {
        content.reader->requireAuthenticated();
    } catch (const std::exception&) {
        return heldGetFail(1, "the held version failed its integrity check; discard what was received");
    }
    return {0, "", ""};
}

CommandResult handleResync(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "resync"}));
    const auto json = hasFlag(call, "json");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault || *vault == 0) return invalid("mirror resync: the vault is its number (vh vault list)");
    return runMirrorOp("mirror resync", [&] { return mirrors::resync(call.user, static_cast<uint32_t>(*vault)); },
                       [&](const nlohmann::json& r) {
                           if (json) return mirrorPretty(r);
                           return fmt::format("Vault {}'s copy starts over from its core's tree ({} entries); {} pending "
                                              "change(s) kept as held (vh mirror held).\n",
                                              *vault, r.value("entries", int64_t{0}), r.value("held", uint64_t{0}));
                       });
}

CommandResult handleSwitch(const CommandCall& call) {
    validatePositionals(call, resolveUsage({"mirror", "switch"}));
    const auto json = hasFlag(call, "json");
    const auto acceptNoAccess = hasFlag(call, "accept-no-access");
    const auto vault = parseUInt(call.positionals.at(0));
    if (!vault || *vault == 0) return invalid("mirror switch: the vault is its number (vh vault list)");
    return runMirrorOp(
        "mirror switch", [&] { return mirrors::switchRole(call.user, static_cast<uint32_t>(*vault), acceptNoAccess); },
        [&](const nlohmann::json& r) {
            if (json) return mirrorPretty(r);
            const auto text = [&](const char* key, const std::string& fallback) {
                return r.contains(key) && r[key].is_string() ? r[key].get<std::string>() : fallback;
            };
            const auto outcome = text("outcome", "");
            const auto role = text("role", "-");
            // The old core's role on the vault on the new core: what its people may do there afterwards.
            const auto peerRole = r.contains("peer_role") && r["peer_role"].is_object()
                                      ? r["peer_role"].value("role_name", std::string("?"))
                                      : std::string{};
            const auto access = text("peer_access", "none");
            const auto oldCore = text("side", "core") == "core" ? std::string("this server") : std::string("the old core");
            const auto roleLine =
                peerRole.empty() ? fmt::format("{} holds no role on the vault on its new core (no access)", oldCore)
                                 : fmt::format("{} holds role '{}' on the vault on its new core ({})", oldCore, peerRole,
                                               access);
            if (outcome == "switched")
                return fmt::format("Vault {} switched: this server is its {} now (term {}){}; {}.\n", *vault, role,
                                   r.value("role_term", int64_t{0}),
                                   r.value("told", true) ? "" : ", the other server has not confirmed yet", roleLine);
            if (outcome == "abandoned") {
                const auto why = r.contains("detail") && r["detail"].is_object() && r["detail"].contains("why") &&
                                         r["detail"]["why"].is_string()
                                     ? ": " + r["detail"]["why"].get<std::string>()
                                     : std::string{};
                return fmt::format("Vault {}'s switch was abandoned ({}{}); nothing changed, this server is still its "
                                   "{}.\n",
                                   *vault, text("reason", "abandoned"), why, role);
            }
            return fmt::format("Vault {}'s switch is still running (vh mirror info {} shows it).\n", *vault, *vault);
        });
}

CommandResult handleMirror(const CommandCall& call) {
    if (call.positionals.empty()) return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    const auto is = [&](const char* name) { return isCommandMatch({"mirror", name}, sub); };
    if (is("add")) return handleAdd(subcall);
    if (is("pending")) return handlePending(subcall);
    if (is("accept")) return handleDecision(subcall, true);
    if (is("decline")) return handleDecision(subcall, false);
    if (is("cancel")) return handleCancel(subcall);
    if (is("list")) return handleList(subcall);
    if (is("info")) return handleInfo(subcall);
    if (is("accept-all")) return handleAcceptAll(subcall);
    if (is("keep-removed")) return handleKeep(subcall);
    if (is("held")) return handleHeld(subcall);
    if (is("save")) return handleHeldGet(subcall);
    if (is("discard")) return handleHeldDecision(subcall, false);
    if (is("retry")) return handleHeldDecision(subcall, true);
    if (is("detach")) return handleDetach(subcall);
    if (is("versions")) return handleVersions(subcall);
    if (is("resync")) return handleResync(subcall);
    if (is("switch")) return handleSwitch(subcall);
    return invalid(call.constructFullArgs(), "Unknown mirror subcommand: '" + std::string(sub) + "'");
}

}
}

void registerMirrorCommands(const std::shared_ptr<Router>& r) {
    r->registerCommand(runtime::Deps::get().shellUsageManager->resolve("mirror"), mirror_cli::handleMirror);
}

}
