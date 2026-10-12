#include "protocols/shell/commands/all.hpp"

#include "db/encoding/timestamp.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/File.hpp"
#include "identities/User.hpp"
#include "ops/Conflicts.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/ConflictResolver.hpp"
#include "usage/include/UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <iomanip>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

// vh sync resolve / vh resolve (#187): list and resolve sync conflicts through ops::conflicts, non-interactively or
// as an interactive session when the client has a terminal.
namespace vh::protocols::shell::commands {
namespace {

namespace conflicts = vh::ops::conflicts;
using Decision = conflicts::Decision;

constexpr uint64_t kDiffMaxBytes = 256 * 1024;
constexpr std::size_t kDiffMaxLines = 2000;

std::string humanBytes(const uint64_t bytes) {
    static constexpr const char* units[] = {"B", "KiB", "MiB", "GiB", "TiB"};
    double value = static_cast<double>(bytes);
    std::size_t unit = 0;
    while (value >= 1024.0 && unit + 1 < std::size(units)) {
        value /= 1024.0;
        ++unit;
    }
    std::ostringstream out;
    if (unit == 0) out << bytes << " B";
    else out << std::fixed << std::setprecision(1) << value << ' ' << units[unit];
    return out.str();
}

std::string when(const std::optional<std::time_t>& t) {
    return t && *t ? db::encoding::timestampToString(*t) : std::string{"-"};
}

std::string shortHash(const std::optional<std::string>& h) {
    if (!h || h->empty()) return "-";
    return h->size() > 16 ? h->substr(0, 16) + "…" : *h;
}

std::string reasonsText(const conflicts::ConflictView& v) {
    std::string out;
    for (const auto& r : v.record.reasons) {
        if (!out.empty()) out += ", ";
        out += r.code;
    }
    return out.empty() ? v.record.type : out;
}

std::optional<Decision> decisionFlag(const CommandCall& call) {
    const bool local = hasFlag(call, std::vector<std::string>{"keep-local", "local"});
    const bool remote = hasFlag(call, std::vector<std::string>{"keep-remote", "remote"});
    if (local && remote) throw ops::Invalid("choose one of --keep-local or --keep-remote");
    if (local) return Decision::KeepLocal;
    if (remote) return Decision::KeepRemote;
    return std::nullopt;
}

// A vault by ID, or by name among the vaults with conflicts the caller can resolve (then among the caller's own).
uint32_t conflictVaultArg(const CommandCall& call, const std::string& value) {
    if (const auto id = parseUInt(value)) return *id;
    const auto summary = conflicts::summary(call.user);
    std::vector<uint32_t> matches;
    for (const auto& v : summary.vaults)
        if (v.vault_name == value) matches.push_back(v.vault_id);
    if (matches.size() == 1) return matches.front();
    if (matches.size() > 1) throw ops::Invalid("more than one vault is named '" + value + "'; use its ID");
    if (const auto own = db::query::vault::Vault::getVault(value, call.user->id)) return own->id;
    throw ops::NotFound("vault not found: " + value);
}

std::vector<uint32_t> idArgs(const CommandCall& call) {
    std::vector<uint32_t> ids;
    for (const auto& p : call.positionals) {
        const auto id = parseUInt(p);
        if (!id || *id == 0) throw ops::Invalid("conflict ids are positive numbers, got '" + p + "'");
        ids.push_back(*id);
    }
    return ids;
}

std::string renderList(const std::vector<conflicts::ConflictView>& list) {
    if (list.empty()) return "No open sync conflicts you can resolve.\n";
    std::map<std::pair<std::string, uint32_t>, std::vector<const conflicts::ConflictView*>> byVault;
    for (const auto& v : list) byVault[{v.vault_name, v.record.vault_id}].push_back(&v);

    std::ostringstream out;
    for (const auto& [vault, items] : byVault) {
        out << "Vault " << vault.first << " (#" << vault.second << "): " << items.size() << " open conflict"
            << (items.size() == 1 ? "" : "s") << "\n";
        Table table({
            {"ID", Align::Right, 2, 8, false, false},
            {"Path", Align::Left, 8, 60, false, true},
            {"Local", Align::Left, 8, 32, false, false},
            {"Remote", Align::Left, 8, 32, false, false},
            {"Why", Align::Left, 4, 28, true, false},
            {"Overwrite", Align::Left, 3, 9, false, false}
        });
        for (const auto* v : items) {
            const auto& r = v->record;
            table.add_row({std::to_string(r.id), r.path,
                           humanBytes(r.local.size_bytes) + ", " + when(r.local.modified_at),
                           humanBytes(r.remote.size_bytes) + ", " + when(r.remote.modified_at), reasonsText(*v),
                           v->can_overwrite ? "yes" : "no"});
        }
        out << table.render() << "\n";
    }
    out << "Resolve with: vh sync resolve <id...> --keep-local | --keep-remote\n";
    return out.str();
}

std::string renderResults(const conflicts::ResolveResult& result) {
    std::ostringstream out;
    for (const auto& item : result.results) {
        out << "  #" << item.conflict_id << ": " << item.status;
        if (item.message) out << " - " << *item.message;
        out << "\n";
    }
    out << vh::sync::toString(result.decision) << ": " << result.resolved << " resolved, " << result.failed
        << " not resolved\n";
    return out.str();
}

CommandResult resultFor(const conflicts::ResolveResult& result, const bool json) {
    CommandResult r;
    r.stdout_text = json ? nlohmann::json(result).dump(2) + "\n" : renderResults(result);
    r.exit_code = result.failed ? 2 : 0;
    return r;
}

std::string sideBySide(const conflicts::ConflictView& v) {
    const auto& r = v.record;
    Table table({
        {"", Align::Left, 8, 14, false, false},
        {"Local (this host)", Align::Left, 8, 44, false, true},
        {"Remote (bucket)", Align::Left, 8, 44, false, true}
    });
    table.add_row({"Size", humanBytes(r.local.size_bytes), humanBytes(r.remote.size_bytes)});
    table.add_row({"Modified", when(r.local.modified_at), when(r.remote.modified_at)});
    table.add_row({"Hash", shortHash(r.local.content_hash), shortHash(r.remote.content_hash)});
    table.add_row({"Type", r.local.mime_type.value_or("-"), r.remote.mime_type.value_or("-")});
    table.add_row({"ETag", "-", r.remote.etag.value_or("-")});
    table.add_row({"Encrypted", "-", r.remote.encrypted ? (*r.remote.encrypted ? "yes" : "no") : "-"});
    std::ostringstream out;
    out << "Conflict #" << r.id << " in vault " << v.vault_name << ": " << r.path << "\n"
        << "Detected " << when(r.created_at) << ", reasons: " << reasonsText(v) << "\n"
        << table.render();
    if (!v.can_overwrite) out << "You do not have Overwrite on this file, so you cannot resolve it.\n";
    return out.str();
}

std::vector<std::string> lines(const std::vector<uint8_t>& bytes) {
    std::vector<std::string> out;
    std::string cur;
    for (const auto b : bytes) {
        if (b == '\n') {
            out.push_back(std::move(cur));
            cur.clear();
        } else if (b != '\r') cur.push_back(static_cast<char>(b));
    }
    if (!cur.empty()) out.push_back(std::move(cur));
    return out;
}

bool looksLikeText(const std::vector<uint8_t>& bytes) {
    return std::ranges::none_of(bytes, [](const uint8_t b) { return b == 0; });
}

// A unified-style line diff (LCS), bounded by kDiffMaxLines per side.
std::string lineDiff(const std::vector<std::string>& a, const std::vector<std::string>& b) {
    const auto n = a.size(), m = b.size();
    std::vector<std::vector<uint16_t>> lcs(n + 1, std::vector<uint16_t>(m + 1, 0));
    for (std::size_t i = n; i-- > 0;)
        for (std::size_t j = m; j-- > 0;)
            lcs[i][j] = a[i] == b[j] ? static_cast<uint16_t>(lcs[i + 1][j + 1] + 1)
                                     : std::max(lcs[i + 1][j], lcs[i][j + 1]);
    std::ostringstream out;
    out << "--- local\n+++ remote\n";
    std::size_t i = 0, j = 0, shown = 0;
    while (i < n || j < m) {
        if (i < n && j < m && a[i] == b[j]) {
            ++i;
            ++j;
            continue;
        }
        if (j < m && (i == n || lcs[i][j + 1] >= lcs[i + 1][j])) out << "+" << b[j++] << "\n";
        else out << "-" << a[i++] << "\n";
        if (++shown >= 400) {
            out << "… (diff truncated)\n";
            break;
        }
    }
    if (shown == 0) out << "(no line differences)\n";
    return out.str();
}

std::string diffFor(const CommandCall& call, const conflicts::ConflictView& v) {
    const auto& r = v.record;
    if (r.local.size_bytes > kDiffMaxBytes || r.remote.size_bytes > kDiffMaxBytes + 16)
        return "Too large for a text diff (limit " + humanBytes(kDiffMaxBytes) + " per side).\n";
    const auto target = conflicts::previewTarget(call.user, r.id);
    std::vector<uint8_t> localBytes;
    {
        const auto reader = target.engine->openPlaintextReader(
            target.file, storage::ReaderOptions{.remote = storage::RemoteFetchPolicy::Off});
        localBytes = storage::readAll(*reader, kDiffMaxBytes);
    }
    const auto remoteBytes = vh::sync::ConflictResolver::fetchRemoteForPreview(target.engine, target.record, kDiffMaxBytes);
    if (!looksLikeText(localBytes) || !looksLikeText(remoteBytes)) return "Not a text file; compare the metadata above.\n";
    const auto a = lines(localBytes);
    const auto b = lines(remoteBytes);
    if (a.size() > kDiffMaxLines || b.size() > kDiffMaxLines)
        return "Too many lines for a text diff (limit " + std::to_string(kDiffMaxLines) + ").\n";
    return lineDiff(a, b);
}

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    return s;
}

void resolveAndPrint(const CommandCall& call, const Decision decision, const std::vector<uint32_t>& ids) {
    call.io->print(renderResults(conflicts::resolve(call.user, decision, ids)));
}

// One conflict: metadata side by side, then keep local / keep remote / diff / skip / quit. False on quit.
bool inspect(const CommandCall& call, const conflicts::ConflictView& v) {
    auto& io = *call.io;
    io.print(sideBySide(v));
    while (true) {
        const auto answer = lower(io.prompt(
            v.can_overwrite ? "[l] keep local  [r] keep remote  [d] text diff (fetches the remote copy)  [s] skip  "
                              "[q] quit:"
                            : "[d] text diff (fetches the remote copy)  [s] skip  [q] quit:",
            "s"));
        if (answer == "q" || answer == "quit") return false;
        if (answer == "s" || answer == "skip" || answer.empty()) return true;
        if (answer == "d" || answer == "diff") {
            try {
                io.print(diffFor(call, v));
            } catch (const std::exception& e) {
                io.print(std::string("Could not diff: ") + e.what() + "\n");
            }
            continue;
        }
        if (v.can_overwrite && (answer == "l" || answer == "local")) {
            resolveAndPrint(call, Decision::KeepLocal, {v.record.id});
            return true;
        }
        if (v.can_overwrite && (answer == "r" || answer == "remote")) {
            resolveAndPrint(call, Decision::KeepRemote, {v.record.id});
            return true;
        }
        io.print("Unknown choice.\n");
    }
}

CommandResult interactive(const CommandCall& call, const std::optional<uint32_t> vaultFilter) {
    auto& io = *call.io;
    while (true) {
        const auto list = conflicts::list(call.user, vaultFilter);
        if (list.empty()) {
            io.print("No open sync conflicts you can resolve.\n");
            return ok("");
        }

        // Numbered, grouped by vault.
        std::map<std::pair<std::string, uint32_t>, std::vector<const conflicts::ConflictView*>> byVault;
        for (const auto& v : list) byVault[{v.vault_name, v.record.vault_id}].push_back(&v);
        std::vector<const conflicts::ConflictView*> numbered;
        std::vector<std::pair<std::string, std::vector<uint32_t>>> vaults;
        std::ostringstream out;
        for (const auto& [vault, items] : byVault) {
            out << "\n[v" << vaults.size() + 1 << "] Vault " << vault.first << " (#" << vault.second << "), "
                << items.size() << " conflict" << (items.size() == 1 ? "" : "s") << ":\n";
            std::vector<uint32_t> resolvable;
            for (const auto* v : items) {
                numbered.push_back(v);
                if (v->can_overwrite) resolvable.push_back(v->record.id);
                out << "  " << numbered.size() << ") #" << v->record.id << "  " << v->record.path << "  local "
                    << humanBytes(v->record.local.size_bytes) << " / remote " << humanBytes(v->record.remote.size_bytes)
                    << (v->can_overwrite ? "" : "  (no Overwrite)") << "\n";
            }
            vaults.emplace_back(vault.first, std::move(resolvable));
        }
        io.print(out.str());

        const auto answer = lower(io.prompt(
            "\nNumber to inspect, 'lv<N>'/'rv<N>' to keep local/remote for every conflict in vault vN, "
            "'r' to refresh, 'q' to quit:", "q"));
        if (answer == "q" || answer == "quit" || answer.empty()) return ok("");
        if (answer == "r" || answer == "refresh") continue;

        if ((answer.starts_with("lv") || answer.starts_with("rv")) && answer.size() > 2) {
            const auto idx = parseUInt(answer.substr(2));
            if (!idx || *idx == 0 || *idx > vaults.size()) {
                io.print("No such vault.\n");
                continue;
            }
            const auto& [name, ids] = vaults[*idx - 1];
            const auto decision = answer[0] == 'l' ? Decision::KeepLocal : Decision::KeepRemote;
            if (ids.empty()) {
                io.print("You cannot resolve any conflict in that vault (Overwrite needed).\n");
                continue;
            }
            const auto verb = decision == Decision::KeepLocal ? "upload the LOCAL copy over the remote object"
                                                              : "replace the local copy with the REMOTE version";
            if (!io.confirm("For " + std::to_string(ids.size()) + " conflict(s) in vault " + name + ", " + verb +
                                "? [no]", true)) continue;
            for (std::size_t i = 0; i < ids.size(); i += conflicts::kMaxResolveBatch)
                resolveAndPrint(call, decision,
                                {ids.begin() + static_cast<std::ptrdiff_t>(i),
                                 ids.begin() + static_cast<std::ptrdiff_t>(std::min(ids.size(), i + conflicts::kMaxResolveBatch))});
            continue;
        }

        if (const auto n = parseUInt(answer); n && *n >= 1 && *n <= numbered.size()) {
            if (!inspect(call, *numbered[*n - 1])) return ok("");
            continue;
        }
        io.print("Unknown choice.\n");
    }
}

CommandResult handleResolve(const CommandCall& call) {
    if (hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    constexpr auto prefix = "sync resolve";
    try {
        const bool json = hasFlag(call, std::vector<std::string>{"json", "j"});
        const auto decision = decisionFlag(call);
        const auto ids = idArgs(call);
        std::optional<uint32_t> vaultId;
        if (const auto v = optVal(call, std::vector<std::string>{"vault", "v"})) vaultId = conflictVaultArg(call, *v);
        const bool all = hasFlag(call, "all");
        const bool list = hasFlag(call, std::vector<std::string>{"list", "l"});

        if (list) {
            if (decision || all || !ids.empty())
                return invalid(std::string(prefix) + ": --list does not take conflict ids, --all or a decision");
            const auto views = conflicts::list(call.user, vaultId);
            if (!json) return ok(renderList(views));
            auto arr = nlohmann::json::array();
            for (const auto& v : views) arr.push_back(v);
            return ok(nlohmann::json{{"conflicts", arr}}.dump(2) + "\n");
        }

        if (all) {
            if (!ids.empty()) return invalid(std::string(prefix) + ": use either conflict ids or --all");
            if (!vaultId) return invalid(std::string(prefix) + ": --all needs --vault");
            if (!decision) return invalid(std::string(prefix) + ": --all needs --keep-local or --keep-remote");
            const auto views = conflicts::list(call.user, vaultId);
            std::vector<uint32_t> targets;
            for (const auto& v : views) targets.push_back(v.record.id);
            if (targets.empty()) return ok(json ? "{\"resolved\":0,\"failed\":0,\"results\":[]}\n"
                                                : "No open sync conflicts in that vault.\n");
            if (!hasFlag(call, std::vector<std::string>{"yes", "y"})) {
                if (!call.io)
                    return invalid(std::string(prefix) + ": resolving every conflict in a vault needs --yes when "
                                                         "there is no terminal to confirm");
                if (!call.io->confirm("Resolve " + std::to_string(targets.size()) + " conflict(s) with " +
                                          vh::sync::toString(*decision) + "? [no]", true))
                    return invalid(std::string(prefix) + ": cancelled; nothing was resolved");
            }
            if (targets.size() > conflicts::kMaxResolveBatch) targets.resize(conflicts::kMaxResolveBatch);
            return resultFor(conflicts::resolve(call.user, *decision, targets), json);
        }

        if (!ids.empty()) {
            if (!decision) return invalid(std::string(prefix) + ": choose --keep-local or --keep-remote");
            return resultFor(conflicts::resolve(call.user, *decision, ids), json);
        }

        if (decision) return invalid(std::string(prefix) + ": name the conflicts (ids) or use --vault <vault> --all");
        if (call.io && !json) return interactive(call, vaultId);
        // No terminal: the list.
        const auto views = conflicts::list(call.user, vaultId);
        if (!json) return ok(renderList(views));
        auto arr = nlohmann::json::array();
        for (const auto& v : views) arr.push_back(v);
        return ok(nlohmann::json{{"conflicts", arr}}.dump(2) + "\n");
    } catch (const ops::Error& e) {
        return invalid(std::string(prefix) + ": " + e.what());
    }
}

CommandResult handleSync(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());
    const auto [sub, subcall] = descend(call);
    if (isCommandMatch({"sync", "resolve"}, sub)) return handleResolve(subcall);
    return invalid(call.constructFullArgs(), "sync: unknown subcommand: '" + std::string(sub) +
                                                 "' (a vault's sync settings are under 'vh vault sync')");
}

} // namespace

void registerSyncCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("sync"), handleSync);
    r->registerCommand(usageManager->resolve("resolve"), handleResolve);
}

} // namespace vh::protocols::shell::commands
