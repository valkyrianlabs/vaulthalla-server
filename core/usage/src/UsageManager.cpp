#include "UsageManager.hpp"
#include "CommandBook.hpp"
#include "CommandUsage.hpp"
#include "usages.hpp"

#include <sstream>
#include <stdexcept>
#include <ranges>
#include <algorithm>

using namespace vh::protocols::shell;

UsageManager::UsageManager() {
    root_ = std::make_shared<CommandUsage>();
    root_->aliases = {"vh"};
    root_->description = "Vaulthalla Command Line Interface";
    root_->optional_flags = {
        Flag::WithAliases("help", "Show help information", {"h", "?"}),
        Flag::Alias("version", "Show version information", "v")
    };
    root_->examples = {
        {"vh help", "Show general help information."},
        {"vh version", "Show the current version of Vaulthalla."}
    };

    registerBook(vault::get(root_->weak_from_this()));
    registerBook(fs_book::get(root_->weak_from_this()));
    registerBook(user::get(root_->weak_from_this()));
    registerBook(group::get(root_->weak_from_this()));
    registerBook(secrets::get(root_->weak_from_this()));
    registerBook(email::get(root_->weak_from_this()));
    registerBook(pricing::get(root_->weak_from_this()));
    registerBook(sync_book::get(root_->weak_from_this()));
    registerBook(resolve_book::get(root_->weak_from_this()));
    registerBook(s3gateway::get(root_->weak_from_this()));
    registerBook(aku::get(root_->weak_from_this()));
    registerBook(upstream_book::get(root_->weak_from_this()));
    registerBook(recovery_book::get(root_->weak_from_this()));
    registerBook(recovery_book::getSnapshot(root_->weak_from_this()));
    registerBook(role::get(root_->weak_from_this()));
    registerBook(permissions::get(root_->weak_from_this()));
    registerBook(setup::get(root_->weak_from_this()));
    registerBook(teardown::get(root_->weak_from_this()));
    registerBook(status::get(root_->weak_from_this()));
    registerBook(help::get(root_->weak_from_this()));
    registerBook(version::get(root_->weak_from_this()));
}

void UsageManager::registerBook(const std::shared_ptr<CommandBook>& book) {
    root_->subcommands.push_back(book->root);
    for (const auto& alias : book->root->aliases) {
        if (index_.contains(alias)) throw std::runtime_error("UsageManager: duplicate top-level alias: " + alias);
        index_[alias] = book;
    }
}

std::shared_ptr<CommandBook> UsageManager::bookFor(const std::string& topLevelAlias) const {
    if (topLevelAlias.empty()) return nullptr;
    if (index_.contains(topLevelAlias)) return index_.at(topLevelAlias);
    return nullptr;
}

std::shared_ptr<CommandUsage> UsageManager::resolve(const std::vector<std::string>& args) const {
    if (args.empty()) return nullptr;
    const auto book = bookFor(args[0]);
    if (!book) throw std::runtime_error("UsageManager: resolve called with unknown top-level alias: " + args[1]);
    if (args.size() == 1) return book->root;
    auto subArgs = args;
    subArgs.erase(subArgs.begin());
    return book->resolve(subArgs);
}

std::shared_ptr<CommandUsage> UsageManager::resolve(const std::string& topLevelArg) const {
    if (topLevelArg.empty()) return nullptr;
    const auto book = bookFor(topLevelArg);
    if (!book) throw std::runtime_error("UsageManager: resolve called with unknown top-level alias: " + topLevelArg);
    return book->root;
}

std::string UsageManager::renderHelp(const std::vector<std::string>& args) const {
    if (args.empty()) return root_->basicStr();
    const auto book = bookFor(args[0]);
    if (!book) {
        std::ostringstream out;
        out << "[UsageManager] Unknown command or alias: ";
        for (const auto& a : args) out << a << ' ';
        out << "\n\n";
        out << index_.begin()->second->root->basicStr();
        return out.str();
    }
    return book->renderHelp(args);
}
