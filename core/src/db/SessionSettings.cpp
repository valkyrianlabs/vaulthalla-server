#include "db/SessionSettings.hpp"

#include <pqxx/pqxx>

#include <set>

namespace vh::db {

namespace {

std::vector<std::pair<std::string, std::string>>& sessionSettingsStack() {
    thread_local std::vector<std::pair<std::string, std::string>> stack;
    return stack;
}

}

SessionSettings::Scope::Scope(std::vector<std::pair<std::string, std::string>> settings) : count_(settings.size()) {
    auto& stack = sessionSettingsStack();
    for (auto& s : settings) stack.push_back(std::move(s));
}

SessionSettings::Scope::~Scope() {
    auto& stack = sessionSettingsStack();
    for (std::size_t i = 0; i < count_ && !stack.empty(); ++i) stack.pop_back();
}

bool SessionSettings::active() noexcept { return !sessionSettingsStack().empty(); }

void SessionSettings::apply(pqxx::work& txn) {
    const auto& stack = sessionSettingsStack();
    if (stack.empty()) return;
    // Innermost first, each name once.
    std::set<std::string> seen;
    for (auto it = stack.rbegin(); it != stack.rend(); ++it)
        if (seen.insert(it->first).second)
            txn.exec("SELECT set_config($1, $2, true)", pqxx::params{it->first, it->second});
}

std::string SessionSettings::current(const std::string& name) {
    const auto& stack = sessionSettingsStack();
    for (auto it = stack.rbegin(); it != stack.rend(); ++it)
        if (it->first == name) return it->second;
    return {};
}

}
