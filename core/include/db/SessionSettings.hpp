#pragma once

#include <pqxx/transaction>

#include <string>
#include <utility>
#include <vector>

// Transaction-local settings for every transaction this thread begins while a scope is alive (db::Transactions::exec
// applies them right after BEGIN, as set_config(name, value, true)). For an operation that runs through code that opens
// its own transactions and must carry a setting into each of them: a change made on a mirror (the backstop's switch
// and the pending change's request id), a change a mirror submitted, executed on the core (vh.mirror_origin,
// vh.actor). Scopes nest; the innermost value of a name wins. Never crosses threads: work handed to another thread
// carries no setting.
namespace vh::db {

class SessionSettings {
public:
    class Scope {
    public:
        explicit Scope(std::vector<std::pair<std::string, std::string>> settings);
        ~Scope();
        Scope(const Scope&) = delete;
        Scope& operator=(const Scope&) = delete;

    private:
        std::size_t count_{};
    };

    // Whether a scope is alive on this thread (one thread-local read).
    [[nodiscard]] static bool active() noexcept;
    // Applies this thread's settings to `txn` (nothing without a scope).
    static void apply(pqxx::work& txn);
    // The innermost value of `name` on this thread, "" without one.
    [[nodiscard]] static std::string current(const std::string& name);
};

}
