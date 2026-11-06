#pragma once

// What the CLI/ws parity suites (test_ops_parity_*.cpp) share: run a shell line and open a ws session as a user.

#include "identities/User.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "UsageManager.hpp"

#include <atomic>
#include <chrono>
#include <exception>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace vh::test::parity {

// Short and unique within the run: names stay readable in the CLI's tables.
inline std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

// An empty shell router (the caller registers its commands), with the usage manager they print from.
inline std::shared_ptr<protocols::shell::Router> shellRouter() {
    if (!runtime::Deps::get().shellUsageManager)
        runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
    return std::make_shared<protocols::shell::Router>();
}

// Exit code and stdout + stderr of one line run as `user`; a throw is exit 1 with its message.
inline std::pair<int, std::string> cli(protocols::shell::Router& router, const std::string& line,
                                       const std::shared_ptr<identities::User>& user) {
    try {
        const auto res = router.executeLine(line, user, nullptr);
        return {res.exit_code, res.stdout_text + res.stderr_text};
    } catch (const std::exception& e) {
        return {1, e.what()};
    }
}

inline std::shared_ptr<protocols::ws::Session> ws(const std::shared_ptr<identities::User>& user) {
    auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    s->user = user;
    return s;
}

// True when fn returned, false when it threw.
inline bool succeeds(const std::function<void()>& fn) {
    try {
        fn();
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}
