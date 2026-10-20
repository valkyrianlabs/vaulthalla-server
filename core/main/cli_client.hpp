#pragma once

// Pieces of the vh client (vaulthalla-cli) shared between cli.cpp and the client-side commands: `vh mcp`
// (cli_mcp.cpp) and `vh skill` (cli_skill.cpp).

#include <mutex>
#include <optional>
#include <string>
#include <vector>

namespace vh::cli {

// The result frame's optional `confirmation`: refused for want of a confirmation (code, and the flags that give it).
struct Confirmation {
    std::string code{};
    std::vector<std::string> flags{};
};

struct Reply {
    int exit_code = 0;
    std::string out{}, err{};
    std::optional<Confirmation> confirmation{};
};

// Lets another thread cancel a running runCaptured (vh mcp's notifications/cancelled).
struct CallControl {
    mutable std::mutex mutex{};
    int fd = -1;  // the call's socket while it is open
    bool cancelled = false;
    void cancel();
};

// Runs one command over the control socket without a terminal (never interactive) and captures its output. Connection
// failures come back as the exit code plain `vh` would use (69 not running, 75 not responding, 77 not permitted) with
// the same message in `err`; a cancelled call is 130, one past `deadlineSeconds` (0: none) is 124.
Reply runCaptured(const std::vector<std::string>& argv, const std::string& line, CallControl* control = nullptr,
                  int deadlineSeconds = 0);

int runMcp(const std::vector<std::string>& argv);
int runSkill(const std::vector<std::string>& argv);

// Local help for a client-side command, from the usage book.
std::string localHelp(const std::vector<std::string>& path);

}
