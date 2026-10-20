#pragma once

// Pieces of the vh client (vaulthalla-cli) shared between cli.cpp and the client-side commands: `vh mcp`
// (cli_mcp.cpp) and `vh skill` (cli_skill.cpp).

#include <string>
#include <vector>

namespace vh::cli {

struct Reply {
    int exit_code = 0;
    std::string out{}, err{};
};

// Runs one command over the control socket without a terminal (never interactive) and captures its output. Connection
// failures come back as the exit code plain `vh` would use (69 not running, 75 not responding, 77 not permitted) with
// the same message in `err`.
Reply runCaptured(const std::vector<std::string>& argv, const std::string& line);

int runMcp(const std::vector<std::string>& argv);
int runSkill(const std::vector<std::string>& argv);

// Local help for a client-side command, from the usage book.
std::string localHelp(const std::vector<std::string>& path);

}
