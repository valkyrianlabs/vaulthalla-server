#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"
#include "Contract.hpp"

#include <fstream>
#include <iostream>
#include <string>

// vh_usage: renders the usage module at build time.
//   vh_usage [--out FILE]          the vh(1) manpage source (Markdown)
//   vh_usage --json [--out FILE]   the server-owned contract: CLI books, ws command book, operation catalog
int main(const int argc, char** argv) {
    bool json = false;
    std::string out;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "--json") json = true;
        else if (arg == "--out" && i + 1 < argc) out = argv[++i];
        else {
            std::cerr << "usage: vh_usage [--json] [--out FILE]\n";
            return 2;
        }
    }

    std::string text;
    if (json) text = vh::contract::document();
    else {
        const vh::protocols::shell::UsageManager mgr;
        text = mgr.root()->markdown();
    }

    if (out.empty()) {
        std::cout << text;
        return std::cout.good() ? 0 : 1;
    }
    std::ofstream f(out, std::ios::binary | std::ios::trunc);
    f << text;
    return f.good() ? 0 : 1;
}
