#include "CommandBook.hpp"
#include "CommandUsage.hpp"

#include <sstream>
#include <algorithm>
#include <ranges>

using namespace vh::protocols::shell;

std::string CommandBook::str() const {
    std::ostringstream out;
    if (!title.empty()) out << title << "\n\n";
    out << root->str();
    return out.str();
}

std::string CommandBook::basicStr() const {
    std::ostringstream out;
    if (!title.empty()) out << title << "\n\n";
    out << root->basicStr();
    return out.str();
}

std::string CommandBook::markdown() const {
    std::ostringstream md;
    if (!title.empty()) md << "# " << title << "\n\n";
    md << root->markdown();
    return md.str();
}

std::shared_ptr<CommandUsage> CommandBook::resolve(const std::vector<std::string>& args) const {
    if (!root)
        throw std::runtime_error("CommandBook::resolve() called with no root");

    auto current = root;
    std::size_t i = 0;

    // Skip executable token if present
    if (i < args.size() && args[i] == "vh")
        ++i;

    // Skip root alias if present
    if (i < args.size() && current->matches(args[i]))
        ++i;

    for (; i < args.size(); ++i) {
        const auto& arg = args[i];

        // Flags/options are not subcommands
        if (!arg.empty() && arg[0] == '-')
            break;

        auto it = std::ranges::find_if(
            current->subcommands,
            [&](const std::shared_ptr<CommandUsage>& cu) {
                return cu->matches(arg);
            }
        );

        if (it == current->subcommands.end())
            break;

        current = *it;
    }

    return current;
}

std::string CommandBook::renderHelp(const std::vector<std::string>& args) const {
    const auto cmd = resolve(args);
    std::ostringstream out;
    if (!cmd) {
        out << root->basicStr();
        out << "\n\n";
        out << "[CommandBook] Unknown command or alias: ";
        for (const auto& a : args) out << a << ' ';
        out << "root is at: " << root->primary() << "\n";
        return out.str();
    }
    // book_theme is optional: dereferencing it unset was undefined behavior (libc++ hardening traps on it).
    out << "\n";
    if (book_theme) out << book_theme->H() << title << book_theme->R();
    else out << title;
    out << "\n\n";
    return out.str() + cmd->str();
}
