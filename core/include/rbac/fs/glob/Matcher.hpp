#pragma once

#include "rbac/fs/glob/model/Pattern.hpp"

#include <filesystem>
#include <string_view>

namespace vh::rbac::fs::glob {
    struct Matcher {
        using Path = std::filesystem::path;

        // Match a precompiled pattern against a vault-absolute path such as:
        //   /docs/report.pdf
        //   /images/raw/cat.png
        static bool matches(const model::Pattern &pattern, const Path &path);

        // Parse + match in one call.
        static bool matches(std::string_view pattern, const Path &path);

        static bool requiresTraversalThrough(std::string_view pattern, const Path &directory);

        static bool requiresTraversalThrough(const model::Pattern& pattern, const Path &directory);

        // Whether the pattern could match `directory` itself or any path below it. Conservative: a wildcard whose
        // literal prefix leads into or above the directory ("/**/x", "/docs/*/secret.txt" for /docs/a) counts, so a
        // false answer proves no entry in that subtree is matched. The listing shortcuts rely on that (#255).
        static bool mayMatchWithin(const model::Pattern& pattern, const Path &directory);

    private:
        static bool validatePath(const Path &path);
        static std::string normalizePath(const Path &path);
    };
}
