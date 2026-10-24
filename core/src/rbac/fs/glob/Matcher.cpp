#include "rbac/fs/glob/Matcher.hpp"
#include "rbac/fs/glob/Tokenizer.hpp"
#include "rbac/fs/glob/model/Token.hpp"

#include <algorithm>

namespace vh::rbac::fs::glob {
    namespace {
        using Token = model::Token;
        using Pattern = model::Pattern;

        [[nodiscard]] bool matchRecursive(
            const std::vector<Token> &tokens,
            const std::string_view path,
            const std::size_t tokenIndex,
            const std::size_t pathIndex
        ) {
            if (tokenIndex == tokens.size() && pathIndex == path.size()) return true;
            if (tokenIndex == tokens.size()) return false;

            const Token &token = tokens[tokenIndex];

            switch (token.type) {
                case Token::Type::Literal: {
                    if (pathIndex + token.value.size() > path.size()) return false;
                    if (path.substr(pathIndex, token.value.size()) != token.value) return false;
                    return matchRecursive(tokens, path, tokenIndex + 1, pathIndex + token.value.size());
                }

                case Token::Type::Slash: {
                    if (pathIndex >= path.size() || path[pathIndex] != '/') return false;
                    return matchRecursive(tokens, path, tokenIndex + 1, pathIndex + 1);
                }

                case Token::Type::Question: {
                    if (pathIndex >= path.size()) return false;
                    if (path[pathIndex] == '/') return false;
                    return matchRecursive(tokens, path, tokenIndex + 1, pathIndex + 1);
                }

                case Token::Type::Star: {
                    std::size_t i = pathIndex;

                    // '*' must consume at least one non-slash character.
                    if (i >= path.size() || path[i] == '/') return false;

                    while (i < path.size() && path[i] != '/') {
                        ++i;
                        if (matchRecursive(tokens, path, tokenIndex + 1, i)) return true;
                    }

                    return false;
                }

                case Token::Type::DoubleStar: {
                    const bool nextIsSlash = tokenIndex + 1 < tokens.size() &&
                                             tokens[tokenIndex + 1].type == Token::Type::Slash;

                    // '**/' = zero or more whole path segments.
                    if (nextIsSlash) {
                        // Zero segments.
                        if (matchRecursive(tokens, path, tokenIndex + 2, pathIndex)) return true;

                        // One or more segments.
                        for (std::size_t i = pathIndex; i < path.size(); ++i)
                            if (path[i] == '/' && matchRecursive(tokens, path, tokenIndex + 2, i + 1))
                                return true;

                        return false;
                    }

                    // Generic '**' = any sequence, including empty.
                    for (std::size_t i = pathIndex; i <= path.size(); ++i)
                        if (matchRecursive(tokens, path, tokenIndex + 1, i))
                            return true;

                    return false;
                }
            }

            return false;
        }

        [[nodiscard]] bool isWildcardToken(const Token &token) {
            return token.type == Token::Type::Star ||
                   token.type == Token::Type::DoubleStar ||
                   token.type == Token::Type::Question;
        }

        [[nodiscard]] std::string literalTraversalPrefix(const Pattern &pattern) {
            std::string prefix;

            for (const auto &token : pattern.tokens) {
                if (isWildcardToken(token)) break;
                prefix += token.value;
            }

            if (prefix.empty()) return "/";
            return prefix;
        }

        [[nodiscard]] bool isAncestorOrSelf(const std::string_view ancestor, const std::string_view path) {
            if (ancestor == "/") return !path.empty() && path.front() == '/';
            if (ancestor.size() > path.size()) return false;
            if (!path.starts_with(ancestor)) return false;
            if (ancestor.size() == path.size()) return true;
            return path[ancestor.size()] == '/';
        }

        [[nodiscard]] bool isStrictAncestor(const std::string_view ancestor, const std::string_view path) {
            return ancestor != path && isAncestorOrSelf(ancestor, path);
        }

        [[nodiscard]] std::string parentDirectory(std::string path) {
            if (path.empty() || path == "/") return "/";

            while (path.size() > 1 && path.back() == '/')
                path.pop_back();

            const auto pos = path.find_last_of('/');
            if (pos == std::string::npos || pos == 0) return "/";
            return path.substr(0, pos);
        }
    }

    bool Matcher::requiresTraversalThrough(const std::string_view pattern, const Path &directory) {
        return requiresTraversalThrough(Tokenizer::parse(pattern), directory);
    }

    bool Matcher::requiresTraversalThrough(const model::Pattern& pattern, const Path &directory) {
        const std::string dir = normalizePath(directory);

        if (dir.empty() || dir.front() != '/') return false;

        // This helper is for ancestor-directory traversal only, not final target match checks.
        if (matches(pattern, directory)) return false;

        const std::string prefix = literalTraversalPrefix(pattern);

        // Directory must be on the corridor leading to the literal prefix.
        if (!isAncestorOrSelf(dir, prefix)) return false;

        // If the literal prefix itself ends in a non-slash leaf (e.g. "/docs"),
        // then traversal is required through its parent directories, and through
        // "/docs" itself only if the pattern continues beyond that leaf via wildcard
        // or additional tokens. The simple and safe first-pass rule is:
        //
        // - allow strict ancestors of the literal prefix
        // - allow self only when the prefix is a directory boundary or the pattern
        //   continues beyond the prefix
        if (isStrictAncestor(dir, prefix)) return true;

        // dir == prefix
        // If prefix already clearly denotes a directory corridor (ends with '/'),
        // traversal through it is required.
        if (!prefix.empty() && prefix.back() == '/') return true;

        // Otherwise, allow self if the pattern continues beyond the literal prefix.
        // That catches cases like:
        //   pattern "/docs/*.txt", dir "/docs"
        // where prefix == "/docs/" in practice due to token stream,
        // and also more awkward future tokenizations.
        std::string normalizedPrefix = prefix;
        if (normalizedPrefix != "/" && normalizedPrefix.back() == '/')
            normalizedPrefix.pop_back();

        return dir == normalizedPrefix || dir == parentDirectory(prefix);
    }

    bool Matcher::mayMatchWithin(const model::Pattern& pattern, const Path &directory) {
        const std::string dir = normalizePath(directory);
        if (dir.empty() || dir.front() != '/') return false;

        if (matches(pattern, directory) || requiresTraversalThrough(pattern, directory)) return true;

        // A literal pattern names one path: it is the directory, below it (traversal) or neither, all answered above.
        if (!std::ranges::any_of(pattern.tokens, isWildcardToken)) return false;

        // A wildcard can stand for any part of the path after its literal prefix. When that prefix is a string prefix
        // of "<dir>/" (or the other way round), something below the directory may match.
        const std::string prefix = literalTraversalPrefix(pattern);
        const std::string within = dir == "/" ? dir : dir + "/";
        return within.starts_with(prefix) || prefix.starts_with(within);
    }

    bool Matcher::validatePath(const Path &path) {
        const std::string normalized = normalizePath(path);
        return !normalized.empty() && normalized.front() == '/';
    }

    std::string Matcher::normalizePath(const Path &path) {
        return path.lexically_normal().generic_string();
    }

    bool Matcher::matches(const model::Pattern &pattern, const Path &path) {
        const std::string normalized = normalizePath(path);
        if (normalized.empty() || normalized.front() != '/') return false;
        return matchRecursive(pattern.tokens, normalized, 0, 0);
    }

    bool Matcher::matches(std::string_view pattern, const Path &path) {
        return matches(Tokenizer::parse(pattern), path);
    }
}
