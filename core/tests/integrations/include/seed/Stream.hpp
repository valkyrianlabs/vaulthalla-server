#pragma once

#include "seed/H64.hpp"
#include "ArgsGenerator.hpp"

#include <atomic>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>

// One root seed per run (VH_TEST_SEED or fresh random, always printed) and counter-based streams derived from it:
// every test draws from its own RNG seeded with h64(root, label, index), installed for the thread that runs it. So a
// test's random choices don't depend on which worker ran it, how many threads there are, or how many draws other
// tests made. Drawing with no stream installed is a harness bug and throws instead of silently using entropy.
namespace vh::test::integration::seed {

namespace detail {
inline std::atomic<uint64_t> g_root{0};
inline std::atomic<bool> g_rootSet{false};
}

inline void setRoot(const uint64_t root) {
    detail::g_root.store(root);
    detail::g_rootSet.store(true);
}

[[nodiscard]] inline uint64_t root() {
    if (!detail::g_rootSet.load()) throw std::logic_error("seed::root() read before the run seed was set");
    return detail::g_root.load();
}

class Stream {
public:
    Stream(std::string label, const uint64_t index)
        : label_(std::move(label)), index_(index), value_(h64(root(), label_, index_)), rng_(value_) {}

    [[nodiscard]] args::Rng& rng() { return rng_; }
    [[nodiscard]] const std::string& label() const { return label_; }
    [[nodiscard]] uint64_t index() const { return index_; }
    [[nodiscard]] uint64_t value() const { return value_; }

private:
    std::string label_;
    uint64_t index_;
    uint64_t value_;
    args::Rng rng_;
};

namespace detail {
inline thread_local Stream* t_current = nullptr;
}

// Installs a stream for this thread for the scope's lifetime (nests: the previous one comes back afterwards).
class Scope {
public:
    explicit Scope(std::string label, const uint64_t index = 0)
        : stream_(std::move(label), index), previous_(detail::t_current) {
        detail::t_current = &stream_;
    }
    ~Scope() { detail::t_current = previous_; }

    Scope(const Scope&) = delete;
    Scope& operator=(const Scope&) = delete;

    [[nodiscard]] const Stream& stream() const { return stream_; }

private:
    Stream stream_;
    Stream* previous_;
};

[[nodiscard]] inline args::Rng& current() {
    if (!detail::t_current)
        throw std::logic_error("integration harness: random draw with no seeded stream installed (wrap it in seed::Scope)");
    return detail::t_current->rng();
}

[[nodiscard]] inline const Stream* currentStream() { return detail::t_current; }

}
