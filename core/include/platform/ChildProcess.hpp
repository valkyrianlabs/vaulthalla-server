#pragma once

#include <sys/resource.h>
#include <sys/types.h>

// Process primitives for preview::derive::Runner, which runs untrusted converter helpers. Everything marked
// "child" runs between fork and exec, so it must stay async-signal-safe.
namespace vh::platform::child {

// Linux: _Fork (no atfork handlers; the child only execs). macOS: fork.
[[nodiscard]] pid_t forkForExec() noexcept;

// Child side, first thing after setsid(): ties the child's life to `parent` and forbids privilege gain on exec.
// Returns 0, an errno, or -1 when `parent` already died (the caller _exits).
// Linux: PR_SET_PDEATHSIG(SIGKILL) + PR_SET_NO_NEW_PRIVS. macOS has neither (the daemon kills the process group
// on stop and exit; helpers are never setuid); only the parent check runs there.
[[nodiscard]] int armChild(pid_t parent) noexcept;

// Child side: caps the child's address space at `bytes` (RLIMIT_AS). Returns 0 or an errno.
// macOS refuses to lower RLIMIT_AS (EINVAL) and doesn't enforce it, so there this does nothing and returns 0; the
// memory cap has to come from the daemon watching the helper's footprint instead (roadmap #218).
[[nodiscard]] int limitAddressSpace(const struct rlimit& limit) noexcept;

// Whether limitAddressSpace() actually enforces anything here.
[[nodiscard]] bool addressSpaceLimitEnforced() noexcept;

// Child side: closes every descriptor >= `lowest` (close_range on Linux, else a loop up to `loopLimit`).
void closeFrom(int lowest, int loopLimit) noexcept;

// A descriptor that becomes readable when `pid` exits (Linux pidfd), or -1: callers then detect the exit on their
// poll tick.
[[nodiscard]] int exitWatchFd(pid_t pid) noexcept;

// Threads in `pid`'s process, or -1 when it can't be read (exited).
[[nodiscard]] long threadCount(pid_t pid) noexcept;

}
