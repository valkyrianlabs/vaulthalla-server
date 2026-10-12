#pragma once

namespace vh::platform::process {

// Keeps this process from writing core dumps. A crashing daemon must die at once instead of waiting on a dump
// (main.cpp, installCrashGuard), and cores must never hold decrypted bytes.
// Linux: prctl(PR_SET_DUMPABLE, 0), which also refuses ptrace from other non-root processes. macOS: RLIMIT_CORE = 0;
// release builds get the attach protection from the hardened runtime instead. Returns 0 or an errno.
[[nodiscard]] int disableCoreDumps() noexcept;

}
