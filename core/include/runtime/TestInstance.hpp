#pragma once

#include <functional>
#include <optional>
#include <string>

// A private test instance of the daemon (VH_TEST_MODE=1), launched by the integration engine (tools/harness). It
// must never reach a real install's state: every path, the CLI socket and the database come from the environment
// and are checked here before anything starts. Any doubt refuses to start (fail closed).
namespace vh::runtime::test_instance {

using EnvLookup = std::function<const char*(const char*)>;

// True when VH_TEST_MODE=1 asks for a test instance.
[[nodiscard]] bool requested(const EnvLookup& env);

// Why the environment is not a safe, fully private test instance, or nullopt when it is.
[[nodiscard]] std::optional<std::string> refusal(const EnvLookup& env);

}
