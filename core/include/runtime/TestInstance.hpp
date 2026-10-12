#pragma once

#include <functional>
#include <optional>
#include <string>
#include <string_view>

// A private test instance of the daemon (VH_TEST_MODE=1), launched by the integration engine (tools/harness). It
// must never reach a real install's state: every path, the CLI socket and the database come from the environment
// and are checked here before anything starts. Any doubt refuses to start (fail closed).
namespace vh::runtime::test_instance {

using EnvLookup = std::function<const char*(const char*)>;

// True when VH_TEST_MODE=1 asks for a test instance.
[[nodiscard]] bool requested(const EnvLookup& env);

// Why the environment is not a safe, fully private test instance, or nullopt when it is.
[[nodiscard]] std::optional<std::string> refusal(const EnvLookup& env);

// Why this host/process must never run a test instance: the production lab (hostname vh-storage*) or the packaged
// service's own cgroup (vaulthalla.service). `cgroup` is the content of /proc/self/cgroup.
[[nodiscard]] std::optional<std::string> hostRefusal(std::string_view hostname, std::string_view cgroup);

// The databases destructive test helpers (schema wipe/nuke) may touch: vh_harness_* or a name containing "test", and
// never vaulthalla, postgres or a template.
[[nodiscard]] bool isTestDatabaseName(std::string_view name);

}
