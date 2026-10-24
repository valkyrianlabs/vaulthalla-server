#include "platform/Mount.hpp"

#include <string_view>

// macOS never mounts (#262): macFUSE is ruled out in every form, and Finder access belongs to Vaulthalla Desktop's
// File Provider (vaulthalla/desktop#1). The kernel bridge is never built here (core/meson.build), so the lifecycle
// half of platform/Mount.hpp, which only fuse/Service.cpp calls, has no darwin implementation.
namespace vh::platform::mount {

std::string_view defaultMode() noexcept { return "disabled"; }

bool supportsMode(const std::string_view mode) noexcept { return mode == "disabled"; }

bool fuseRuntimeAvailable() noexcept { return false; }

}
