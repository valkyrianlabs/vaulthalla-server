#pragma once

#include "recovery/Hooks.hpp"

// The provider version index (upstream_object_version) learns Vaulthalla's own writes from the PUT/COPY responses.
// Owned by the provider recovery slice.
namespace vh::recovery::provider {

// Records the version a successful own write created (origin 'vaulthalla', with the generation's IV/key/hash/sizes)
// and supersedes the previous latest. No-op when the response carried no version id. Never throws.
void noteOwnWrite(const hooks::UpstreamWrite& write) noexcept;

}
