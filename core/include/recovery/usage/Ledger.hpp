#pragma once

#include "recovery/Hooks.hpp"

// Local per-vault upstream usage accounting (vault_upstream_usage_daily). Owned by the provider policy + cost slice.
namespace vh::recovery::usage {

// Counts one successful upstream write (first put vs overwrite, replaced bytes, deletes). Never throws.
void noteUpstreamWrite(const hooks::UpstreamWrite& write) noexcept;

}
