#include "recovery/Hooks.hpp"
#include "recovery/provider/OwnWrites.hpp"
#include "recovery/usage/Ledger.hpp"

namespace vh::recovery::hooks {

void afterUpstreamWrite(const UpstreamWrite& write) noexcept {
    usage::noteUpstreamWrite(write);
    provider::noteOwnWrite(write);
}

}
