#pragma once

namespace vh::protocols::shell::commands {

// Removes `vh fs put` staging files an earlier daemon left behind (they hold plaintext). Called when the CLI server
// starts, before any transfer can be in progress.
void sweepFsStaging() noexcept;

}
