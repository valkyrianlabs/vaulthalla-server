// libFuzzer entry point for the VHF1 reader (spec 02 §7 "Fuzz"); the iteration itself is vhf1_fuzz_body.hpp.
// Build and run: see the fuzz target in core/meson.build (-Dfuzz=true, clang).
#include "vhf1_fuzz_body.hpp"

#include <cstddef>
#include <cstdint>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, const std::size_t size) {
    vh::crypto::vhf1::fuzz::runOne({data, size});
    return 0;
}
