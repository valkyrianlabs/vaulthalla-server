#pragma once

#include "seed/Stream.hpp"

#include <cstdint>
#include <limits>
#include <stdexcept>

namespace vh::test::integration::randomizer {
    // Draws from the seeded stream of the running test (seed/Stream.hpp), never from entropy.
    inline std::size_t generateRandomIndex(const std::size_t count) {
        if (count == 0) throw std::runtime_error("generateRandomIndex(): count must be > 0");
        return seed::current().uniform_int<std::size_t>(0, count - 1);
    }

    inline bool coin(const uintmax_t outOf = 10000, const uintmax_t p = 5000) {
        return generateRandomIndex(outOf) < p;
    }

    struct Permission {
        template<typename MaskT, typename EnumT>
        static MaskT random() {
            const MaskT allMask = static_cast<MaskT>(EnumT::All);
            if (allMask == 0) throw std::runtime_error("PermRandomizer: enum defines no permission bits");

            MaskT mask = 0;
            for (std::size_t i = 0; i < std::numeric_limits<MaskT>::digits; ++i)
                if ((allMask & (MaskT{1} << i)) && coin())
                    mask |= (MaskT{1} << i);

            if (mask == 0) {
                std::size_t chosen = 0;
                do chosen = generateRandomIndex(std::numeric_limits<MaskT>::digits);
                while ((allMask & (MaskT{1} << chosen)) == 0);

                mask |= (MaskT{1} << chosen);
            }

            return mask;
        }
    };
}
