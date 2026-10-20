#pragma once

#include <array>
#include <memory>
#include <string>
#include <nlohmann/json_fwd.hpp>
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"

namespace vh::vault::model {

struct Capacity {
    uintmax_t capacity{}, logical_size{}, physical_size{}, cache_size{}, free_space{}, file_count{}, directory_count{},
              average_file_size_bytes{}, largest_file_size_bytes{};
    double encryption_overhead{}, decryption_overhead{}, compression_ratio{};
    std::array<std::pair<std::string, uintmax_t>, 10> top_file_extensions_by_size{};

    Capacity() = default;  // empty figures (tests); the daemon measures a vault with the constructor below
    explicit Capacity(unsigned int vaultId);
};

void to_json(nlohmann::json& j, const std::shared_ptr<Capacity>& stats);

}
