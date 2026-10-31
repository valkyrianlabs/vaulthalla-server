#include "protocols/device/Transfer.hpp"

#include "WsProtocol.hpp"
#include "protocols/device/Endpoints.hpp"
#include "storage/PlaintextReader.hpp"

#include <nlohmann/json.hpp>

#include <chrono>
#include <charconv>
#include <cstring>
#include <map>
#include <mutex>

namespace vh::protocols::device::transfer {

namespace {

std::mutex& slotsMutex() {
    static std::mutex m;
    return m;
}

std::map<uint32_t, unsigned>& slots() {
    static std::map<uint32_t, unsigned> m;
    return m;
}

struct SlotToken {
    explicit SlotToken(const uint32_t id) : deviceRowId(id) {}
    SlotToken(const SlotToken&) = delete;
    SlotToken& operator=(const SlotToken&) = delete;
    ~SlotToken() {
        std::scoped_lock lock(slotsMutex());
        if (const auto it = slots().find(deviceRowId); it != slots().end() && --it->second == 0) slots().erase(it);
    }
    uint32_t deviceRowId;
};

constexpr uint64_t splitmix64(uint64_t x) noexcept {
    x += 0x9E3779B97F4A7C15ull;
    x = (x ^ (x >> 30)) * 0xBF58476D1CE4E5B9ull;
    x = (x ^ (x >> 27)) * 0x94D049BB133111EBull;
    return x ^ (x >> 31);
}

// Word i of the stream is splitmix64(seed + i): any offset is computable, so the reader is stateless.
class RandomSource final : public storage::PlaintextReader {
public:
    RandomSource(const uint64_t bytes, const uint64_t seed) : seed_(seed) { generation_.size = bytes; }

    [[nodiscard]] uint64_t size() const override { return generation_.size; }
    [[nodiscard]] const storage::Generation& generation() const override { return generation_; }

    std::size_t read(const uint64_t offset, const std::span<uint8_t> out) override {
        if (offset >= generation_.size) return 0;
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(out.size(), generation_.size - offset));
        std::size_t done = 0;
        uint64_t word = offset / 8;
        auto skip = static_cast<std::size_t>(offset % 8);
        while (done < n) {
            const uint64_t value = splitmix64(seed_ + word++);
            uint8_t bytes[8];
            std::memcpy(bytes, &value, sizeof bytes);
            const auto take = std::min<std::size_t>(8 - skip, n - done);
            std::memcpy(out.data() + done, bytes + skip, take);
            done += take;
            skip = 0;
        }
        return n;
    }

private:
    uint64_t seed_;
    storage::Generation generation_{};
};

}

bool isTarget(const std::string_view target) noexcept {
    constexpr std::string_view prefix = "/transfer";
    return target.starts_with(prefix) &&
           (target.size() == prefix.size() || target[prefix.size()] == '/' || target[prefix.size()] == '?');
}

Slot acquire(const uint32_t deviceRowId) {
    std::scoped_lock lock(slotsMutex());
    auto& held = slots()[deviceRowId];
    if (held >= kMaxConcurrentPerDevice) return nullptr;
    ++held;
    return std::make_shared<SlotToken>(deviceRowId);
}

unsigned inFlightForTesting(const uint32_t deviceRowId) {
    std::scoped_lock lock(slotsMutex());
    const auto it = slots().find(deviceRowId);
    return it == slots().end() ? 0 : it->second;
}

std::string probeJson() {
    const auto now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    return nlohmann::json{{"node_id", endpoints::nodeId()},
                          {"server_time_ms", static_cast<int64_t>(now)},
                          {"capabilities", contract::capabilityNames()}}.dump();
}

std::optional<uint64_t> sourceBytes(const std::string_view target) {
    const auto q = target.find('?');
    if (q == std::string_view::npos) return std::nullopt;
    std::string_view query = target.substr(q + 1);
    while (!query.empty()) {
        const auto amp = query.find('&');
        const auto pair = query.substr(0, amp);
        query = amp == std::string_view::npos ? std::string_view{} : query.substr(amp + 1);
        if (!pair.starts_with("bytes=")) continue;
        const auto value = pair.substr(6);
        uint64_t n = 0;
        const auto [end, ec] = std::from_chars(value.data(), value.data() + value.size(), n);
        if (ec != std::errc{} || end != value.data() + value.size() || value.empty() || n > kMaxBytes)
            return std::nullopt;
        return n;
    }
    return std::nullopt;
}

std::shared_ptr<storage::PlaintextReader> randomSource(const uint64_t bytes, const uint64_t seed) {
    return std::make_shared<RandomSource>(bytes, seed);
}

}
