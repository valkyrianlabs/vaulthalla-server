#pragma once

// What the HTTP upload suites (test_http_upload_content.cpp, test_http_upload_resumable.cpp) share: reading a routed
// Response, deterministic content checked against a stored file, and the process's resident memory while a large
// transfer runs.

#include "fs/model/File.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/model/preview/Response.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"

#include <nlohmann/json.hpp>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <fstream>
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace vh::test::http_upload {

inline boost::beast::http::status statusOf(const protocols::http::model::preview::Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

// `name` is a boost::beast::http::field or a header name.
template <class Name>
std::string headerOf(const protocols::http::model::preview::Response& r, const Name& name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

inline nlohmann::json jsonOf(const protocols::http::model::preview::Response& r) {
    const auto* s = std::get_if<protocols::http::string_response>(&r);
    return s && !s->body().empty() ? nlohmann::json::parse(s->body()) : nlohmann::json{};
}

// Deterministic content, generated a chunk at a time so no test holds a large file in memory.
inline uint8_t patternByte(const uint64_t offset, const uint8_t seed = 0) {
    return static_cast<uint8_t>(((offset * 131u + (offset >> 13)) + seed) & 0xff);
}

// The plaintext of a stored file compared with the pattern, read a window at a time, then authenticated.
inline bool matchesPattern(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& file,
                           const uint64_t size, const uint8_t seed = 0) {
    auto reader = engine->openPlaintextReader(file);
    if (reader->size() != size) return false;
    std::vector<uint8_t> window(1 << 20);
    for (uint64_t off = 0; off < size;) {
        const auto n = reader->read(off, std::span<uint8_t>(window.data(), window.size()));
        if (n == 0) return false;
        for (std::size_t i = 0; i < n; ++i)
            if (window[i] != patternByte(off + i, seed)) return false;
        off += n;
    }
    reader->requireAuthenticated();
    return true;
}

// The process's resident set now (not a high-water mark: earlier suites in this binary may have peaked higher).
inline uint64_t residentBytes() {
#if defined(__APPLE__)
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS)
        return 0;
    return info.resident_size;
#else
    std::ifstream statm("/proc/self/statm");
    uint64_t size = 0, resident = 0;
    statm >> size >> resident;
    return resident * static_cast<uint64_t>(::sysconf(_SC_PAGESIZE));
#endif
}

// Samples the resident set every few milliseconds while it lives; finish() is the most it rose above the value at
// construction.
class RssSampler {
public:
    RssSampler() : base_(residentBytes()), peak_(base_) {
        thread_ = std::thread([this] {
            while (!stop_.load()) {
                const auto now = residentBytes();
                if (now > peak_.load()) peak_.store(now);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });
    }
    ~RssSampler() { finish(); }
    RssSampler(const RssSampler&) = delete;
    RssSampler& operator=(const RssSampler&) = delete;

    uint64_t finish() {
        if (thread_.joinable()) {
            stop_.store(true);
            thread_.join();
        }
        const auto now = residentBytes();
        if (now > peak_.load()) peak_.store(now);
        return peak_.load() > base_ ? peak_.load() - base_ : 0;
    }

private:
    uint64_t base_;
    std::atomic<uint64_t> peak_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

}
