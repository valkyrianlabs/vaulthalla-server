#pragma once

#include <atomic>
#include <chrono>
#include <cstddef>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// A small request/response HTTP client over libcurl for the upstream control plane (#237): provider admin APIs,
// SQS, Cloudflare's REST API. Unlike the vault data path's ad-hoc handles it always bounds a request: 10 s to
// connect, `timeout` overall, `max_response_bytes` of body (longer bodies are cut and flagged).
//
// Test seam: setTransportForTesting replaces the network for every request (honoured only in paths::testMode), so
// adapters are unit-tested against recorded provider responses.
namespace vh::storage::s3::curl::http {

struct Request {
    std::string method = "GET";
    std::string url;
    std::vector<std::pair<std::string, std::string>> headers;
    std::string body;
    std::chrono::seconds timeout{60};
    std::size_t max_response_bytes = 16 * 1024 * 1024;
};

struct Response {
    bool transport_ok = true;
    std::string transport_error;    // curl's message; never contains request headers
    long status = 0;
    std::string body;
    bool truncated = false;
    std::vector<std::pair<std::string, std::string>> headers;   // as received (names keep their case)

    [[nodiscard]] std::optional<std::string> header(std::string_view name) const;   // case-insensitive
    [[nodiscard]] bool ok() const { return transport_ok && status / 100 == 2; }
};

using Transport = std::function<Response(const Request&)>;

[[nodiscard]] Response perform(const Request& request);

// Cooperative cancellation for long requests (SQS long polls): while a ScopedCancellation is alive on a thread, every
// request that thread performs checks `flag` about every 100 ms and aborts (transport error "cancelled") once it is
// set. Test transports honour it through cancellationRequested().
class ScopedCancellation {
public:
    explicit ScopedCancellation(const std::atomic<bool>* flag);
    ~ScopedCancellation();
    ScopedCancellation(const ScopedCancellation&) = delete;
    ScopedCancellation& operator=(const ScopedCancellation&) = delete;

private:
    const std::atomic<bool>* previous_;
};

[[nodiscard]] bool cancellationRequested();
// A ScopedCancellation is installed on this thread (the data-path curl handles only add their abort hook then).
[[nodiscard]] bool cancellationActive();
// CURLOPT_XFERINFOFUNCTION for handles that don't go through perform(): aborts once cancellation is requested.
int cancellationProgressHook(void* clientp, long long dltotal, long long dlnow, long long ultotal, long long ulnow);

void setTransportForTesting(std::optional<Transport> transport);

}
