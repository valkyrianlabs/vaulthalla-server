#include "storage/s3/curl/Http.hpp"
#include "storage/s3/curl/helpers.hpp"

#include <curl/curl.h>
#include <paths.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>

namespace vh::storage::s3::curl::http {

namespace {

std::mutex& transportMutex() {
    static std::mutex m;
    return m;
}

std::optional<Transport>& testTransport() {
    static std::optional<Transport> t;
    return t;
}

bool iequals(const std::string_view a, const std::string_view b) {
    return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](const char x, const char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
    });
}

struct Sink {
    std::string* body;
    std::size_t limit;
    bool truncated = false;
};

size_t onBody(const char* ptr, const size_t size, const size_t nmemb, void* userdata) {
    auto* sink = static_cast<Sink*>(userdata);
    const auto n = size * nmemb;
    if (sink->body->size() + n > sink->limit) {
        sink->body->append(ptr, sink->limit - sink->body->size());
        sink->truncated = true;
        return 0;   // aborts the transfer (CURLE_WRITE_ERROR)
    }
    sink->body->append(ptr, n);
    return n;
}

size_t onHeader(const char* ptr, const size_t size, const size_t nmemb, void* userdata) {
    auto* headers = static_cast<std::vector<std::pair<std::string, std::string>>*>(userdata);
    const auto n = size * nmemb;
    std::string line(ptr, n);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    if (line.starts_with("HTTP/")) {
        headers->clear();   // a redirect or 100-continue: keep only the final response's headers
        return n;
    }
    if (const auto colon = line.find(':'); colon != std::string::npos) {
        auto name = line.substr(0, colon);
        auto value = line.substr(colon + 1);
        trimInPlace(name);
        trimInPlace(value);
        headers->emplace_back(std::move(name), std::move(value));
    }
    return n;
}

thread_local const std::atomic<bool>* cancelFlag = nullptr;

int onProgress(void*, curl_off_t, curl_off_t, curl_off_t, curl_off_t) {
    return cancellationRequested() ? 1 : 0;   // non-zero aborts (CURLE_ABORTED_BY_CALLBACK)
}

struct CurlDeleter {
    void operator()(CURL* h) const { curl_easy_cleanup(h); }
};

struct SlistDeleter {
    void operator()(curl_slist* l) const { curl_slist_free_all(l); }
};

}

std::optional<std::string> Response::header(const std::string_view name) const {
    for (const auto& [k, v] : headers)
        if (iequals(k, name)) return v;
    return std::nullopt;
}

ScopedCancellation::ScopedCancellation(const std::atomic<bool>* flag) : previous_(cancelFlag) { cancelFlag = flag; }

ScopedCancellation::~ScopedCancellation() { cancelFlag = previous_; }

bool cancellationRequested() { return cancelFlag && cancelFlag->load(std::memory_order_acquire); }

bool cancellationActive() { return cancelFlag != nullptr; }

int cancellationProgressHook(void*, long long, long long, long long, long long) { return cancellationRequested() ? 1 : 0; }

void setTransportForTesting(std::optional<Transport> transport) {
    std::scoped_lock lock(transportMutex());
    testTransport() = std::move(transport);
}

Response perform(const Request& request) {
    if (paths::testMode) {
        std::optional<Transport> transport;
        {
            std::scoped_lock lock(transportMutex());
            transport = testTransport();
        }
        if (transport) return (*transport)(request);
    }

    ensureCurlGlobalInit();
    Response out;
    const std::unique_ptr<CURL, CurlDeleter> handle(curl_easy_init());
    if (!handle) {
        out.transport_ok = false;
        out.transport_error = "curl_easy_init failed";
        return out;
    }
    auto* h = handle.get();

    curl_slist* raw = nullptr;
    for (const auto& [name, value] : request.headers) raw = curl_slist_append(raw, (name + ": " + value).c_str());
    raw = curl_slist_append(raw, "Expect:");   // no 100-continue round trip
    const std::unique_ptr<curl_slist, SlistDeleter> headerList(raw);

    Sink sink{&out.body, request.max_response_bytes};
    char errorBuffer[CURL_ERROR_SIZE] = {};

    curl_easy_setopt(h, CURLOPT_URL, request.url.c_str());
    curl_easy_setopt(h, CURLOPT_NOSIGNAL, 1L);
    if (cancelFlag) {
        curl_easy_setopt(h, CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(h, CURLOPT_XFERINFOFUNCTION, onProgress);
    } else {
        curl_easy_setopt(h, CURLOPT_NOPROGRESS, 1L);
    }
    curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 0L);   // a redirect is an answer (S3 region hints), not a hop
    curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(h, CURLOPT_TIMEOUT, static_cast<long>(std::max<long long>(1, request.timeout.count())));
    curl_easy_setopt(h, CURLOPT_HTTPHEADER, headerList.get());
    curl_easy_setopt(h, CURLOPT_WRITEFUNCTION, onBody);
    curl_easy_setopt(h, CURLOPT_WRITEDATA, &sink);
    curl_easy_setopt(h, CURLOPT_HEADERFUNCTION, onHeader);
    curl_easy_setopt(h, CURLOPT_HEADERDATA, &out.headers);
    curl_easy_setopt(h, CURLOPT_ERRORBUFFER, errorBuffer);

    if (request.method == "HEAD") {
        curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
    } else if (request.method == "GET") {
        curl_easy_setopt(h, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(h, CURLOPT_CUSTOMREQUEST, request.method.c_str());
        curl_easy_setopt(h, CURLOPT_POSTFIELDSIZE_LARGE, static_cast<curl_off_t>(request.body.size()));
        curl_easy_setopt(h, CURLOPT_POSTFIELDS, request.body.data());
    }

    const auto rc = curl_easy_perform(h);
    curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &out.status);
    out.truncated = sink.truncated;
    if (rc == CURLE_ABORTED_BY_CALLBACK) {
        out.transport_ok = false;
        out.transport_error = "cancelled";
    } else if (rc != CURLE_OK && !(rc == CURLE_WRITE_ERROR && sink.truncated)) {
        out.transport_ok = false;
        out.transport_error = errorBuffer[0] ? std::string(errorBuffer) : std::string(curl_easy_strerror(rc));
    }
    return out;
}

}
