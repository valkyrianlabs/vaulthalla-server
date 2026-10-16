#pragma once

#include "helpers.hpp"
#include "storage/s3/curl/Http.hpp"

#include <curl/curl.h>
#include <stdexcept>
#include <string>
#include <vector>

class CurlEasy {
public:
    CurlEasy() : h_(curl_easy_init()) {
        if (!h_) throw std::runtime_error("curl_easy_init failed");
        curl_easy_setopt(h_, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(h_, CURLOPT_FOLLOWLOCATION, 1L);
        // …put **every default** you repeat here once…
    }
    ~CurlEasy() { curl_easy_cleanup(h_); }
    explicit operator CURL*() const       { return h_; }
    explicit operator const CURL*() const { return h_; }

private:
    CURL* h_;
};

class SList {
public:
    void add(std::string s) {
        store_.push_back(std::move(s));
        head_ = curl_slist_append(head_, store_.back().c_str());
    }
    ~SList() { curl_slist_free_all(head_); }
    [[nodiscard]] curl_slist* get() const { return head_; }

private:
    std::vector<std::string> store_;
    curl_slist*              head_ = nullptr;
};

struct HttpResponse {
    CURLcode curl  = CURLE_OK;
    long     http  = 0;
    std::string body;
    std::string hdr;
    bool ok() const { return curl == CURLE_OK && http / 100 == 2; }
};

template <class SetupFn>
static HttpResponse performCurl(SetupFn&& setup) {
    const CurlEasy h;                    // RAII handle
    std::string bodyBuf, hdrBuf;

    curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_WRITEFUNCTION, +[](char* p,size_t s,size_t n,void* ud){
        auto* buf = static_cast<std::string*>(ud);
        buf->append(p, s * n);
        return s * n;
    });
    curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_WRITEDATA,  &bodyBuf);
    curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_HEADERFUNCTION, vh::storage::s3::curl::writeToString);
    curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_HEADERDATA, &hdrBuf);

    setup(static_cast<CURL*>(h));                      // caller-specific tweaks

    // A thread that installed an http::ScopedCancellation (the upstream event service) gets its S3 requests aborted on
    // shutdown too; every other caller is unchanged.
    if (vh::storage::s3::curl::http::cancellationActive()) {
        curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_NOPROGRESS, 0L);
        curl_easy_setopt(static_cast<CURL*>(h), CURLOPT_XFERINFOFUNCTION,
                         +[](void* p, curl_off_t dt, curl_off_t dn, curl_off_t ut, curl_off_t un) -> int {
                             return vh::storage::s3::curl::http::cancellationProgressHook(p, dt, dn, ut, un);
                         });
    }

    HttpResponse r;
    r.curl = curl_easy_perform(static_cast<CURL*>(h));
    curl_easy_getinfo(static_cast<CURL*>(h), CURLINFO_RESPONSE_CODE, &r.http);
    r.body.swap(bodyBuf);
    r.hdr.swap(hdrBuf);
    return r;
}

