#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/http/model/preview/Response.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

// PUT /upload/content?vault_id=&path=: one file, created or replaced conditionally, its body streamed (#258).
//
//   If-Match: <content_version>   replace the file only while it is still that generation (the strong ETag
//                                 /download/content serves; Overwrite on the file). Stale, or the file is open through
//                                 the FUSE mount: 412 with the current ETag.
//   If-None-Match: *              create it only if nothing is there (Write on the path; missing parent folders are
//                                 created, as for an upload). Something there: 412 (a file, with its ETag) or 409.
//
// Exactly one of the two is required (428 otherwise), and a Content-Length (411; at most 8 GiB, as /upload/session).
// Everything is refused before a body byte is read. The body goes to the upload staging seam
// (protocols/http/upload/Staging.hpp) in bounded chunks and is committed through Filesystem::createFile with
// source_path, the same streaming seal and compare-and-swap `vh fs put` and text saves use; access is checked again
// with the caller as they are at commit. 201 (created) or 200 (replaced) answers {"created", "entry"} with the file's
// entry JSON (content_version, metadata_version) and the new ETag. Human and device callers only; shares are refused.
namespace vh::protocols::http::upload::content {

[[nodiscard]] bool isRequest(boost::beast::http::verb method, std::string_view target);

struct Begun;

// One accepted request: the open staging file, waiting for its body. Destroying it unfinished removes the staging.
class Upload {
public:
    Upload();
    Upload(Upload&& other) noexcept;
    Upload& operator=(Upload&& other) noexcept;
    Upload(const Upload&) = delete;
    Upload& operator=(const Upload&) = delete;
    ~Upload();

    // Appends body bytes. Throws past the declared length or on a write error.
    void write(const void* data, std::size_t size);

    // Seals and commits the staged body; never throws (every refusal is a response).
    [[nodiscard]] model::preview::Response commit(const request& req);

private:
    friend Begun begin(const request& req, std::optional<uint64_t> contentLength);
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

struct Begun {
    std::optional<model::preview::Response> refusal;  // answered instead, before any body byte is read
    Upload upload;
};

// Authenticates, authorizes, checks the precondition and the space, and opens the staging file.
[[nodiscard]] Begun begin(const request& req, std::optional<uint64_t> contentLength);

// The whole-body form (Router::route; the HTTP session streams instead): begin with the request's Content-Length
// header, write the body, commit.
[[nodiscard]] model::preview::Response handle(request&& req);

}
