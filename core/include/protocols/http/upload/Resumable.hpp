#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/http/model/preview/Response.hpp"

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <exception>
#include <filesystem>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Resumable uploads (capability http.upload.resumable, docs/reference/transfer-protocol.md §3), on the web listener
// (cookie, or ?share=1 + share_refresh) and the device listener (the device's user):
//
//   POST   /upload/sessions                                   create (201)
//   GET    /upload/sessions/<id>                              status
//   PUT    /upload/sessions/<id>/files/<file_id>?offset=<n>   one part, streamed (Session::handle_resumable_part)
//   POST   /upload/sessions/<id>/finish                       200 complete | 202 finalizing | 409 incomplete
//   DELETE /upload/sessions/<id>                              cancel (204; committed files stay)
//
// Sessions, files and parts are rows (migration 114). Bytes never exist in plaintext at rest: each part is its own
// AES-256-GCM message under the vault key with a fresh IV in the spool (<backing>/.upload-spool/<id>/, outside the
// FUSE mount and every vault tree), so an attempt that fails half-way can never put a second plaintext under the
// file's keystream. A per-file sealing cursor re-encrypts the stored parts in order into the file's own GCM stream
// (the vault file format), on a bounded worker pool; the sealed file is linked into place by Filesystem::createFile's
// sealed writer with the file's precondition (reject, create-only, compare-and-swap). Errors are typed:
// {"error": {"code", "message"}} with the status, never status-by-substring.
namespace vh::protocols::http::upload::resumable {

// Any /upload/sessions route (create, status, part, finish, cancel).
[[nodiscard]] bool isRoute(std::string_view target);
// PUT /upload/sessions/<id>/files/<file_id>: the body is streamed, never buffered.
[[nodiscard]] bool isPartRequest(boost::beast::http::verb method, std::string_view target);

// Buffered requests (Router::route). A part sent here (tests, or a client whose body the session buffered) is handled
// like a streamed one from its in-memory body.
[[nodiscard]] model::preview::Response handle(request&& req);

// The typed JSON answer for a failure while streaming a part's body (an I/O error, a body past its length).
[[nodiscard]] model::preview::Response errorResponse(const request& req, const std::exception& e);

struct PartBegun;

// One accepted part: the range is reserved and the spool attempt file is open, waiting for the body. Destroying it
// unfinished releases the range and removes the attempt (nothing is recorded).
class Part {
public:
    Part();
    Part(Part&& other) noexcept;
    Part& operator=(Part&& other) noexcept;
    Part(const Part&) = delete;
    Part& operator=(const Part&) = delete;
    ~Part();

    // Feeds body bytes (bounded: nothing is kept but the current chunk). Throws past Content-Length or on I/O errors.
    void write(const void* data, std::size_t size);
    // Records the part (durably) and answers; never throws. `receive` is the time spent reading the body.
    [[nodiscard]] model::preview::Response finish(const request& req, std::chrono::nanoseconds receive);

    struct Impl;

private:
    friend PartBegun beginPart(const request& req, std::optional<uint64_t> contentLength);
    std::unique_ptr<Impl> impl_;
};

struct PartBegun {
    std::optional<model::preview::Response> refusal;  // answered instead, before any body byte is read
    Part part;
};

// Authenticates, checks the session, the file and every part rule, and opens the attempt. A refusal closes the
// connection (the body is unread).
[[nodiscard]] PartBegun beginPart(const request& req, std::optional<uint64_t> contentLength);

// The daemon side: state, the sealing/commit worker pool, recovery and expiry.
class Service {
public:
    using Clock = std::function<std::time_t()>;

    // Loads every session from the database, reconciles the spool with it, and resumes what a restart interrupted
    // (sealing and commits). Call once at startup, after the storage engines are up and before requests are served.
    static void recover();
    // Stops the workers (waits for the step each is in). Requests that need them start them again.
    static void shutdown();
    // Removes sessions past their idle TTL or maximum age (rows and spool), and spool directories without a row.
    // Returns how many sessions went. The DB janitor calls it.
    static std::size_t sweepExpired();

    // The spool root: <backing>/.upload-spool.
    [[nodiscard]] static std::filesystem::path spoolRoot();

    // Tests: drop every in-memory session and stop the workers, as a restart would (rows and spool stay).
    static void forgetForTesting();
    // Tests: wall clock used for activity and expiry.
    static void setClockForTesting(Clock clock);
    static void resetClockForTesting();
    // Tests: how long finish waits for commits before answering 202 (default 5 s).
    static void setFinishWaitForTesting(std::chrono::milliseconds wait);
    // Tests: blocks until no file is sealing or committing (or the timeout passes); true when idle.
    [[nodiscard]] static bool waitIdleForTesting(std::chrono::milliseconds timeout);
    // Tests: hold every commit (sealing still runs) until released.
    static void holdCommitsForTesting(bool hold);
};

}
