#pragma once

#include <stdexcept>
#include <string>
#include <utility>

// Refusals raised by ops:: operations. They are what crosses the shared boundary: the CLI adapter turns them into
// a usage-error result (exit 2), the ws handler templates into an ERROR response. Anything that is not an
// ops::Error is a fault, not a refusal, and keeps propagating as before.
namespace vh::ops {

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// RBAC or a business invariant refused the actor.
struct Denied : Error {
    using Error::Error;
};

struct NotFound : Error {
    using Error::Error;
};

// The request itself is malformed (bad name, out-of-range value).
struct Invalid : Error {
    using Error::Error;
};

// The request collides with existing state (name or id already taken).
struct Conflict : Error {
    using Error::Error;
};

// A refusal with its own stable code where none of the kinds above says enough for the client to act on it (device
// pairing: "no_pairing_window", "rate_limited", "device_unknown"). The ws data.code is `code`; the CLI treats it like
// any other refusal.
struct Refused : Error {
    std::string code;
    Refused(std::string code_, const std::string& text) : Error(text), code(std::move(code_)) {}
};

// The operation needs a person's explicit acceptance first (e.g. an encryption waiver over existing bucket data).
// `code` is stable for clients; what() is the text to show. The caller asks, then repeats the request with the
// acceptance set. Operations never prompt themselves.
struct NeedsConfirmation : Error {
    std::string code;
    NeedsConfirmation(std::string code_, const std::string& text) : Error(text), code(std::move(code_)) {}
};

}
