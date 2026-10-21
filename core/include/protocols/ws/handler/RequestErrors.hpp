#pragma once

#include "ops/Error.hpp"

#include <nlohmann/json.hpp>

#include <stdexcept>

namespace vh::protocols::ws::handler {

// Call from a catch block (e.g. a handler's function-try-block): rethrows the exception being handled, as
// ops::Invalid with the same message when it is a malformed request (std::invalid_argument, or a JSON access error
// on the payload: a missing member or one of the wrong type), so the ws answer carries data.code "invalid". An
// ops::Error and every other exception propagate unchanged.
[[noreturn]] inline void rethrowRequestErrorsAsInvalid() {
    try {
        throw;
    } catch (const ops::Error&) {
        throw;
    } catch (const std::invalid_argument& e) {
        throw ops::Invalid(e.what());
    } catch (const nlohmann::json::exception& e) {
        throw ops::Invalid(e.what());
    }
}

}
