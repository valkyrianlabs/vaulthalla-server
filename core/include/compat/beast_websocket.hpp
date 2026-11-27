#pragma once

// Boost.Beast's websocket stream, included through this header everywhere in the project.
//
// GCC 14 at -O3 reports -Wmaybe-uninitialized inside Beast's own code: stream::impl_type::write_ping builds a
// detail::frame_header whose `key` is only set for a client (the role that masks), and the inlined prepare_key
// "reads" it on the path GCC cannot rule out. It surfaces in whichever translation unit inlines idle_ping_op, which
// changes with the unity grouping (it failed the v1.27.0 package build and no development build, which is -O0). GCC
// checks the pragma state at the warning's location, which is Beast's text, and only the first inclusion of a header
// counts: including it here, under the pragma, silences the warning for Beast's code alone. Project code keeps
// -Wmaybe-uninitialized. Same approach as compat/gcc_variant.hpp.

#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#if defined(__GNUC__) && !defined(__clang__)
#pragma GCC diagnostic pop
#endif
