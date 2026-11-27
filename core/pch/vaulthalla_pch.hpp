#pragma once

// Precompiled header for -O0 builds (development, tests, PR CI). Stable standard and third-party headers only,
// never project headers. Not used by optimized builds: GCC drops #pragma GCC diagnostic state from precompiled
// headers, which would undo core/include/compat/gcc_variant.hpp, and -Wmaybe-uninitialized only runs when optimizing.

// fmt 9 wraps its headers in #pragma GCC push_options / optimize("Og") / pop_options in unoptimized builds. GCC loses
// that push/pop state across a precompiled header, leaving every file that uses the PCH in an -Og state with
// __OPTIMIZE__ defined (emmintrin.h then switches to its inline-function forms, which fail at -O0). FMT_GCC_PRAGMA
// is fmt's own override for those pragmas; they only made unoptimized fmt code more compact.
//
// libpqxx stays out for the same reason: its headers fence their own uses of deprecated APIs with #pragma GCC
// diagnostic, and through a precompiled header every std::optional parameter would warn from inside libpqxx.
#define FMT_GCC_PRAGMA(arg)

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <variant>
#include <vector>

#include <boost/asio.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include "compat/beast_websocket.hpp"
#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include "compat/fmt_extern.hpp"
