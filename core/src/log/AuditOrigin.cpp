#include "log/AuditOrigin.hpp"

#include <utility>

namespace vh::log {

namespace {
thread_local const AuditOrigin* innermost = nullptr;
}

AuditOrigin::AuditOrigin(std::string origin) : origin_(std::move(origin)), previous_(innermost) { innermost = this; }

AuditOrigin::~AuditOrigin() { innermost = previous_; }

const std::string* AuditOrigin::current() noexcept { return innermost ? &innermost->origin_ : nullptr; }

}
