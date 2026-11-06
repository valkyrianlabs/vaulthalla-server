#include "auth/mfa/Pending.hpp"

#include <algorithm>

namespace vh::auth::mfa {

std::string_view refusalCode(const PendingKind kind) noexcept {
    return kind == PendingKind::Enrollment ? "mfa_enrollment_required" : "mfa_required";
}

bool pendingAllows(const PendingKind kind, const std::string_view command) noexcept {
    if (std::ranges::find(kPendingCommands, command) != kPendingCommands.end()) return true;
    return kind == PendingKind::Enrollment &&
           std::ranges::find(kPendingEnrollmentCommands, command) != kPendingEnrollmentCommands.end();
}

std::optional<Pending> SessionState::pending() const {
    std::lock_guard lock(mutex_);
    return pending_;
}

std::optional<PendingKind> SessionState::pendingKind() const {
    std::lock_guard lock(mutex_);
    return pending_ ? std::optional<PendingKind>(pending_->kind) : std::nullopt;
}

void SessionState::setPending(Pending pending) {
    std::lock_guard lock(mutex_);
    pending_ = std::move(pending);
    registration_.reset();
}

void SessionState::clearPending() {
    std::lock_guard lock(mutex_);
    pending_.reset();
    registration_.reset();
}

void SessionState::setRegistration(Registration registration) {
    std::lock_guard lock(mutex_);
    registration_ = std::move(registration);
}

std::optional<Registration> SessionState::takeRegistration(const std::string_view id) {
    std::lock_guard lock(mutex_);
    if (!registration_ || registration_->id != id) return std::nullopt;
    auto out = std::move(registration_);
    registration_.reset();
    if (std::chrono::steady_clock::now() >= out->expires) return std::nullopt;
    return out;
}

void SessionState::clear() {
    std::lock_guard lock(mutex_);
    pending_.reset();
    registration_.reset();
}

}
