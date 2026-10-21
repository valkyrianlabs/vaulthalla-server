#pragma once

#include <string>

namespace vh::log {

// Attributes audit lines to where a request came from without touching every call site: while an AuditOrigin is
// alive on a thread, each audit-log line that thread writes ends with " [via <origin>]" (the ws router sets
// "device <id>" around a paired device's command; the actor named in the line stays the device's user).
class AuditOrigin {
public:
    explicit AuditOrigin(std::string origin);
    ~AuditOrigin();
    AuditOrigin(const AuditOrigin&) = delete;
    AuditOrigin& operator=(const AuditOrigin&) = delete;

    // The innermost origin on this thread, or null.
    [[nodiscard]] static const std::string* current() noexcept;

private:
    std::string origin_;
    const AuditOrigin* previous_;
};

}
