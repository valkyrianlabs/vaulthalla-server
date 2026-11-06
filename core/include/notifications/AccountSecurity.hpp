#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

// Account-security notices (#360; MFA design note sections 7.1-7.4): a recovery-code sign-in, an MFA reset, a factor
// enrolled, removed or suspended, new recovery codes, repeated second-factor failures, a session signed out after
// failed step-ups, and the MFA policy weakened. Each goes to operator_emails.recipients.security and, when the account
// has an email address, to the account itself, through the operator email queue (OperatorEmailService). Delivery
// needs email configured; nothing here blocks or throws, and a full queue drops the notice (logged). The audit trail,
// not email, is the record: every notice has its audit event.
namespace vh::notifications::account {

struct Notice {
    std::string event;    // stable key, e.g. "mfa.recovery_signin"
    std::string title;    // the subject: "Recovery code used"
    std::string summary;  // one sentence
    std::optional<uint32_t> user_id{};  // the account concerned
    std::vector<std::pair<std::string, std::string>> facts{};  // ids, counts, times; never codes or secrets
    std::optional<std::string> advice{};
    std::string severity{"warning"};
    bool to_security{true};  // operator_emails.recipients.security
    bool to_user{true};      // the account's own address
};

void send(const Notice& notice) noexcept;

// Tests: notices go to `sink` instead of the queue (null restores the queue).
using Sink = std::function<void(const Notice&)>;
void setSinkForTesting(Sink sink);

}
