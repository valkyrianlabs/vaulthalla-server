#pragma once

#include "health/Findings.hpp"

#include <vector>

// health_finding_state (migration 172): the acknowledged and silenced marks on health finding classes. Trusted:
// ops::health authorizes; health::Findings applies the rules.
namespace vh::db::query::health {

struct FindingState {
    [[nodiscard]] static std::vector<::vh::health::Mark> list();
    // Sets the mark of (class, subject), replacing any other; returns it as stored.
    static ::vh::health::Mark put(const ::vh::health::Mark& mark);
    // True when a mark was there.
    static bool remove(const std::string& cls, const std::string& subject);
    static void remove(const std::vector<::vh::health::Key>& keys);
};

}
