#include "sync/manifest/WriteCapability.hpp"

namespace vh::sync::manifest {

std::string_view to_string(const WriteCapability capability) {
    switch (capability) {
    case WriteCapability::Unknown: return "unknown";
    case WriteCapability::Conditional: return "conditional";
    case WriteCapability::VersionLog: return "version_log";
    case WriteCapability::Insufficient: return "insufficient";
    }
    return "unknown";
}

std::optional<WriteCapability> publishModeFromString(const std::string_view text) {
    if (text == "conditional") return WriteCapability::Conditional;
    if (text == "version_log") return WriteCapability::VersionLog;
    return std::nullopt;
}

bool sendsPreconditions(const WriteCapability capability) noexcept {
    return capability == WriteCapability::Conditional || capability == WriteCapability::Unknown;
}

}
