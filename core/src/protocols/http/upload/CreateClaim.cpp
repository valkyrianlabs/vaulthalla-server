#include "protocols/http/upload/CreateClaim.hpp"

#include <mutex>
#include <set>
#include <utility>

namespace vh::protocols::http::upload {

namespace {

[[nodiscard]] std::mutex& createClaimsMutex() {
    static std::mutex m;
    return m;
}

[[nodiscard]] std::set<std::string>& createClaims() {
    static std::set<std::string> s;
    return s;
}

}

CreateClaim::CreateClaim(std::string key) : key_(std::move(key)) {
    std::scoped_lock lock(createClaimsMutex());
    held_ = createClaims().insert(key_).second;
}

CreateClaim::~CreateClaim() {
    if (!held_) return;
    std::scoped_lock lock(createClaimsMutex());
    createClaims().erase(key_);
}

}
