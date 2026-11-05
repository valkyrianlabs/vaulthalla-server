#pragma once

#include <memory>

namespace vh::crypto::model { struct Secret; }

namespace vh::db::query::crypto {

struct Secret {
    static void upsertSecret(const std::shared_ptr<vh::crypto::model::Secret>& secret);
    static std::shared_ptr<vh::crypto::model::Secret> getSecret(const std::string& key);
    [[nodiscard]] static bool secretExists(const std::string& key);
    static void deleteSecret(const std::string& key);
};

}
