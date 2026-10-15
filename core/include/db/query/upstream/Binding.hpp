#pragma once

#include <cstdint>
#include <string>
#include <vector>

// Vault bindings of an upstream bucket name (the s3 table), across every API key. ops::upstream filters them by bucket
// identity (provider + account), so a binding made through another key of the same account still counts.
namespace vh::db::query::upstream {

struct VaultBinding {
    uint32_t vault_id = 0;
    std::string vault_name;
    bool deleted = false;          // pending deletion (the binding stays reserved until the purge)
    uint32_t api_key_id = 0;
};

class Binding {
public:
    [[nodiscard]] static std::vector<VaultBinding> forBucketName(const std::string& bucket);
};

}
