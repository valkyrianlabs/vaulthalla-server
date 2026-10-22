// vh_live_bucket: creates and deletes the fixed test buckets of tooling (tools/smoke) through the guarded live-test
// helper (live_bucket.hpp). Never installed; built with the unit tests.
//
//   vh_live_bucket create vh-test-gateway-smoke   a leftover of a crashed run is emptied and deleted first
//   vh_live_bucket delete vh-test-gateway-smoke   empties (objects, unfinished uploads), deletes, checks it is gone
//
// Only names in fixedTestBuckets(); anything else is refused before a request is made. Credential: the R2 admin key
// VH_R2_ADMIN_* from the environment (never printed). Exit 0 done, 1 provider failure, 2 usage / refused / no key.

#include "live_bucket.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"

#include <paths.h>

#include <iostream>
#include <string>

namespace live = vh::test_support::live;

int main(const int argc, char** argv) {
    if (argc != 3 || (std::string(argv[1]) != "create" && std::string(argv[1]) != "delete")) {
        std::cerr << "usage: vh_live_bucket create|delete <fixed test bucket>\n";
        return 2;
    }
    const std::string command = argv[1], name = argv[2];
    if (!live::isFixedTestBucket(name)) {
        std::cerr << "vh_live_bucket: refusing '" << name << "': not a fixed test bucket of this tool\n";
        return 2;
    }
    const auto target = live::target();
    if (!target.configured()) {
        std::cerr << "vh_live_bucket: missing";
        for (const auto& m : target.missing) std::cerr << ' ' << m;
        std::cerr << '\n';
        return 2;
    }
    try {
        vh::paths::enableTestMode();
        const auto config = live::env("VH_PATH_TO_CONFIG");
        vh::paths::configPath = config.empty() ? std::string(VH_TOOL_DEFAULT_CONFIG) : config;
        vh::config::Registry::init();
        vh::log::Registry::init();

        const auto key = live::apiKey(target);
        const auto admin = live::guardedAdmin(key);
        if (command == "create") {
            if (admin->headBucket(name)) {
                std::cout << "[live] " << name << " is a leftover of an earlier run: emptying and deleting it" << std::endl;
                live::emptyAndDeleteBucket(*admin, key, name);
            }
            admin->createBucket({.name = name, .region = std::nullopt});
            if (!admin->headBucket(name)) throw std::runtime_error("HeadBucket can't see the new bucket");
            std::cout << "[live] created " << name << std::endl;
        } else {
            live::emptyAndDeleteBucket(*admin, key, name);
            std::cout << "[live] deleted " << name << " (HeadBucket: gone)" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "vh_live_bucket " << command << ' ' << name << ": " << e.what() << '\n';
        return 1;
    }
    return 0;
}
