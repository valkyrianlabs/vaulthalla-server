#pragma once

#include "types/Type.hpp"

#include <unordered_map>
#include <string>
#include <functional>
#include <memory>

namespace vh::test::integration {
    struct TestCase;

    namespace entity { class Registrar; }
    namespace cli { struct Context; }

    namespace cmd {
        using singleArgFunc = std::function<EntityResult(const std::shared_ptr<void> &entity)>;
        using dualArgFunc = std::function<EntityResult(const std::shared_ptr<void> &entity,
                                                       const std::shared_ptr<void> &target)>;
        using tripleArgFunc = std::function<EntityResult(const std::shared_ptr<void> &entity,
                                                         const std::shared_ptr<void> &target,
                                                         const std::shared_ptr<void> &subject)>;
        using tripleArgWithSubjTypeFunc = std::function<EntityResult(const std::shared_ptr<void> &entity,
                                                                     const std::shared_ptr<void> &target,
                                                                     const EntityType &subjectType,
                                                                     const std::shared_ptr<void> &subject)>;

        using CallType = std::variant<singleArgFunc, dualArgFunc, tripleArgFunc, tripleArgWithSubjTypeFunc>;

        class Router {
        public:
            explicit Router(const std::shared_ptr<cli::Context> &ctx);

            void registerRoute(const std::string &path, const CallType &handler);

            std::shared_ptr<TestCase> route(const std::shared_ptr<TestCase> &test) const;

            void dispatch(const std::shared_ptr<TestCase> &test) const;

            std::vector<std::shared_ptr<TestCase> > route(const std::vector<std::shared_ptr<TestCase>> &tests) const;

        private:
            std::shared_ptr<entity::Registrar> registrar_;
            std::pmr::unordered_map<std::string, CallType> routes_{};

            void registerAll();
        };
    }
}
