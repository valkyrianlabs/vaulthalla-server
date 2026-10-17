// TEMPORARY: deleted at integration. Link stubs for the ops::recovery functions the surfaces (CLI, ws) call while
// the operations themselves are built on other branches (ops/RecoveryPoints.cpp, ops/RecoveryPolicy.cpp). Every one
// refuses with ops::Invalid, so both surfaces answer the same way until the real operations replace this file.

#include "ops/Error.hpp"
#include "ops/Recovery.hpp"

namespace vh::ops::recovery {

namespace {

[[noreturn]] void recoveryStubRefuse() { throw Invalid("recovery: not implemented in this build"); }

}

Status status(const Actor&, uint32_t, bool) { recoveryStubRefuse(); }

Status update(const Actor&, uint32_t, const Update&) { recoveryStubRefuse(); }

Disclosure versioningDisclosure(const Actor&, uint32_t, const std::optional<ProviderRetention>&) { recoveryStubRefuse(); }

Status suspendVersioning(const Actor&, uint32_t, bool) { recoveryStubRefuse(); }

CostReport costs(const Actor&, uint32_t) { recoveryStubRefuse(); }

std::vector<RecoveryPoint> list(const Actor&, uint32_t, const ListQuery&) { recoveryStubRefuse(); }

PointDetail inspect(const Actor&, const std::string&) { recoveryStubRefuse(); }


void deletePoint(const Actor&, const std::string&, bool) { recoveryStubRefuse(); }

Plan plan(const Actor&, const PlanRequest&) { recoveryStubRefuse(); }

Plan getPlan(const Actor&, uint64_t) { recoveryStubRefuse(); }

RestoreResult restore(const Actor&, const RestoreRequest&) { recoveryStubRefuse(); }

}
