#pragma once

// Forward declarations for file recovery. Declarations only: include the defining header to use a type.

namespace vh::recovery {
    enum class Mode;
    enum class Backend;
    enum class PointKind;
    enum class ItemAction;
    struct RecoveryId;
    struct Money;
    struct EncryptionContext;
    struct Retention;
    struct RecoveryPoint;
    struct PlanItem;
    struct RequestEstimate;
    struct Plan;
    struct ItemOutcome;
    struct RestoreResult;
    struct ProviderRetention;
    struct LocalVersioningPolicy;
    struct ProviderVersioningState;
    struct Backlog;
    struct StoreUsage;
    struct Status;
    struct CostFigure;
    struct AccumulationPoint;
    struct RetentionScenario;
    struct Assumption;
    struct CostReport;
    struct Disclosure;
}

namespace vh::recovery::store {
    struct VaultRef;
    struct GenerationMeta;
    class Capture;
    struct BlobHandle;
    struct SweepReport;
}

namespace vh::db::query::recovery {
    struct PolicyRow;
    struct BlobRow;
    struct SnapshotRow;
    struct GenerationRow;
    struct ObjectVersionRow;
    struct UsageCounters;
    struct UsageDay;
    struct PlanRow;
}
