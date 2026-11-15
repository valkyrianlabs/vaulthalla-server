// The applier's pure merge (design/sync/manifest-applier.md, work item 2; sync/manifest/Reconcile.hpp):
//   ManifestReconcile          one test per row of the design's "Conflict rules", "Identity and local state" and
//                              "What it applies, in order" that the pure function owns
//   ManifestReconcileProperty  seeded random concurrent operations on two replicas of one vault: both replicas end on
//                              one tree (and, for changes that don't overlap, on the same tree whichever publishes
//                              first), applying a head twice changes nothing, the plan takes ours to the result, and no
//                              tree is ever broken. A failure prints its seed; VH_RECONCILE_SEED=<n> reruns one.
#include "sync/manifest/Reconcile.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <cstdlib>
#include <format>
#include <map>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace vh::sync::manifest::test_manifest_reconcile {

namespace {

std::string uidN(const unsigned n, const uint8_t salt = 0) {
    Uid u{};
    u.fill(salt);
    u[0] = static_cast<uint8_t>(n >> 8);
    u[1] = static_cast<uint8_t>(n);
    return uidText(u);
}

const std::string kRoot = uidN(1);

Entry dir(const std::string& uid, std::optional<std::string> parent, std::string name) {
    Entry e;
    e.uid = uid;
    e.kind = EntryKind::Dir;
    e.parent = std::move(parent);
    e.name = std::move(name);
    e.mode = 0755;
    return e;
}

Entry file(const std::string& uid, const std::string& parent, std::string name, const std::string& generation = "g0") {
    Entry e;
    e.uid = uid;
    e.kind = EntryKind::File;
    e.parent = parent;
    e.name = std::move(name);
    e.mode = 0644;
    e.size = 10;
    e.format = 1;
    e.key_version = 1;
    e.generation = generation;
    e.object = ObjectRef{"\"" + generation + "\"", 146, std::nullopt, std::nullopt};
    e.mtime = "m-" + generation;
    return e;
}

Content vault(std::vector<Entry> entries) {
    Content c;
    c.producer = {"node", 1, "vaulthalla test"};
    c.vault = VaultInfo{"Finance", "2026-10-01T00:00:00Z", std::nullopt, "cache", std::nullopt};
    c.keys = {KeyRecord{1, "aa", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt}};
    c.recovery_policy = RecoveryPolicy{};
    c.entries.push_back(dir(kRoot, std::nullopt, ""));
    for (auto& e : entries) c.entries.push_back(std::move(e));
    normalize(c);
    return c;
}

Entry& at(Content& c, const std::string& uid) {
    const auto it = std::ranges::find(c.entries, uid, &Entry::uid);
    if (it == c.entries.end()) throw std::out_of_range("no entry " + uid);
    return *it;
}

const Entry* find(const Content& c, const std::string& uid) {
    const auto it = std::ranges::find(c.entries, uid, &Entry::uid);
    return it == c.entries.end() ? nullptr : &*it;
}

void erase(Content& c, const std::string& uid) { std::erase_if(c.entries, [&](const Entry& e) { return e.uid == uid; }); }

void trash(Content& c, const std::string& uid) { at(c, uid).trashed = Trashed{"2026-11-15T00:00:00Z", "admin", std::nullopt}; }

void edit(Content& c, const std::string& uid, const std::string& generation) {
    auto& e = at(c, uid);
    const auto fresh = file(uid, *e.parent, e.name, generation);
    e.generation = fresh.generation;
    e.object = fresh.object;
    e.mtime = fresh.mtime;
}

std::size_t count(const Reconciliation& r, const ConflictKind kind) {
    return static_cast<std::size_t>(std::ranges::count(r.conflicts, kind, &Conflict::kind));
}

std::vector<OpKind> kindsFor(const Reconciliation& r, const std::string& uid) {
    std::vector<OpKind> out;
    for (const auto& op : r.plan)
        if (op.uid == uid) out.push_back(op.kind);
    return out;
}

// Every reconciliation in this file: the plan takes ours to the result, the result is a sound tree, and applying the
// same head again (before and after the record) changes nothing.
Reconciliation checked(const Content& base, const Content& theirs, const Content& ours) {
    auto r = reconcile(base, theirs, ours);
    if (r.stopped()) return r;
    EXPECT_EQ(applyPlan(ours, r.plan), r.result) << "the plan takes ours to the result";
    for (const auto& p : treeProblems(r.result)) ADD_FAILURE() << "broken tree: " << p;
    EXPECT_TRUE(reconcile(base, theirs, r.result).plan.empty()) << "the same head twice";
    EXPECT_TRUE(reconcile(theirs, theirs, r.result).plan.empty()) << "the same head after its record";
    return r;
}

const std::string kDocs = uidN(2), kPhotos = uidN(3), kReport = uidN(10), kNotes = uidN(11);

Content baseVault() {
    return vault({dir(kDocs, kRoot, "Docs"), dir(kPhotos, kRoot, "Photos"), file(kReport, kDocs, "report.pdf"),
                  file(kNotes, kDocs, "notes.txt")});
}

}

// ── ManifestReconcile: one-sided changes ─────────────────────────────────────────────────────────────────────────

TEST(ManifestReconcile, AChangeOnOneSideTakesThatSide) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    at(theirs, kReport).name = "final.pdf";              // placement, theirs
    edit(theirs, kNotes, "g1");                          // content, theirs
    at(ours, kNotes).mode = 0600;                        // attributes, ours
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(r.conflicts.empty());
    EXPECT_EQ(find(r.result, kReport)->name, "final.pdf");
    EXPECT_EQ(find(r.result, kNotes)->generation, "g1");
    EXPECT_EQ(find(r.result, kNotes)->mtime, "m-g1") << "mtime follows content";
    EXPECT_EQ(find(r.result, kNotes)->mode, 0600u);
    EXPECT_EQ(kindsFor(r, kReport), std::vector{OpKind::Move});
    EXPECT_EQ(kindsFor(r, kNotes), std::vector{OpKind::ReplaceContent});
}

TEST(ManifestReconcile, TheSameChangeOnBothSidesIsInSync) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    for (auto* c : {&theirs, &ours}) {
        at(*c, kReport).name = "final.pdf";
        edit(*c, kNotes, "g1");
    }
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(r.conflicts.empty());
    EXPECT_TRUE(r.plan.empty());
    EXPECT_EQ(r.result, ours);
}

TEST(ManifestReconcile, EntriesTheHeadAddedAreCreatedParentsFirst) {
    const auto base = baseVault();
    auto theirs = base;
    const auto a = uidN(21), b = uidN(20), f = uidN(22), link = uidN(23);
    // uids sort against the tree on purpose: the deeper directory sorts first.
    theirs.entries.push_back(dir(b, a, "inner"));
    theirs.entries.push_back(dir(a, kRoot, "outer"));
    theirs.entries.push_back(file(f, b, "x.bin"));
    Entry l;
    l.uid = link;
    l.kind = EntryKind::Symlink;
    l.parent = kDocs;
    l.name = "latest";
    l.target = "report.pdf";
    theirs.entries.push_back(l);
    normalize(theirs);
    const auto r = checked(base, theirs, base);
    ASSERT_EQ(r.plan.size(), 4u);
    EXPECT_EQ(r.plan[0].kind, OpKind::CreateDir);
    EXPECT_EQ(r.plan[0].uid, a) << "parents first";
    EXPECT_EQ(r.plan[1].uid, b);
    EXPECT_EQ(r.plan[2].kind, OpKind::Create);
    EXPECT_EQ(r.plan[3].kind, OpKind::Create);
    EXPECT_FALSE(r.plan[2].ours) << "nothing local to compare and set against";
}

TEST(ManifestReconcile, EntriesOnlyOursHasAreKeptAndDeletesGoChildrenFirst) {
    const auto base = baseVault();
    auto ours = base;
    ours.entries.push_back(file(uidN(30), kPhotos, "local.jpg"));
    normalize(ours);
    auto theirs = base;
    erase(theirs, kReport);
    erase(theirs, kNotes);
    erase(theirs, kDocs);
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(find(r.result, uidN(30))) << "ours added it: never deleted by an apply";
    EXPECT_FALSE(find(r.result, kDocs));
    ASSERT_EQ(r.plan.size(), 3u);
    for (const auto& op : r.plan) EXPECT_EQ(op.kind, OpKind::Delete);
    EXPECT_EQ(r.plan.back().uid, kDocs) << "children first";
}

// ── ManifestReconcile: the conflict rules ────────────────────────────────────────────────────────────────────────

TEST(ManifestReconcile, ContentEditEditKeepsOursAndOpensAConflictForThePlanner) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    edit(theirs, kReport, "theirs");
    edit(ours, kReport, "ours");
    const auto r = checked(base, theirs, ours);
    ASSERT_EQ(count(r, ConflictKind::ContentEditEdit), 1u);
    const auto& c = r.conflicts.front();
    EXPECT_TRUE(c.open);
    ASSERT_TRUE(c.theirs);
    EXPECT_EQ(c.theirs->generation, "theirs") << "the incoming object, for the index row";
    EXPECT_EQ(find(r.result, kReport)->generation, "ours") << "the files row stays";
    EXPECT_TRUE(r.plan.empty());
}

TEST(ManifestReconcile, OursEditedTheirsPurgedKeepsOurs) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    erase(theirs, kReport);
    edit(ours, kReport, "g1");
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::EditBeatsDelete), 1u);
    ASSERT_TRUE(find(r.result, kReport));
    EXPECT_EQ(find(r.result, kReport)->generation, "g1");
}

TEST(ManifestReconcile, TheirsEditedOursTrashedIsRestoredToItsIncomingPlace) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    edit(theirs, kReport, "g1");
    at(theirs, kReport).parent = kPhotos;
    trash(ours, kReport);
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::EditBeatsTrash), 1u);
    const auto* e = find(r.result, kReport);
    ASSERT_TRUE(e);
    EXPECT_FALSE(e->trashed);
    EXPECT_EQ(e->parent, kPhotos);
    EXPECT_EQ(e->generation, "g1");
    EXPECT_EQ(kindsFor(r, kReport), std::vector{OpKind::Restore});
}

TEST(ManifestReconcile, TheirsEditedOursPurgedIsCreatedAgain) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    edit(theirs, kReport, "g1");
    erase(ours, kReport);
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::EditBeatsDelete), 1u);
    EXPECT_EQ(kindsFor(r, kReport), std::vector{OpKind::Create});
}

TEST(ManifestReconcile, OursEditedTheirsTrashedStaysLive) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    trash(theirs, kReport);
    edit(ours, kReport, "g1");
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::EditBeatsTrash), 1u);
    EXPECT_FALSE(find(r.result, kReport)->trashed);
}

TEST(ManifestReconcile, AnUneditedEntryFollowsTheOtherSidesDeleteOrTrash) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    trash(theirs, kReport);
    erase(theirs, kNotes);
    at(ours, kReport).name = "renamed.pdf";   // a rename is not an edit: the trash wins
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(find(r.result, kReport)->trashed);
    EXPECT_FALSE(find(r.result, kNotes));
    EXPECT_EQ(kindsFor(r, kReport), std::vector{OpKind::Trash});
    EXPECT_EQ(kindsFor(r, kNotes), std::vector{OpKind::Delete});
}

TEST(ManifestReconcile, DeleteDeleteTrashTrashAndTrashPurgeConverge) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    erase(theirs, kNotes);
    erase(ours, kNotes);                       // delete / delete
    trash(theirs, kReport);
    trash(ours, kReport);                      // trash / trash
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(r.conflicts.empty());
    EXPECT_TRUE(r.plan.empty());

    auto t2 = base, o2 = base;
    trash(t2, kReport);
    erase(o2, kReport);                        // trash / purge: both deleted, nothing edited
    EXPECT_FALSE(find(checked(base, t2, o2).result, kReport));
    auto t3 = base, o3 = base;
    erase(t3, kReport);
    trash(o3, kReport);
    const auto r3 = checked(base, t3, o3);
    EXPECT_FALSE(find(r3.result, kReport));
    EXPECT_EQ(kindsFor(r3, kReport), std::vector{OpKind::Purge});
}

TEST(ManifestReconcile, PlacementChangedOnBothSidesTheHeadWinsAndIsReported) {
    const auto base = baseVault();
    for (const int variant : {0, 1, 2}) {   // rename/rename, move/move, rename/move
        SCOPED_TRACE(variant);
        auto theirs = base, ours = base;
        if (variant == 0) {
            at(theirs, kReport).name = "theirs.pdf";
            at(ours, kReport).name = "ours.pdf";
        } else if (variant == 1) {
            at(theirs, kReport).parent = kPhotos;
            at(ours, kReport).parent = kRoot;
        } else {
            at(theirs, kReport).name = "theirs.pdf";
            at(ours, kReport).parent = kPhotos;
        }
        const auto r = checked(base, theirs, ours);
        EXPECT_EQ(count(r, ConflictKind::Placement), 1u);
        EXPECT_EQ(find(r.result, kReport)->parent, find(theirs, kReport)->parent);
        EXPECT_EQ(find(r.result, kReport)->name, find(theirs, kReport)->name);
        ASSERT_TRUE(r.conflicts.front().ours);
        EXPECT_EQ(*r.conflicts.front().ours, *find(ours, kReport)) << "our undone placement is reported";
    }
}

TEST(ManifestReconcile, AttributesChangedOnBothSidesTheHeadWins) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    at(theirs, kReport).mode = 0600;
    at(ours, kReport).mode = 0640;
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::Attributes), 1u);
    EXPECT_EQ(find(r.result, kReport)->mode, 0600u);
}

TEST(ManifestReconcile, AMoveThatWouldCloseACycleIsNotApplied) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    at(theirs, kDocs).parent = kPhotos;   // theirs: Docs into Photos
    at(ours, kPhotos).parent = kDocs;     // ours: Photos into Docs
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::CycleNotApplied), 1u);
    EXPECT_EQ(find(r.result, kDocs)->parent, kRoot) << "Docs keeps its local parent";
    EXPECT_EQ(find(r.result, kPhotos)->parent, kDocs);
    // The other writer applies that root (its side unchanged since): one tree.
    const auto back = checked(theirs, r.result, theirs);
    EXPECT_EQ(back.result.entries, r.result.entries);
}

TEST(ManifestReconcile, TwoUidsWithOneNameTheGreaterIsRenamedTheSameOnEveryWriter) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    const auto small = uidN(40), large = uidN(41);
    theirs.entries.push_back(file(large, kDocs, "plan.txt"));
    ours.entries.push_back(file(small, kDocs, "plan.txt"));
    normalize(theirs);
    normalize(ours);
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(count(r, ConflictKind::NameClash), 1u);
    EXPECT_EQ(find(r.result, small)->name, "plan.txt");
    EXPECT_EQ(find(r.result, large)->name, "plan.txt (" + large.substr(0, 8) + ")");
    // The other order (ours published first): the same names.
    const auto other = checked(base, ours, theirs);
    EXPECT_EQ(find(other.result, small)->name, "plan.txt");
    EXPECT_EQ(find(other.result, large)->name, find(r.result, large)->name);
}

TEST(ManifestReconcile, NamesThatDifferOnlyByCaseDoNotClash) {
    const auto base = baseVault();
    auto theirs = base;
    theirs.entries.push_back(file(uidN(42), kDocs, "Report.pdf"));
    normalize(theirs);
    const auto r = checked(base, theirs, base);
    EXPECT_TRUE(r.conflicts.empty());
    EXPECT_EQ(find(r.result, uidN(42))->name, "Report.pdf");
}

TEST(ManifestReconcile, AFolderDeletedOnOneSideIsKeptForWhatTheOtherAddedOrEdited) {
    const auto base = baseVault();
    {
        auto theirs = base, ours = base;   // theirs deleted Docs with its files; ours added one and edited one
        erase(theirs, kDocs);
        erase(theirs, kReport);
        erase(theirs, kNotes);
        ours.entries.push_back(file(uidN(50), kDocs, "new.txt"));
        normalize(ours);
        const auto r = checked(base, theirs, ours);
        EXPECT_EQ(count(r, ConflictKind::FolderKept), 1u);
        EXPECT_TRUE(find(r.result, kDocs));
        EXPECT_TRUE(find(r.result, uidN(50)));
        EXPECT_FALSE(find(r.result, kReport)) << "deleted with it on the deleting side, unchanged here";
    }
    {
        auto theirs = base, ours = base;   // ours deleted Docs; theirs edited a file in it
        erase(ours, kDocs);
        erase(ours, kReport);
        erase(ours, kNotes);
        edit(theirs, kNotes, "g1");
        const auto r = checked(base, theirs, ours);
        EXPECT_EQ(count(r, ConflictKind::FolderKept), 1u);
        EXPECT_TRUE(find(r.result, kDocs));
        EXPECT_TRUE(find(r.result, kNotes));
        EXPECT_FALSE(find(r.result, kReport));
    }
}

TEST(ManifestReconcile, AHeadWhoseOwnTreeIsBrokenIsRepairedUnderRecovered) {
    const auto base = baseVault();
    auto theirs = base;
    const auto x = uidN(60), y = uidN(61), orphan = uidN(62);
    theirs.entries.push_back(dir(x, y, "x"));            // a cycle only the head has
    theirs.entries.push_back(dir(y, x, "y"));
    theirs.entries.push_back(file(orphan, uidN(99), "lost.bin"));   // a folder no side has
    normalize(theirs);
    const auto r = checked(base, theirs, base);
    EXPECT_EQ(count(r, ConflictKind::Repaired), 2u);
    const auto rec = recoveredDirUid(kRoot);
    ASSERT_TRUE(find(r.result, rec));
    EXPECT_EQ(find(r.result, rec)->name, "Recovered");
    EXPECT_EQ(find(r.result, orphan)->parent, rec);
    EXPECT_EQ(find(r.result, x)->parent, rec) << "the least uid of the cycle";
    EXPECT_EQ(recoveredDirUid(kRoot), rec) << "the same directory on every writer";
}

// ── ManifestReconcile: history, keys, settings, snapshots ────────────────────────────────────────────────────────

TEST(ManifestReconcile, HistoryIsAUnionAndTombstonesStay) {
    auto base = baseVault();
    auto theirs = base, ours = base;
    const FileVersion v1{"v1", std::nullopt, 1, 146, "\"e1\"", "2026-11-01T00:00:00Z", std::nullopt, false, std::nullopt};
    const FileVersion v2{"v2", std::nullopt, 1, 146, "\"e2\"", "2026-11-02T00:00:00Z", std::nullopt, false, std::nullopt};
    at(theirs, kReport).versions = {v1, v2};
    at(ours, kReport).versions = {v1};
    Entry tomb;
    tomb.uid = uidN(70);
    tomb.kind = EntryKind::Tombstone;
    tomb.versions = {v1};
    theirs.entries.push_back(tomb);
    normalize(theirs);
    const auto r = checked(base, theirs, ours);
    EXPECT_TRUE(r.conflicts.empty());
    EXPECT_EQ(find(r.result, kReport)->versions.size(), 2u);
    ASSERT_TRUE(find(r.result, uidN(70)));
    EXPECT_EQ(find(r.result, uidN(70))->kind, EntryKind::Tombstone);
    EXPECT_EQ(kindsFor(r, kReport), std::vector{OpKind::AddHistory});
    // A purge on the head keeps the purged file's versions as a tombstone.
    auto purged = base;
    erase(purged, kReport);
    at(ours, kReport).versions = {v1};
    const auto p = checked(base, purged, ours);
    ASSERT_TRUE(find(p.result, kReport));
    EXPECT_EQ(find(p.result, kReport)->kind, EntryKind::Tombstone);
    EXPECT_EQ(kindsFor(p, kReport), (std::vector{OpKind::Delete, OpKind::AddHistory}));
}

TEST(ManifestReconcile, AKeyVersionNotHeldOrWithAnotherKeyCheckStopsEverything) {
    const auto base = baseVault();
    auto theirs = base;
    erase(theirs, kReport);
    theirs.keys.push_back(KeyRecord{2, "bb", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt});
    auto r = reconcile(base, theirs, base);
    ASSERT_TRUE(r.stopped());
    EXPECT_EQ(r.key_problems, (std::vector{KeyProblem{2, "manifest_key_missing"}}));
    EXPECT_TRUE(r.plan.empty());
    EXPECT_EQ(r.result, base);
    theirs.keys = {KeyRecord{1, "zz", std::nullopt, std::nullopt, std::nullopt, std::nullopt, std::nullopt}};
    r = reconcile(base, theirs, base);
    EXPECT_EQ(r.key_problems, (std::vector{KeyProblem{1, "manifest_key_mismatch"}}));
}

TEST(ManifestReconcile, EnvelopesAreAUnionAndRecoveryGrantsAreNeverMerged) {
    const auto base = baseVault();
    auto theirs = base;
    theirs.keys[0].envelopes = std::vector<std::string>{"kid-a"};
    theirs.recovery_policy->grants.push_back(Grant{"g1", std::string(64, 'a'), "customer", 1, std::nullopt,
                                                   std::nullopt, std::nullopt, std::nullopt, std::nullopt,
                                                   std::nullopt});
    theirs.recovery_policy->account_policy = AccountPolicyBytes{"{\"seq\":2}", "sig"};
    const auto r = checked(base, theirs, base);
    EXPECT_EQ(r.result.recovery_policy, base.recovery_policy) << "grants come only from the account's policy";
    ASSERT_TRUE(r.incoming_account_policy);
    EXPECT_EQ(r.incoming_account_policy->policy, "{\"seq\":2}");
    ASSERT_TRUE(r.result.keys[0].envelopes);
    EXPECT_EQ(*r.result.keys[0].envelopes, std::vector<std::string>{"kid-a"});
    ASSERT_EQ(r.plan.size(), 1u);
    EXPECT_EQ(r.plan[0].kind, OpKind::AddEnvelopes);
}

TEST(ManifestReconcile, VaultSettingsMergePerFieldAndTheHeadWinsAConflict) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    theirs.vault->quota_bytes = 1000;          // theirs only
    ours.vault->sync_strategy = "sync";        // ours only
    theirs.vault->name = "Theirs";
    ours.vault->name = "Ours";                 // both
    const auto r = checked(base, theirs, ours);
    EXPECT_EQ(r.result.vault->quota_bytes, 1000u);
    EXPECT_EQ(r.result.vault->sync_strategy, "sync");
    EXPECT_EQ(r.result.vault->name, "Theirs");
    EXPECT_EQ(count(r, ConflictKind::VaultSetting), 1u);
    ASSERT_FALSE(r.plan.empty());
    EXPECT_EQ(r.plan[0].kind, OpKind::SetVault);
}

TEST(ManifestReconcile, SnapshotRecordsMergeByUidAndRecordsWithoutOneAreLeftAlone) {
    auto base = baseVault();
    const SnapshotRecord kept{uidN(80), std::nullopt, "kept", "2026-11-01T00:00:00Z", "/", {}};
    const SnapshotRecord gone{uidN(81), std::nullopt, "gone", "2026-11-01T00:00:00Z", "/", {}};
    const SnapshotRecord added{uidN(82), std::nullopt, "added", "2026-11-02T00:00:00Z", "/", {}};
    const SnapshotRecord legacy{"", 7, "legacy", "2026-10-01T00:00:00Z", "/", {}};
    base.snapshots = {kept, gone};
    auto theirs = base, ours = base;
    theirs.snapshots = {kept, added, legacy};   // theirs deleted `gone`, added `added`; `legacy` has no uid
    const SnapshotRecord seven{uidN(83), std::nullopt, "ours 7", "2026-11-03T00:00:00Z", "/", {}};
    ours.snapshots.push_back(seven);            // another server's snapshot 7 is not ours
    normalize(theirs);
    normalize(ours);
    const auto r = checked(base, theirs, ours);
    std::set<std::string> names;
    for (const auto& s : r.result.snapshots) names.insert(*s.name);
    EXPECT_EQ(names, (std::set<std::string>{"kept", "added", "ours 7"}));
}

TEST(ManifestReconcile, TheSameHeadTwiceChangesNothing) {
    const auto base = baseVault();
    auto theirs = base, ours = base;
    at(theirs, kReport).parent = kPhotos;
    erase(theirs, kNotes);
    edit(ours, kReport, "g1");
    const auto first = checked(base, theirs, ours);
    ASSERT_FALSE(first.plan.empty());
    const auto again = reconcile(base, theirs, first.result);
    EXPECT_TRUE(again.plan.empty());
    EXPECT_EQ(again.result, first.result);
}

// ── ManifestReconcileProperty ────────────────────────────────────────────────────────────────────────────────────

namespace {

// One replica's database as a model: local operations as the server allows them (unique names per folder, no move
// into a descendant, files only in the trash), then the collector's view (a trashed file names a live folder or none).
class Replica {
public:
    Replica(Content c, const uint64_t seed, const uint8_t salt, std::optional<std::string> confine = std::nullopt)
        : db(std::move(c)), base(db), rng_(seed), salt_(salt), confine_(std::move(confine)) {}

    Content db;
    Content base;

    void localOps(const unsigned n) {
        for (unsigned i = 0; i < n; ++i) oneOp();
        settle();
        normalize(db);
    }

private:
    std::mt19937_64 rng_;
    uint8_t salt_;
    unsigned next_{0};
    std::optional<std::string> confine_;   // only entries under this folder (the disjoint property)

    std::size_t pick(const std::size_t n) { return std::uniform_int_distribution<std::size_t>(0, n - 1)(rng_); }

    const Entry* entry(const std::string& uid) const { return find(db, uid); }
    bool live(const Entry& e) const { return e.kind != EntryKind::Tombstone && !e.trashed; }

    bool under(const std::string& uid, const std::string& ancestor) const {
        const Entry* e = entry(uid);
        for (std::size_t guard = 0; e && guard <= db.entries.size(); ++guard) {
            if (e->uid == ancestor) return true;
            if (!e->parent) return false;
            e = entry(*e->parent);
        }
        return false;
    }
    bool mine(const std::string& uid) const { return !confine_ || (uid != *confine_ && under(uid, *confine_)); }

    std::vector<std::string> liveDirs() const {
        std::vector<std::string> out;
        for (const auto& e : db.entries)
            if (live(e) && e.kind == EntryKind::Dir && (!confine_ || under(e.uid, *confine_))) out.push_back(e.uid);
        return out;
    }
    std::vector<std::string> liveEntries(const bool filesOnly) const {
        std::vector<std::string> out;
        for (const auto& e : db.entries)
            if (live(e) && e.parent && mine(e.uid) && (!filesOnly || e.kind == EntryKind::File)) out.push_back(e.uid);
        return out;
    }
    std::vector<std::string> trashed() const {
        std::vector<std::string> out;
        for (const auto& e : db.entries)
            if (e.trashed && (!confine_ || (e.parent && under(*e.parent, *confine_)))) out.push_back(e.uid);
        return out;
    }
    bool nameFree(const std::string& parent, const std::string& name) const {
        return std::ranges::none_of(db.entries, [&](const Entry& e) {
            return live(e) && e.parent == parent && e.name == name;
        });
    }
    std::string freeName(const std::string& parent) {
        static const std::vector<std::string> pool{"a", "b", "c", "d"};
        for (int i = 0; i < 4; ++i)
            if (const auto& n = pool[pick(pool.size())]; nameFree(parent, n)) return n;
        for (unsigned i = 0;; ++i)
            if (const auto n = "n" + std::to_string(i); nameFree(parent, n)) return n;
    }
    std::string freshUid() {
        Uid u{};
        for (auto& byte : u) byte = static_cast<uint8_t>(pick(256));
        u[15] = salt_;
        ++next_;
        return uidText(u);
    }

    void oneOp() {
        const auto dirs = liveDirs();
        switch (pick(11)) {
        case 0:
        case 1: {   // create a file
            const auto parent = dirs[pick(dirs.size())];
            db.entries.push_back(file(freshUid(), parent, freeName(parent), "g" + std::to_string(rng_() % 100000)));
            break;
        }
        case 2: {   // mkdir
            const auto parent = dirs[pick(dirs.size())];
            db.entries.push_back(dir(freshUid(), parent, freeName(parent)));
            break;
        }
        case 3: {   // rename
            const auto all = liveEntries(false);
            if (all.empty()) break;
            auto& e = at(db, all[pick(all.size())]);
            e.name = freeName(*e.parent);
            break;
        }
        case 4: {   // move
            const auto all = liveEntries(false);
            if (all.empty()) break;
            auto& e = at(db, all[pick(all.size())]);
            const auto to = dirs[pick(dirs.size())];
            if (to == e.uid || under(to, e.uid) || to == *e.parent) break;
            const auto name = nameFree(to, e.name) ? e.name : freeName(to);
            e.parent = to;
            e.name = name;
            break;
        }
        case 5:
        case 6: {   // edit
            const auto files = liveEntries(true);
            if (files.empty()) break;
            edit(db, files[pick(files.size())], "g" + std::to_string(rng_() % 100000));
            break;
        }
        case 7: {   // chmod
            const auto all = liveEntries(false);
            if (all.empty()) break;
            at(db, all[pick(all.size())]).mode = static_cast<uint32_t>(0600 + pick(64));
            break;
        }
        case 8: {   // trash
            const auto files = liveEntries(true);
            if (files.empty()) break;
            trash(db, files[pick(files.size())]);
            break;
        }
        case 9: {   // restore or purge from the trash
            const auto t = trashed();
            if (t.empty()) break;
            auto& e = at(db, t[pick(t.size())]);
            if (pick(2) == 0) {
                erase(db, e.uid);
            } else if (e.parent && nameFree(*e.parent, e.name)) {
                e.trashed.reset();
            }
            break;
        }
        case 10: {   // delete (a folder with everything live in it)
            const auto all = liveEntries(false);
            if (all.empty()) break;
            const auto victim = all[pick(all.size())];
            std::vector<std::string> gone;
            for (const auto& e : db.entries)
                if (live(e) && under(e.uid, victim)) gone.push_back(e.uid);
            for (const auto& g : gone) erase(db, g);
            break;
        }
        }
        normalize(db);
    }

    // The collector's view: a trashed file names its folder only while that folder is live.
    void settle() {
        for (auto& e : db.entries)
            if (e.trashed && e.parent) {
                const auto* p = entry(*e.parent);
                if (!p || !live(*p) || p->kind != EntryKind::Dir) e.parent.reset();
            }
    }
};

uint64_t seedFrom(const uint64_t fallback) {
    if (const char* s = std::getenv("VH_RECONCILE_SEED")) return std::strtoull(s, nullptr, 10);
    return fallback;
}

// Applies the head to a replica (if it moved), checking every property, then publishes it (the database is at a root,
// so a publish is its database). False after a failure.
using Tally = std::map<ConflictKind, std::size_t>;

bool sync(Replica& w, Content& head, const uint64_t seed, const char* who, Tally& tally) {
    if (w.base != head) {
        const auto r = reconcile(w.base, head, w.db);
        for (const auto& c : r.conflicts) ++tally[c.kind];
        if (r.stopped()) {
            ADD_FAILURE() << "seed " << seed << " " << who << ": stopped";
            return false;
        }
        bool ok = true;
        if (applyPlan(w.db, r.plan) != r.result) {
            ADD_FAILURE() << "seed " << seed << " " << who << ": the plan does not take ours to the result";
            ok = false;
        }
        for (const auto& p : treeProblems(r.result)) {
            ADD_FAILURE() << "seed " << seed << " " << who << ": broken tree: " << p;
            ok = false;
        }
        if (const auto again = reconcile(w.base, head, r.result); !again.plan.empty() || again.result != r.result) {
            ADD_FAILURE() << "seed " << seed << " " << who << ": applying the head twice changed "
                          << again.plan.size() << " thing(s)"
                          << (again.plan.empty() ? std::string()
                                                 : std::format(", first {} {}", to_string(again.plan.front().kind),
                                                               again.plan.front().uid));
            ok = false;
        }
        if (const auto recorded = reconcile(head, head, r.result); !recorded.plan.empty()) {
            ADD_FAILURE() << "seed " << seed << " " << who << ": the recorded head changed something";
            ok = false;
        }
        if (!ok) return false;
        w.db = r.result;
    }
    head = w.db;
    w.base = head;
    return true;
}

struct Run {
    Content head;
    Content a, b;
    bool ok{true};
    Tally tally;
};

Run simulate(const uint64_t seed, const bool disjoint, const bool aFirst, const unsigned rounds) {
    const auto mineA = uidN(5), mineB = uidN(6);
    auto start = vault({dir(mineA, kRoot, "A"), dir(mineB, kRoot, "B"), dir(kDocs, mineA, "Docs"),
                        dir(kPhotos, mineB, "Photos"), file(kReport, kDocs, "report.pdf"),
                        file(kNotes, kPhotos, "notes.txt")});
    Replica a(start, seed * 2 + 1, 0xa1, disjoint ? std::optional(mineA) : std::nullopt);
    Replica b(start, seed * 2 + 2, 0xb2, disjoint ? std::optional(mineB) : std::nullopt);
    Run run{start, {}, {}, true, {}};
    std::mt19937_64 order(seed);
    for (unsigned round = 0; round < rounds && run.ok; ++round) {
        a.localOps(static_cast<unsigned>(order() % 5));
        b.localOps(static_cast<unsigned>(order() % 5));
        const bool first = disjoint ? aFirst : (order() % 2 == 0);
        run.ok = first ? sync(a, run.head, seed, "A", run.tally) && sync(b, run.head, seed, "B", run.tally)
                       : sync(b, run.head, seed, "B", run.tally) && sync(a, run.head, seed, "A", run.tally);
    }
    // Quiescence: nobody writes; each applies what the other published.
    for (unsigned i = 0; i < 4 && run.ok && !(a.db == run.head && b.db == run.head && a.base == run.head &&
                                               b.base == run.head);
         ++i)
        run.ok = sync(a, run.head, seed, "A", run.tally) && sync(b, run.head, seed, "B", run.tally);
    run.a = a.db;
    run.b = b.db;
    return run;
}

constexpr uint64_t kSeeds = 300;

}

TEST(ManifestReconcileProperty, ReplicasConvergeOnOneSoundTreeWhateverTheyDo) {
    std::size_t entries = 0;
    Tally tally;
    for (uint64_t i = 0; i < kSeeds; ++i) {
        const auto seed = seedFrom(i);
        const auto run = simulate(seed, false, true, 6);
        ASSERT_TRUE(run.ok) << "seed " << seed;
        ASSERT_EQ(run.a, run.head) << "seed " << seed << ": replica A did not converge";
        ASSERT_EQ(run.b, run.head) << "seed " << seed << ": replica B did not converge";
        for (const auto& p : treeProblems(run.head)) FAIL() << "seed " << seed << ": " << p;
        entries += run.head.entries.size();
        for (const auto& [kind, n] : run.tally) tally[kind] += n;
        if (std::getenv("VH_RECONCILE_SEED")) break;
    }
    EXPECT_GT(entries, 0u);
    // The generator reaches the rules it is meant to exercise (a regression in it would make the property vacuous).
    for (const auto& [kind, n] : tally) RecordProperty(std::string(to_string(kind)), static_cast<int>(n));
    if (!std::getenv("VH_RECONCILE_SEED")) {
        for (const auto kind : {ConflictKind::ContentEditEdit, ConflictKind::Placement, ConflictKind::Attributes,
                                ConflictKind::EditBeatsDelete, ConflictKind::EditBeatsTrash, ConflictKind::FolderKept,
                                ConflictKind::NameClash, ConflictKind::CycleNotApplied}) {
            EXPECT_GT(tally[kind], 0u) << to_string(kind);
        }
    }
}

TEST(ManifestReconcileProperty, ChangesThatDoNotOverlapEndOnTheSameTreeInEitherOrder) {
    for (uint64_t i = 0; i < kSeeds; ++i) {
        const auto seed = seedFrom(i);
        const auto ab = simulate(seed, true, true, 4);
        const auto ba = simulate(seed, true, false, 4);
        ASSERT_TRUE(ab.ok && ba.ok) << "seed " << seed;
        ASSERT_EQ(ab.head.entries, ba.head.entries) << "seed " << seed << ": the publish order changed the tree";
        if (std::getenv("VH_RECONCILE_SEED")) break;
    }
}

}
