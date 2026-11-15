#pragma once

#include "crypto/vhf1/Format.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/manifest/Store.hpp"

#include <cstddef>
#include <ctime>
#include <map>
#include <optional>
#include <string>
#include <vector>

// The root on a bucket without conditional writes (design/encryption/06-publish-without-preconditions.md §5): the
// provider versions of `.vaulthalla/root`, in provider order, are the log, and rule C1 picks the canonical chain.
//
//   C1   succ(X) is the earliest version (provider order) whose root has epoch X.epoch + 1 and prev = SHA-256(X).
//        From an anchor A the canonical chain is A, succ(A), succ(succ(A)), ...; its last element is the head. The
//        anchor is the settled known root, a customer checkpoint, or with neither the chain whose head has the highest
//        epoch (ties: the longer chain, then the earliest head). Every other version is a sibling, a branch, a
//        duplicate or stale, and is ignored.
//
//   Repair never deletes an authentic root whose epoch is above the head's, nor one such a root builds on: a chain
//   from the anchor that stops below one is incomplete (a version missing in between, or a broken provider order), and the reader falls back to the
//   anchorless choice instead (Reader.cpp).
//
// Opening a version is one GET by version id; a version's bytes never change, so opened roots are cached by id
// (RootCache, kept by the caller across publishes).
namespace vh::sync::manifest {

struct OpenedRoot {
    RootDocument root;
    std::string sha256;
};

class RootCache {
public:
    // nullptr: not opened yet, or (with *known) opened and not authentic.
    [[nodiscard]] const OpenedRoot* find(const std::string& versionId, bool* known = nullptr) const;
    void put(const std::string& versionId, std::optional<OpenedRoot> root);
    void clear() { roots_.clear(); }

private:
    std::map<std::string, std::optional<OpenedRoot>> roots_;
};

class RootLog {
public:
    RootLog(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys, RootCache& cache);

    // One ListObjectVersions of the root key: every page, or (stopAt) the pages down to that version, which is then the
    // oldest one held. Throws the store's errors.
    void list(const std::optional<std::string>& stopAt = std::nullopt);
    // Whether the last list() stopped before the oldest version.
    [[nodiscard]] bool partial() const noexcept { return partial_; }
    // Oldest first, delete markers included.
    [[nodiscard]] const std::vector<StoredVersion>& versions() const { return versions_; }
    [[nodiscard]] std::optional<std::size_t> indexOf(const std::string& versionId) const;
    // The root at index i: nullptr for a delete marker or a version that doesn't authenticate (or vanished).
    const OpenedRoot* open(std::size_t i);
    // The newest version holding the root of that hash, opening at most kMaxScanned versions newest first.
    std::optional<std::size_t> findBySha(const std::string& sha256);
    // The earliest version whose root has epoch 1 (no prev): where a chain starts when nothing is known.
    std::optional<std::size_t> genesis();
    [[nodiscard]] unsigned gets() const noexcept { return gets_; }
    [[nodiscard]] bool isLatest(std::size_t i) const { return i + 1 == versions_.size(); }

    static constexpr std::size_t kMaxScanned = 64;

private:
    ObjectStore& store_;
    const Uid& vaultUid_;
    const crypto::vhf1::KeyLookup& keys_;
    RootCache& cache_;
    std::vector<StoredVersion> versions_;
    bool partial_{false};
    unsigned gets_{0};
};

struct Walk {
    std::size_t anchor{};
    std::size_t head{};
    std::vector<std::size_t> chain;    // anchor, succ(anchor), ..., head (indexes into the log, ascending)
    // Versions newer than the head that are not on the chain and repair may delete: delete markers, versions that
    // don't authenticate, authentic roots whose epoch is at most the head's and that no kept root builds on.
    std::vector<std::size_t> strays;
    // Authentic roots newer than the head with a higher epoch than the head's, and the roots those build on: never
    // deleted. Their presence means the chain from this anchor is incomplete.
    std::vector<std::size_t> ahead;
};

// Rule C1 from the anchor at `anchor` (which must open).
[[nodiscard]] Walk walk(RootLog& log, std::size_t anchor);

// With no anchor: among the chains of the authentic versions (each walked from a version that is no one's earliest
// successor) the one whose head has the highest epoch; ties: the longer chain, then the earliest head. Every authentic
// root lies on some chain, so nothing authentic is ahead of that head. nullopt when no version authenticates.
[[nodiscard]] std::optional<Walk> walkBlind(RootLog& log);

// succ of the root (epoch, sha): the earliest version at index >= from whose root has epoch + 1 and prev = sha. With
// epoch 0 and no sha, the genesis: the earliest root of epoch 1. A base that is gone from the bucket (rebuilt from the
// database) is named this way too.
[[nodiscard]] std::optional<std::size_t> successorOf(RootLog& log, uint64_t epoch, const std::optional<std::string>& sha,
                                                     std::size_t from = 0);

// The version ids strictly between positions a and b (a < b) in the log.
[[nodiscard]] std::vector<std::string> idsBetween(const RootLog& log, std::size_t a, std::size_t b);

// A settled root's window (spec 06 §5.3): the ids between its base and itself when it settled. True when the current
// log puts an id between them that wasn't there then (the provider broke A3 or A4). Unknown positions (a version
// gone) can't be judged: false.
[[nodiscard]] bool windowBroken(const RootLog& log, const std::string& baseVersionId, const std::string& versionId,
                                const std::vector<std::string>& window);

}
