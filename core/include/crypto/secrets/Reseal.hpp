#pragma once

#include "platform/Sealer.hpp"

#include <cstddef>
#include <string>
#include <vector>

// Resealing every sealed secret of this host under a TPM policy (#351; design/sealing/master-secrets.md §5).
//
// A reseal never changes a secret and never creates one: each blob is unsealed under its current policy, sealed again
// beside it under the target policy at the current PCR values, unsealed and compared byte for byte, and only then
// swapped in (platform::sealer::reseal, which also owns the crash recovery). It is a rewrap in the sense of
// #352/#353 for the sealing layer: the dependent rows (vault keys, API keys, ...) are wrapped by the secrets, not by
// the blobs, so none of them is touched. Nothing here calls KeyProvider::init/initGuarded, so no secret can be minted
// over existing rows.
namespace vh::crypto::secrets::reseal {

struct Entry {
    std::string name{};  // the sealed slot name: master, psql, vault_master, vault_master.v2, ak_master, ...
    platform::sealer::Policy policy{platform::sealer::Policy::None};
    bool complete{true};  // both parts of the blob are there
};

// Every sealed secret on this host and the policy its blob carries, by name.
[[nodiscard]] std::vector<Entry> inventory();

struct Item {
    std::string name{};
    platform::sealer::Policy from{platform::sealer::Policy::None}, to{platform::sealer::Policy::None};
    bool changed{false};
};

struct Report {
    platform::sealer::Policy target{platform::sealer::Policy::None};
    std::vector<Item> items{};
    [[nodiscard]] std::size_t changed() const;
};

// Reseals every sealed secret to `target` at the current PCR values. Secrets already carrying exactly that policy are
// left alone, so a run interrupted halfway (or one that hit a blob it can't open) is repeated until it completes.
// Throws platform::sealer::PolicyUnsatisfied (typed, unchanged) when a blob is bound to a PCR 7 value this boot no
// longer has, and std::runtime_error for any other failure; both name the secret and how many were resealed before it.
// The secrets resealed before the failure stay resealed (each is complete and verified).
Report run(platform::sealer::Policy target);

}
