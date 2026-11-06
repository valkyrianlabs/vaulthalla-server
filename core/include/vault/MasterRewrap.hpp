#pragma once

#include "crypto/secrets/Rewrap.hpp"

#include <chrono>

// The vault_master rewrap (#352): the versioned master-secret rewrap engine (crypto/secrets/Rewrap.hpp) for the vault
// master, which wraps every vault key version (vault_keys, vault_keys_trashed, vault_deletion_key). It replaces the
// vault master without touching a single file body: only the wraps change, verified against each row's key check
// (migration 113) before anything switches.
namespace vh::vault::master::rewrap {

namespace engine = crypto::secrets::rewrap;

using Refused = engine::Refused;
using State = engine::State;
using Status = engine::Status;
using Options = engine::Options;
using RotateResult = engine::RotateResult;
using RollbackResult = engine::RollbackResult;
using FinalizeResult = engine::FinalizeResult;
using CrashHook = engine::CrashHook;
using engine::kDefaultBatch;
using engine::kDefaultWindow;
using engine::setCrashHookForTesting;

inline constexpr auto kSlot = crypto::secrets::versioned::Slot::VaultMaster;

[[nodiscard]] inline State state() { return engine::state(kSlot); }
[[nodiscard]] inline Status status() { return engine::status(kSlot); }
inline RotateResult rotate(const Options& options = {}) { return engine::rotate(kSlot, options); }
inline RollbackResult rollback() { return engine::rollback(kSlot); }
inline FinalizeResult finalize() { return engine::finalize(kSlot); }
inline FinalizeResult expireIfDue(const std::chrono::system_clock::time_point now = std::chrono::system_clock::now()) {
    return engine::expireIfDue(kSlot, now);
}

}
