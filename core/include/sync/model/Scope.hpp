#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <unordered_set>
#include <vector>

// An event-scoped sync pass (#96): reconcile only the keys upstream notifications named, from the remote object index
// the events were applied to. No LIST, no manifest refresh; requests are only the transfers the plan needs.
namespace vh::sync::model {

struct PassScope {
    // Vault paths as the pass keys its maps ("/dir/a.txt").
    std::unordered_set<std::u8string> keys;
    // Keys whose latest event is a removal: a local copy unchanged since both sides last agreed is removed instead of
    // re-uploaded (a full pass can't tell a deletion from an absence; an event can).
    std::unordered_set<std::u8string> removed;
    // Keys whose latest event is an external create/overwrite: the remote object changed, whatever sizes or ETags a
    // hashless index row lets the baseline compare (a same-size overwrite after an upload would look unchanged).
    std::unordered_set<std::u8string> changed;
    // Inbox rows this pass settles, handed back to the caller.
    std::vector<int64_t> inbox_ids;
    // Called once when the pass ends: ok = the plan ran with no failed operation.
    std::function<void(bool ok, const std::string& error)> on_finish;

    [[nodiscard]] bool contains(const std::u8string& key) const { return keys.contains(key); }
};

}
