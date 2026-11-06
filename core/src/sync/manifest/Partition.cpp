#include "sync/manifest/Partition.hpp"

#include <stdexcept>

namespace vh::sync::manifest {

namespace partition_detail {

struct Slot {
    Range range;
    std::size_t first{};  // index of the first entry in the range
    std::size_t count{};
    std::size_t bytes{};
};

uint8_t firstByte(const Entry& e) { return parseUid(e.uid, "bad_segment", "entry uid")[0]; }

// Fills first/count/bytes of every slot from the sorted entries.
void assign(std::vector<Slot>& slots, const std::vector<uint8_t>& lead, const std::vector<std::size_t>& sizes) {
    std::size_t i = 0;
    for (auto& s : slots) {
        s.first = i;
        s.count = 0;
        s.bytes = 0;
        while (i < lead.size() && lead[i] <= s.range.hi) {
            if (lead[i] < s.range.lo) throw std::logic_error("manifest partition: entries out of order");
            s.bytes += sizes[i];
            ++s.count;
            ++i;
        }
    }
    if (i != lead.size()) throw std::logic_error("manifest partition: ranges don't cover every entry");
}

bool tooBig(const Slot& s, const PartitionLimits& l) { return s.count > l.split_entries || s.bytes > l.split_bytes; }

bool fitsMerged(const Slot& a, const Slot& b, const PartitionLimits& l) {
    return a.count + b.count <= l.split_entries && a.bytes + b.bytes <= l.split_bytes;
}

}

std::vector<PlannedSegment> partition(const std::vector<Entry>& entries, const std::vector<Range>& previousRanges,
                                      const std::string& vaultUid, const PartitionLimits& limits) {
    using partition_detail::Slot;
    std::vector<uint8_t> lead;
    std::vector<std::size_t> sizes;
    lead.reserve(entries.size());
    sizes.reserve(entries.size());
    for (const auto& e : entries) {
        lead.push_back(partition_detail::firstByte(e));
        sizes.push_back(canonicalJson(toJson(e)).size() + 1);  // + the separating comma
    }

    std::vector<Slot> slots;
    int next = 0;
    for (const auto& r : previousRanges) {
        if (r.lo != next) {
            slots.clear();
            break;
        }
        slots.push_back(Slot{.range = r});
        next = r.hi + 1;
    }
    if (slots.empty() || next != 0x100) slots = {Slot{.range = Range{0x00, 0xff}}};

    for (bool changed = true; changed;) {
        changed = false;
        partition_detail::assign(slots, lead, sizes);
        for (std::size_t i = 0; i < slots.size(); ++i) {
            const auto r = slots[i].range;
            if (partition_detail::tooBig(slots[i], limits) && r.lo < r.hi) {
                const auto mid = static_cast<uint8_t>(r.lo + (r.hi - r.lo) / 2);
                slots[i].range = {r.lo, mid};
                slots.insert(slots.begin() + static_cast<std::ptrdiff_t>(i) + 1,
                             Slot{.range = Range{static_cast<uint8_t>(mid + 1), r.hi}});
                changed = true;
                break;
            }
        }
        if (changed) continue;
        for (std::size_t i = 0; i < slots.size() && !changed; ++i) {
            if (slots[i].count >= limits.merge_entries) continue;
            if (i + 1 < slots.size() && partition_detail::fitsMerged(slots[i], slots[i + 1], limits)) {
                slots[i].range.hi = slots[i + 1].range.hi;
                slots.erase(slots.begin() + static_cast<std::ptrdiff_t>(i) + 1);
                changed = true;
            } else if (i > 0 && partition_detail::fitsMerged(slots[i - 1], slots[i], limits)) {
                slots[i - 1].range.hi = slots[i].range.hi;
                slots.erase(slots.begin() + static_cast<std::ptrdiff_t>(i));
                changed = true;
            }
        }
    }
    partition_detail::assign(slots, lead, sizes);

    std::vector<PlannedSegment> out;
    out.reserve(slots.size());
    for (const auto& s : slots) {
        PlannedSegment p;
        p.doc.vault_uid = vaultUid;
        p.doc.range = s.range;
        p.doc.entries.assign(entries.begin() + static_cast<std::ptrdiff_t>(s.first),
                             entries.begin() + static_cast<std::ptrdiff_t>(s.first + s.count));
        p.plaintext = canonicalJson(toJson(p.doc));
        out.push_back(std::move(p));
    }
    return out;
}

}
