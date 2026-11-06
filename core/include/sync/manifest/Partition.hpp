#pragma once

#include "sync/manifest/Document.hpp"

#include <cstddef>
#include <string>
#include <vector>

// Cutting the entries into segments (spec 03 §3.3): entries are partitioned by the first byte of their uid, a segment
// splits when it exceeds 8,192 entries or 4 MiB of plaintext, and merges with a neighbour below 1,024 (when the merged
// segment stays within the split limits). The plan starts from the previous root's ranges, so a change touches only
// the segment its uid falls in: the publisher reuses every segment whose range and plaintext are unchanged.
namespace vh::sync::manifest {

struct PartitionLimits {
    std::size_t split_entries{8192};
    std::size_t split_bytes{4u << 20};
    std::size_t merge_entries{1024};
};

struct PlannedSegment {
    SegmentDocument doc;
    std::string plaintext;  // canonicalJson(toJson(doc)): what gets sealed, and what reuse compares
};

// entries ascending by uid (Content's order). previousRanges: the previous root's segment ranges in order (empty for
// a first publish: one range 00..ff). The result covers 00..ff in order; a range may hold no entries (an empty vault
// is one empty segment).
[[nodiscard]] std::vector<PlannedSegment> partition(const std::vector<Entry>& entries,
                                                    const std::vector<Range>& previousRanges,
                                                    const std::string& vaultUid, const PartitionLimits& limits = {});

}
