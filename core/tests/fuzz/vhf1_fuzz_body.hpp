#pragma once

// One fuzz iteration over the VHF1 reader (header parser, chunk walker, range reader). Shared by the libFuzzer target
// (fuzz_vhf1.cpp, -Dfuzz=true) and Vhf1Fuzz in the unit tests, which replays a deterministic input set so this code
// is compiled and run by every CI build. Violations call std::abort(): a crash, never an ignored result.
//
// The first input byte picks a mode:
//   0: the rest is an object, read as-is (structure, expectation and header-tag checks; forged tags never pass, but
//      a seed may be a genuine object, so modes 0 and 1 have no plaintext oracle: they must only not crash).
//   1: the rest supplies a header body; it is re-tagged with the right key when the key version is held, so the
//      chunk walker and the size math see arbitrary chunk sizes and object sizes behind an authentic header.
//   2: the rest seeds a genuine object (plaintext, chunk size) and a list of mutations (truncate, extend, bit flips,
//      chunk swaps, splices). Whatever any reader returns must be the original plaintext at that offset.

#include "crypto/SecretKey.hpp"
#include "crypto/vhf1/Format.hpp"
#include "crypto/vhf1/Reader.hpp"
#include "crypto/vhf1/Writer.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <memory>
#include <optional>
#include <span>
#include <vector>

namespace vh::crypto::vhf1::fuzz {

inline void require(const bool ok) {
    if (!ok) std::abort();
}

// A cursor over the fuzz input that yields zeros once exhausted.
class Input {
public:
    explicit Input(std::span<const uint8_t> data) : data_(data) {}
    uint8_t u8() { return pos_ < data_.size() ? data_[pos_++] : 0; }
    uint16_t u16() { return static_cast<uint16_t>((u8() << 8) | u8()); }
    uint32_t u32() { return (static_cast<uint32_t>(u16()) << 16) | u16(); }
    std::span<const uint8_t> rest() { return data_.subspan(std::min(pos_, data_.size())); }
    std::span<const uint8_t> take(std::size_t n) {
        const auto avail = data_.size() - std::min(pos_, data_.size());
        const auto out = data_.subspan(std::min(pos_, data_.size()), std::min(n, avail));
        pos_ += out.size();
        return out;
    }
    [[nodiscard]] bool empty() const { return pos_ >= data_.size(); }

private:
    std::span<const uint8_t> data_;
    std::size_t pos_{};
};

struct Fixture {
    SecretKeyPtr key1, key2;
    Uid vault{}, object{};
    KeyLookup keys;

    Fixture() {
        std::array<uint8_t, 32> raw{};
        for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<uint8_t>(i);
        key1 = std::make_shared<const SecretKey>(raw);
        for (std::size_t i = 0; i < raw.size(); ++i) raw[i] = static_cast<uint8_t>(32 + i);
        key2 = std::make_shared<const SecretKey>(raw);
        // The golden vectors' vault and file uids, so the vectors' objects make a useful seed corpus.
        vault = {0x56, 0x48, 0xf1, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7, 0x08, 0x19, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e};
        object = {0x9b, 0x1d, 0xeb, 0x4d, 0x3b, 0x7d, 0x4b, 0xad, 0x9b, 0xdd, 0x2b, 0x0d, 0x7b, 0x3d, 0xcb, 0x6d};
        keys = [k1 = key1, k2 = key2](const uint32_t v) -> SecretKeyPtr { return v == 1 ? k1 : v == 2 ? k2 : nullptr; };
    }

    [[nodiscard]] Expectation expect(const Kind kind = Kind::FileContent) const { return {kind, vault, object, {}}; }
};

inline const Fixture& fixture() {
    static const Fixture f;
    return f;
}

// Reads `object` every way there is. `original`, when given, is the plaintext the object was sealed from: anything
// a reader returns must be exactly that plaintext at that offset.
inline void readAllWays(const std::span<const uint8_t> object, const Expectation& expect, const KeyLookup& keys,
                        const std::vector<uint8_t>* original, Input& in) {
    const auto matches = [&](const uint64_t offset, const std::span<const uint8_t> got) {
        if (original == nullptr || got.empty()) return;  // an empty read emits nothing, so it proves nothing
        require(offset <= original->size() && got.size() <= original->size() - offset);
        require(std::equal(got.begin(), got.end(), original->begin() + static_cast<std::ptrdiff_t>(offset)));
    };

    // Whole object.
    try {
        const auto plain = open(object, expect, keys);
        require(original == nullptr || plain.size() == original->size());
        matches(0, plain.span());
    } catch (const Error&) {
    }

    // Header, then a streamed walk in input-chosen steps.
    std::optional<OpenedHeader> header;
    try {
        header = openHeader(object, expect, keys);
    } catch (const Error&) {
        return;
    }
    try {
        ChunkWalker walker(*header, object.size());
        const auto c = header->chunkSize();
        auto body = object.subspan(std::min(object.size(), kHeaderSize));
        while (!body.empty()) {
            const std::size_t step = 1 + in.u16() % 4096;
            const auto part = body.first(std::min(step, body.size()));
            walker.update(part, [&](const uint64_t i, const std::span<const uint8_t> p) { matches(i * c, p); });
            body = body.subspan(part.size());
        }
        walker.finish();
    } catch (const Error&) {
    }

    // Range reads: the authenticated size is either right or (sometimes) off by the input's choice.
    try {
        const std::optional<uint64_t> authSize =
            in.u8() % 8 == 0 ? std::nullopt : std::optional<uint64_t>(object.size() + (in.u8() % 4 == 0 ? in.u8() : 0));
        RangeReader reader(*header, authSize, object.size());
        const auto psize = reader.layout().plaintextSize;
        for (int k = 0; k < 4; ++k) {
            const uint64_t a = in.u32() % (psize + 2), b = a + in.u16() % 3000;
            try {
                const auto plan = reader.plan(a, b);
                std::span<const uint8_t> window;
                if (plan.objectRange) {
                    require(plan.objectRange->end <= object.size());
                    window = object.subspan(plan.objectRange->begin, plan.objectRange->size());
                }
                const auto got = reader.read(a, b, window);
                require(got.size() == b - a);
                matches(a, got.span());
            } catch (const Error& e) {
                if (e.code() == ErrorCode::ChunkAuthFailed) require(reader.failed());
            }
        }
    } catch (const Error&) {
    }
}

inline void mutate(std::vector<uint8_t>& obj, Input& in, const uint64_t chunkSealed) {
    const int count = in.u8() % 6;
    for (int m = 0; m < count && !obj.empty(); ++m) {
        const auto pos = static_cast<std::size_t>(in.u32() % obj.size());
        switch (in.u8() % 6) {
            case 0: obj.resize(pos); break;                                                    // truncate
            case 1: {                                                                           // extend
                const std::vector<uint8_t> tail(obj.begin() + static_cast<std::ptrdiff_t>(pos), obj.end());
                obj.insert(obj.end(), tail.begin(), tail.end());
                break;
            }
            case 2: obj[pos] ^= static_cast<uint8_t>(1u << (in.u8() % 8)); break;               // flip
            case 3: {                                                                           // swap two chunks
                const auto n = (obj.size() - std::min(obj.size(), kHeaderSize)) / chunkSealed;
                if (n < 2) break;
                const auto i = in.u8() % n, j = in.u8() % n;
                for (uint64_t k = 0; k < chunkSealed; ++k)
                    std::swap(obj[kHeaderSize + i * chunkSealed + k], obj[kHeaderSize + j * chunkSealed + k]);
                break;
            }
            case 4: obj.erase(obj.begin() + static_cast<std::ptrdiff_t>(pos),                  // cut a span out
                              obj.begin() + static_cast<std::ptrdiff_t>(std::min(obj.size(), pos + in.u16() % 2048)));
                break;
            default: {                                                                          // overwrite with input
                const auto src = in.take(in.u8());
                for (std::size_t k = 0; k < src.size() && pos + k < obj.size(); ++k) obj[pos + k] = src[k];
                break;
            }
        }
    }
}

inline void runOne(const std::span<const uint8_t> data) {
    const auto& f = fixture();
    Input in(data);
    switch (in.u8() % 3) {
        case 0: {
            const auto object = in.rest();
            Input knobs(object);
            readAllWays(object, f.expect(), f.keys, nullptr, knobs);
            break;
        }
        case 1: {
            // A header body from the input, re-tagged so it authenticates when its key version is held.
            std::vector<uint8_t> object(kHeaderSize);
            const auto src = in.take(kHeaderBodySize);
            std::ranges::copy(src, object.begin());
            std::ranges::copy(kMagic, object.begin());
            // Valid structure (version 1, length 120, suite 1, kind 1, reserved 0); chunk size and key version stay
            // the input's.
            const std::array<uint8_t, 6> fixedFields{0, 1, 0, static_cast<uint8_t>(kHeaderSize), 0, 1};
            std::ranges::copy(fixedFields, object.begin() + 8);
            object[15] = 1;
            std::fill_n(object.begin() + 20, 4, uint8_t{0});
            std::ranges::copy(f.vault, object.begin() + 24);
            std::ranges::copy(f.object, object.begin() + 40);
            const uint32_t kv = (static_cast<uint32_t>(object[16]) << 24) | (static_cast<uint32_t>(object[17]) << 16) |
                                (static_cast<uint32_t>(object[18]) << 8) | object[19];
            if (const auto key = f.keys(kv); key && object[14] >= kMinChunkLog2 && object[14] <= kMaxChunkLog2) {
                const std::span<const uint8_t, kHeaderBodySize> body(object.data(), kHeaderBodySize);
                Salt salt{};
                std::copy_n(object.begin() + 56, kSaltSize, salt.begin());
                const auto hh = headerHash(body);
                const auto tag = headerTag(*deriveKeys(*key, salt, hh).headerKey, body);
                std::ranges::copy(tag, object.begin() + kHeaderBodySize);
            }
            const auto chunks = in.take(in.u16());
            object.insert(object.end(), chunks.begin(), chunks.end());
            readAllWays(object, f.expect(), f.keys, nullptr, in);
            break;
        }
        default: {
            HeaderParams p;
            p.kind = Kind::FileContent;
            p.keyVersion = 1 + in.u8() % 2;
            p.vaultUid = f.vault;
            p.objectUid = f.object;
            const auto saltSrc = in.take(kSaltSize);
            std::ranges::copy(saltSrc, p.salt.begin());
            p.chunkLog2 = static_cast<uint8_t>(kMinChunkLog2 + in.u8() % 3);
            const auto ptext = in.take(in.u16() % 9000);
            std::vector<uint8_t> original(ptext.begin(), ptext.end());
            auto object = seal(original, p, *f.keys(p.keyVersion));
            {
                // Untouched, it must read back exactly.
                const auto plain = open(object, f.expect(), f.keys, object.size());
                require(std::ranges::equal(plain.span(), original));
            }
            mutate(object, in, chunkSizeOf(p.chunkLog2) + kTagSize);
            readAllWays(object, f.expect(), f.keys, &original, in);
            break;
        }
    }
}

}
