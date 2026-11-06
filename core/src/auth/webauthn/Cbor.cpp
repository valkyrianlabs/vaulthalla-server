#include "auth/webauthn/Cbor.hpp"

#include <cbor.h>

#include <algorithm>
#include <cstring>
#include <vector>

namespace vh::auth::webauthn::cbor {

namespace {

// A map key, compared by value: integers by sign and magnitude, text strings by content.
struct ScanKey {
    bool text = false;
    bool negative = false;
    std::uint64_t value = 0;
    ByteView bytes;

    bool operator==(const ScanKey& o) const {
        if (text != o.text) return false;
        if (text) return bytes.size() == o.bytes.size() && std::equal(bytes.begin(), bytes.end(), o.bytes.begin());
        return negative == o.negative && value == o.value;
    }
};

struct ScanFrame {
    bool map = false;
    std::uint64_t remaining = 0;  // items left: entries of an array, 2 x pairs of a map
    std::vector<ScanKey> keys;
};

bool cborValidUtf8(const std::uint8_t* p, const std::size_t n) {
    std::size_t i = 0;
    while (i < n) {
        const std::uint8_t c = p[i];
        std::size_t len = 0;
        std::uint32_t cp = 0;
        if (c < 0x80) { ++i; continue; }
        if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1F; }
        else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0F; }
        else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07; }
        else return false;
        if (n - i < len) return false;
        for (std::size_t k = 1; k < len; ++k) {
            if ((p[i + k] & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (p[i + k] & 0x3F);
        }
        // Overlong forms, surrogates and code points past U+10FFFF.
        if ((len == 2 && cp < 0x80) || (len == 3 && cp < 0x800) || (len == 4 && cp < 0x10000)) return false;
        if ((cp >= 0xD800 && cp <= 0xDFFF) || cp > 0x10FFFF) return false;
        i += len;
    }
    return true;
}

// Driven by libcbor's streaming decoder, one item header (or whole string) per call.
struct StrictScanner {
    const Limits& limits;
    std::vector<ScanFrame> stack;
    std::size_t items = 0;
    bool failed = false;
    bool done = false;

    explicit StrictScanner(const Limits& l) : limits(l) {}

    void fail() { failed = true; }

    // Accounts one item in its parent; `key` is set for integers and text strings (the only legal map keys).
    void item(const std::optional<ScanKey>& key) {
        if (failed) return;
        if (++items > limits.maxItems) return fail();
        if (!stack.empty()) {
            auto& top = stack.back();
            if (top.map && top.remaining % 2 == 0) {  // this item is a key
                if (!key) return fail();
                if (std::ranges::find(top.keys, *key) != top.keys.end()) return fail();
                top.keys.push_back(*key);
            }
            --top.remaining;
        }
    }

    void close() {
        while (!stack.empty() && stack.back().remaining == 0) stack.pop_back();
        if (stack.empty()) done = true;
    }

    void scalar(const std::optional<ScanKey>& key = std::nullopt) {
        item(key);
        if (!failed) close();
    }

    void container(const bool map, const std::uint64_t count) {
        item(std::nullopt);
        if (failed) return;
        if (count > limits.maxContainerSize) return fail();
        if (count == 0) return close();
        if (stack.size() + 1 > limits.maxDepth) return fail();
        stack.push_back({map, map ? count * 2 : count, {}});
    }
};

StrictScanner& scanner(void* p) { return *static_cast<StrictScanner*>(p); }

void onUnsigned(void* p, const std::uint64_t v) { scanner(p).scalar(ScanKey{false, false, v, {}}); }
void onNegative(void* p, const std::uint64_t v) { scanner(p).scalar(ScanKey{false, true, v, {}}); }
void onRefused(void* p) { scanner(p).fail(); }

cbor_callbacks makeStrictCallbacks() {
    cbor_callbacks cb = cbor_empty_callbacks;
    // Generic lambdas convert to whichever integer width this libcbor declares.
    cb.uint8 = [](void* p, auto v) { onUnsigned(p, v); };
    cb.uint16 = [](void* p, auto v) { onUnsigned(p, v); };
    cb.uint32 = [](void* p, auto v) { onUnsigned(p, v); };
    cb.uint64 = [](void* p, auto v) { onUnsigned(p, v); };
    cb.negint8 = [](void* p, auto v) { onNegative(p, v); };
    cb.negint16 = [](void* p, auto v) { onNegative(p, v); };
    cb.negint32 = [](void* p, auto v) { onNegative(p, v); };
    cb.negint64 = [](void* p, auto v) { onNegative(p, v); };
    cb.byte_string = [](void* p, cbor_data, auto) { scanner(p).scalar(); };
    cb.string = [](void* p, cbor_data data, auto len) {
        if (!cborValidUtf8(data, static_cast<std::size_t>(len))) return scanner(p).fail();
        scanner(p).scalar(ScanKey{true, false, 0, ByteView(data, static_cast<std::size_t>(len))});
    };
    cb.array_start = [](void* p, auto n) { scanner(p).container(false, n); };
    cb.map_start = [](void* p, auto n) { scanner(p).container(true, n); };
    cb.boolean = [](void* p, bool) { scanner(p).scalar(); };
    cb.null = [](void* p) { scanner(p).scalar(); };
    cb.byte_string_start = onRefused;
    cb.string_start = onRefused;
    cb.indef_array_start = onRefused;
    cb.indef_map_start = onRefused;
    cb.indef_break = onRefused;
    cb.undefined = onRefused;
    cb.tag = [](void* p, auto) { scanner(p).fail(); };
    cb.float2 = [](void* p, auto) { scanner(p).fail(); };
    cb.float4 = [](void* p, auto) { scanner(p).fail(); };
    cb.float8 = [](void* p, auto) { scanner(p).fail(); };
    return cb;
}

const cbor_callbacks kStrictCallbacks = makeStrictCallbacks();

}

std::optional<std::size_t> scan(const ByteView in, const Limits& limits) {
    StrictScanner s(limits);
    std::size_t offset = 0;
    while (!s.done) {
        if (offset >= in.size()) return std::nullopt;
        const auto r = cbor_stream_decode(in.data() + offset, in.size() - offset, &kStrictCallbacks, &s);
        if (r.status != CBOR_DECODER_FINISHED || r.read == 0 || s.failed) return std::nullopt;
        offset += r.read;
    }
    return offset;
}

void ItemDeleter::operator()(cbor_item_t* item) const {
    if (item) cbor_decref(&item);
}

Item decode(const ByteView in, const Limits& limits) {
    const auto length = scan(in, limits);
    if (!length || *length != in.size()) return nullptr;
    cbor_load_result result{};
    Item item(cbor_load(in.data(), in.size(), &result));
    if (!item || result.error.code != CBOR_ERR_NONE || result.read != in.size()) return nullptr;
    return item;
}

std::optional<std::int64_t> asInt(const cbor_item_t* item) {
    if (!item) return std::nullopt;
    auto* it = const_cast<cbor_item_t*>(item);
    if (cbor_isa_uint(it)) {
        const auto v = cbor_get_int(it);
        if (v > static_cast<std::uint64_t>(INT64_MAX)) return std::nullopt;
        return static_cast<std::int64_t>(v);
    }
    if (cbor_isa_negint(it)) {
        const auto v = cbor_get_int(it);  // the value is -1 - v
        if (v > static_cast<std::uint64_t>(INT64_MAX)) return std::nullopt;
        return -1 - static_cast<std::int64_t>(v);
    }
    return std::nullopt;
}

std::optional<ByteView> asBytes(const cbor_item_t* item) {
    auto* it = const_cast<cbor_item_t*>(item);
    if (!it || !cbor_isa_bytestring(it) || !cbor_bytestring_is_definite(it)) return std::nullopt;
    const auto n = cbor_bytestring_length(it);
    if (n == 0) return ByteView{};
    return ByteView(cbor_bytestring_handle(it), n);
}

std::optional<std::string_view> asText(const cbor_item_t* item) {
    auto* it = const_cast<cbor_item_t*>(item);
    if (!it || !cbor_isa_string(it) || !cbor_string_is_definite(it)) return std::nullopt;
    const auto n = cbor_string_length(it);
    if (n == 0) return std::string_view{};
    return std::string_view(reinterpret_cast<const char*>(cbor_string_handle(it)), n);
}

bool isMap(const cbor_item_t* item) {
    auto* it = const_cast<cbor_item_t*>(item);
    return it && cbor_isa_map(it) && cbor_map_is_definite(it);
}

bool isArray(const cbor_item_t* item) {
    auto* it = const_cast<cbor_item_t*>(item);
    return it && cbor_isa_array(it) && cbor_array_is_definite(it);
}

std::size_t size(const cbor_item_t* item) {
    auto* it = const_cast<cbor_item_t*>(item);
    if (isMap(it)) return cbor_map_size(it);
    if (isArray(it)) return cbor_array_size(it);
    return 0;
}

const cbor_item_t* arrayAt(const cbor_item_t* array, const std::size_t i) {
    if (!isArray(array) || i >= size(array)) return nullptr;
    return cbor_array_handle(const_cast<cbor_item_t*>(array))[i];
}

const cbor_item_t* mapKeyAt(const cbor_item_t* map, const std::size_t i) {
    if (!isMap(map) || i >= size(map)) return nullptr;
    return cbor_map_handle(const_cast<cbor_item_t*>(map))[i].key;
}

const cbor_item_t* mapValueAt(const cbor_item_t* map, const std::size_t i) {
    if (!isMap(map) || i >= size(map)) return nullptr;
    return cbor_map_handle(const_cast<cbor_item_t*>(map))[i].value;
}

const cbor_item_t* find(const cbor_item_t* map, const std::int64_t key) {
    for (std::size_t i = 0; i < size(map); ++i)
        if (const auto k = asInt(mapKeyAt(map, i)); k && *k == key) return mapValueAt(map, i);
    return nullptr;
}

const cbor_item_t* find(const cbor_item_t* map, const std::string_view key) {
    for (std::size_t i = 0; i < size(map); ++i)
        if (const auto k = asText(mapKeyAt(map, i)); k && *k == key) return mapValueAt(map, i);
    return nullptr;
}

}
