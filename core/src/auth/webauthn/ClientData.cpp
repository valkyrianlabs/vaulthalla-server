#include "auth/webauthn/ClientData.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <utility>
#include <vector>

namespace vh::auth::webauthn::clientdata {

namespace {

using Json = nlohmann::json;

// A SAX consumer: validates the structure as it streams and keeps only the top-level members the verifier reads.
class StrictClientData {
public:
    ClientData out;
    bool sawType = false, sawChallenge = false, sawOrigin = false;

    bool null() { return value(Kind::Other); }
    bool boolean(const bool v) {
        if (!value(Kind::Bool)) return false;
        if (topLevel() && pending_ == "crossOrigin") out.crossOrigin = v;
        return true;
    }
    bool number_integer(Json::number_integer_t) { return value(Kind::Other); }
    bool number_unsigned(Json::number_unsigned_t) { return value(Kind::Other); }
    bool number_float(Json::number_float_t, const Json::string_t&) { return value(Kind::Other); }
    bool binary(Json::binary_t&) { return false; }
    bool string(Json::string_t& v) {
        if (!value(Kind::String)) return false;
        if (!topLevel()) return true;
        if (pending_ == "type") { out.type = v; sawType = true; }
        else if (pending_ == "challenge") { out.challenge = v; sawChallenge = true; }
        else if (pending_ == "origin") { out.origin = v; sawOrigin = true; }
        else if (pending_ == "topOrigin") out.topOrigin = v;
        return true;
    }
    bool start_object(std::size_t) {
        if (!value(Kind::Other)) return false;
        return push(true);
    }
    bool end_object() { return pop(); }
    bool start_array(std::size_t) {
        if (!value(Kind::Other)) return false;
        return push(false);
    }
    bool end_array() { return pop(); }
    bool key(Json::string_t& k) {
        if (stack_.empty() || !stack_.back().object) return false;
        auto& keys = stack_.back().keys;
        if (std::ranges::find(keys, k) != keys.end()) return false;  // duplicate member
        keys.push_back(k);
        if (stack_.size() == 1) pending_ = k;
        return true;
    }
    bool parse_error(std::size_t, const std::string&, const nlohmann::detail::exception&) { return false; }

private:
    enum class Kind { String, Bool, Other };
    struct Frame {
        bool object = false;
        std::vector<std::string> keys;
    };
    std::vector<Frame> stack_;
    std::string pending_;
    bool started_ = false;

    [[nodiscard]] bool topLevel() const { return stack_.size() == 1; }

    // Accounts one value (or the start of a container) at the current position.
    bool value(const Kind kind) {
        if (stack_.empty()) {
            // The document itself: exactly one top-level object (start_object pushes it).
            if (started_) return false;
            started_ = true;
            return true;
        }
        if (stack_.size() != 1 || !stack_.back().object) return true;  // nested: structure only
        const std::string key = std::exchange(pending_, {});
        const bool wantString = key == "type" || key == "challenge" || key == "origin" || key == "topOrigin";
        const bool wantBool = key == "crossOrigin";
        if (wantString && kind != Kind::String) return false;
        if (wantBool && kind != Kind::Bool) return false;
        // Restore for string()/boolean(), which read the key right after this check.
        pending_ = key;
        return true;
    }

    bool push(const bool object) {
        if (stack_.empty() && !object) return false;  // the document must be an object
        stack_.push_back({object, {}});
        return stack_.size() <= kMaxDepth;
    }

    bool pop() {
        if (stack_.empty()) return false;
        stack_.pop_back();
        pending_.clear();
        return true;
    }
};

}

std::optional<ClientData> parse(const ByteView json) {
    if (json.empty() || json.size() > kMaxBytes) return std::nullopt;
    if (json.size() >= 3 && json[0] == 0xEF && json[1] == 0xBB && json[2] == 0xBF) return std::nullopt;  // BOM
    StrictClientData sax;
    const bool ok = Json::sax_parse(json.begin(), json.end(), &sax, nlohmann::detail::input_format_t::json,
                                    /*strict=*/true, /*ignore_comments=*/false);
    if (!ok || !sax.sawType || !sax.sawChallenge || !sax.sawOrigin) return std::nullopt;
    return std::move(sax.out);
}

}
