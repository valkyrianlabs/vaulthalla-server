#pragma once

#include <algorithm>
#include <cstdint>
#include <functional>
#include <limits>
#include <memory>
#include <optional>
#include <random>
#include <regex>
#include <sstream>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <variant>
#include <vector>

namespace vh::args {

// -------------------------------------------------------------------------------------------------
// Core context and RNG utilities
// -------------------------------------------------------------------------------------------------
struct GenContext {
  std::string token;       // e.g. "name", "email"
  std::string usage_path;  // e.g. "user/create"
};

class Rng {
 public:
  explicit Rng(const uint64_t seed) : eng_(seed) {}
  template <class Int>
  Int uniform_int(Int lo, Int hi) {
    std::uniform_int_distribution<Int> d(lo, hi);
    return d(eng_);
  }
  double uniform01() { return std::uniform_real_distribution<double>(0.0, 1.0)(eng_); }
  std::mt19937_64 &engine() { return eng_; }

 private:
  std::mt19937_64 eng_;
};

inline uint64_t stable_seed(std::string_view a, std::string_view b) {
  // FNV-1a 64-bit
  constexpr uint64_t kOffset = 1469598103934665603ull;
  constexpr uint64_t kPrime = 1099511628211ull;
  uint64_t h = kOffset;
  auto mix = [&](std::string_view s) {
    for (unsigned char c : s) {
      h ^= c;
      h *= kPrime;
    }
  };
  mix(a);
  h ^= 0xff;  // separator
  h *= kPrime;
  mix(b);
  // Stable by design: the same (token, usage) always seeds the same sequence. Callers that want variety derive it
  // from a printed run seed (the integration harness does), never from the clock.
  return h;
}

// -------------------------------------------------------------------------------------------------
// IGenerator interface + handle type
// -------------------------------------------------------------------------------------------------
using Value = std::variant<std::string, int64_t, uint64_t, double, bool>;

inline std::string to_string_value(const Value &v) {
  struct V {
    std::string operator()(const std::string &s) const { return s; }
    std::string operator()(int64_t x) const { return std::to_string(x); }
    std::string operator()(uint64_t x) const { return std::to_string(x); }
    std::string operator()(double x) const {
      std::ostringstream oss;
      oss.setf(std::ios::fixed); oss.precision(6);
      oss << x; return oss.str();
    }
    std::string operator()(bool b) const { return b ? "true" : "false"; }
  };
  return std::visit(V{}, v);
}

struct IGenerator {
  virtual ~IGenerator() = default;
  virtual Value generate(Rng &rng, const GenContext &ctx) const = 0;
};

using Gen = std::shared_ptr<const IGenerator>;

// -------------------------------------------------------------------------------------------------
// Primitive generators
// -------------------------------------------------------------------------------------------------
class Const : public IGenerator {
 public:
  explicit Const(Value v) : v_(std::move(v)) {}
  Value generate(Rng &, const GenContext &) const override { return v_; }
 private:
  Value v_;
};

class OneOf : public IGenerator {
 public:
  explicit OneOf(std::vector<Value> options) : opts_(std::move(options)) {}
  Value generate(Rng &rng, const GenContext &) const override {
    if (opts_.empty()) return std::string{};
    auto idx = rng.uniform_int<size_t>(0, opts_.size() - 1);
    return opts_[idx];
  }
 private:
  std::vector<Value> opts_;
};

class WeightedOneOf : public IGenerator {
 public:
  explicit WeightedOneOf(std::vector<std::pair<Value, double>> weighted)
      : items_(std::move(weighted)) {}
  Value generate(Rng &rng, const GenContext &) const override {
    if (items_.empty()) return std::string{};
    double total = 0.0; for (auto &p : items_) total += p.second;
    double r = rng.uniform01() * total;
    for (auto &p : items_) { if ((r -= p.second) <= 0.0) return p.first; }
    return items_.back().first;
  }
 private:
  std::vector<std::pair<Value, double>> items_;
};

class IntRange : public IGenerator {
 public:
  IntRange(int64_t lo, int64_t hi) : lo_(lo), hi_(hi) {}
  Value generate(Rng &rng, const GenContext &) const override {
    return static_cast<int64_t>(rng.uniform_int<int64_t>(lo_, hi_));
  }
 private:
  int64_t lo_, hi_;
};

class Bool : public IGenerator {
 public:
  explicit Bool(double true_prob = 0.5) : p_(true_prob) {}
  Value generate(Rng &rng, const GenContext &) const override {
    return rng.uniform01() < p_;
  }
 private:
  double p_;
};

class RandomString : public IGenerator {
 public:
  struct Spec {
    size_t min_length{1};
    size_t max_length{16};
    std::string alphabet =
        "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    // Insert separators at the given 0-based positions (pre-insertion positions).
    char separator{'-'};
    std::vector<size_t> separator_positions;  // e.g. {8, 13, 18}
  };

  explicit RandomString(Spec s) : s_(std::move(s)) {}

  Value generate(Rng &rng, const GenContext &) const override {
    if (s_.min_length > s_.max_length) std::swap(const_cast<size_t&>(s_.min_length), const_cast<size_t&>(s_.max_length));
    const size_t len = rng.uniform_int<size_t>(s_.min_length, s_.max_length);
    std::string out; out.reserve(len + s_.separator_positions.size());
    for (size_t i = 0, sep_i = 0; i < len; ++i) {
      if (sep_i < s_.separator_positions.size() && s_.separator_positions[sep_i] == i) {
        out.push_back(s_.separator); ++sep_i;
      }
      const auto idx = rng.uniform_int<size_t>(0, s_.alphabet.size() - 1);
      out.push_back(s_.alphabet[idx]);
    }
    return out;
  }

 private:
  Spec s_;
};

class RegexLike final : public IGenerator {
 public:
  // Extremely small subset: tokens: {A}=alpha, {a}=lower, {9}=digit, {*}=any, literal otherwise.
  // Example: "user_{a}{a}{9}{9}".
  explicit RegexLike(std::string mask) : mask_(std::move(mask)) {}
  Value generate(Rng &rng, const GenContext &) const override {
    auto any_of = [&](std::string_view alpha) {
      return alpha[rng.uniform_int<size_t>(0, alpha.size() - 1)];
    };
    static const std::string ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    static const std::string ALPHA_L = "abcdefghijklmnopqrstuvwxyz";
    static const std::string DIGIT = "0123456789";
    static const std::string ANY = ALPHA + ALPHA_L + DIGIT + "-_";

    std::string out; out.reserve(mask_.size());
    for (size_t i = 0; i < mask_.size(); ++i) {
      if (mask_[i] == '{') {
        size_t j = mask_.find('}', i + 1);
        if (j == std::string::npos) break;  // malformed → stop
        const auto tok = mask_.substr(i + 1, j - i - 1);
        if (tok == "A") out.push_back(any_of(ALPHA));
        else if (tok == "a") out.push_back(any_of(ALPHA_L));
        else if (tok == "9") out.push_back(any_of(DIGIT));
        else if (tok == "*") out.push_back(any_of(ANY));
        else { /* literal passthrough */ out.append("{").append(tok).append("}"); }
        i = j;  // jump to closing brace
      } else {
        out.push_back(mask_[i]);
      }
    }
    return out;
  }
 private:
  std::string mask_;
};

class Join final : public IGenerator {
 public:
  Join(std::vector<Gen> parts, std::string delimiter)
      : parts_(std::move(parts)), delim_(std::move(delimiter)) {}
  Value generate(Rng &rng, const GenContext &ctx) const override {
    std::ostringstream oss;
    for (size_t i = 0; i < parts_.size(); ++i) {
      if (i) oss << delim_;
      oss << to_string_value(parts_[i]->generate(rng, ctx));
    }
    return oss.str();
  }
 private:
  std::vector<Gen> parts_;
  std::string delim_;
};

class Transform : public IGenerator {
 public:
  using Fn = std::function<Value(const Value &, Rng &, const GenContext &)>;
  Transform(Gen base, Fn fn) : base_(std::move(base)), fn_(std::move(fn)) {}
  Value generate(Rng &rng, const GenContext &ctx) const override {
    Value v = base_->generate(rng, ctx);
    return fn_(v, rng, ctx);
  }
 private:
  Gen base_;
  Fn fn_;
};

class UUIDv4 : public IGenerator {
 public:
  Value generate(Rng &rng, const GenContext &) const override {
    auto hex = [&](int n) {
      static const char *H = "0123456789abcdef";
      std::string s; s.reserve(n);
      for (int i = 0; i < n; ++i) s.push_back(H[rng.uniform_int<int>(0, 15)]);
      return s;
    };
    std::ostringstream oss;
    oss << hex(8) << '-' << hex(4) << '-' << '4' << hex(3) << '-'
        << ((rng.uniform_int<int>(0, 3) | 0x8)) << hex(3) << '-' << hex(12);
    return oss.str();
  }
};

// -------------------------------------------------------------------------------------------------
// Builder helpers (fluent, convenient names)
// -------------------------------------------------------------------------------------------------
struct ArgGenerator {
  static Gen Constant(Value v) { return std::make_shared<Const>(std::move(v)); }
  static Gen OneOf(std::vector<Value> options) { return std::make_shared<class OneOf>(std::move(options)); }
  static Gen Weighted(std::vector<std::pair<Value, double>> weighted) { return std::make_shared<WeightedOneOf>(std::move(weighted)); }
  static Gen RandomInt(int64_t lo, int64_t hi) { return std::make_shared<IntRange>(lo, hi); }
  static Gen RandomBool(double true_prob = 0.5) { return std::make_shared<Bool>(true_prob); }
  static Gen RandomString(size_t min_len, size_t max_len, std::string alphabet = {}, char sep='\0', std::vector<size_t> positions = {}) {
    RandomString::Spec s; s.min_length = min_len; s.max_length = max_len;
    if (!alphabet.empty()) s.alphabet = std::move(alphabet);
    s.separator = (sep == '\0') ? '-' : sep; s.separator_positions = std::move(positions);
    return std::make_shared<class RandomString>(std::move(s));
  }
  static Gen RegexMask(std::string mask) { return std::make_shared<class RegexLike>(std::move(mask)); }
  static Gen Join(std::vector<Gen> parts, std::string delim) { return std::make_shared<class Join>(std::move(parts), std::move(delim)); }
  static Gen Transform(Gen base, Transform::Fn fn) { return std::make_shared<class Transform>(std::move(base), std::move(fn)); }
  static Gen UUID() { return std::make_shared<class UUIDv4>(); }
};

// -------------------------------------------------------------------------------------------------
// ArgsGenerator: token → generator registry with sensible defaults
// -------------------------------------------------------------------------------------------------
class ArgsGenerator {
 public:
  using Map = std::unordered_map<std::string, Gen>;

  ArgsGenerator() = default;
  explicit ArgsGenerator(Map m) : map_(std::move(m)) {}

  // Register or override per-token generator.
  ArgsGenerator &set(std::string token, Gen g) {
    map_[std::move(token)] = std::move(g);
    return *this;
  }

  // Generate a value for the token; returns nullopt if no generator registered.
  std::optional<std::string> valueFor(const std::string &token,
                                      const std::string &usage_path) const {
    auto it = map_.find(token);
    if (it == map_.end()) return std::nullopt;
    Rng rng(stable_seed(token, usage_path));
    GenContext ctx{token, usage_path};
    return to_string_value(it->second->generate(rng, ctx));
  }

  // Convenience: provide a reasonable default set you can extend.
  static ArgsGenerator WithDefaults() {
    ArgsGenerator g;
    const std::string ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789";

    g.set("name", ArgGenerator::Join({
              ArgGenerator::Constant(std::string("user_")),
              ArgGenerator::RandomString(6, 10, ALNUM)
            }, ""));

    g.set("username", g.map_["name"]);

    g.set("new_name", ArgGenerator::Join({
              ArgGenerator::Constant(std::string("user_new_")),
              ArgGenerator::RandomString(6, 10, ALNUM)
            }, ""));

    g.set("email", ArgGenerator::Join({
              ArgGenerator::RandomString(6, 10, ALNUM),
              ArgGenerator::Constant(std::string("@example.org"))
            }, ""));

    g.set("role", ArgGenerator::OneOf({std::string("admin"), std::string("user"), std::string("viewer")}));

    g.set("uid", ArgGenerator::RandomInt(1000, 65000));
    g.set("linux-uid", g.map_["uid"]);
    g.set("vault_id", ArgGenerator::RandomInt(1, 5));
    g.set("id", g.map_["vault_id"]);

    g.set("quota", ArgGenerator::OneOf({std::string("5G"), std::string("10G"), std::string("25G"), std::string("100G")}));
    g.set("permissions", ArgGenerator::RandomInt(0, 0xFFFF));

    g.set("accessKey", ArgGenerator::RegexMask("{a}{a}{a}{a}{9}{9}{9}-{A}{A}{9}{9}{9}-{*}{*}{*}{*}{*}{*}{*}{*}"));
    g.set("secret", ArgGenerator::Join({ArgGenerator::UUID(), ArgGenerator::UUID()}, "-"));

    g.set("region", ArgGenerator::OneOf({std::string("us-west-1"), std::string("us-east-1"), std::string("eu-central-1")}));
    g.set("endpoint", ArgGenerator::Join({
              ArgGenerator::Constant(std::string("https://s3.")),
              ArgGenerator::OneOf({std::string("example.org"), std::string("local"), std::string("corp")})
            }, ""));

    g.set("pattern", ArgGenerator::Constant(std::string("^/path/to/something/.*$")));
    g.set("provider", ArgGenerator::OneOf({std::string("aws"), std::string("r2"), std::string("minio")}));

    return g;
  }

 private:
  Map map_;
};

// -------------------------------------------------------------------------------------------------
// Adapter to existing ArgValueProvider interface
// -------------------------------------------------------------------------------------------------
class ArgValueProvider {
 public:
  virtual ~ArgValueProvider() = default;
  virtual std::optional<std::string> valueFor(const std::string &token,
                                              const std::string &usage_path) = 0;
};

class ArgsGeneratorProvider : public ArgValueProvider {
 public:
  explicit ArgsGeneratorProvider(ArgsGenerator g) : g_(std::move(g)) {}
  std::optional<std::string> valueFor(const std::string &token,
                                      const std::string &usage_path) override {
    return g_.valueFor(token, usage_path);
  }
 private:
  ArgsGenerator g_;
};

// -------------------------------------------------------------------------------------------------
// Example presets & combinators for common CLI shapes
// -------------------------------------------------------------------------------------------------
inline Gen Email(std::string domain = "example.org") {
  const std::string ALNUM = "abcdefghijklmnopqrstuvwxyz0123456789";
  return ArgGenerator::Join({
      ArgGenerator::RandomString(6, 12, ALNUM),
      ArgGenerator::Constant(std::string("@" + domain))
  }, "");
}

inline Gen Slug(size_t min_len = 8, size_t max_len = 16) {
  const std::string ALPHA = "abcdefghijklmnopqrstuvwxyz";
  return ArgGenerator::RandomString(min_len, max_len, ALPHA + "0123456789", '-', {4, 9});
}

inline Gen HumanName() {
  return ArgGenerator::Join({
      ArgGenerator::RegexMask("{A}{a}{a}{a}{a}"),
      ArgGenerator::RegexMask("{A}{a}{a}{a}{a}")
  }, " ");
}

inline Gen Quota() {
    return ArgGenerator::OneOf({std::string("5G"), std::string("10G"), std::string("25G"), std::string("100G"), std::string("unlimited"), std::string("1T"), std::string("500M")});
}

}
