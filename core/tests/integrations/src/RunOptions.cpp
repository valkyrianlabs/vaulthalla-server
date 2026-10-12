#include "RunOptions.hpp"
#include "cmd/generators.hpp"
#include "seed/H64.hpp"

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <random>
#include <thread>

namespace vh::test::integration {

namespace {

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

std::string env(const char* key) {
    const char* v = std::getenv(key);
    return v ? std::string(v) : std::string();
}

std::optional<std::pair<std::string, cli::Config>> configNamed(const std::string& name) {
    if (name.empty() || name == "minimal") return std::pair{std::string("minimal"), cli::Config::Minimal()};
    if (name == "default") return std::pair{name, cli::Config::Default()};
    if (name == "medium") return std::pair{name, cli::Config::Medium()};
    if (name == "large") return std::pair{name, cli::Config::Large()};
    if (name == "extralarge" || name == "extra_large") return std::pair{std::string("extralarge"), cli::Config::ExtraLarge()};
    if (name == "ng_stress" || name == "stress") return std::pair{std::string("ng_stress"), cli::Config::NG_STRESS()};
    return std::nullopt;
}

}

bool RunOptions::has(const std::string_view stage) const {
    return std::ranges::find(stages, stage) != stages.end();
}

std::string RunOptions::stagesText() const {
    std::string out;
    for (const auto& s : stages) out += (out.empty() ? "" : ",") + s;
    return out.empty() ? "(none)" : out;
}

std::string RunOptions::negativeControlText() const {
    switch (negativeControl) {
        case NegativeControl::Assertion: return "assertion";
        case NegativeControl::Oracle: return "oracle";
        default: return "none";
    }
}

std::optional<RunOptions> RunOptions::fromEnv(std::string& error) {
    RunOptions o;
    o.reportDir = env("VH_TEST_REPORT_DIR");

    if (const auto text = env("VH_TEST_SEED"); !text.empty()) {
        const auto parsed = seed::parseSeed(text);
        if (!parsed) {
            error = "VH_TEST_SEED must be a 64-bit decimal or 0x-hex number, got '" + text + "'";
            return std::nullopt;
        }
        o.seed = *parsed;
        o.seedFromEnv = true;
    } else {
        // The one place entropy enters a run, and it is printed in the header, the summary and the reports.
        std::random_device rd;
        o.seed = (static_cast<uint64_t>(rd()) << 32) ^ static_cast<uint64_t>(rd());
    }

    const auto cfg = configNamed(lower(env("VH_TEST_CONFIG")));
    if (!cfg) {
        error = "VH_TEST_CONFIG must be one of minimal, default, medium, large, extralarge, ng_stress";
        return std::nullopt;
    }
    o.configName = cfg->first;
    o.config = cfg->second;

    const auto nc = lower(env("VH_TEST_NEGATIVE_CONTROL"));
    if (nc == "assertion") o.negativeControl = NegativeControl::Assertion;
    else if (nc == "oracle") o.negativeControl = NegativeControl::Oracle;
    else if (!nc.empty() && nc != "none") {
        error = "VH_TEST_NEGATIVE_CONTROL must be assertion or oracle";
        return std::nullopt;
    }

    std::vector<std::string> wanted;
    const auto stagesEnv = lower(env("VH_TEST_STAGES"));
    if (stagesEnv.empty() || stagesEnv == "all") {
        for (const auto s : kStages) wanted.emplace_back(s);
    } else {
        std::string_view rest = stagesEnv;
        while (!rest.empty()) {
            const auto comma = rest.find(',');
            const auto item = std::string(rest.substr(0, comma));
            rest = comma == std::string_view::npos ? std::string_view{} : rest.substr(comma + 1);
            if (item.empty()) continue;
            if (std::ranges::find(kStages, item) == kStages.end()) {
                error = "VH_TEST_STAGES: unknown stage '" + item + "' (stages: seed,assign,read,update,validate,fuse,teardown)";
                return std::nullopt;
            }
            wanted.push_back(item);
        }
    }
    auto want = [&](const std::string_view s) { return std::ranges::find(wanted, s) != wanted.end(); };
    if (o.negativeControl == NegativeControl::Assertion && !want("read")) wanted.emplace_back("read");
    if (o.negativeControl == NegativeControl::Oracle && !want("validate")) wanted.emplace_back("validate");
    for (const auto s : {"assign", "read", "update", "validate", "teardown"})
        if (want(s) && !want("seed")) wanted.emplace_back("seed");
    for (const auto s : kStages)
        if (want(s)) o.stages.emplace_back(s);

    o.uidBase = kDefaultLinuxIdBase;
    if (const auto text = env("VH_TEST_UID_BASE"); !text.empty()) {
        const auto parsed = seed::parseSeed(text);
        if (!parsed || *parsed > UINT32_MAX) {
            error = "VH_TEST_UID_BASE must be a 32-bit number";
            return std::nullopt;
        }
        o.uidBase = static_cast<uint32_t>(*parsed);
    }

    o.seedThreads = std::max(1u, std::thread::hardware_concurrency() / 2);
    if (const auto text = env("VH_TEST_SEED_THREADS"); !text.empty()) {
        const auto parsed = seed::parseSeed(text);
        if (!parsed || *parsed == 0 || *parsed > 256) {
            error = "VH_TEST_SEED_THREADS must be between 1 and 256";
            return std::nullopt;
        }
        o.seedThreads = static_cast<unsigned int>(*parsed);
    }

    return o;
}

}
