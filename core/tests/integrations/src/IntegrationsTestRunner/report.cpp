#include "IntegrationsTestRunner.hpp"
#include "TestCase.hpp"
#include "fuse/Actor.hpp"
#include "seed/H64.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>

// Machine-readable results in VH_TEST_REPORT_DIR: report.json (seed, config, every test with status, message,
// duration and the command that ran) and junit.xml for CI viewers.
namespace vh::test::integration {

namespace {

constexpr std::size_t kOutputExcerpt = 4096;

std::string excerpt(const std::string& s) {
    if (s.size() <= kOutputExcerpt) return s;
    return s.substr(0, kOutputExcerpt) + "\n... (" + std::to_string(s.size() - kOutputExcerpt) + " more bytes)";
}

std::string isoTime(const std::chrono::system_clock::time_point tp) {
    const auto t = std::chrono::system_clock::to_time_t(tp);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
    return buf;
}

std::string xmlEscape(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    for (const char c : in) {
        switch (c) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            case '\'': out += "&apos;"; break;
            default:
                // XML 1.0 forbids most control characters even escaped.
                if (static_cast<unsigned char>(c) < 0x20 && c != '\n' && c != '\t' && c != '\r') out += "?";
                else out += c;
        }
    }
    return out;
}

bool writeFile(const std::filesystem::path& p, const std::string& content) {
    const auto tmp = p.string() + ".tmp";
    {
        std::ofstream out(tmp, std::ios::binary | std::ios::trunc);
        if (!out) return false;
        out << content;
        if (!out.good()) return false;
    }
    std::error_code ec;
    std::filesystem::rename(tmp, p, ec);
    return !ec;
}

}

void IntegrationsTestRunner::writeReports(const int exitStatus) const {
    if (options_.reportDir.empty()) {
        std::cout << "Reports: VH_TEST_REPORT_DIR is not set, no report.json / junit.xml written" << std::endl;
        return;
    }

    const auto finishedAt = std::chrono::system_clock::now();
    const auto durationMs = std::chrono::duration<double, std::milli>(finishedAt - startedAt_).count();

    nlohmann::json report;
    report["schema"] = "vh-integration-report/1";
    report["seed"] = seed::fmtSeed(options_.seed);
    report["seed_source"] = options_.seedFromEnv ? "VH_TEST_SEED" : "random";
    report["config"] = {
        {"name", options_.configName},
        {"users", config_.numUsers},
        {"vaults", config_.numVaults},
        {"groups", config_.numGroups},
        {"admin_roles", config_.numAdminRoles},
        {"vault_roles", config_.numVaultRoles},
    };
    report["stages_selected"] = options_.stages;
    report["negative_control"] = options_.negativeControlText();
    report["uid_base"] = options_.uidBase;
    report["seed_threads"] = options_.seedThreads;
    report["fs_op_timeout_ms"] = fuse::opTimeout().count();
    report["started_at"] = isoTime(startedAt_);
    report["duration_ms"] = durationMs;

    int total = 0, failed = 0;
    nlohmann::json stages = nlohmann::json::array();
    std::ostringstream junitCases;
    for (const auto& stage : stages_) {
        nlohmann::json tests = nlohmann::json::array();
        int stageFailed = 0;
        double stageMs = 0;
        std::ostringstream cases;
        for (const auto& t : stage.tests) {
            if (!t) continue;
            ++total;
            const bool ok = t->assertion.ok;
            if (!ok) {
                ++failed;
                ++stageFailed;
            }
            stageMs += t->duration_ms;
            nlohmann::json j{
                {"name", t->name},
                {"path", t->path},
                {"status", ok ? "pass" : "fail"},
                {"message", t->assertion.message},
                {"duration_ms", t->duration_ms},
                {"command", t->command},
                {"exit_code", t->result.exit_code},
                {"expect_exit", t->expect_exit},
                {"stream", t->stream},
                {"stream_index", t->streamIndex},
                {"wedge", t->wedge},
            };
            if (!ok) {
                j["stdout"] = excerpt(t->result.stdout_text);
                j["stderr"] = excerpt(t->result.stderr_text);
            }
            tests.push_back(std::move(j));

            cases << "    <testcase classname=\"" << xmlEscape(stage.name) << "\" name=\"" << xmlEscape(t->name)
                  << "\" time=\"" << t->duration_ms / 1000.0 << "\">\n";
            if (!ok) {
                const auto firstLine = t->assertion.message.substr(0, t->assertion.message.find('\n'));
                cases << "      <failure message=\"" << xmlEscape(firstLine) << "\">"
                      << xmlEscape(t->assertion.message + "\n\nstderr:\n" + excerpt(t->result.stderr_text))
                      << "</failure>\n";
            }
            cases << "      <system-out>" << xmlEscape("command: " + t->command) << "</system-out>\n";
            cases << "    </testcase>\n";
        }
        stages.push_back({{"name", stage.name}, {"tests", std::move(tests)}});
        junitCases << "  <testsuite name=\"" << xmlEscape(stage.name) << "\" tests=\"" << stage.tests.size()
                   << "\" failures=\"" << stageFailed << "\" time=\"" << stageMs / 1000.0 << "\">\n"
                   << cases.str() << "  </testsuite>\n";
    }

    report["summary"] = {
        {"total", total},
        {"passed", total - failed},
        {"failed", failed},
        {"wedges", fuse::wedgeCount()},
        {"unreaped_actors", fuse::unreapedActors().size()},
    };
    report["exit_code"] = exitStatus;
    report["stages"] = std::move(stages);

    std::ostringstream junit;
    junit << "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
          << "<testsuites name=\"vh_integration_tests\" tests=\"" << total << "\" failures=\"" << failed
          << "\" time=\"" << durationMs / 1000.0 << "\">\n"
          << "  <properties>\n"
          << "    <property name=\"seed\" value=\"" << seed::fmtSeed(options_.seed) << "\"/>\n"
          << "    <property name=\"config\" value=\"" << xmlEscape(options_.configName) << "\"/>\n"
          << "    <property name=\"stages\" value=\"" << xmlEscape(options_.stagesText()) << "\"/>\n"
          << "    <property name=\"negative_control\" value=\"" << options_.negativeControlText() << "\"/>\n"
          << "  </properties>\n"
          << junitCases.str() << "</testsuites>\n";

    const std::filesystem::path dir(options_.reportDir);
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
    const bool jsonOk = writeFile(dir / "report.json", report.dump(2, ' ', false, nlohmann::json::error_handler_t::replace) + "\n");
    const bool junitOk = writeFile(dir / "junit.xml", junit.str());
    if (!jsonOk || !junitOk) std::cerr << "Reports: failed to write into " << dir << std::endl;
    else std::cout << "Reports: " << (dir / "report.json").string() << ", " << (dir / "junit.xml").string() << std::endl;
}

}
