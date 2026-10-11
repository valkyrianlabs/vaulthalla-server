#include "IntegrationsTestRunner.hpp"
#include "TestCase.hpp"
#include "Validator.hpp"
#include "fuse/Actor.hpp"
#include "seed/H64.hpp"

#include <unistd.h> // isatty
#include <cstdlib>
#include <iostream>
#include <array>
#include <unordered_map>
#include <vector>
#include <string>
#include <iomanip>

namespace vh::test::integration {
    static std::string joinLines(const std::vector<std::string>& lines) {
        std::ostringstream oss;
        for (const auto& e : lines) oss << e << '\n';
        return oss.str();
    }

    void IntegrationsTestRunner::validateStage(const TestStage& stage) const {
        for (const auto& t : stage.tests) {
            if (!t) continue;

            std::vector<std::string> errors;

            // exit code check
            if (t->expect_exit != t->result.exit_code) {
                errors.push_back(stage.name + ": unexpected exit code for " + t->name);
            }

            if (t->wedge) errors.push_back(stage.name + ": wedge in " + t->name + ": " + t->result.stderr_text);

            // stdout expectations by path, plus the test's own; forbidden text is looked for on stderr too, where
            // the CLI writes its errors.
            std::vector<std::string> mustHave = t->must_contain, mustNotHave = t->must_not_contain;
            if (const auto it = expectations_by_path_.find(t->path); it != expectations_by_path_.end()) {
                mustHave.insert(mustHave.end(), it->second.must_have.begin(), it->second.must_have.end());
                mustNotHave.insert(mustNotHave.end(), it->second.must_not_have.begin(), it->second.must_not_have.end());
            }
            for (const auto& needle : mustHave) {
                if (!t->result.stdout_text.contains(needle)) {
                    errors.push_back(stage.name + ": missing expected text for " + t->name + ": " + needle);
                }
            }
            for (const auto& needle : mustNotHave) {
                if (t->result.stdout_text.contains(needle)) {
                    errors.push_back(stage.name + ": found forbidden text for " + t->name + ": " + needle);
                }
                if (t->result.stderr_text.contains(needle)) {
                    errors.push_back(stage.name + ": found forbidden text on stderr for " + t->name + ": " + needle);
                }
            }

            // resolve final assertion (preserve earlier failures by appending)
            if (errors.empty()) {
                if (t->assertion.ok) t->assertion = AssertionResult::Pass();
                // else: keep prior fail (e.g., seed id extraction), do not override to pass
            } else {
                const bool had_prior = !t->assertion.ok && !t->assertion.message.empty();
                const auto combined = had_prior
                    ? (t->assertion.message + "\n" + joinLines(errors))
                    : joinLines(errors);
                t->assertion = AssertionResult::Fail(combined);
            }
        }
    }

    int IntegrationsTestRunner::printResults() const {
        std::ostream& os = std::cout;

        // color / TTY
        const bool color_enabled = [=]() -> bool {
            if (std::getenv("NO_COLOR")) return false;      // https://no-color.org
            if (std::getenv("CLICOLOR_FORCE")) return true; // force on
            if (!isatty(fileno(stdout))) return false;
            const char* term = std::getenv("TERM");
            if (!term) return false;
            if (std::string(term) == "dumb") return false;
            return true;
        }();

        const char* reset = color_enabled ? "\033[0m"  : "";
        const char* bold  = color_enabled ? "\033[1m"  : "";
        const char* red   = color_enabled ? "\033[31m" : "";
        const char* green = color_enabled ? "\033[32m" : "";
        const char* yellow= color_enabled ? "\033[33m" : "";
        const char* cyan  = color_enabled ? "\033[36m" : "";
        const char* gray  = color_enabled ? "\033[37m" : "";
        const char* ok_glyph   = color_enabled ? "✔" : "OK";
        const char* fail_glyph = color_enabled ? "✘" : "X";

        constexpr int term_cols = 100;
        auto hr = [&](char c = '-') {
            for (int i = 0; i < term_cols; ++i) os << c;
            os << '\n';
        };

        int total = 0, passed = 0, failed = 0;

        struct StageRecap { std::string name; int pass = 0; int total = 0; int fail = 0; };
        std::vector<StageRecap> recaps;

        os << bold << "CLI Test Results" << reset << "\n";
        hr();

        for (const auto& stage : stages_) {
            if (stage.name.empty()) continue;

            int stage_total = 0, stage_pass = 0, stage_fail = 0;
            os << bold << stage.name << reset << "\n";

            // --- Aggregate duplicate test names per result (PASS/FAIL) ---
            struct Agg {
                int count = 0;
                bool ok = false;

                // Exit-code mismatch capture (any within group)
                bool any_exit_mismatch = false;
                int sample_expect_exit = 0;
                int sample_exit_code = 0;
                std::string sample_stderr;

                // Assertion message capture for FAIL groups
                std::string sample_message;
                bool details_identical = true; // across grouped items
                bool captured_mismatch_sample = false; // store first mismatch details
                bool captured_message = false;         // store first assertion message
            };

            // Maintain print order by first occurrence of (name, ok)
            std::vector<std::pair<std::string, bool>> order;
            // name -> [0]=FAIL agg, [1]=PASS agg
            std::unordered_map<std::string, std::array<Agg,2>> by_name;

            for (const auto& t : stage.tests) {
                if (!t) continue;

                ++stage_total; ++total;
                const bool ok = t->assertion.ok;
                if (ok) { ++stage_pass; ++passed; } else { ++stage_fail; ++failed; }

                auto& arr = by_name[t->name]; // default-constructed
                auto& agg = arr[ok ? 1 : 0];
                if (agg.count == 0) {
                    // first occurrence of this (name, ok) pair
                    agg.ok = ok;
                    order.emplace_back(t->name, ok);
                }
                ++agg.count;

                // Track exit-code mismatch presence & sample
                const bool mismatch = (t->expect_exit != t->result.exit_code);
                if (mismatch) {
                    agg.any_exit_mismatch = true;
                    if (!agg.captured_mismatch_sample) {
                        agg.sample_expect_exit = t->expect_exit;
                        agg.sample_exit_code = t->result.exit_code;
                        agg.sample_stderr = t->result.stderr_text;
                        agg.captured_mismatch_sample = true;
                    } else {
                        // if another mismatch has different details, mark not identical
                        if (agg.sample_expect_exit != t->expect_exit ||
                            agg.sample_exit_code  != t->result.exit_code ||
                            agg.sample_stderr     != t->result.stderr_text)
                        {
                            agg.details_identical = false;
                        }
                    }
                }

                // For FAIL groups, capture assertion messages
                if (!ok) {
                    if (!agg.captured_message) {
                        agg.sample_message = t->assertion.message;
                        agg.captured_message = true;
                    } else if (agg.sample_message != t->assertion.message) {
                        agg.details_identical = false;
                    }
                }
            }

            // Print grouped lines in original encounter order
            for (const auto& [name, ok] : order) {
                const auto it = by_name.find(name);
                if (it == by_name.end()) continue;
                const Agg& agg = it->second[ok ? 1 : 0];
                if (agg.count == 0) continue;

                const char* col = ok ? green : red;

                os << "  " << col << (ok ? ok_glyph : fail_glyph) << ' '
                   << (ok ? "PASS" : "FAIL") << reset << "  "
                   << bold << name << reset;

                if (agg.count > 1) {
                    os << " " << gray << "(" << agg.count << "×)" << reset;
                }

                // If any exit-code mismatch occurred in the group, show a sample note
                if (agg.any_exit_mismatch) {
                    os << ' ' << yellow << "[exit " << agg.sample_exit_code
                       << " ≠ expected " << agg.sample_expect_exit << "]" << reset;
                }
                os << '\n';

                // Show stderr sample if we had a mismatch
                if (agg.any_exit_mismatch && !agg.sample_stderr.empty()) {
                    os << cyan << "          " << agg.sample_stderr << reset << '\n';
                    if (agg.count > 1 && !agg.details_identical) {
                        os << "      " << yellow << "• " << reset
                           << "Additional failures had differing exit/stderr details.\n";
                    }
                }

                // For FAILs, show assertion messages
                if (!ok && !agg.sample_message.empty()) {
                    std::istringstream iss(agg.sample_message);
                    std::string line;
                    bool printed_any = false;
                    while (std::getline(iss, line)) {
                        if (line.empty()) continue;
                        os << "      " << yellow << "• " << reset << line << '\n';
                        printed_any = true;
                    }
                    if (agg.count > 1 && !agg.details_identical) {
                        os << "      " << yellow << "• " << reset
                           << "(showing first of " << agg.count << " failures; messages vary)\n";
                    } else if (!printed_any && agg.count > 1) {
                        os << "      " << yellow << "• " << reset
                           << "(grouped " << agg.count << " failures; no message details)\n";
                    }
                }
            }

            // Stage summary line
            os << "  " << cyan << "Stage summary:" << reset
               << " " << stage_pass << "/" << stage_total << " passed";
            if (stage_fail) os << "  " << red << stage_fail << " failed" << reset;
            os << '\n';

            recaps.push_back(StageRecap{stage.name, stage_pass, stage_total, stage_fail});

            os << gray; hr(); os << reset;
        }

        // Final recap by stage
        os << bold << "Stage Recap" << reset << "\n";
        for (const auto& r : recaps) {
            const bool ok = (r.fail == 0);
            os << "  " << (ok ? green : red) << (ok ? ok_glyph : fail_glyph) << reset
               << " " << bold << r.name << reset
               << " — " << (ok ? green : red) << (r.total - r.fail) << "/" << r.total << " passed" << reset;
            if (r.fail) os << "  " << red << r.fail << " failed" << reset;
            os << '\n';
        }
        hr();

        os << bold << "Overall: "
           << (failed ? red : green) << (total - failed) << "/" << total << " passed"
           << reset << "\n";
        if (const auto wedges = fuse::wedgeCount(); wedges > 0)
            os << red << "Wedges: " << wedges << " filesystem probe(s) hit their deadline" << reset << "\n";
        if (const auto stuck = fuse::unreapedActors(); !stuck.empty())
            os << red << "Unreaped vh_fs_actor processes: " << stuck.size() << reset << "\n";
        if (total == 0) os << red << "No tests ran: that is a failure, not a pass." << reset << "\n";
        if (options_.negativeControl != NegativeControl::None)
            os << yellow << "Negative control (" << options_.negativeControlText()
               << ") was injected: this run is expected to fail." << reset << "\n";

        const auto seedText = seed::fmtSeed(options_.seed);
        os << "Seed: " << seedText << (options_.seedFromEnv ? " (VH_TEST_SEED)" : " (random)") << "  config: "
           << options_.configName << "  stages: " << options_.stagesText() << "\n";
        os << "Reproduce: VH_TEST_SEED=" << seedText << " VH_TEST_CONFIG=" << options_.configName
           << " VH_TEST_STAGES=" << options_.stagesText() << " VH_TEST_SEED_THREADS=" << options_.seedThreads
           << " bash bin/tests/run_proof.sh\n";

        return failed > 0 || total == 0 ? 1 : 0;
    }
}
