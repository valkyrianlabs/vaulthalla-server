#include "config/Config.hpp"
#include "config/config_yaml.hpp"
#include "log/Redact.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <yaml-cpp/yaml.h>

#include <regex>
#include <string>

// #327: log lines name files by entry id (or an opaque per-run tag), never by name or path, unless the operator asks
// for `logging.file_paths: full`.

namespace {

struct FilePathsMode {
    explicit FilePathsMode(const vh::log::FilePaths mode) : previous(vh::log::filePaths()) { vh::log::setFilePaths(mode); }
    ~FilePathsMode() { vh::log::setFilePaths(previous); }
    vh::log::FilePaths previous;
};

const std::filesystem::path kSensitive{"/Patients/Jane Doe/MRI 2026-11-05.dcm"};

void expectNoTraceOfThePath(const std::string& line) {
    for (const auto* fragment : {"Patients", "Jane", "Doe", "MRI", "dcm", "/"})
        EXPECT_EQ(line.find(fragment), std::string::npos) << line << " contains " << fragment;
}

}

TEST(LogRedact, DefaultsToIds) {
    EXPECT_EQ(vh::config::LoggingConfig{}.file_paths, vh::config::LogFilePaths::Ids);
}

TEST(LogRedact, IdsModeNamesAFileByItsEntryIdOnly) {
    FilePathsMode mode(vh::log::FilePaths::Ids);
    const auto line = vh::log::file(42, kSensitive);
    EXPECT_EQ(line, "entry 42");
    expectNoTraceOfThePath(line);
}

TEST(LogRedact, IdsModeTagsAPathWithoutAnIdOpaquelyAndStably) {
    FilePathsMode mode(vh::log::FilePaths::Ids);
    const auto tag = vh::log::path(kSensitive);
    EXPECT_TRUE(std::regex_match(tag, std::regex("path#[0-9a-f]{16}"))) << tag;
    expectNoTraceOfThePath(tag);
    // Stable within the run, so one file's lines can be followed; equivalent spellings agree; other paths differ.
    EXPECT_EQ(tag, vh::log::path(kSensitive));
    EXPECT_EQ(tag, vh::log::path("/Patients/./Jane Doe/MRI 2026-11-05.dcm"));
    EXPECT_NE(tag, vh::log::path("/Patients/John Doe/MRI 2026-11-05.dcm"));
    // A missing or zero id falls back to the tag.
    EXPECT_EQ(vh::log::file(std::nullopt, kSensitive), tag);
    EXPECT_EQ(vh::log::file(0, kSensitive), tag);
}

TEST(LogRedact, FullModeAddsThePath) {
    FilePathsMode mode(vh::log::FilePaths::Full);
    EXPECT_EQ(vh::log::file(42, kSensitive), "entry 42 (" + kSensitive.string() + ")");
    EXPECT_EQ(vh::log::path(kSensitive), kSensitive.string());
}

TEST(LogRedact, ConfigParsesBothSpellingsAndRefusesOthers) {
    using vh::config::LogFilePaths;
    EXPECT_EQ(vh::config::logFilePathsFromString("ids"), LogFilePaths::Ids);
    EXPECT_EQ(vh::config::logFilePathsFromString("FULL"), LogFilePaths::Full);
    EXPECT_THROW((void)vh::config::logFilePathsFromString("names"), std::invalid_argument);

    vh::config::LoggingConfig cfg;
    ASSERT_TRUE(YAML::convert<vh::config::LoggingConfig>::decode(YAML::Load("file_paths: full"), cfg));
    EXPECT_EQ(cfg.file_paths, LogFilePaths::Full);
    vh::config::LoggingConfig absent;
    ASSERT_TRUE(YAML::convert<vh::config::LoggingConfig>::decode(YAML::Load("{}"), absent));
    EXPECT_EQ(absent.file_paths, LogFilePaths::Ids);

    nlohmann::json j = cfg;
    EXPECT_EQ(j.at("file_paths"), "full");
    vh::config::LoggingConfig back;
    j.get_to(back);
    EXPECT_EQ(back.file_paths, LogFilePaths::Full);
}
