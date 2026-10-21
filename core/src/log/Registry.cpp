#include "log/Registry.hpp"
#include "config/Registry.hpp"
#include "log/AuditOrigin.hpp"

#include <spdlog/pattern_formatter.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/basic_file_sink.h>
#include <paths.h>
#include <filesystem>

namespace vh::log {

namespace {

// `%*` in the audit sink's pattern: " [via <origin>]" while an AuditOrigin is alive on the logging thread (the
// audit logger is synchronous, so that is the thread that wrote the line).
class AuditOriginFlag final : public spdlog::custom_flag_formatter {
public:
    void format(const spdlog::details::log_msg&, const std::tm&, spdlog::memory_buf_t& dest) override {
        const auto* origin = AuditOrigin::current();
        if (!origin) return;
        constexpr std::string_view open{" [via "};
        dest.append(open.data(), open.data() + open.size());
        dest.append(origin->data(), origin->data() + origin->size());
        dest.push_back(']');
    }

    [[nodiscard]] std::unique_ptr<custom_flag_formatter> clone() const override {
        return std::make_unique<AuditOriginFlag>();
    }
};

std::unique_ptr<spdlog::formatter> auditFormatter(const std::string& pattern) {
    auto formatter = std::make_unique<spdlog::pattern_formatter>();
    formatter->add_flag<AuditOriginFlag>('*').set_pattern(pattern + "%*");
    return formatter;
}

// Kept so reopenMainLog()/reopenAuditLog() can swap them after rotation.
std::shared_ptr<spdlog::sinks::stdout_color_sink_mt> console_sink_;
std::shared_ptr<spdlog::sinks::rotating_file_sink_mt> main_file_sink_;
std::shared_ptr<spdlog::sinks::basic_file_sink_mt> audit_file_sink_;

// The main sink's parameters from init().
constexpr size_t main_max_bytes_ = 10 * 1024 * 1024; // 10 MiB
constexpr size_t main_max_files_ = 5;

void replaceSinkEverywhere(
    const std::shared_ptr<spdlog::sinks::sink>& old_sink,
    const std::shared_ptr<spdlog::sinks::sink>& new_sink)
{
    // Swap on every registered logger that currently uses old_sink.
    spdlog::apply_all([&](const std::shared_ptr<spdlog::logger>& lg) {
        // Take a copy of sinks, replace in the copy, then set_sinks() atomically.
        auto sinks_copy = lg->sinks();
        bool touched = false;
        for (auto &s : sinks_copy) {
            if (s.get() == old_sink.get()) {
                s = new_sink;
                touched = true;
            }
        }
        if (touched) {
            // flush before swap to minimize dangling writes
            lg->flush();
            lg->sinks() = std::move(sinks_copy);
        }
    });

    // old_sink will be destroyed when last ref goes away → file closed.
}

}


void Registry::init() {
    if (initialized_) {
        spdlog::warn("[LogRegistry] Already initialized, ignoring second init()");
        return;
    }

    log_dir_ = paths::getLogPath();
    main_log_path_  = log_dir_ / "vaulthalla.log";
    audit_log_path_ = log_dir_ / "audit.log";

    namespace fs = std::filesystem;
    if (!fs::exists(log_dir_)) fs::create_directories(log_dir_);

    const auto cnf = config::Registry::get().logging;

    // console
    console_sink_ = std::make_shared<spdlog::sinks::stdout_color_sink_mt>();
    console_sink_->set_level(cnf.levels.console_log_level);
    console_sink_->set_color_mode(spdlog::color_mode::automatic);
    console_sink_->set_pattern(CONSOLE_LOG_FORMAT);

    // main file sink (rotating)
    main_file_sink_ = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        main_log_path_.string(), main_max_bytes_, main_max_files_);
    main_file_sink_->set_level(cnf.levels.file_log_level);
    main_file_sink_->set_pattern(FILE_LOG_FORMAT);

    auto makeLogger = [&](const std::string& name,
                          const spdlog::level::level_enum lvl = spdlog::level::debug) {
        const auto logger = std::make_shared<spdlog::logger>(
            name, spdlog::sinks_init_list{console_sink_, main_file_sink_});
        logger->set_level(lvl);
        logger->flush_on(spdlog::level::warn);
        spdlog::register_logger(logger);
    };

    const auto& sub_levels = cnf.levels.subsystem_levels;
    makeLogger("vaulthalla", sub_levels.vaulthalla);
    makeLogger("fuse",       sub_levels.fuse);
    makeLogger("filesystem", sub_levels.filesystem);
    makeLogger("cloud",      sub_levels.cloud);
    makeLogger("crypto",     sub_levels.crypto);
    makeLogger("auth",       sub_levels.auth);
    makeLogger("ws",         sub_levels.websocket);
    makeLogger("http",       sub_levels.http);
    makeLogger("shell",      sub_levels.shell);
    makeLogger("db",         sub_levels.db);
    makeLogger("sync",       sub_levels.sync);
    makeLogger("thumb",      sub_levels.thumb);
    makeLogger("storage",    sub_levels.storage);
    makeLogger("types",      sub_levels.types);
    makeLogger("runtime",    sub_levels.runtime);

    // audit: file-only sink (append)
    {
        audit_file_sink_ = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
            audit_log_path_.string(), /*truncate=*/false);
        audit_file_sink_->set_formatter(auditFormatter("%+"));
        std::vector<spdlog::sink_ptr> sinks = { audit_file_sink_ };
        const auto logger = std::make_shared<spdlog::logger>("audit", sinks.begin(), sinks.end());
        logger->set_level(spdlog::level::info);
        logger->flush_on(spdlog::level::info);
        spdlog::register_logger(logger);
    }

    initialized_ = true;
    spdlog::info("[LogRegistry] Initialized");
}

std::shared_ptr<spdlog::logger> Registry::get(const std::string& name) {
    auto logger = spdlog::get(name);
    if (!logger) {
        if (!initialized_) throw std::runtime_error("[LogRegistry] LogRegistry not initialized, cannot get logger: " + name);
        throw std::runtime_error("[LogRegistry] Logger not found: " + name);
    }
    return logger;
}

bool Registry::isInitialized() { return initialized_; }

// LogRegistry.cpp (add helper)

void Registry::reopenMainLog() {
    if (!initialized_) return;

    // Build a fresh rotating sink with the same settings.
    auto fresh = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
        main_log_path_.string(), main_max_bytes_, main_max_files_);

    // Keep level/pattern identical to the old sink.
    fresh->set_level(main_file_sink_->level());
    fresh->set_pattern(FILE_LOG_FORMAT);

    replaceSinkEverywhere(main_file_sink_, fresh);
    main_file_sink_ = std::move(fresh);
}

void Registry::reopenAuditLog() {
    if (!initialized_) return;

    // Only the "audit" logger uses this sink, but make it symmetric.
    auto fresh = std::make_shared<spdlog::sinks::basic_file_sink_mt>(
        audit_log_path_.string(), /*truncate=*/false);
    fresh->set_level(audit_file_sink_->level());
    fresh->set_formatter(auditFormatter(FILE_LOG_FORMAT));

    // Swap on the audit logger (and any others that might have it)
    replaceSinkEverywhere(audit_file_sink_, fresh);
    audit_file_sink_ = std::move(fresh);
}

}
