#include "protocols/device/Scope.hpp"

namespace vh::protocols::device::scope {

int rank(const std::string_view s) noexcept {
    if (s == "read") return 1;
    if (s == "write") return 2;
    if (s == "destructive") return 3;
    return 0;
}

bool allows(const std::string_view scope, const std::string_view effect) noexcept {
    return rank(effect) > 0 && rank(scope) > 0 && rank(effect) <= rank(scope);
}

std::span<const LaneClass> laneClasses() noexcept {
    using boost::beast::http::verb;
    static constexpr LaneClass kTable[]{
        {"GET, HEAD", "/preview*, /download*", "read", verb::get, "/download/content"},
        {"POST", "/preview/batch", "read", verb::post, "/preview/batch"},
        {"any", "/transfer* (calibration: nothing stored)", "read", verb::post, "/transfer/sink"},
        {"POST", "/mcp (each tool call held to the scope by the MCP ceiling)", "read", verb::post, "/mcp"},
        {"any", "/upload*", "write", verb::put, "/upload/content"},
        {"anything else", "", "write", verb::post, "/download/content"},
    };
    return kTable;
}

std::string_view laneEffect(const boost::beast::http::verb method, const std::string_view target) noexcept {
    const auto under = [&](const std::string_view prefix) {
        return target.starts_with(prefix) && (target.size() == prefix.size() || target[prefix.size()] == '/' ||
                                              target[prefix.size()] == '?');
    };
    if (under("/upload")) return "write";
    if (under("/mcp") || under("/transfer")) return "read";
    const bool safe = method == boost::beast::http::verb::get || method == boost::beast::http::verb::head;
    if ((under("/preview") || under("/download")) && safe) return "read";
    if (method == boost::beast::http::verb::post && (target == "/preview/batch" || target.starts_with("/preview/batch?")))
        return "read";
    return "write";
}

}
