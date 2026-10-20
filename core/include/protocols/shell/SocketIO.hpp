#pragma once

#include <nlohmann/json_fwd.hpp>
#include <cstdint>
#include <string>
#include <string_view>

namespace vh::protocols::shell {

struct IO {
    virtual ~IO() = default;
    virtual void print(std::string_view s) = 0;
    virtual bool confirm(std::string_view prompt, bool def_no) = 0;
    virtual std::string prompt(std::string_view prompt,
                               std::string_view def) = 0;
    virtual std::string promptSecret(std::string_view prompt) = 0;
};

class SocketIO final : public IO {
public:
    static constexpr uint32_t kMaxFrameBytes = 1u << 20; // 1 MiB

    explicit SocketIO(int fd);
    void print(std::string_view msg) override;
    bool confirm(std::string_view promptIn, bool def_no) override;
    bool confirm(std::string_view promptIn);
    std::string prompt(std::string_view promptIn, std::string_view def) override;
    std::string prompt(std::string_view promptIn);
    std::string promptSecret(std::string_view promptIn) override;

    // False once the vh client has hung up (Ctrl-C): commands that wait on something else (a device asking to
    // pair) check it between waits. Never blocks.
    [[nodiscard]] bool peerConnected() const;

    // Throws on EOF, on a frame larger than maxBytes, and when the socket's receive timeout expires.
    static nlohmann::json recv_json(int fd, uint32_t maxBytes = kMaxFrameBytes);
    // Never raises SIGPIPE; returns false if the peer is gone.
    static bool send_json(int fd, const nlohmann::json& j);

private:
    int fd_, id_counter_ = 0;
    std::string next_id();
};

}
