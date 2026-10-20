#include "protocols/shell/SocketIO.hpp"

#include <nlohmann/json.hpp>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <algorithm>
#include <cerrno>
#include <string>
#include <stdexcept>
#include <cstring>

namespace vh::protocols::shell {

namespace {

// Frames are length-prefixed; a single read()/write() may move fewer bytes than asked, so loop. EAGAIN means the
// socket's SO_RCVTIMEO/SO_SNDTIMEO expired: the peer went quiet, which is reported rather than waited on forever.
bool cliSocketReadAll(const int fd, void* buf, std::size_t n) {
    auto* p = static_cast<unsigned char*>(buf);
    while (n) {
        const ssize_t r = ::recv(fd, p, n, 0);
        if (r == 0) return false;
        if (r < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK)
                throw std::runtime_error("timed out waiting for input from the vh client");
            return false;
        }
        p += r;
        n -= static_cast<std::size_t>(r);
    }
    return true;
}

bool cliSocketWriteAll(const int fd, const void* buf, std::size_t n) {
    const auto* p = static_cast<const unsigned char*>(buf);
    while (n) {
        // MSG_NOSIGNAL: a client that hung up (Ctrl-C) must not SIGPIPE the daemon.
        const ssize_t w = ::send(fd, p, n, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        if (w == 0) return false;
        p += w;
        n -= static_cast<std::size_t>(w);
    }
    return true;
}

}

SocketIO::SocketIO(const int fd) : fd_(fd) {}

bool SocketIO::send_json(const int fd, const nlohmann::json& j) {
    const std::string s = j.dump();
    const uint32_t len = htonl(static_cast<uint32_t>(s.size()));
    return cliSocketWriteAll(fd, &len, 4) && cliSocketWriteAll(fd, s.data(), s.size());
}

nlohmann::json SocketIO::recv_json(const int fd, const uint32_t maxBytes) {
    uint32_t len_be = 0;
    if (!cliSocketReadAll(fd, &len_be, 4)) throw std::runtime_error("EOF reading length");
    const uint32_t len = ntohl(len_be);
    if (len > maxBytes) throw std::runtime_error("frame too large (" + std::to_string(len) + " bytes)");
    std::string body(len, '\0');
    if (!cliSocketReadAll(fd, body.data(), len)) throw std::runtime_error("EOF reading body");
    return nlohmann::json::parse(body);
}

bool SocketIO::peerConnected() const {
    pollfd pfd{.fd = fd_, .events = POLLIN, .revents = 0};
    const int rc = ::poll(&pfd, 1, 0);
    if (rc < 0) return errno == EINTR;
    if (rc == 0) return true;
    if (pfd.revents & (POLLHUP | POLLERR | POLLNVAL)) return false;
    // Readable with nothing to read is the client's EOF; a stray frame is not a hang-up.
    char byte = 0;
    const ssize_t n = ::recv(fd_, &byte, 1, MSG_PEEK | MSG_DONTWAIT);
    return n > 0 || (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR));
}

std::string SocketIO::next_id() {
    return "p" + std::to_string(++id_counter_);
}

void SocketIO::print(const std::string_view msg) {
    send_json(fd_, {{"type", "output"}, {"text", std::string{msg}}});
}

bool SocketIO::confirm(const std::string_view promptIn, const bool def_no) {
    auto id = next_id();
    if (!send_json(fd_, {
        {"type", "prompt"},
        {"style", "confirm"},
        {"id", id},
        {"text", std::string{promptIn}},
        {"default", def_no ? "no" : "yes"}
    })) throw std::runtime_error("vh client disconnected");

    while (true) {
        auto j = recv_json(fd_);
        if (j.value("type", "") == "input" && j.value("id", "") == id) {
            std::string v = j.value("value", "");
            std::ranges::transform(v.begin(), v.end(), v.begin(), ::tolower);
            if (v == "y" || v == "yes") return true;
            if (v == "n" || v == "no") return false;
            if (v.empty()) return !def_no;
            return false; // anything else is not a yes
        }
    }
}

std::string SocketIO::prompt(const std::string_view promptIn, const std::string_view def) {
    auto id = next_id();
    if (!send_json(fd_, {
        {"type", "prompt"},
        {"style", "input"},
        {"id", id},
        {"text", std::string{promptIn}},
        {"default", std::string{def}}
    })) throw std::runtime_error("vh client disconnected");

    while (true) {
        auto j = recv_json(fd_);
        if (j.value("type", "") == "input" && j.value("id", "") == id) {
            return j.value("value", std::string{def});
        }
    }
}

bool SocketIO::confirm(const std::string_view promptIn) { return confirm(promptIn, true); }
std::string SocketIO::prompt(const std::string_view promptIn) { return prompt(promptIn, ""); }

std::string SocketIO::promptSecret(const std::string_view promptIn) {
    auto id = next_id();
    if (!send_json(fd_, {
        {"type", "prompt"},
        {"style", "secret"},
        {"id", id},
        {"text", std::string{promptIn}},
        {"default", ""}
    })) throw std::runtime_error("vh client disconnected");

    while (true) {
        auto j = recv_json(fd_);
        if (j.value("type", "") == "input" && j.value("id", "") == id)
            return j.value("value", std::string{});
    }
}

}
