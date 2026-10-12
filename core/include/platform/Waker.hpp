#pragma once

namespace vh::platform {

// Wakes one waiting thread from a signal handler. notify() is async-signal-safe; wait() blocks until a notify().
// Linux: an eventfd. macOS (no eventfd): a non-blocking self-pipe.
class Waker {
public:
    Waker();  // throws std::system_error
    ~Waker();

    Waker(const Waker&) = delete;
    Waker& operator=(const Waker&) = delete;

    void notify() const noexcept;
    // False on an unexpected read error; the caller falls back to polling whatever flag the handler set.
    [[nodiscard]] bool wait() const noexcept;

private:
    int readFd_{-1};
    int writeFd_{-1};
};

}
