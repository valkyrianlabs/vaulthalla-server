#include "crypto/encryptors/GPG.hpp"
#include <unistd.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <fmt/format.h>
#include <nlohmann/json.hpp>

using namespace vh::crypto::encryptors;
using json = nlohmann::json;

void GPG::encryptToFile(const json& payload,
                                 const std::string& recipient,
                                 const std::string& outputPath,
                                 const bool armor) {
    const std::string serialized = payload.dump();

    int pipefd[2];
    if (pipe(pipefd) == -1) throw std::runtime_error("Failed to create pipe for GPG input");

    const pid_t pid = fork();
    if (pid < 0) throw std::runtime_error("Failed to fork GPG process");

    if (pid == 0) {
        // Child process: exec GPG with input from pipe
        dup2(pipefd[0], STDIN_FILENO);
        close(pipefd[1]);
        close(pipefd[0]);

        std::vector args = {
            "gpg",
            "--batch",
            "--yes",
            "--trust-model", "always",
            "--encrypt",
            "--recipient", recipient.c_str(),
            "--output", outputPath.c_str()
        };
        if (armor)
            args.push_back("--armor");

        args.push_back(nullptr);
        execvp("gpg", const_cast<char* const*>(args.data()));
        _exit(127); // exec failed
    }

    // Parent process: write serialized JSON to GPG stdin
    close(pipefd[0]);

    const char* data = serialized.data();
    const size_t total = serialized.size();
    ssize_t written = 0;

    while (written < static_cast<ssize_t>(total)) {
        const ssize_t n = write(pipefd[1], data + written, total - written);
        if (n <= 0) throw std::runtime_error("Failed to write JSON to GPG stdin pipe");
        written += n;
    }

    close(pipefd[1]);

    int status = 0;
    waitpid(pid, &status, 0);
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
        throw std::runtime_error(fmt::format("GPG encryption failed with status {}", WEXITSTATUS(status)));
}
