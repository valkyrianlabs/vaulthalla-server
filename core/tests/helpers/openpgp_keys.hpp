#pragma once

// Throwaway OpenPGP keys for the read-grant tests, made with the system gpg in a private home directory of their own
// (the secret keys never leave it; its gpg-agent is stopped and the directory removed when the keyring goes away).
// Never a real key: every key here is generated per test run.
//
//   Keyring k;                         // skips (available() == false) without gpg
//   auto fpr = k.generate("Sentinel (credential handoff) <sentinel@example.test>");   // ed25519 + cv25519
//   k.publicKey(fpr);  k.decrypt(message);

#include "crypto/openpgp/Gpg.hpp"

#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <unistd.h>

namespace vh::test::openpgp {

namespace pgp = vh::crypto::openpgp;

class Keyring {
public:
    Keyring() : exe_(pgp::executable()) {}
    ~Keyring() {
        if (exe_) (void)run({"--homedir", home_.path().string(), "--kill", "all"}, {}, gpgconf());
    }
    Keyring(const Keyring&) = delete;
    Keyring& operator=(const Keyring&) = delete;

    [[nodiscard]] bool available() const { return exe_.has_value(); }

    // An ed25519 primary key (certify, sign) with a cv25519 encryption subkey, like the Sentinel handoff key.
    // `fakedTime` ("20200101T000000") and `expire` ("1d") make an already expired one.
    std::string generate(const std::string& uid, const std::string& expire = "never",
                         const std::optional<std::string>& fakedTime = std::nullopt) {
        std::vector<std::string> extra;
        if (fakedTime) extra = {"--faked-system-time", *fakedTime};
        gpg(extra, {"--quick-gen-key", uid, "ed25519", "cert,sign", expire});
        const auto fpr = fingerprintOf(uid);
        gpg(extra, {"--quick-add-key", fpr, "cv25519", "encr", expire});
        return fpr;
    }

    // A primary key that may only sign: no encryption subkey at all.
    std::string generateSignOnly(const std::string& uid) {
        gpg({}, {"--quick-gen-key", uid, "ed25519", "sign", "never"});
        return fingerprintOf(uid);
    }

    // Revokes the whole key with the revocation certificate gpg made for it.
    void revoke(const std::string& fpr) {
        const auto cert = home_.path() / "openpgp-revocs.d" / (fpr + ".rev");
        std::ifstream in(cert);
        std::stringstream text;
        text << in.rdbuf();
        auto body = text.str();
        if (const auto pos = body.find(":-----BEGIN"); pos != std::string::npos) body.erase(pos, 1);
        gpgInput({"--import"}, body);
    }

    [[nodiscard]] std::string publicKey(const std::string& fpr) const {
        const auto r = run(base({"--armor", "--export", fpr}), {});
        if (r.exit_code != 0 || r.out.empty()) throw std::runtime_error("gpg --export failed: " + r.err);
        return r.out;
    }

    [[nodiscard]] std::string secretKey(const std::string& fpr) const {
        const auto r = run(base({"--pinentry-mode", "loopback", "--passphrase", "", "--armor", "--export-secret-keys", fpr}), {});
        if (r.exit_code != 0) throw std::runtime_error("gpg --export-secret-keys failed: " + r.err);
        return r.out;
    }

    // The plaintext, or nullopt when none of this keyring's secret keys opens the message.
    [[nodiscard]] std::optional<std::string> decrypt(const std::string& message) const {
        const auto r = run(base({"--pinentry-mode", "loopback", "--passphrase", "", "--decrypt"}), message);
        if (r.exit_code != 0) return std::nullopt;
        return r.out;
    }

private:
    // Its own short directory under /tmp: this keyring runs a gpg-agent, whose socket path must stay under the unix
    // socket limit (104 bytes on macOS, where $TMPDIR is already long).
    class ShortHome {
    public:
        ShortHome() {
            std::string tmpl = "/tmp/vhk-XXXXXX";
            if (!::mkdtemp(tmpl.data())) throw std::runtime_error("mkdtemp failed");
            path_ = tmpl;
        }
        ~ShortHome() {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
        ShortHome(const ShortHome&) = delete;
        ShortHome& operator=(const ShortHome&) = delete;
        [[nodiscard]] const std::filesystem::path& path() const { return path_; }

    private:
        std::filesystem::path path_;
    };

    std::optional<std::filesystem::path> exe_;
    ShortHome home_;

    [[nodiscard]] std::filesystem::path gpgconf() const { return exe_->parent_path() / "gpgconf"; }

    [[nodiscard]] std::vector<std::string> base(std::vector<std::string> args) const {
        std::vector<std::string> out{"--homedir", home_.path().string(), "--batch", "--no-tty", "--quiet"};
        out.insert(out.end(), args.begin(), args.end());
        return out;
    }

    [[nodiscard]] pgp::RunResult run(const std::vector<std::string>& args, const std::string& input,
                                     std::optional<std::filesystem::path> exe = std::nullopt) const {
        if (!exe_) throw std::runtime_error("gpg is not installed");
        return pgp::run(exe ? *exe : *exe_, args, input, std::chrono::seconds(60));
    }

    void gpg(const std::vector<std::string>& extra, const std::vector<std::string>& args) {
        std::vector<std::string> all{"--pinentry-mode", "loopback", "--passphrase", ""};
        all.insert(all.end(), extra.begin(), extra.end());
        all.insert(all.end(), args.begin(), args.end());
        const auto r = run(base(all), {});
        if (r.exit_code != 0) throw std::runtime_error("gpg failed: " + r.err);
    }

    void gpgInput(const std::vector<std::string>& args, const std::string& input) {
        const auto r = run(base(args), input);
        if (r.exit_code != 0) throw std::runtime_error("gpg failed: " + r.err);
    }

    [[nodiscard]] std::string fingerprintOf(const std::string& uid) const {
        const auto r = run(base({"--with-colons", "--list-keys", "=" + uid}), {});
        std::istringstream lines(r.out);
        std::string line;
        while (std::getline(lines, line))
            if (line.starts_with("fpr:")) {
                std::vector<std::string> f;
                std::string cur;
                for (const char c : line) {
                    if (c == ':') { f.push_back(cur); cur.clear(); } else cur += c;
                }
                if (f.size() > 9) return f[9];
            }
        throw std::runtime_error("no key for " + uid + ": " + r.err);
    }
};

}
