// vh-recovery: the offline recovery-kit tool (design/encryption/03-metadata-recovery.md §5.3; #370).
//
// A recovery kit is generated on a customer-controlled device, never on the server: run this on a workstation or an
// offline machine, keep the kit file there (or print it), and give the server only the public key. The tool never
// opens a network connection and talks to no daemon.
//
//   vh-recovery kit create --output kit.json          a new seed; prints the public key to enroll
//   vh-recovery kit public-key kit.json               the recipient public key (base64)
//   vh-recovery kit add-vault kit.json --status s.json
//                                                     pin a vault from `vh vault keys status <vault> --json`: its uid,
//                                                     origin node, attestation public keys and manifest checkpoint
//   vh-recovery kit show kit.json                     what the kit holds (never the seed)
//
// A kit file is written with mode 0600 and never over an existing file (add-vault replaces it atomically).

#include <vl/keykit/kit.hpp>
#include <vl/keykit/seed.hpp>

#include <nlohmann/json.hpp>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using vl::keykit::Kit;

constexpr const char* kUsage =
    "usage: vh-recovery kit create --output <kit.json>\n"
    "       vh-recovery kit public-key <kit.json|->\n"
    "       vh-recovery kit add-vault <kit.json> --status <status.json|->\n"
    "       vh-recovery kit show <kit.json|->\n"
    "\n"
    "Generate the recovery kit on your own device, never on the server. Keep it offline (or in a password manager);\n"
    "anyone holding it can decrypt the vaults it serves. Enroll its public key on a vault with:\n"
    "  vh vault keys recipient add <vault> --public-key <key>\n";

std::string readAll(const std::string& path) {
    if (path == "-") return {std::istreambuf_iterator<char>(std::cin), std::istreambuf_iterator<char>()};
    std::ifstream in(path, std::ios::binary);
    if (!in) throw std::runtime_error("can't read " + path + ": " + std::strerror(errno));
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

// Writes `text` to `path` with mode 0600: O_EXCL for a new file; `replace` writes a sibling and renames it over.
void writePrivate(const std::string& path, std::string text, const bool replace) {
    const auto target = replace ? path + ".tmp-" + std::to_string(::getpid()) : path;
    const int fd = ::open(target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) {
        vl::keykit::wipe(text);
        throw std::runtime_error("can't create " + target + ": " + std::strerror(errno) +
                                 (errno == EEXIST ? " (a kit is never overwritten)" : ""));
    }
    std::size_t done = 0;
    while (done < text.size()) {
        const auto n = ::write(fd, text.data() + done, text.size() - done);
        if (n < 0) {
            if (errno == EINTR) continue;
            ::close(fd);
            ::unlink(target.c_str());
            vl::keykit::wipe(text);
            throw std::runtime_error("can't write " + target + ": " + std::strerror(errno));
        }
        done += static_cast<std::size_t>(n);
    }
    vl::keykit::wipe(text);
    if (::fsync(fd) != 0 || ::close(fd) != 0) throw std::runtime_error("can't write " + target);
    if (replace && ::rename(target.c_str(), path.c_str()) != 0) {
        ::unlink(target.c_str());
        throw std::runtime_error("can't replace " + path + ": " + std::strerror(errno));
    }
}

Kit loadKit(const std::string& path) {
    auto text = readAll(path);
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(text);
    } catch (const std::exception&) {
        vl::keykit::wipe(text);
        throw std::runtime_error(path + " is not a JSON recovery kit");
    }
    vl::keykit::wipe(text);
    auto kit = vl::keykit::parseKit(doc);
    if (doc.contains("recovery_seed") && doc["recovery_seed"].is_string())
        vl::keykit::wipe(doc["recovery_seed"].get_ref<std::string&>());
    return kit;
}

std::optional<std::string> option(const std::vector<std::string>& args, const std::string& name) {
    for (std::size_t i = 0; i + 1 < args.size(); ++i)
        if (args[i] == name) return args[i + 1];
    return std::nullopt;
}

int create(const std::vector<std::string>& args) {
    const auto output = option(args, "--output");
    if (!output) throw std::runtime_error("kit create needs --output <kit.json> (the kit holds your recovery seed)");
    Kit kit{vl::keykit::RecoverySeed::generate(), {}};
    const auto pk = vl::keykit::base64Encode(kit.seed.x25519PublicKey());
    writePrivate(*output, vl::keykit::toJson(kit).dump(2) + "\n", false);
    std::cout << pk << "\n";
    std::cerr << "Wrote a new recovery kit to " << *output << " (mode 0600). Keep it offline: it decrypts every vault\n"
              << "you enroll it on. The line above is its public key; enroll it on a vault with\n"
              << "  vh vault keys recipient add <vault> --public-key " << pk << "\n"
              << "then pin the vault in the kit: vh vault keys status <vault> --json > status.json &&\n"
              << "  vh-recovery kit add-vault " << *output << " --status status.json\n";
    return 0;
}

int publicKey(const std::vector<std::string>& args) {
    if (args.empty()) throw std::runtime_error("kit public-key needs the kit file");
    std::cout << vl::keykit::base64Encode(loadKit(args[0]).seed.x25519PublicKey()) << "\n";
    return 0;
}

// The vault statuses of `vh vault keys status --json` ({"vaults": [...]}) or one status object.
std::vector<nlohmann::json> statusesOf(const nlohmann::json& doc) {
    if (doc.is_object() && doc.contains("vaults") && doc["vaults"].is_array())
        return {doc["vaults"].begin(), doc["vaults"].end()};
    if (doc.is_object()) return {doc};
    throw std::runtime_error("the status file is not `vh vault keys status --json` output");
}

int addVault(const std::vector<std::string>& args) {
    if (args.empty()) throw std::runtime_error("kit add-vault needs the kit file");
    const auto statusPath = option(args, "--status");
    if (!statusPath) throw std::runtime_error("kit add-vault needs --status <vh vault keys status --json output>");
    auto kit = loadKit(args[0]);
    const auto statuses = statusesOf(nlohmann::json::parse(readAll(*statusPath)));
    unsigned added = 0;
    for (const auto& s : statuses) {
        if (!s.contains("vault_uid") || !s["vault_uid"].is_string())
            throw std::runtime_error("a status entry has no vault_uid (is the daemon older than #370?)");
        nlohmann::json entry{{"vault_uid", s["vault_uid"]}};
        nlohmann::json origin = nlohmann::json::object();
        if (s.contains("node_id") && s["node_id"].is_string()) origin["node_id"] = s["node_id"];
        if (s.contains("vault_id")) origin["vault_id"] = s["vault_id"];
        entry["origin"] = origin;
        auto keys = nlohmann::json::array();
        if (s.contains("attestation_public_keys") && s["attestation_public_keys"].is_array())
            for (const auto& k : s["attestation_public_keys"])
                keys.push_back({{"key_id", k.at("key_id")}, {"public_key", k.at("public_key")}});
        entry["attestation_public_keys"] = keys;
        if (s.contains("checkpoint") && s["checkpoint"].is_object()) entry["checkpoint"] = s["checkpoint"];
        auto vault = vl::keykit::kitVaultFromJson(entry);
        std::erase_if(kit.vaults, [&](const auto& v) { return v.vault_uid == vault.vault_uid; });
        kit.vaults.push_back(std::move(vault));
        ++added;
    }
    writePrivate(args[0], vl::keykit::toJson(kit).dump(2) + "\n", true);
    std::cerr << "Pinned " << added << " vault(s) in " << args[0] << "\n";
    return 0;
}

int show(const std::vector<std::string>& args) {
    if (args.empty()) throw std::runtime_error("kit show needs the kit file");
    const auto kit = loadKit(args[0]);
    nlohmann::json out{{"public_key", vl::keykit::base64Encode(kit.seed.x25519PublicKey())},
                       {"signing_public_key", vl::keykit::base64Encode(kit.seed.ed25519PublicKey())}, {"vaults", nlohmann::json::array()}};
    for (const auto& v : kit.vaults) out["vaults"].push_back(vl::keykit::toJson(v));
    std::cout << out.dump(2) << "\n";
    return 0;
}

}

int main(int argc, char** argv) {
    std::vector<std::string> args(argv + 1, argv + argc);
    if (args.size() < 2 || args[0] != "kit" || args[1] == "help" || args[1] == "--help") {
        std::cerr << kUsage;
        return args.size() >= 2 && (args[1] == "help" || args[1] == "--help") ? 0 : 2;
    }
    const auto command = args[1];
    args.erase(args.begin(), args.begin() + 2);
    try {
        if (command == "create") return create(args);
        if (command == "public-key") return publicKey(args);
        if (command == "add-vault") return addVault(args);
        if (command == "show") return show(args);
        std::cerr << "vh-recovery: unknown command 'kit " << command << "'\n" << kUsage;
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "vh-recovery: " << e.what() << "\n";
        return 1;
    }
}
