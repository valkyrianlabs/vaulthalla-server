#pragma once

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <istream>
#include <string>

namespace vh::crypto::password {

// Password strength checks. The dictionary and common-password lists ship with the package
// (deploy/password-lists, installed under <datadir>/vaulthalla/password-lists) and are read from local files only:
// nothing on the startup path touches the network, so a host without outbound internet starts its listeners like
// any other (#316). The one network check left, the Have I Been Pwned range lookup, runs when a
// password is set, is bounded by short timeouts, and never decides the outcome when the service can't be reached.
class Strength {
  public:
    static unsigned short passwordStrengthCheck(const std::string& password);
    // True when the password is a dictionary word once case and leading/trailing digits and symbols are stripped
    // ("Sunshine2024!"). Words merely appearing inside a longer password don't count: a random 64-character password
    // almost always contains some three-letter word.
    static bool isDictionaryWord(const std::string& password);
    static bool isCommonWeakPassword(const std::string& password);

    // The outcome of the breach-corpus lookup. Unavailable means the service could not be asked (offline host, DNS
    // failure, refused connection, timeout, HTTP error): the caller treats it as "not known to be breached" and logs it.
    enum class BreachCheck { NotFound, Found, Unavailable };
    static BreachCheck checkPwnedPassword(const std::string& password);

    // Replaces the lists. Each loader builds a new set and swaps it in, so concurrent readers see the old list or the
    // new one, never a half-built one.
    static void loadDictionary(std::istream& words);
    static void loadCommonWeakPasswords(std::istream& passwords);

    struct ListFile {
        std::filesystem::path path;
        bool loaded = false;
        std::size_t entries = 0;
        std::string problem;  // why it was not loaded (missing, unreadable, empty); empty when loaded
    };
    struct BundledListReport {
        ListFile dictionary;
        ListFile commonPasswords;
        [[nodiscard]] bool complete() const noexcept { return dictionary.loaded && commonPasswords.loaded; }
    };
    static constexpr const char* kDictionaryFile = "dictionary.txt";
    static constexpr const char* kCommonPasswordsFile = "common-passwords.txt";
    // Loads <dir>/dictionary.txt and <dir>/common-passwords.txt. Never throws and never touches the network: a missing
    // or unreadable file leaves that list as it was and is reported (the checks it feeds then pass, as before a load).
    static BundledListReport loadBundledLists(const std::filesystem::path& dir) noexcept;

    static std::size_t dictionarySize();
    static std::size_t commonWeakPasswordCount();

    static std::string SHA1Hex(const std::string& input);

    // Bounds for the breach lookup. Connect covers DNS + TCP + TLS; total covers the whole request.
    struct NetworkTimeouts {
        std::chrono::milliseconds connect{3000};
        std::chrono::milliseconds total{5000};
    };
    static NetworkTimeouts networkTimeouts();

    // Tests only: the breach lookup's endpoint (default https://api.pwnedpasswords.com/range/) and timeouts, and a
    // counter of every outbound request this class has made.
    static void setBreachEndpointForTesting(std::string urlPrefix);
    static void setNetworkTimeoutsForTesting(NetworkTimeouts timeouts);
    static void resetNetworkForTesting();
    static std::size_t outboundRequestCount();

  private:
    static std::string fetchURL(const std::string& url);  // throws on any failure
};

}
