#include "crypto/password/Strength.hpp"
#include "crypto/util/SHA1.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <curl/curl.h>
#include <fstream>
#include <memory>
#include <mutex>
#include <ranges>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <unordered_set>
#include <utility>

namespace vh::crypto::password {

namespace {

using WordSet = std::unordered_set<std::string>;

// Readers take a snapshot under the mutex and look up without it; loaders build a whole new set first and swap it in.
struct Lists {
    std::mutex mutex;
    std::shared_ptr<const WordSet> dictionary = std::make_shared<const WordSet>();
    std::shared_ptr<const WordSet> commonWeak = std::make_shared<const WordSet>();
};

Lists& lists() {
    static Lists instance;
    return instance;
}

std::shared_ptr<const WordSet> dictionarySnapshot() {
    std::scoped_lock lock(lists().mutex);
    return lists().dictionary;
}

std::shared_ptr<const WordSet> commonWeakSnapshot() {
    std::scoped_lock lock(lists().mutex);
    return lists().commonWeak;
}

void trim(std::string& s) {
    s.erase(0, s.find_first_not_of(" \t\r\n"));
    s.erase(s.find_last_not_of(" \t\r\n") + 1);
}

void lowercase(std::string& s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
}

WordSet readDictionary(std::istream& words) {
    WordSet set;
    std::string word;
    while (std::getline(words, word)) {
        trim(word);
        if (word.length() < 3) continue;
        lowercase(word);
        set.insert(std::move(word));
    }
    return set;
}

WordSet readCommonPasswords(std::istream& passwords) {
    WordSet set;
    std::string password;
    while (std::getline(passwords, password)) {
        trim(password);
        if (password.empty()) continue;
        lowercase(password);
        set.insert(std::move(password));
    }
    return set;
}

// Reads one bundled list file into a set; on any problem fills `file.problem` and returns nothing.
template <typename Reader>
std::shared_ptr<const WordSet> readListFile(Strength::ListFile& file, Reader read) noexcept {
    try {
        std::error_code ec;
        const auto status = std::filesystem::status(file.path, ec);
        if (status.type() == std::filesystem::file_type::not_found) {
            file.problem = "missing";
            return nullptr;
        }
        if (ec) {
            file.problem = "unreadable: " + ec.message();
            return nullptr;
        }
        if (status.type() != std::filesystem::file_type::regular) {
            file.problem = "not a regular file";
            return nullptr;
        }
        std::ifstream in(file.path);
        if (!in) {
            file.problem = "unreadable";
            return nullptr;
        }
        auto set = std::make_shared<const WordSet>(read(in));
        if (in.bad()) {
            file.problem = "read error";
            return nullptr;
        }
        if (set->empty()) {
            file.problem = "empty";
            return nullptr;
        }
        file.entries = set->size();
        file.loaded = true;
        return set;
    } catch (const std::exception& e) {
        file.problem = e.what();
    } catch (...) {
        file.problem = "unknown error";
    }
    return nullptr;
}

// Network settings for the breach lookup (the only outbound request this class makes).
constexpr const char* kDefaultBreachEndpoint = "https://api.pwnedpasswords.com/range/";
// A range response is ~35 bytes per suffix and about 1,000 suffixes; anything far larger is not a range response.
constexpr std::size_t kMaxResponseBytes = 4 * 1024 * 1024;

struct NetworkSettings {
    std::mutex mutex;
    std::string breachEndpoint = kDefaultBreachEndpoint;
    Strength::NetworkTimeouts timeouts{};
};

NetworkSettings& network() {
    static NetworkSettings instance;
    return instance;
}

std::atomic<std::size_t> outboundRequests{0};

struct ResponseBuffer {
    std::string body;
    bool overflow = false;
};

size_t appendCapped(void* contents, const size_t size, const size_t nmemb, void* userdata) {
    auto* out = static_cast<ResponseBuffer*>(userdata);
    const size_t length = size * nmemb;
    if (out->body.size() + length > kMaxResponseBytes) {
        out->overflow = true;
        return 0;  // aborts the transfer (CURLE_WRITE_ERROR)
    }
    out->body.append(static_cast<const char*>(contents), length);
    return length;
}

}

unsigned short Strength::passwordStrengthCheck(const std::string& password) {
    if (password.empty()) return 1;

    unsigned short score = 0;

    const size_t len = password.size();
    if (len >= 8) score += 20;
    if (len >= 12) score += 10;
    if (len >= 16) score += 10;
    if (len >= 20) score += 10;

    const bool hasUpper = std::ranges::any_of(password.begin(), password.end(), ::isupper);
    const bool hasLower = std::ranges::any_of(password.begin(), password.end(), ::islower);
    const bool hasDigit = std::ranges::any_of(password.begin(), password.end(), ::isdigit);
    const bool hasSymbol = std::ranges::any_of(password.begin(), password.end(), [](unsigned char c) { return std::ispunct(c); });

    if (hasLower) score += 15;
    if (hasUpper) score += 15;
    if (hasDigit) score += 15;
    if (hasSymbol) score += 15;

    if (!hasUpper && !hasDigit && !hasSymbol) score /= 2;

    // Clamp
    if (score < 1) score = 1;
    if (score > 100) score = 100;

    return score;
}

bool Strength::isDictionaryWord(const std::string& password) {
    const auto dictionary = dictionarySnapshot();
    if (dictionary->empty()) return false; // fallback if not loaded

    const auto isLetter = [](const unsigned char c) { return std::isalpha(c) != 0; };
    const auto first = std::ranges::find_if(password, isLetter);
    if (first == password.end()) return false;
    const auto last = std::ranges::find_if(password.rbegin(), password.rend(), isLetter).base();

    std::string core(first, last);
    lowercase(core);
    return dictionary->contains(core);
}

bool Strength::isCommonWeakPassword(const std::string& password) {
    std::string lowerPw = password;
    lowercase(lowerPw);
    return commonWeakSnapshot()->contains(lowerPw);
}

Strength::BreachCheck Strength::checkPwnedPassword(const std::string& password) {
    const std::string sha1Hex = SHA1Hex(password); // Needs to be uppercase hex
    const std::string prefix = sha1Hex.substr(0, 5);
    const std::string suffix = sha1Hex.substr(5);

    std::string endpoint;
    {
        std::scoped_lock lock(network().mutex);
        endpoint = network().breachEndpoint;
    }

    std::string response;
    try {
        response = fetchURL(endpoint + prefix);
    } catch (...) {
        return BreachCheck::Unavailable;
    }

    std::istringstream stream(response);
    std::string line;
    while (std::getline(stream, line)) {
        const size_t delimPos = line.find(':');
        if (delimPos != std::string::npos) {
            const std::string hashSuffix = line.substr(0, delimPos);
            if (hashSuffix == suffix) return BreachCheck::Found;
        }
    }

    return BreachCheck::NotFound;
}

void Strength::loadCommonWeakPasswords(std::istream& passwords) {
    auto set = std::make_shared<const WordSet>(readCommonPasswords(passwords));
    std::scoped_lock lock(lists().mutex);
    lists().commonWeak = std::move(set);
}

void Strength::loadDictionary(std::istream& words) {
    auto set = std::make_shared<const WordSet>(readDictionary(words));
    std::scoped_lock lock(lists().mutex);
    lists().dictionary = std::move(set);
}

Strength::BundledListReport Strength::loadBundledLists(const std::filesystem::path& dir) noexcept {
    BundledListReport report;
    try {
        report.dictionary.path = dir / kDictionaryFile;
        report.commonPasswords.path = dir / kCommonPasswordsFile;
    } catch (...) {
        report.dictionary.problem = report.commonPasswords.problem = "invalid directory";
        return report;
    }

    auto dictionary = readListFile(report.dictionary, readDictionary);
    auto common = readListFile(report.commonPasswords, readCommonPasswords);

    std::scoped_lock lock(lists().mutex);
    if (dictionary) lists().dictionary = std::move(dictionary);
    if (common) lists().commonWeak = std::move(common);
    return report;
}

std::size_t Strength::dictionarySize() { return dictionarySnapshot()->size(); }

std::size_t Strength::commonWeakPasswordCount() { return commonWeakSnapshot()->size(); }

std::string Strength::SHA1Hex(const std::string& input) {
    SHA1 sha1;
    sha1.update(input);
    std::string digest = sha1.final();

    // Convert to uppercase for HIBP
    std::ranges::transform(digest, digest.begin(), [](const unsigned char c) { return static_cast<char>(std::toupper(c)); });
    return digest;
}

Strength::NetworkTimeouts Strength::networkTimeouts() {
    std::scoped_lock lock(network().mutex);
    return network().timeouts;
}

void Strength::setBreachEndpointForTesting(std::string urlPrefix) {
    std::scoped_lock lock(network().mutex);
    network().breachEndpoint = std::move(urlPrefix);
}

void Strength::setNetworkTimeoutsForTesting(const NetworkTimeouts timeouts) {
    std::scoped_lock lock(network().mutex);
    network().timeouts = timeouts;
}

void Strength::resetNetworkForTesting() {
    std::scoped_lock lock(network().mutex);
    network().breachEndpoint = kDefaultBreachEndpoint;
    network().timeouts = NetworkTimeouts{};
}

std::size_t Strength::outboundRequestCount() { return outboundRequests.load(); }

std::string Strength::fetchURL(const std::string& url) {
    const auto timeouts = networkTimeouts();
    outboundRequests.fetch_add(1);

    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl(curl_easy_init(), &curl_easy_cleanup);
    if (!curl) throw std::runtime_error("Failed to init curl");

    ResponseBuffer response;
    curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, appendCapped);
    curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &response);
    curl_easy_setopt(curl.get(), CURLOPT_USERAGENT, "Vaulthalla-Password-Check");
    // Never block a caller (a ws handler thread) for long: an offline or firewalled host must fail fast.
    curl_easy_setopt(curl.get(), CURLOPT_CONNECTTIMEOUT_MS, static_cast<long>(timeouts.connect.count()));
    curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT_MS, static_cast<long>(timeouts.total.count()));
    curl_easy_setopt(curl.get(), CURLOPT_NOSIGNAL, 1L);  // threaded caller: no SIGALRM-based DNS timeouts
    curl_easy_setopt(curl.get(), CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 0L);

    const CURLcode res = curl_easy_perform(curl.get());
    if (res != CURLE_OK || response.overflow)
        throw std::runtime_error("Request failed: " + std::string(curl_easy_strerror(res)));

    return std::move(response.body);
}

}
