// What the vault data path actually puts on the wire, DB-free: the real storage::s3::Controller and real libcurl
// against a capture server on 127.0.0.1, one request per operation that signs through curl::buildAuthorizationHeader
// (object PUT from a buffer and from a file, conditional PUT, GET to a buffer and to a file, streamed GET with a range,
// HEAD, both copy-in-place metadata updates, DELETE, ListObjectsV2 pages, multipart initiate/part/complete/abort, the
// ListBuckets credential probe, the bucket-empty check).
//
// For every captured request:
//  - vl-sigv4's verifier accepts it at its own x-amz-date (signature, payload hash for the operations that sign the
//    body, signed headers present, the credential-scope date equal to x-amz-date's date);
//  - the retired data-path signer (curl::buildAuthorizationTrace) given the same headers, path, query and date
//    computes the same Authorization: what the old code would have sent at that instant.
//
// VH_S3_WIRE_DUMP=<file> also writes every captured request (request line, header lines in order, body) with the
// time-dependent parts masked (x-amz-date, the scope date, the signature, the capture port), so two builds can be
// compared byte for byte (the vl-sigv4 data-path migration was checked that way against the code before it).

#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <vl/sigv4/canonical.hpp>
#include <vl/sigv4/verifier.hpp>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <utility>
#include <vector>

namespace s3wire {

namespace s3 = vh::storage::s3;
namespace legacy = vh::storage::s3::curl;
namespace vlsig = vl::sigv4;

struct Captured {
    std::string method;
    std::string target;
    std::vector<std::pair<std::string, std::string>> headers;   // as sent: name case kept, value after ": " verbatim
    std::string body;

    [[nodiscard]] std::optional<std::string> header(const std::string& name) const {
        for (const auto& [k, v] : headers)
            if (vlsig::toLower(k) == name) return v;
        return std::nullopt;
    }
};

// A one-request-per-connection HTTP/1.1 server that records what it receives and answers like S3 would.
class CaptureServer {
public:
    using Responder = std::function<std::string(const Captured&)>;

    explicit CaptureServer(Responder responder) : responder_(std::move(responder)) {
        fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
        if (fd_ < 0) throw std::runtime_error("capture server: socket failed");
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0;
        if (::bind(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof addr) != 0 || ::listen(fd_, 8) != 0) {
            ::close(fd_);
            throw std::runtime_error("capture server: bind/listen failed");
        }
        socklen_t len = sizeof addr;
        ::getsockname(fd_, reinterpret_cast<sockaddr*>(&addr), &len);
        port_ = ntohs(addr.sin_port);
        thread_ = std::thread([this] { run(); });
    }

    ~CaptureServer() {
        stop_ = true;
        thread_.join();
        ::close(fd_);
    }

    CaptureServer(const CaptureServer&) = delete;
    CaptureServer& operator=(const CaptureServer&) = delete;

    [[nodiscard]] unsigned short port() const { return port_; }

    [[nodiscard]] std::vector<Captured> take() {
        std::scoped_lock lock(mutex_);
        return std::exchange(requests_, {});
    }

private:
    void run() {
        while (!stop_) {
            pollfd p{.fd = fd_, .events = POLLIN, .revents = 0};
            if (::poll(&p, 1, 50) <= 0) continue;
            const int conn = ::accept(fd_, nullptr, nullptr);
            if (conn < 0) continue;
            timeval timeout{.tv_sec = 5, .tv_usec = 0};
            ::setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof timeout);
#ifdef SO_NOSIGPIPE
            const int one = 1;
            ::setsockopt(conn, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof one);
#endif
            serve(conn);
            ::close(conn);
        }
    }

    static void sendAll(const int conn, const std::string& data) {
#ifdef MSG_NOSIGNAL
        constexpr int flags = MSG_NOSIGNAL;
#else
        constexpr int flags = 0;
#endif
        std::size_t off = 0;
        while (off < data.size()) {
            const auto n = ::send(conn, data.data() + off, data.size() - off, flags);
            if (n <= 0) return;
            off += static_cast<std::size_t>(n);
        }
    }

    void serve(const int conn) {
        std::string in;
        char buf[4096];
        std::size_t headEnd = std::string::npos;
        while ((headEnd = in.find("\r\n\r\n")) == std::string::npos) {
            const auto n = ::recv(conn, buf, sizeof buf, 0);
            if (n <= 0) return;
            in.append(buf, static_cast<std::size_t>(n));
        }
        Captured req;
        const auto head = in.substr(0, headEnd);
        std::size_t lineStart = 0;
        bool first = true;
        while (lineStart <= head.size()) {
            const auto lineEnd = std::min(head.find("\r\n", lineStart), head.size());
            const auto line = head.substr(lineStart, lineEnd - lineStart);
            if (first) {
                const auto sp1 = line.find(' ');
                const auto sp2 = line.find(' ', sp1 + 1);
                req.method = line.substr(0, sp1);
                req.target = line.substr(sp1 + 1, sp2 - sp1 - 1);
                first = false;
            } else if (const auto colon = line.find(':'); colon != std::string::npos) {
                auto value = line.substr(colon + 1);
                if (value.starts_with(' ')) value.erase(0, 1);   // curl writes "name: value"
                req.headers.emplace_back(line.substr(0, colon), std::move(value));
            }
            lineStart = lineEnd + 2;
        }
        if (const auto expect = req.header("expect"); expect && vlsig::toLower(*expect) == "100-continue")
            sendAll(conn, "HTTP/1.1 100 Continue\r\n\r\n");
        std::size_t length = 0;
        if (const auto cl = req.header("content-length")) length = std::stoull(*cl);
        req.body = in.substr(headEnd + 4);
        while (req.body.size() < length) {
            const auto n = ::recv(conn, buf, sizeof buf, 0);
            if (n <= 0) break;
            req.body.append(buf, static_cast<std::size_t>(n));
        }
        const auto response = responder_(req);
        {
            std::scoped_lock lock(mutex_);
            requests_.push_back(std::move(req));
        }
        sendAll(conn, response);
    }

    Responder responder_;
    int fd_ = -1;
    unsigned short port_ = 0;
    std::atomic<bool> stop_{false};
    std::thread thread_;
    std::mutex mutex_;
    std::vector<Captured> requests_;
};

std::string httpResponse(const int status, const std::string& reason, const std::string& body,
                         const std::vector<std::string>& extraHeaders = {}, const bool head = false) {
    std::string out = "HTTP/1.1 " + std::to_string(status) + " " + reason + "\r\n";
    for (const auto& h : extraHeaders) out += h + "\r\n";
    out += "Content-Length: " + std::to_string(head ? 0 : body.size()) + "\r\nConnection: close\r\n\r\n";
    if (!head) out += body;
    return out;
}

// What S3 answers, by request shape.
std::string answerLikeS3(const Captured& r) {
    const auto& t = r.target;
    if (r.method == "HEAD")
        return httpResponse(200, "OK", "", {"ETag: \"head-etag\"", "x-amz-meta-vh-iv: aXY="}, true);
    if (r.method == "POST" && t.ends_with("?uploads"))
        return httpResponse(200, "OK", "<InitiateMultipartUploadResult><UploadId>up%2Bload</UploadId>"
                                       "</InitiateMultipartUploadResult>");
    if (r.method == "POST")
        return httpResponse(200, "OK",
                            "<CompleteMultipartUploadResult><ETag>\"mp-3\"</ETag></CompleteMultipartUploadResult>",
                            {"ETag: \"mp-3\""});
    if (r.method == "PUT") return httpResponse(200, "OK", "", {"ETag: \"put-etag\""});
    if (r.method == "DELETE") return httpResponse(204, "No Content", "");
    if (t.find("list-type=2") != std::string::npos)
        return httpResponse(200, "OK", "<ListBucketResult><IsTruncated>false</IsTruncated></ListBucketResult>");
    if (t == "/") return httpResponse(200, "OK", "<ListAllMyBucketsResult></ListAllMyBucketsResult>");
    if (r.header("range")) return httpResponse(206, "Partial Content", "bcd", {"Content-Range: bytes 1-3/5"});
    return httpResponse(200, "OK", "abcde");
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

class S3DataPathWire : public ::testing::Test {
protected:
    CaptureServer server{answerLikeS3};
    std::shared_ptr<vh::vault::model::APIKey> key = std::make_shared<vh::vault::model::APIKey>(
        7, "wire-unit", vh::vault::model::S3Provider::AWS, "AKIAWIREUNIT00000000",
        "wire/unit+secret=0000000000000000000000", "us-east-2", "http://127.0.0.1:" + std::to_string(server.port()));
    s3::Controller controller{key, "vh-wire-bucket"};
    std::filesystem::path scratch;

    void SetUp() override {
        vh::storage::upstream::guard::setForTesting({});
        scratch = std::filesystem::temp_directory_path() / ("vh-s3-wire-" + std::to_string(::getpid()));
        std::filesystem::create_directories(scratch);
    }

    void TearDown() override { std::filesystem::remove_all(scratch); }

    [[nodiscard]] std::string port() const { return std::to_string(server.port()); }

    // The request one operation sent, after checking it is exactly one.
    Captured only(const char* op) {
        auto got = server.take();
        EXPECT_EQ(got.size(), 1u) << op;
        if (got.empty()) return {};
        return got.front();
    }
};

std::string maskPort(std::string text, const std::string& port) {
    const auto replaceAll = [&](const std::string& from, const std::string& to) {
        for (std::size_t at = 0; (at = text.find(from, at)) != std::string::npos; at += to.size())
            text.replace(at, from.size(), to);
    };
    replaceAll(port, "<PORT>");
    return text;
}

// The masked form of a request (time-dependent parts and the capture port replaced) for VH_S3_WIRE_DUMP.
std::string masked(const std::string& op, const Captured& r, const std::string& port) {
    std::string out = "### " + op + "\n" + r.method + " " + maskPort(r.target, port) + "\n";
    for (const auto& [name, value] : r.headers) {
        std::string v = value;
        if (vlsig::toLower(name) == "x-amz-date") v = "<AMZDATE>";
        if (vlsig::toLower(name) == "authorization") {
            const auto cred = v.find("Credential=");
            const auto slash = v.find('/', cred);
            if (slash != std::string::npos) v.replace(slash + 1, 8, "<DATE>");
            if (const auto sig = v.find("Signature="); sig != std::string::npos) v = v.substr(0, sig + 10) + "<SIG>";
        }
        out += name + ": " + maskPort(v, port) + "\n";
    }
    out += "<body " + std::to_string(r.body.size()) + " bytes>\n" + r.body + "\n";
    return out;
}

void dump(const std::string& text) {
    const char* target = std::getenv("VH_S3_WIRE_DUMP");
    if (!target || !*target) return;
    std::ofstream(target, std::ios::binary | std::ios::app) << text;
}

// The checks every captured data-path request must pass (file comment).
void expectSignedLikeBefore(const std::string& op, const Captured& r, const vh::vault::model::APIKey& key) {
    SCOPED_TRACE(op + ": " + r.method + " " + r.target);
    const auto amzDate = r.header("x-amz-date");
    const auto authorization = r.header("authorization");
    const auto payloadHash = r.header("x-amz-content-sha256");
    ASSERT_TRUE(amzDate && authorization && payloadHash);
    const auto signedAt = vlsig::parseAmzDate(*amzDate);
    ASSERT_TRUE(signedAt) << *amzDate;

    vlsig::VerificationInput input{.method = r.method, .target = r.target, .host = {},
                                   .headers = vlsig::HeaderList(r.headers.begin(), r.headers.end()), .body = r.body};
    const auto verified = vlsig::verify(input, key.secret_access_key, *signedAt);
    EXPECT_TRUE(verified.ok()) << vlsig::errorCodeName(verified.code) << ": " << verified.message;
    const auto scope = "/" + amzDate->substr(0, 8) + "/" + key.region + "/s3/aws4_request";
    EXPECT_NE(authorization->find(scope), std::string::npos) << *authorization;

    // The retired signer over the same signed headers (values verbatim), path, query and date.
    const auto signedPos = authorization->find("SignedHeaders=") + 14;
    const auto signedNames = authorization->substr(signedPos, authorization->find(',', signedPos) - signedPos);
    std::map<std::string, std::string> signedHeaders;
    std::size_t start = 0;
    while (start <= signedNames.size()) {
        const auto end = std::min(signedNames.find(';', start), signedNames.size());
        const auto name = signedNames.substr(start, end - start);
        const auto value = r.header(name);
        EXPECT_TRUE(value) << "signed header " << name << " was not sent";
        signedHeaders[name] = value.value_or("");
        start = end + 1;
    }
    const auto apiKey = std::make_shared<vh::vault::model::APIKey>(key);
    const auto old = legacy::buildAuthorizationTrace(apiKey, r.method, r.target, signedHeaders, *payloadHash, "",
                                                     amzDate->substr(0, 8));
    EXPECT_EQ(*authorization, old.authorization);
}

}

using s3wire::S3DataPathWire;

TEST_F(S3DataPathWire, EveryDataPathRequestIsSignedAsBeforeAndVerifies) {
    using namespace s3wire;
    std::vector<std::pair<std::string, std::vector<Captured>>> sent;
    const auto record = [&](const std::string& op, const std::function<void()>& call) {
        call();
        sent.emplace_back(op, server.take());
    };

    s3::RequestOptions options;
    options.metadata = {{"vh-encrypted", "true"}, {"vh-iv", "aXYtYmFzZTY0Kz0="}, {"vh-key-version", "3"},
                        {"content-hash", "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"}};
    options.system_headers = {{"X-Amz-Storage-Class", "STANDARD_IA"}};
    const std::string object = "dir/a b+c=d.txt";

    record("PutObject (buffer, conditional)", [&] {
        controller.uploadBufferWithMetadataConditional(object, bytesOf("ciphertext"), options,
                                                       std::string("\"put-etag\""), std::nullopt);
    });
    record("PutObject (buffer, if-none-match)", [&] {
        controller.uploadBufferWithMetadataConditional(".vaulthalla/index-v1.json", bytesOf("{}"), s3::RequestOptions{},
                                                       std::nullopt, std::string("*"));
    });
    const auto file = scratch / "upload.bin";
    std::ofstream(file, std::ios::binary) << "file body";
    record("PutObject (file)", [&] { controller.uploadObjectWithMetadata(object, file, options); });
    record("GetObject (buffer)", [&] {
        std::vector<uint8_t> out;
        controller.downloadToBuffer(object, out);
        EXPECT_EQ(out, bytesOf("abcde"));
    });
    record("GetObject (file)", [&] { controller.downloadObject(object, scratch / "download.bin"); });
    record("GetObject (stream, range, if-match)", [&] {
        s3::GetObjectOptions get;
        get.range = std::make_pair<uint64_t, uint64_t>(1, 3);
        get.if_match = "\"put-etag\"";
        std::string body;
        (void)controller.streamObject(object, get,
                                      [&](const std::span<const uint8_t> b) { body.append(b.begin(), b.end()); });
        EXPECT_EQ(body, "bcd");
    });
    record("HeadObject", [&] { EXPECT_TRUE(controller.getHeadObject(object)); });
    record("CopyObject (content hash)", [&] { controller.setObjectContentHash(object, "abc123", options); });
    record("CopyObject (encryption metadata)", [&] {
        controller.setObjectEncryptionMetadata(object, "aXY=", 4, options);
    });
    record("DeleteObject", [&] { controller.deleteObject(object); });
    record("ListObjectsV2 page", [&] {
        (void)controller.listObjectKeysPage("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J+wm36Hy4vbOwM=", 1000);
    });
    record("CreateMultipartUpload",
           [&] { EXPECT_EQ(controller.initiateMultipartUpload(object, options), "up%2Bload"); });
    record("UploadPart", [&] {
        std::string etag;
        controller.uploadPart(object, "up%2Bload", 2, "part two", etag);
        EXPECT_EQ(etag, "\"put-etag\"");
    });
    record("CompleteMultipartUpload", [&] {
        controller.completeMultipartUpload(object, "up%2Bload", {"\"e1\"", "\"e2\""});
    });
    record("AbortMultipartUpload", [&] { controller.abortMultipartUpload(object, "up%2Bload"); });
    record("Multipart driver (buffer)", [&] {
        controller.uploadLargeObject("big.bin", bytesOf("0123456789"), 4, options);
    });
    record("ListBuckets probe", [&] { EXPECT_TRUE(controller.validateAPICredentials().ok); });
    record("Bucket empty check", [&] { EXPECT_TRUE(controller.isBucketEmpty()); });

    std::size_t requests = 0;
    for (const auto& [op, captured] : sent) {
        EXPECT_FALSE(captured.empty()) << op << " sent nothing";
        for (const auto& r : captured) {
            ++requests;
            expectSignedLikeBefore(op, r, *key);
            dump(masked(op, r, port()));
        }
    }
    EXPECT_EQ(requests, 22u);   // 17 single requests + the driver's initiate, 3 parts and complete
}

// Header values are signed the way S3 reads them: trimmed, inner whitespace collapsed (SigV4). The old signer signed
// them verbatim, so a value like this one never verified; no data-path caller sends one (test_sigv4_goldens.cpp,
// legacySignerDeviations), and the request still goes out with the value as the caller wrote it.
TEST_F(S3DataPathWire, UntrimmedHeaderValuesAreSignedAsS3ReadsThem) {
    using namespace s3wire;
    s3::RequestOptions options;
    options.metadata = {{"owner", "  Cooper   Larson "}};
    controller.uploadBufferWithMetadata("k", bytesOf("x"), options);
    const auto r = only("PutObject");
    EXPECT_EQ(r.header("x-amz-meta-owner").value_or(""), "  Cooper   Larson ");
    const auto signedAt = vlsig::parseAmzDate(r.header("x-amz-date").value_or(""));
    ASSERT_TRUE(signedAt);
    vlsig::VerificationInput input{.method = r.method, .target = r.target, .host = {},
                                   .headers = vlsig::HeaderList(r.headers.begin(), r.headers.end()), .body = r.body};
    const auto verified = vlsig::verify(input, key->secret_access_key, *signedAt);
    EXPECT_TRUE(verified.ok()) << verified.message;
}
