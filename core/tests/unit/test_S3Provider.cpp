// The s3::Controller data plane against the shared live test bucket (tests/helpers/live_bucket.hpp; testing.md "Live
// provider tests"): every key under the test's own vh-test-runs/<run>/<test>/ prefix, removed again in TearDown.
// Skips without VAULTHALLA_TEST_R2_* (or VAULTHALLA_TEST_S3_* for the AWS instance).

#include "../helpers/live_bucket.hpp"

#include "vault/model/APIKey.hpp"
#include "storage/s3/Controller.hpp"
#include "preview/image.hpp"
#include "preview/pdf.hpp"
#include "preview/render/Raster.hpp"
#include "fs/model/Entry.hpp"

#include <filesystem>
#include <fstream>
#include <gtest/gtest.h>
#include <algorithm>
#include <cctype>
#include <optional>
#include <unordered_map>

using namespace vh::storage::s3;
using namespace vh::vault::model;
using namespace vh::fs::model;
using namespace vh::preview;

class S3ProviderIntegrationTest : public vh::test_support::live::LiveBucketTest {
protected:
    inline static std::filesystem::path test_dir;
    inline static std::optional<vh::preview::render::PdfiumLibrary> pdfium;

    static void SetUpTestSuite() {
        test_dir = std::filesystem::temp_directory_path() / "vaulthalla_test_dir";
        std::filesystem::create_directories(test_dir);
        pdfium.emplace();
    }

    static void TearDownTestSuite() {
        std::filesystem::remove_all(test_dir);
        pdfium.reset();
    }

    [[nodiscard]] Controller& s3() { return live().controller(); }
    // An object key under this test's prefix.
    [[nodiscard]] std::filesystem::path objectKey(const std::filesystem::path& relative) {
        return live().key(relative.string());
    }
    static std::filesystem::path asset(const std::filesystem::path& name) {
        return std::filesystem::path(VH_TEST_ASSETS_DIR) / name;
    }

    static void writeTextFile(const std::filesystem::path &path, const std::string &content) {
        std::ofstream out(path);
        out << content;
    }

    static std::optional<std::string> headerValue(
        const std::unordered_map<std::string, std::string>& headers,
        std::string name) {
        std::ranges::transform(name, name.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        for (const auto& [key, value] : headers) {
            auto normalized = key;
            std::ranges::transform(normalized, normalized.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (normalized == name) return value;
        }
        return std::nullopt;
    }
};

TEST_P(S3ProviderIntegrationTest, test_DeleteUnicodeFilename) {
    const std::filesystem::path name = u8"Screenshot 2025-06-26 at 3.29.35\u202FPM.png";
    const auto key = objectKey(name);
    ASSERT_TRUE(std::filesystem::exists(asset(name)));

    std::cout << "Uploading file: " << key << std::endl;
    ASSERT_NO_THROW(s3().uploadObject(key, asset(name)));

    std::cout << "Downloading file: " << key << std::endl;
    const auto downloadedPath = test_dir / "downloaded.png";
    ASSERT_NO_THROW(s3().downloadObject(key, downloadedPath));

    std::cout << "Deleting file: " << key << std::endl;
    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_BulkUploadDownloadDeleteTestAssets) {
    const std::vector<std::filesystem::path> filenames = {
        "sample.jpg",
        "sample.pdf",
        u8"Screenshot 2025-06-26 at 3.29.35\u202FPM.png"
    };

    std::vector<std::filesystem::path> uploadedKeys;

    for (const auto &name: filenames) {
        const std::filesystem::path src = asset(name);
        ASSERT_TRUE(std::filesystem::exists(src)) << "Test asset missing: " << src;

        const std::filesystem::path relKey = objectKey(std::filesystem::path("test-assets") / src.filename());
        const std::filesystem::path dest = test_dir / src.filename();
        std::filesystem::copy_file(src, dest, std::filesystem::copy_options::overwrite_existing);

        ASSERT_TRUE(std::filesystem::exists(dest)) << "Failed to copy file to: " << dest;

        std::cout << "Uploading file: " << relKey << std::endl;
        ASSERT_NO_THROW(s3().uploadObject(relKey, dest)) << "Upload failed for: " << relKey;

        uploadedKeys.push_back(relKey);

        std::vector<uint8_t> buffer;
        std::cout << "Downloading file to buffer: " << relKey << std::endl;
        EXPECT_NO_THROW(s3().downloadToBuffer(relKey, buffer)) << "Download failed for: " << relKey;
        EXPECT_GT(buffer.size(), 10) << "Buffer too small for: " << relKey;
    }

    for (const auto &key: uploadedKeys) {
        std::cout << "Deleting uploaded key: " << key << std::endl;
        EXPECT_NO_THROW(s3().deleteObject(key)) << "Failed to delete key: " << key;
    }
}

TEST_P(S3ProviderIntegrationTest, test_S3SimpleUploadRoundTrip) {
    const auto key = objectKey("simple-test.txt");
    const auto filePath = test_dir / key.filename();

    // Write some test content to the file
    writeTextFile(filePath, "This is a test file for S3 upload.");

    ASSERT_TRUE(std::filesystem::exists(filePath)) << "File not created at: " << filePath;

    std::cout << "Uploading file: " << filePath << std::endl;
    EXPECT_NO_THROW(s3().uploadObject(key, filePath)) << "Failed to upload file to S3: " << key;

    std::cout << "Downloading file: " << filePath << std::endl;
    // Download the file for verification
    const auto downloadedPath = test_dir / "downloaded.txt";
    EXPECT_NO_THROW(s3().downloadObject(key, downloadedPath));

    // Compare original and downloaded files
    std::ifstream original(filePath);
    std::ifstream downloaded(downloadedPath);
    std::ostringstream originalContent, downloadedContent;
    originalContent << original.rdbuf();
    downloadedContent << downloaded.rdbuf();
    EXPECT_TRUE(originalContent.str() == downloadedContent.str());

    // Cleanup
    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_S3EncryptedFileMetadataRoundTrip) {
    const auto key = objectKey("encrypted-metadata-test.bin");
    const auto filePath = test_dir / key.filename();
    writeTextFile(filePath, "ciphertext metadata payload");

    ASSERT_NO_THROW(s3().uploadObjectWithMetadata(
        key,
        filePath,
        {
            {"vh-encrypted", "true"},
            {"vh-iv", "bWluaW8tdGVzdC1pdi0xMg=="},
            {"vh-key-version", "3"},
            {"content-hash", "metadata-round-trip"},
        }));

    const auto head = s3().getHeadObject(key);
    ASSERT_TRUE(head.has_value());
    EXPECT_EQ("true", headerValue(*head, "x-amz-meta-vh-encrypted").value_or(""));
    EXPECT_EQ("bWluaW8tdGVzdC1pdi0xMg==", headerValue(*head, "x-amz-meta-vh-iv").value_or(""));
    EXPECT_EQ("3", headerValue(*head, "x-amz-meta-vh-key-version").value_or(""));
    EXPECT_EQ("metadata-round-trip", headerValue(*head, "x-amz-meta-content-hash").value_or(""));

    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_S3MultipartUploadRoundtrip) {
    const auto key = objectKey("multipart-test-2.txt");

    // Generate a temporary file with ~15MB of data
    const auto filePath = test_dir / key.filename();
    const auto part = std::string(5 * 1024 * 1024, 'x'); // 5MB
    std::ofstream out(filePath, std::ios::binary);
    out << part << part << part; // total 15MB
    out.close();

    ASSERT_TRUE(std::filesystem::exists(filePath));

    // Upload the file using multipart logic
    EXPECT_NO_THROW(s3().uploadLargeObject(key, filePath.string(), 5 * 1024 * 1024));

    // Download for verification
    const auto downloadedPath = test_dir / "downloaded.txt";
    EXPECT_NO_THROW(s3().downloadObject(key, downloadedPath.string()));

    // Compare original and downloaded files
    std::ifstream original(filePath, std::ios::binary);
    std::ifstream downloaded(downloadedPath, std::ios::binary);
    std::ostringstream originalContent, downloadedContent;
    originalContent << original.rdbuf();
    downloadedContent << downloaded.rdbuf();
    EXPECT_TRUE(downloadedContent.str().contains("xxxxx")) << downloadedContent.str();
    // EXPECT_EQ(originalContent.str(), downloadedContent.str());

    // Cleanup
    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_S3MultipartAbortOnFailure) {
    // Left unfinished if the test stops before the abort: TearDown aborts it (ListMultipartUploads under the prefix).
    const auto key = objectKey("abort-test.txt");

    std::string uploadId = s3().initiateMultipartUpload(key);
    ASSERT_FALSE(uploadId.empty());

    const auto bogus = std::string(5 * 1024 * 1024, 'Z');
    std::string etag;

    // Simulate partial upload then abort
    EXPECT_NO_THROW(s3().uploadPart(key, uploadId, 1, bogus, etag));

    EXPECT_NO_THROW(s3().abortMultipartUpload(key, uploadId));
}

TEST_P(S3ProviderIntegrationTest, test_S3ListObjectsAndDownloadToBuffer) {
    const auto key = objectKey("list-download-test.txt");
    const auto filePath = test_dir / key.filename();
    writeTextFile(filePath, "This file should appear in listObjects and download into buffer.");
    ASSERT_NO_THROW(s3().uploadObject(key, filePath.string()));

    const auto xml = s3().listObjects(live().prefix());

    const auto entries = fromS3XML(xml);
    EXPECT_FALSE(entries.empty()) << "fromS3XML should return at least one entry";
    auto match = std::ranges::find_if(entries.begin(), entries.end(), [&](const auto &entry) {
        return !entry->isDirectory() && entry->path.filename() == key.filename();
    });
    EXPECT_TRUE(match != entries.end()) << "Uploaded key not found in fromS3XML()";

    std::vector<uint8_t> buffer;
    EXPECT_NO_THROW(s3().downloadToBuffer(key, buffer));

    const std::string expected = "appear in listObjects";
    const auto it = std::search(buffer.begin(), buffer.end(),
                                expected.begin(), expected.end());

    EXPECT_TRUE(it != buffer.end()) << "Downloaded buffer does not contain expected content";

    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_ResizeAndCompressImageBuffer) {
    const auto key = objectKey("test-image.jpg");
    const auto srcPath = asset("sample.jpg");
    ASSERT_TRUE(std::filesystem::exists(srcPath));
    ASSERT_NO_THROW(s3().uploadObject(key, srcPath.string()));

    std::vector<uint8_t> buffer;
    ASSERT_NO_THROW(s3().downloadToBuffer(key, buffer));

    auto jpeg = image::resize_and_compress_buffer(
        buffer.data(),
        buffer.size(),
        std::nullopt,
        std::make_optional("128")
    );

    EXPECT_GT(jpeg.size(), 100); // sanity check: JPEG data exists
    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_ResizeAndCompressPdfBuffer) {
    const auto key = objectKey("test-pdf.pdf");
    const auto srcPath = asset("sample.pdf");
    ASSERT_TRUE(std::filesystem::exists(srcPath));
    ASSERT_NO_THROW(s3().uploadObject(key, srcPath.string()));

    std::vector<uint8_t> buffer;
    ASSERT_NO_THROW(s3().downloadToBuffer(key, buffer));

    auto jpeg = pdf::resize_and_compress_buffer(
        buffer.data(),
        buffer.size(),
        std::nullopt,
        std::make_optional("128")
    );

    EXPECT_GT(jpeg.size(), 100);
    EXPECT_NO_THROW(s3().deleteObject(key));
}

TEST_P(S3ProviderIntegrationTest, test_ValidateS3Credentials) {
    EXPECT_NO_THROW(const auto ok = s3().validateAPICredentials());
}

TEST_P(S3ProviderIntegrationTest, test_isBucketEmpty) {
    EXPECT_NO_THROW(const auto _ = s3().isBucketEmpty());
}

INSTANTIATE_TEST_SUITE_P(Live, S3ProviderIntegrationTest,
                         ::testing::Values(vh::test_support::live::Provider::R2, vh::test_support::live::Provider::Aws),
                         vh::test_support::live::providerName);
