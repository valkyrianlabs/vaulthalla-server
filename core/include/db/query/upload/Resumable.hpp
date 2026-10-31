#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The resumable upload tables (migration 114: upload_session, upload_session_file, upload_session_part). Trusted
// primitives: protocols/http/upload/Resumable authorizes every request before it reaches them.
namespace vh::db::query::upload {

struct SessionRow {
    std::string id;
    std::string mode;                       // user | share
    std::optional<uint32_t> user_id;
    std::optional<std::string> share_session_id;
    uint32_t vault_id{};
    std::string state{"open"};
    std::time_t created_at{};
    std::time_t last_activity_at{};
};

struct FileRow {
    std::string upload_id;
    std::string file_id;
    uint32_t ordinal{};
    std::string path;                       // vault path of the target
    std::string display_path;               // the path as the client addressed it (share-relative for shares)
    uint64_t size_bytes{};
    std::optional<std::string> mime_type;
    std::string precondition;               // reject | create_only | if_match
    std::optional<std::string> expected_source_id;
    std::string encryption_iv;              // base64; "" for an empty file
    uint32_t key_version{};
    std::string state{"receiving"};         // receiving | sealing | committing | committed | failed
    uint64_t sealed_bytes{};
    std::optional<std::string> error_code, error_message, error_etag;
    std::optional<uint32_t> entry_id;
    std::optional<std::string> share_upload_id;
    std::optional<std::string> share_parent_path;
};

struct PartRow {
    std::string upload_id;
    std::string file_id;
    uint64_t offset{};
    uint64_t length{};
    std::string encryption_iv;              // base64, the part's own spool IV
};

struct LoadedSession {
    SessionRow session;
    std::vector<FileRow> files;             // by ordinal
    std::vector<PartRow> parts;
};

class Resumable {
public:
    static void create(const SessionRow& session, const std::vector<FileRow>& files);
    // Records a durably stored part and slides the session's last activity to `now`, in one transaction.
    static void insertPart(const PartRow& part, std::time_t now);
    static void deletePart(const std::string& uploadId, const std::string& fileId, uint64_t offset);
    static void deleteParts(const std::string& uploadId, const std::string& fileId);
    static void setSealed(const std::string& uploadId, const std::string& fileId, uint64_t sealedBytes);
    static void setFileState(const std::string& uploadId, const std::string& fileId, const std::string& state);
    static void markCommitted(const std::string& uploadId, const std::string& fileId, uint32_t entryId);
    static void markFailed(const std::string& uploadId, const std::string& fileId, const std::string& code,
                           const std::string& message, const std::optional<std::string>& etag);
    static void setSessionState(const std::string& uploadId, const std::string& state);
    static void remove(const std::string& uploadId);

    [[nodiscard]] static std::vector<LoadedSession> loadAll();
    [[nodiscard]] static bool exists(const std::string& uploadId);
    // Sessions idle since before `now - idleSeconds` or created before `now - maxAgeSeconds`.
    [[nodiscard]] static std::vector<std::string> expired(std::time_t now, int64_t idleSeconds, int64_t maxAgeSeconds);
};

}
