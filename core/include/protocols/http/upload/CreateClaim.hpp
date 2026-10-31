#pragma once

#include <string>

// Creates of one path through the HTTP upload lanes (PUT /upload/content with If-None-Match: *, and the reject /
// create-only files of /upload/sessions) commit one at a time: the second finds the first's file and is refused,
// instead of both taking the new-file branch of Filesystem::createFile. Key: "<vault id>:<vault path>".
namespace vh::protocols::http::upload {

class CreateClaim {
public:
    explicit CreateClaim(std::string key);
    ~CreateClaim();
    CreateClaim(const CreateClaim&) = delete;
    CreateClaim& operator=(const CreateClaim&) = delete;

    // False when another create of the same key is in progress (nothing is claimed then).
    [[nodiscard]] bool held() const { return held_; }

private:
    std::string key_;
    bool held_{false};
};

}
