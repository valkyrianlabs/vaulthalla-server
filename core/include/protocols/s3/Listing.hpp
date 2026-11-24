#pragma once

#include <optional>
#include <string>
#include <string_view>

// Object listing positions as the S3 API carries them.
//
// A listing is in ascending UTF-8 byte order of the key, and a page starts strictly after a position: a key
// (StartAfter, the v1 Marker) or the last item of the page before, which with a delimiter may be a common prefix
// (db::query::s3::ObjectListParams::after). ListObjectsV2 hands that last item to the client as a continuation token.
namespace vh::protocols::s3::listing {

// The continuation token for a page that ended at `position`: "vh1." and the unpadded base64url of the position's
// bytes. Clients send a token back exactly as they received it and never decode it, whatever EncodingType they asked
// for, so it is made only of characters that mean nothing to XML or to a query string. It is not a secret and not
// authenticated: it says where to resume, and a client may already start anywhere with StartAfter.
[[nodiscard]] std::string encodeContinuationToken(std::string_view position);

// The position `token` stands for, or nullopt for anything this gateway did not issue: another shape, bytes that are
// not base64url, an empty position, or a position that is not key text (isKeyText).
[[nodiscard]] std::optional<std::string> decodeContinuationToken(std::string_view token);

// `value` can be a key or part of one: well-formed UTF-8 (no overlong forms, no surrogates, nothing past U+10FFFF)
// without NUL. Anything else can't be stored as a key, so a listing parameter that fails this names no position.
[[nodiscard]] bool isKeyText(std::string_view value);

}
