#!/usr/bin/env python3
"""Extract the WebAuthn Level 3 test vectors (section 16, "Test Vectors") into core/test-assets/webauthn/.

    curl -sSLo /tmp/webauthn-3.html https://www.w3.org/TR/webauthn-3/
    python3 -I tools/dev/extract_w3c_webauthn_vectors.py /tmp/webauthn-3.html \
        core/test-assets/webauthn/w3c-webauthn-l3-vectors.json

Copies every h'...' byte-string literal of sections 16.2 onwards verbatim (hex), per section and ceremony. The
vectors are consumed by core/tests/unit/test_webauthn_vectors.cpp (#355).
"""
import html
import json
import re
import sys


def section_text(page: str) -> str:
    start = page.find('id="sctn-test-vectors"')
    end = page.find('id="test-vectors-extensions"', start)
    if start < 0 or end < 0:
        sys.exit("no section 16 test vectors in this document")
    chunk = re.sub(r"<script.*?</script>", "", page[start:end], flags=re.S)
    return html.unescape(re.sub(r"<[^>]+>", "", chunk))


def main() -> None:
    page = open(sys.argv[1], encoding="utf-8").read()
    text = "\n" + section_text(page).split("\n", 1)[1]
    parts = re.split(r"\n\s*(16\.\d+)\. ([^\n]+)\n", text)
    vectors = []
    for k in range(1, len(parts), 3):
        number, title, body = parts[k], parts[k + 1].strip(), parts[k + 2]
        if number == "16.1":
            continue
        ceremonies = re.split(r"\n\s*(Registration|Authentication):\n", "\n" + body)
        vector = {"section": number, "title": title}
        for c in range(1, len(ceremonies), 2):
            values = {m.group(1): m.group(2) for m in re.finditer(r"^(\w+) = h'([0-9a-f]*)'", ceremonies[c + 1], re.M)}
            vector[ceremonies[c].lower()] = values
        vectors.append(vector)
    out = {
        "source": 'W3C Web Authentication Level 3, section 16 "Test Vectors" (non-normative), '
                  "https://www.w3.org/TR/webauthn-3/#sctn-test-vectors",
        "retrieved": "2026-11-05",
        "license": "W3C Software and Document License, https://www.w3.org/copyright/software-license/",
        "rp_id": "example.org",
        "origin": "https://example.org",
        "top_origin": "https://example.com",
        "note": "Hex byte strings copied verbatim from the specification (h'...' literals) by "
                "tools/dev/extract_w3c_webauthn_vectors.py.",
        "vectors": vectors,
    }
    with open(sys.argv[2], "w", encoding="utf-8") as f:
        json.dump(out, f, indent=1)
        f.write("\n")


if __name__ == "__main__":
    main()
