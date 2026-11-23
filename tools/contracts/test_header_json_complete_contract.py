"""A header that holds an nlohmann::json by value includes <nlohmann/json.hpp>, not only json_fwd.hpp.

A by-value member (or a default argument, or a const) needs the complete type. With only the forward declaration
such a header compiles exactly while an earlier file in the same unity chunk happened to include the full header,
and breaks when the chunks move: v1.24.0's macOS -O3 package build failed on ops/Mfa.hpp after new sources shifted
`Mfa.cpp` to the front of its chunk, although every PR build had passed.
"""

import re
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
HEADERS = REPO / "core" / "include"
FWD = re.compile(r'#\s*include\s*<nlohmann/json_fwd\.hpp>')
FULL = re.compile(r'#\s*include\s*<nlohmann/json\.hpp>')
# A json held by value: a member or variable declared as the type itself, or wrapped in a by-value standard holder.
BY_VALUE = re.compile(
    r'^\s*(?:static\s+|inline\s+|constexpr\s+|const\s+)*'
    r'(?:nlohmann::(?:ordered_)?json|std::(?:optional|vector|map|unordered_map|pair|array)<[^;()&*]*nlohmann::(?:ordered_)?json[^;()&*]*>)'
    r'\s+\w+\s*(?:\{|=|;)'
)


class HeaderJsonCompleteContract(unittest.TestCase):
    def test_by_value_json_needs_the_full_header(self) -> None:
        offenders = []
        for path in sorted(HEADERS.rglob("*.hpp")):
            text = path.read_text(encoding="utf-8", errors="replace")
            if not FWD.search(text) or FULL.search(text):
                continue
            for lineno, line in enumerate(text.splitlines(), 1):
                if BY_VALUE.search(line.split("//", 1)[0]):
                    offenders.append(f"{path.relative_to(REPO)}:{lineno}: {line.strip()}")
        self.assertEqual(offenders, [], "include <nlohmann/json.hpp> in these headers:\n" + "\n".join(offenders))

    def test_the_check_sees_a_by_value_member(self) -> None:
        self.assertTrue(BY_VALUE.search("    nlohmann::json factors{};"))
        self.assertTrue(BY_VALUE.search("    std::optional<nlohmann::json> detail;"))
        self.assertFalse(BY_VALUE.search("    void f(const nlohmann::json& in);"))
        self.assertFalse(BY_VALUE.search("    nlohmann::json toJson() const;"))


if __name__ == "__main__":
    unittest.main()
