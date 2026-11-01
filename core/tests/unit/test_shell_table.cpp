#include <gtest/gtest.h>

#include "protocols/shell/Table.hpp"

#include <sstream>
#include <string>
#include <string_view>
#include <vector>

// #273: `vh fs ls` (and every shell table) measured, truncated and padded cells by bytes, so a long multi-byte name was
// cut mid-sequence and the columns after it shifted. Cells are now measured in display columns.

namespace vh::protocols::shell::test {

namespace {

// Independent of the code under test: structural UTF-8 validity (lead byte, continuation count, no overlongs, no
// surrogates, nothing past U+10FFFF).
bool validUtf8(const std::string_view s) {
    for (std::size_t i = 0; i < s.size();) {
        const auto b = static_cast<unsigned char>(s[i]);
        std::size_t len = b < 0x80 ? 1 : (b & 0xE0) == 0xC0 ? 2 : (b & 0xF0) == 0xE0 ? 3 : (b & 0xF8) == 0xF0 ? 4 : 0;
        if (len == 0 || i + len > s.size()) return false;
        char32_t cp = len == 1 ? b : b & (0x7F >> len);
        for (std::size_t k = 1; k < len; ++k) {
            const auto c = static_cast<unsigned char>(s[i + k]);
            if ((c & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3F);
        }
        constexpr char32_t min[] = {0, 0, 0x80, 0x800, 0x10000};
        if (cp < min[len] || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return false;
        i += len;
    }
    return true;
}

std::vector<std::string> tableLines(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream in(s);
    for (std::string line; std::getline(in, line);) out.push_back(line);
    return out;
}

// Long names with accents (precomposed and combining), CJK, emoji with modifiers and ZWJ sequences, and flags.
const std::vector<std::string> kNames{
    "Résumé — überarbeitete Fassung für die Präsentation (endgültig).pdf",
    "Café déjà vu, naïve façade, and a very long tail.txt",
    "日本語のファイル名がとても長い場合の表示テスト・第二版.docx",
    "프로젝트 계획서 최종본 수정 완료.hwp",
    "🎉 party 👩🏽‍💻 dev 👨‍👩‍👧‍👦 family 🇺🇸🇯🇵 flags ✅ done ☕.png",
    "short.txt",
};

}

TEST(ShellTextWidth, CountsDisplayColumnsNotBytes) {
    EXPECT_EQ(text::width("abc"), 3u);
    EXPECT_EQ(text::width("é"), 1u);             // U+00E9, 2 bytes
    EXPECT_EQ(text::width("é"), 1u);       // e + combining acute
    EXPECT_EQ(text::width("日本語"), 6u);        // wide
    EXPECT_EQ(text::width("한국어"), 6u);
    EXPECT_EQ(text::width("ＡＢ"), 4u);           // fullwidth forms
    EXPECT_EQ(text::width("😀"), 2u);
    EXPECT_EQ(text::width("👍🏽"), 2u);           // skin-tone modifier
    EXPECT_EQ(text::width("👨‍👩‍👧"), 2u);         // ZWJ sequence: one glyph
    EXPECT_EQ(text::width("❤️"), 1u);            // text-default symbol + VS16 (wcwidth)
    EXPECT_EQ(text::width("🇺🇸"), 2u);           // regional-indicator pair
    EXPECT_EQ(text::width(""), 0u);
}

TEST(ShellTextWidth, SanitizeReplacesMalformedBytes) {
    EXPECT_EQ(text::sanitize("ok"), "ok");
    EXPECT_EQ(text::sanitize("日本"), "日本");
    EXPECT_EQ(text::sanitize("a\xFF" "b"), "a�" "b");
    EXPECT_EQ(text::sanitize("cut\xE6\x97"), "cut��");     // truncated 3-byte sequence
    EXPECT_EQ(text::sanitize("\xC0\xAF"), "��");           // overlong '/'
    EXPECT_EQ(text::sanitize("\xED\xA0\x80"), "���"); // UTF-16 surrogate
    EXPECT_EQ(text::sanitize("\xF4\x90\x80\x80"), "����"); // above U+10FFFF
    for (const auto& name : kNames) EXPECT_EQ(text::sanitize(name), name);
}

TEST(ShellTextWidth, HeadAndTailKeepWholeCharacters) {
    EXPECT_EQ(text::head("日本語", 3), "日");
    EXPECT_EQ(text::head("日本語", 4), "日本");
    EXPECT_EQ(text::head("éé", 1), "é");   // the combining mark stays with its base
    EXPECT_EQ(text::head("a👨‍👩‍👧b", 2), "a");               // the whole ZWJ sequence or nothing
    EXPECT_EQ(text::head("a👨‍👩‍👧b", 3), "a👨‍👩‍👧");
    EXPECT_EQ(text::tail("日本語", 3), "語");
    EXPECT_EQ(text::tail("x🇺🇸", 2), "🇺🇸");
    EXPECT_EQ(text::tail("ab", 5), "ab");
    for (const auto& name : kNames)
        for (std::size_t w = 0; w <= text::width(name); ++w) {
            const auto h = text::head(name, w);
            const auto t = text::tail(name, w);
            EXPECT_TRUE(validUtf8(h)) << name << " head " << w;
            EXPECT_TRUE(validUtf8(t)) << name << " tail " << w;
            EXPECT_LE(text::width(h), w);
            EXPECT_LE(text::width(t), w);
            EXPECT_GE(text::width(h) + 1, w) << "head left more than one column unused";
        }
}

TEST(ShellTable, EllipsizesMultiByteNamesByColumns) {
    Table table({{.header = "NAME", .max = 6, .ellipsize_middle = true}});
    table.add_row({"日本語のファイル"}); // 16 columns: keep 5 = "日" (2) + "…" (1) + "ル" (2), one pad
    table.add_row({"Résumé final.pdf"}); // keep 5 = "Ré" + "…" + "pdf"
    table.add_row({"ééééééé"}); // 7 columns, 14 code points
    EXPECT_EQ(table.render(),
              "  NAME  \n"
              "  ------\n"
              "  日…ル \n"
              "  Ré…pdf\n"
              "  éé…ééé\n");
}

TEST(ShellTable, PadsByDisplayWidth) {
    Table table({{.header = "NAME"}, {.header = "SIZE", .align = Align::Right}});
    table.add_row({"日本", "1"});
    table.add_row({"abcd", "22"});
    table.add_row({"é", "333"});
    EXPECT_EQ(table.render(),
              "  NAME  SIZE\n"
              "  ----  ----\n"
              "  日本     1\n"
              "  abcd    22\n"
              "  é      333\n");
}

TEST(ShellTable, LongMultiByteNamesStayValidAndAligned) {
    // The fs ls layout (NAME last, so it shrinks to the terminal), clamped by bytes before #273.
    for (const bool ellipsize : {true, false})
        for (const int term : {40, 60, 100}) {
            Table table({{.header = "TYPE"},
                         {.header = "SIZE", .align = Align::Right},
                         {.header = "NAME", .ellipsize_middle = ellipsize}},
                        term);
            for (const auto& name : kNames) table.add_row({"file", "12.3 KiB", name});
            const auto out = table.render();
            ASSERT_TRUE(validUtf8(out)) << out;

            const auto ls = tableLines(out);
            ASSERT_EQ(ls.size(), kNames.size() + 2);
            for (const auto& line : ls) {
                EXPECT_EQ(text::width(line), text::width(ls[1])) << "misaligned row:\n" << out;
                EXPECT_LE(static_cast<int>(text::width(line)), term) << line;
            }
            for (std::size_t i = 0; i < kNames.size(); ++i) {
                const auto& line = ls[i + 2];
                ASSERT_TRUE(line.starts_with("  file  12.3 KiB  ")) << line;
                if (text::width(kNames[i]) <= static_cast<std::size_t>(term) - 18) {
                    EXPECT_TRUE(line.contains(kNames[i])) << line;
                } else if (ellipsize) {
                    EXPECT_TRUE(line.contains("…")) << line;
                }
            }
        }

    // A column after a clamped NAME starts at the same column on every row.
    Table table({{.header = "NAME", .max = 30, .ellipsize_middle = true}, {.header = "SIZE", .align = Align::Right}});
    for (const auto& name : kNames) table.add_row({name, "12.3 KiB"});
    const auto out = table.render();
    ASSERT_TRUE(validUtf8(out)) << out;
    for (const auto& line : tableLines(out)) {
        EXPECT_EQ(text::width(line), 2u + 30 + 2 + 8) << "misaligned row:\n" << out;
        EXPECT_TRUE(line.ends_with("    SIZE") || line.ends_with("--------") || line.ends_with("  12.3 KiB")) << line;
    }
}

TEST(ShellTable, WrapsMultiByteTextByColumns) {
    Table table({{.header = "NOTE", .max = 7, .wrap = true}, {.header = "N"}});
    table.add_row({"日本語 のファイル", "1"});
    const auto out = table.render();
    ASSERT_TRUE(validUtf8(out)) << out;
    EXPECT_EQ(out,
              "  NOTE     N\n"
              "  -------  -\n"
              "  日本語   1\n"
              "  のファ    \n"
              "  イル      \n");
}

TEST(ShellTable, MalformedBytesRenderAsReplacementCharacters) {
    Table table({{.header = "NAME"}, {.header = "N"}});
    table.add_row({"bad\xFF\xFEname", "1"});
    const auto out = table.render();
    ASSERT_TRUE(validUtf8(out)) << out;
    EXPECT_NE(out.find("bad��name  1"), std::string::npos) << out;
}

}
