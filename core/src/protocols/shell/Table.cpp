#include "protocols/shell/Table.hpp"

#include <algorithm>
#include <array>
#include <optional>
#include <utility>

namespace vh::protocols::shell {

namespace text::detail {

struct Range { char32_t lo, hi; };

// Characters that take no column of their own: combining marks, Hangul medial/final jamo, zero-width and bidi format
// characters, variation selectors, emoji skin-tone modifiers and tag characters. Sorted for binary search.
constexpr std::array kZeroWidth{
    Range{0x0300, 0x036F}, Range{0x0483, 0x0489}, Range{0x0591, 0x05BD}, Range{0x05BF, 0x05BF},
    Range{0x05C1, 0x05C2}, Range{0x05C4, 0x05C5}, Range{0x05C7, 0x05C7}, Range{0x0610, 0x061A},
    Range{0x064B, 0x065F}, Range{0x0670, 0x0670}, Range{0x06D6, 0x06DC}, Range{0x06DF, 0x06E4},
    Range{0x06E7, 0x06E8}, Range{0x06EA, 0x06ED}, Range{0x0E31, 0x0E31}, Range{0x0E34, 0x0E3A},
    Range{0x0E47, 0x0E4E}, Range{0x1160, 0x11FF}, Range{0x1AB0, 0x1AFF}, Range{0x1DC0, 0x1DFF},
    Range{0x200B, 0x200F}, Range{0x202A, 0x202E}, Range{0x2060, 0x2064}, Range{0x20D0, 0x20FF},
    Range{0x302A, 0x302D}, Range{0x3099, 0x309A}, Range{0xFE00, 0xFE0F}, Range{0xFE20, 0xFE2F},
    Range{0xFEFF, 0xFEFF}, Range{0x1F3FB, 0x1F3FF}, Range{0xE0000, 0xE007F}, Range{0xE0100, 0xE01EF},
};

// East Asian Wide and Fullwidth characters, and emoji shown with emoji presentation by default. Sorted.
constexpr std::array kWide{
    Range{0x1100, 0x115F}, Range{0x231A, 0x231B}, Range{0x2329, 0x232A}, Range{0x23E9, 0x23EC},
    Range{0x23F0, 0x23F0}, Range{0x23F3, 0x23F3}, Range{0x25FD, 0x25FE}, Range{0x2614, 0x2615},
    Range{0x2648, 0x2653}, Range{0x267F, 0x267F}, Range{0x2693, 0x2693}, Range{0x26A1, 0x26A1},
    Range{0x26AA, 0x26AB}, Range{0x26BD, 0x26BE}, Range{0x26C4, 0x26C5}, Range{0x26CE, 0x26CE},
    Range{0x26D4, 0x26D4}, Range{0x26EA, 0x26EA}, Range{0x26F2, 0x26F3}, Range{0x26F5, 0x26F5},
    Range{0x26FA, 0x26FA}, Range{0x26FD, 0x26FD}, Range{0x2705, 0x2705}, Range{0x270A, 0x270B},
    Range{0x2728, 0x2728}, Range{0x274C, 0x274C}, Range{0x274E, 0x274E}, Range{0x2753, 0x2755},
    Range{0x2757, 0x2757}, Range{0x2795, 0x2797}, Range{0x27B0, 0x27B0}, Range{0x27BF, 0x27BF},
    Range{0x2B1B, 0x2B1C}, Range{0x2B50, 0x2B50}, Range{0x2B55, 0x2B55}, Range{0x2E80, 0x303E},
    Range{0x3041, 0x33FF}, Range{0x3400, 0x4DBF}, Range{0x4E00, 0x9FFF}, Range{0xA000, 0xA4CF},
    Range{0xA960, 0xA97F}, Range{0xAC00, 0xD7A3}, Range{0xF900, 0xFAFF}, Range{0xFE10, 0xFE19},
    Range{0xFE30, 0xFE6F}, Range{0xFF00, 0xFF60}, Range{0xFFE0, 0xFFE6}, Range{0x16FE0, 0x16FE4},
    Range{0x17000, 0x187F7}, Range{0x18800, 0x18CD5}, Range{0x1B000, 0x1B2FB}, Range{0x1F004, 0x1F004},
    Range{0x1F0CF, 0x1F0CF}, Range{0x1F18E, 0x1F18E}, Range{0x1F191, 0x1F19A}, Range{0x1F200, 0x1F202},
    Range{0x1F210, 0x1F23B}, Range{0x1F240, 0x1F248}, Range{0x1F250, 0x1F251}, Range{0x1F260, 0x1F265},
    Range{0x1F300, 0x1F64F}, Range{0x1F680, 0x1F6FF}, Range{0x1F7E0, 0x1F7EB}, Range{0x1F90C, 0x1F9FF},
    Range{0x1FA70, 0x1FAFF}, Range{0x20000, 0x2FFFD}, Range{0x30000, 0x3FFFD},
};

constexpr char32_t kZeroWidthJoiner = 0x200D;
constexpr std::string_view kReplacement = "\xEF\xBF\xBD";

template <std::size_t N>
constexpr bool inRanges(const std::array<Range, N>& ranges, const char32_t cp) {
    const auto it = std::ranges::lower_bound(ranges, cp, {}, &Range::hi);
    return it != ranges.end() && it->lo <= cp && cp <= it->hi;
}

constexpr bool isZeroWidth(const char32_t cp) { return cp == kZeroWidthJoiner || inRanges(kZeroWidth, cp); }
constexpr std::size_t columns(const char32_t cp) { return isZeroWidth(cp) ? 0 : inRanges(kWide, cp) ? 2 : 1; }

// Length of the well-formed UTF-8 sequence at s[i] and its code point, or nullopt (RFC 3629: no overlongs, no
// surrogates, nothing above U+10FFFF).
inline std::optional<std::pair<std::size_t, char32_t>> decode(const std::string_view s, const std::size_t i) {
    const auto b0 = static_cast<unsigned char>(s[i]);
    if (b0 < 0x80) return std::pair{std::size_t{1}, char32_t{b0}};
    std::size_t len;
    char32_t cp, min;
    if ((b0 & 0xE0) == 0xC0) { len = 2; cp = b0 & 0x1F; min = 0x80; }
    else if ((b0 & 0xF0) == 0xE0) { len = 3; cp = b0 & 0x0F; min = 0x800; }
    else if ((b0 & 0xF8) == 0xF0) { len = 4; cp = b0 & 0x07; min = 0x10000; }
    else return std::nullopt;
    if (i + len > s.size()) return std::nullopt;
    for (std::size_t k = 1; k < len; ++k) {
        const auto b = static_cast<unsigned char>(s[i + k]);
        if ((b & 0xC0) != 0x80) return std::nullopt;
        cp = (cp << 6) | (b & 0x3F);
    }
    if (cp < min || cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return std::nullopt;
    return std::pair{len, cp};
}

// One user-perceived character of valid UTF-8: a base code point with the zero-width ones that follow it, and anything
// joined to it by a ZWJ (emoji sequences render as one glyph).
struct Cluster { std::size_t bytes, columns; };

inline Cluster cluster(const std::string_view s, const std::size_t at) {
    auto [len, base] = decode(s, at).value_or(std::pair{std::size_t{1}, char32_t{0xFFFD}});
    Cluster c{len, columns(base)};
    bool joined = base == kZeroWidthJoiner;
    while (at + c.bytes < s.size()) {
        const auto next = decode(s, at + c.bytes);
        if (!next) break;
        if (!joined && !isZeroWidth(next->second)) break;
        c.bytes += next->first;
        joined = next->second == kZeroWidthJoiner;
    }
    return c;
}

}

namespace text {

std::string sanitize(const std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (const auto d = detail::decode(s, i)) {
            out.append(s.substr(i, d->first));
            i += d->first;
        } else {
            out.append(detail::kReplacement);
            ++i;
        }
    }
    return out;
}

std::size_t width(const std::string_view s) {
    std::size_t w = 0;
    for (std::size_t i = 0; i < s.size();) {
        const auto c = detail::cluster(s, i);
        w += c.columns;
        i += c.bytes;
    }
    return w;
}

std::string_view head(const std::string_view s, const std::size_t columns) {
    std::size_t i = 0, w = 0;
    while (i < s.size()) {
        const auto c = detail::cluster(s, i);
        if (w + c.columns > columns) break;
        w += c.columns;
        i += c.bytes;
    }
    return s.substr(0, i);
}

std::string_view tail(const std::string_view s, const std::size_t columns) {
    std::vector<detail::Cluster> clusters;
    for (std::size_t i = 0; i < s.size(); i += clusters.back().bytes) clusters.push_back(detail::cluster(s, i));
    std::size_t start = s.size(), w = 0;
    for (auto it = clusters.rbegin(); it != clusters.rend() && w + it->columns <= columns; ++it) {
        w += it->columns;
        start -= it->bytes;
    }
    return s.substr(start);
}

}

namespace {

void appendTableCell(std::string& out, const std::string_view cell, const std::size_t width, const Align align) {
    const std::size_t used = text::width(cell);
    const std::string pad(width > used ? width - used : 0, ' ');
    if (align == Align::Right) out += pad;
    out += cell;
    if (align == Align::Left) out += pad;
}

}

std::string Table::render() const {
    if (cols_.empty()) return {};

    // Cells may carry any bytes (file names); everything below works on valid UTF-8 and display columns.
    const std::size_t ncol = cols_.size();
    std::vector<std::string> headers(ncol);
    for (std::size_t i = 0; i < ncol; ++i) headers[i] = text::sanitize(cols_[i].header);
    std::vector<std::vector<std::string>> rows;
    rows.reserve(rows_.size());
    for (auto const& r : rows_) {
        auto& row = rows.emplace_back(ncol);
        for (std::size_t i = 0; i < ncol && i < r.size(); ++i) row[i] = text::sanitize(r[i].text);
    }

    // 1) Compute natural widths from content (before wrapping)
    std::vector<std::size_t> width(ncol, 0);
    for (std::size_t i = 0; i < ncol; ++i) width[i] = std::max(cols_[i].min, text::width(headers[i]));
    for (auto const& r : rows)
        for (std::size_t i = 0; i < ncol; ++i)
            width[i] = std::max(width[i], std::min(cols_[i].max, text::width(r[i])));

    // 2) Budget to terminal width: 2 leading spaces + "  " between cols
    constexpr std::size_t pad_left = 2;
    constexpr std::size_t gap = 2;
    auto total_width = [&](const std::vector<std::size_t>& w){
        std::size_t sum = pad_left + (ncol ? (gap * (ncol-1)) : 0);
        for (auto x : w) sum += x;
        return sum;
    };

    constexpr int fallback_term = 100;
    const int tw = term_width_ > 0 ? term_width_ : fallback_term;

    // Choose a preferred "flex" column to soak/shrink space: last wrapping column, else last column
    std::optional<std::size_t> flex_idx;
    for (std::size_t i = ncol; i-- > 0;) if (cols_[i].wrap) { flex_idx = i; break; }
    if (!flex_idx) flex_idx = ncol - 1;

    // Clamp to max and then shrink if needed to fit terminal
    for (std::size_t i = 0; i < ncol; ++i) width[i] = std::clamp(width[i], cols_[i].min, cols_[i].max);
    while (static_cast<int>(total_width(width)) > tw && width[*flex_idx] > cols_[*flex_idx].min) --width[*flex_idx];

    // 3) Emit header
    std::string out;
    out.reserve(128 + rows_.size() * 96);

    out += "  "; // pad_left
    for (std::size_t i = 0; i < ncol; ++i) {
        if (i) out += std::string(gap, ' ');
        appendTableCell(out, text::head(headers[i], width[i]), width[i], cols_[i].align);
    }
    out += '\n';

    out += "  ";
    for (std::size_t i = 0; i < ncol; ++i) {
        if (i) out += std::string(gap, ' ');
        out += std::string(width[i], '-');
    }
    out += '\n';

    // 4) Emit rows, wrapping/ellipsizing as needed
    for (auto const& r : rows) {
        std::vector<std::vector<std::string>> lines_per_cell(ncol);
        std::size_t max_lines = 1;
        for (std::size_t i = 0; i < ncol; ++i) {
            const std::string& cell = r[i];
            if (cols_[i].wrap) lines_per_cell[i] = wrap_lines(cell, width[i]);
            else if (text::width(cell) <= width[i]) lines_per_cell[i] = {cell};
            else if (cols_[i].ellipsize_middle && width[i] > 1) lines_per_cell[i] = {ellipsize_middle(cell, width[i])};
            else lines_per_cell[i] = {std::string(text::head(cell, width[i]))};
            max_lines = std::max(max_lines, lines_per_cell[i].size());
        }

        // print each visual line
        for (std::size_t l = 0; l < max_lines; ++l) {
            out += "  ";
            for (std::size_t i = 0; i < ncol; ++i) {
                if (i) out += std::string(gap, ' ');
                const std::string_view cell = l < lines_per_cell[i].size() ? std::string_view{lines_per_cell[i][l]} : "";
                appendTableCell(out, cell, width[i], cols_[i].align);
            }
            out += '\n';
        }
    }

    return out;
}

std::vector<std::string> Table::wrap_lines(const std::string& s, const std::size_t width) {
    if (width == 0) return {""};
    std::vector<std::string> out;
    std::string_view rest = s;
    while (!rest.empty()) {
        auto line = text::head(rest, width);
        // A character wider than the column still goes out whole, on a line of its own.
        if (line.empty()) line = rest.substr(0, text::detail::cluster(rest, 0).bytes);
        // try to break on space (ASCII, so never inside a multi-byte sequence)
        if (line.size() < rest.size() && rest[line.size()] != ' ') {
            const auto sp = line.rfind(' ');
            if (sp != std::string_view::npos && sp > 0) line = line.substr(0, sp);
        }
        out.emplace_back(line);
        rest.remove_prefix(line.size());
        // trim leading space on next chunk
        if (!rest.empty() && rest.front() == ' ') rest.remove_prefix(1);
    }
    if (out.empty()) out.push_back("");
    return out;
}

std::string Table::ellipsize_middle(const std::string& s, const std::size_t width) {
    if (text::width(s) <= width || width <= 1) return std::string(text::head(s, width));
    if (width == 2) return std::string("..");
    const std::size_t keep = width - 1; // one column for the ellipsis
    const auto left = text::head(s, keep / 2);
    const auto right = text::tail(s, keep - text::width(left));
    return std::string(left) + "…" + std::string(right);
}

}
