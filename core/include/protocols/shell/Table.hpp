#pragma once

#include <cstddef>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

namespace vh::protocols::shell {

// Terminal text measured in display columns, not bytes (#273). Cells are UTF-8; a malformed byte is shown as U+FFFD.
// Widths follow wcwidth: combining marks, variation selectors, skin-tone modifiers and a character joined by a ZWJ
// take no column, East Asian wide characters and emoji take two. Truncation keeps whole characters with their
// combining marks, so the output is always valid UTF-8.
namespace text {

// The cell as valid UTF-8: each malformed or overlong sequence, surrogate and stray continuation byte becomes U+FFFD.
[[nodiscard]] std::string sanitize(std::string_view s);

// Columns a valid UTF-8 string takes in a terminal.
[[nodiscard]] std::size_t width(std::string_view s);

// The longest prefix (or suffix) of whole characters that fits in `columns`.
[[nodiscard]] std::string_view head(std::string_view s, std::size_t columns);
[[nodiscard]] std::string_view tail(std::string_view s, std::size_t columns);

}

enum class Align { Left, Right };

struct Column {
    std::string header;
    Align align = Align::Left;
    std::size_t min = 1;
    std::size_t max = std::numeric_limits<std::size_t>::max();
    bool wrap = false;               // if true, text can flow to multiple lines
    bool ellipsize_middle = false;   // if true, clamp with … in the middle (useful for paths)
};

struct Cell {
    std::string text;
};

class Table {
public:
    explicit Table(std::vector<Column> cols, const int term_width = 0)
        : cols_(std::move(cols)), term_width_(term_width) {}

    void add_row(std::vector<std::string> cells) {
        std::vector<Cell> row;
        row.reserve(cells.size());
        for (auto& s : cells) row.push_back(Cell{std::move(s)});
        rows_.push_back(std::move(row));
    }

    [[nodiscard]] std::string render() const;

    // If you have your own terminal width function, set it here
    void set_term_width(int w) { term_width_ = w; }

private:
    std::vector<Column> cols_;
    std::vector<std::vector<Cell>> rows_;
    int term_width_ = 0;

    // Word wrap to `width` display columns, breaking on spaces where it can.
    static std::vector<std::string> wrap_lines(const std::string& s, std::size_t width);

    // Clamp to `width` display columns with a … in the middle.
    static std::string ellipsize_middle(const std::string& s, std::size_t width);
};

}
