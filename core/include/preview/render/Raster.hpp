#pragma once

#include <cstdint>
#include <span>
#include <stdexcept>
#include <vector>

// Lossy server-side rendering (images and PDF pages -> JPEG), bounded against hostile input: every decode is
// preceded by a header check against the pixel cap, JPEGs decode at the smallest DCT scale that still covers the
// target size, PDF rendering is serialized behind one process-wide lock (PDFium is not thread-safe), and nothing
// touches the disk.
namespace vh::preview::render {

struct Limits {
    uint64_t maxSourceBytes{512ull * 1024 * 1024};
    uint64_t maxPixels{100'000'000};   // decoded RGB pixels
    uint32_t maxDimension{2048};       // output edge cap
};

[[nodiscard]] Limits limitsFromConfig();

struct Raster {
    std::vector<uint8_t> rgb;  // packed RGB8
    uint32_t width{};
    uint32_t height{};
};

class InvalidInput final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};
class LimitExceeded final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

// Decodes an image whose longest edge will be fit into targetMaxDim. JPEG: TurboJPEG with DCT scaling (only the
// pixels needed; the fast IDCT for thumbnail-sized targets); other formats: stb_image from memory, with any alpha
// composited over white. Throws InvalidInput / LimitExceeded.
[[nodiscard]] Raster decodeImage(std::span<const uint8_t> bytes, uint32_t targetMaxDim, const Limits& limits);

// Renders one PDF page so that its longest edge is targetMaxDim (never above limits.maxDimension). pageCount is
// set to the document's page count. Throws InvalidInput (bad document / page out of range) / LimitExceeded.
[[nodiscard]] Raster renderPdfPage(std::span<const uint8_t> bytes, uint32_t page, uint32_t targetMaxDim,
                                   const Limits& limits, uint32_t& pageCount);

// Downscales to fit maxDim (never upscales; returns a copy when already small enough).
[[nodiscard]] Raster fit(const Raster& source, uint32_t maxDim);
// Same, without the copy when nothing has to change.
[[nodiscard]] Raster fit(Raster&& source, uint32_t maxDim);

enum class Subsampling { S444, S420 };

// Outputs up to this edge are thumbnails: chroma 4:2:0 (about a third smaller, no visible difference at that size)
// and a fast inverse DCT when decoding JPEG sources for them.
inline constexpr uint32_t kThumbnailEncodeMax = 512;

// Baseline JPEG, quality 85; 4:4:4 unless asked otherwise.
[[nodiscard]] std::vector<uint8_t> encodeJpeg(const Raster& raster, int quality = 85,
                                              Subsampling subsampling = Subsampling::S444);

// PDFium's process-wide init/teardown. Hold exactly one for as long as anything may render a PDF (the daemon's main,
// test suites); every render serializes behind the same lock as init and destroy.
class PdfiumLibrary {
public:
    PdfiumLibrary();
    ~PdfiumLibrary();
    PdfiumLibrary(const PdfiumLibrary&) = delete;
    PdfiumLibrary& operator=(const PdfiumLibrary&) = delete;
};

}
