#define STB_IMAGE_IMPLEMENTATION
#define STB_IMAGE_RESIZE_IMPLEMENTATION
// Only the formats the server renders; every other stb parser (HDR, PSD, PIC, TGA...) stays out of the daemon.
#define STBI_ONLY_PNG
#define STBI_ONLY_GIF
#define STBI_ONLY_BMP
#define STBI_ONLY_PNM
#define STBI_ONLY_JPEG  // never reached (JPEG goes to TurboJPEG); keeps stb's shared helpers referenced
#define STBI_MAX_DIMENSIONS 32768
#include "preview/render/Raster.hpp"

#include "config/Registry.hpp"

#include <stb/stb_image.h>
#include <stb/stb_image_resize.h>
#include <turbojpeg.h>
#include <fpdfview.h>
#include <cpp/fpdf_scopers.h>

#include <algorithm>
#include <cmath>
#include <limits>
#include <memory>
#include <mutex>

namespace vh::preview::render {

namespace {

struct TjDeleter {
    void operator()(void* handle) const noexcept {
        if (handle) tjDestroy(handle);
    }
};
using TjHandle = std::unique_ptr<void, TjDeleter>;

[[nodiscard]] bool looksLikeJpeg(const std::span<const uint8_t> bytes) {
    return bytes.size() > 3 && bytes[0] == 0xFF && bytes[1] == 0xD8 && bytes[2] == 0xFF;
}

[[nodiscard]] uint64_t pixels(const uint64_t w, const uint64_t h) { return w * h; }

// Progressive (SOF2) JPEGs keep a full-resolution coefficient buffer (about 2 bytes per pixel per component)
// whatever the DCT output scale, so their source dimensions are what costs memory.
[[nodiscard]] bool isProgressiveJpeg(const std::span<const uint8_t> b) {
    std::size_t i = 2;
    while (i + 4 <= b.size()) {
        if (b[i] != 0xFF) return false;
        const auto marker = b[i + 1];
        if (marker == 0xD8 || marker == 0x01 || (marker >= 0xD0 && marker <= 0xD7)) {
            i += 2;
            continue;
        }
        if (marker == 0xDA) return false;  // start of scan without a progressive frame header
        if (marker == 0xC2 || marker == 0xC6 || marker == 0xCA || marker == 0xCE) return true;
        const std::size_t len = (static_cast<std::size_t>(b[i + 2]) << 8) | b[i + 3];
        if (len < 2) return false;
        i += 2 + len;
    }
    return false;
}

void checkSource(const std::span<const uint8_t> bytes, const Limits& limits) {
    if (bytes.empty()) throw InvalidInput("Empty image");
    if (bytes.size() > limits.maxSourceBytes) throw LimitExceeded("Source exceeds the preview size limit");
    if (bytes.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        throw LimitExceeded("Source too large to decode");
}

[[nodiscard]] Raster decodeJpeg(const std::span<const uint8_t> bytes, const uint32_t targetMaxDim, const Limits& limits) {
    TjHandle tj(tjInitDecompress());
    if (!tj) throw std::runtime_error("TurboJPEG unavailable");
    int width = 0, height = 0, subsamp = 0, colorspace = 0;
    if (tjDecompressHeader3(tj.get(), bytes.data(), static_cast<unsigned long>(bytes.size()), &width, &height, &subsamp,
                            &colorspace) != 0 || width <= 0 || height <= 0)
        throw InvalidInput("Invalid JPEG header");

    // Bound the SOURCE before decoding (a 65500x65500 progressive JPEG is a few MB but needs gigabytes).
    const auto sourceCap = isProgressiveJpeg(bytes) ? limits.maxPixels / 2 : limits.maxPixels;
    if (pixels(width, height) > sourceCap) throw LimitExceeded("Image exceeds the pixel limit");

    // Smallest DCT scale whose longest edge still covers the target (so the final resize only ever shrinks).
    int count = 0;
    const tjscalingfactor* factors = tjGetScalingFactors(&count);
    int outW = width, outH = height;
    const auto longest = static_cast<uint32_t>(std::max(width, height));
    for (int i = 0; factors && i < count; ++i) {
        const int sw = TJSCALED(width, factors[i]);
        const int sh = TJSCALED(height, factors[i]);
        if (static_cast<uint32_t>(std::max(sw, sh)) >= std::min(targetMaxDim, longest) &&
            pixels(sw, sh) < pixels(outW, outH)) {
            outW = sw;
            outH = sh;
        }
    }
    if (pixels(outW, outH) > limits.maxPixels) throw LimitExceeded("Image exceeds the pixel limit");

    Raster r;
    r.width = static_cast<uint32_t>(outW);
    r.height = static_cast<uint32_t>(outH);
    r.rgb.resize(static_cast<std::size_t>(outW) * static_cast<std::size_t>(outH) * 3);
    // The accurate IDCT only where its quality can still show: thumbnail-sized targets take the fast one.
    const int flags = targetMaxDim <= kThumbnailEncodeMax ? TJFLAG_FASTDCT : TJFLAG_ACCURATEDCT;
    if (tjDecompress2(tj.get(), bytes.data(), static_cast<unsigned long>(bytes.size()), r.rgb.data(), outW, 0, outH,
                      TJPF_RGB, flags) != 0 &&
        tjGetErrorCode(tj.get()) == TJERR_FATAL)
        throw InvalidInput(std::string("JPEG decode failed: ") + tjGetErrorStr2(tj.get()));
    return r;
}

[[nodiscard]] Raster decodeStb(const std::span<const uint8_t> bytes, const Limits& limits) {
    int width = 0, height = 0, channels = 0;
    const auto len = static_cast<int>(bytes.size());
    if (!stbi_info_from_memory(bytes.data(), len, &width, &height, &channels) || width <= 0 || height <= 0)
        throw InvalidInput("Unsupported or invalid image");
    if (pixels(width, height) > limits.maxPixels) throw LimitExceeded("Image exceeds the pixel limit");

    // Images with alpha (grey+alpha, RGBA) are composited over white like PDF pages are; dropping the alpha channel
    // showed whatever colour sat under transparent pixels (often black).
    const bool alpha = channels == 2 || channels == 4;
    const int want = alpha ? 4 : 3;
    std::unique_ptr<unsigned char, decltype(&stbi_image_free)> data(
        stbi_load_from_memory(bytes.data(), len, &width, &height, &channels, want), &stbi_image_free);
    if (!data) throw InvalidInput(std::string("Image decode failed: ") + stbi_failure_reason());
    Raster r;
    r.width = static_cast<uint32_t>(width);
    r.height = static_cast<uint32_t>(height);
    const auto pixelCount = static_cast<std::size_t>(width) * static_cast<std::size_t>(height);
    if (!alpha) {
        r.rgb.assign(data.get(), data.get() + pixelCount * 3);
        return r;
    }
    r.rgb.resize(pixelCount * 3);
    const auto* src = data.get();
    for (std::size_t i = 0; i < pixelCount; ++i, src += 4) {
        const unsigned a = src[3];
        for (int c = 0; c < 3; ++c)
            r.rgb[i * 3 + c] = static_cast<uint8_t>((src[c] * a + 255u * (255u - a) + 127u) / 255u);
    }
    return r;
}

// PDFium is not thread-safe: init, destroy and every render share this lock.
std::mutex& pdfiumMutex() {
    static std::mutex mutex;
    return mutex;
}

}

PdfiumLibrary::PdfiumLibrary() {
    FPDF_LIBRARY_CONFIG config{};
    config.version = 2;  // no V8/XFA in the packaged build; later versions only add experimental knobs
    std::scoped_lock lock(pdfiumMutex());
    FPDF_InitLibraryWithConfig(&config);
}

PdfiumLibrary::~PdfiumLibrary() {
    std::scoped_lock lock(pdfiumMutex());
    FPDF_DestroyLibrary();
}

Limits limitsFromConfig() {
    const auto& cfg = config::Registry::get();
    Limits limits;
    limits.maxSourceBytes = std::max<uint64_t>(1, cfg.http_preview.max_preview_size_bytes);
    limits.maxPixels = std::max<uint64_t>(1, cfg.preview.max_render_pixels);
    return limits;
}

Raster decodeImage(const std::span<const uint8_t> bytes, const uint32_t targetMaxDim, const Limits& limits) {
    checkSource(bytes, limits);
    return looksLikeJpeg(bytes) ? decodeJpeg(bytes, std::max<uint32_t>(1, targetMaxDim), limits) : decodeStb(bytes, limits);
}

Raster renderPdfPage(const std::span<const uint8_t> bytes, const uint32_t page, const uint32_t targetMaxDim,
                     const Limits& limits, uint32_t& pageCount) {
    checkSource(bytes, limits);
    const auto target = std::clamp<uint32_t>(targetMaxDim, 16, limits.maxDimension);

    std::scoped_lock lock(pdfiumMutex());
    const ScopedFPDFDocument doc(FPDF_LoadMemDocument64(bytes.data(), bytes.size(), nullptr));
    if (!doc) throw InvalidInput("Invalid or encrypted PDF");

    const int count = FPDF_GetPageCount(doc.get());
    if (count <= 0) throw InvalidInput("PDF has no pages");
    pageCount = static_cast<uint32_t>(count);
    if (page >= pageCount) throw InvalidInput("PDF page out of range");

    const ScopedFPDFPage pg(FPDF_LoadPage(doc.get(), static_cast<int>(page)));
    if (!pg) throw InvalidInput("Failed to load PDF page");

    const double pw = FPDF_GetPageWidth(pg.get());
    const double ph = FPDF_GetPageHeight(pg.get());
    if (!(pw > 0) || !(ph > 0) || !std::isfinite(pw) || !std::isfinite(ph)) throw InvalidInput("Invalid PDF page size");
    const double ratio = static_cast<double>(target) / std::max(pw, ph);
    const int w = std::max(1, static_cast<int>(std::lround(pw * ratio)));
    const int h = std::max(1, static_cast<int>(std::lround(ph * ratio)));
    if (pixels(w, h) > limits.maxPixels) throw LimitExceeded("PDF page exceeds the pixel limit");

    // PDFium renders straight into the packed RGB raster: a 24bpp bitmap over our buffer, with
    // FPDF_REVERSE_BYTE_ORDER turning its native BGR into RGB. No intermediate BGRA bitmap, no conversion pass.
    Raster r;
    r.width = static_cast<uint32_t>(w);
    r.height = static_cast<uint32_t>(h);
    r.rgb.resize(static_cast<std::size_t>(w) * static_cast<std::size_t>(h) * 3);
    const ScopedFPDFBitmap bmp(FPDFBitmap_CreateEx(w, h, FPDFBitmap_BGR, r.rgb.data(), w * 3));
    if (!bmp) throw LimitExceeded("Could not allocate the PDF bitmap");
    FPDFBitmap_FillRect(bmp.get(), 0, 0, w, h, 0xFFFFFFFF);
    FPDF_RenderPageBitmap(bmp.get(), pg.get(), 0, 0, w, h, 0, FPDF_ANNOT | FPDF_REVERSE_BYTE_ORDER);
    return r;
}

Raster fit(Raster&& source, const uint32_t maxDim) {
    if (source.width == 0 || source.height == 0) throw InvalidInput("Empty raster");
    if (std::max(source.width, source.height) <= maxDim) return std::move(source);
    return fit(static_cast<const Raster&>(source), maxDim);
}

Raster fit(const Raster& source, const uint32_t maxDim) {
    if (source.width == 0 || source.height == 0) throw InvalidInput("Empty raster");
    const auto longest = std::max(source.width, source.height);
    if (longest <= maxDim) return source;
    const double ratio = static_cast<double>(maxDim) / static_cast<double>(longest);
    Raster out;
    out.width = std::max<uint32_t>(1, static_cast<uint32_t>(std::lround(source.width * ratio)));
    out.height = std::max<uint32_t>(1, static_cast<uint32_t>(std::lround(source.height * ratio)));
    out.rgb.resize(static_cast<std::size_t>(out.width) * out.height * 3);
    if (!stbir_resize_uint8(source.rgb.data(), static_cast<int>(source.width), static_cast<int>(source.height), 0,
                            out.rgb.data(), static_cast<int>(out.width), static_cast<int>(out.height), 0, 3))
        throw std::runtime_error("Resize failed");
    return out;
}

std::vector<uint8_t> encodeJpeg(const Raster& raster, const int quality, const Subsampling subsampling) {
    TjHandle tj(tjInitCompress());
    if (!tj) throw std::runtime_error("TurboJPEG unavailable");
    unsigned char* buffer = nullptr;
    unsigned long size = 0;
    if (tjCompress2(tj.get(), raster.rgb.data(), static_cast<int>(raster.width), 0, static_cast<int>(raster.height),
                    TJPF_RGB, &buffer, &size, subsampling == Subsampling::S420 ? TJSAMP_420 : TJSAMP_444, quality,
                    0) != 0) {
        if (buffer) tjFree(buffer);
        throw std::runtime_error(std::string("JPEG encode failed: ") + tjGetErrorStr2(tj.get()));
    }
    std::vector<uint8_t> out(buffer, buffer + size);
    tjFree(buffer);
    return out;
}

}
