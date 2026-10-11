-- PDF page renders and thumbnails carry the document's page count in their own index row (preview::cache::Store).
--
-- Serving a cached PDF page used to look up and decrypt a second artifact ('pdf-info') just to send the page count
-- header. The count now rides on the page's row; rows written before this migration have NULL and fall back to the
-- old 'pdf-info' artifact until they are regenerated. Idempotent.
ALTER TABLE cache_index ADD COLUMN IF NOT EXISTS page_count INTEGER;
