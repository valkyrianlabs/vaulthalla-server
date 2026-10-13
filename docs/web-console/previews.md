---
title: File Previews
navTitle: Previews
description: What the web console can preview, play, view and edit, which optional packages add STEP models and media conversion, and what preview-only and download share links allow.
order: 125
status: published
tags:
  - web
  - web-console
  - previews
  - sharing
---

# File Previews

Opening a file in **Files** (double-click or Enter), or on a share link, shows it in the preview sheet. The daemon decides how each file can be shown from its name and type, and the console follows that decision. Every request goes through the same Vaulthalla permissions as downloads, and nothing decrypted is written to disk on the server to show it.

:::toc[On this page]{depth="3" theme="compact"}
:::

## What Opens In The Browser

| File type | How it is shown | Needs |
| --- | --- | --- |
| Photos and raster images (JPEG, PNG, GIF, BMP, PNM) | Server-rendered JPEG preview, plus thumbnails in the file list | Preview |
| PDF | Server-rendered pages: Previous/Next buttons or PageUp/PageDown, fit to page or width | Preview |
| SVG, WebP, AVIF, ICO | The original image, shown as is | Download |
| Video (`video/*`) | Native browser player with seeking, never autoplays | Download |
| Audio (`audio/*`) | Native browser player with seeking | Download |
| 3D models: GLB, glTF, STL, OBJ | Interactive 3D viewer | Download |
| 3D models: STEP, STP | Converted to glTF on the server, then shown in the 3D viewer. Needs the optional `vaulthalla-preview-cad` package | Download |
| Text, code, config and log files | Text view; editable in the console | Download (Overwrite to save) |
| Markdown | Rendered view; editable in the console | Download (Overwrite to save) |

Anything else shows its details and a Download button.

**Preview** means the file only ever leaves the server as a lossy, server-rendered JPEG. **Download** means the browser receives the original bytes (or, for STEP models and converted video, a full-fidelity conversion of them). For your own vaults both come from your vault **Read** permission. For share links they are separate operations; see [Share Links](#share-links).

### Images And PDFs

The server renders images and PDF pages to JPEG and caches the result encrypted. Renders are capped: an image or page whose source file is larger than `http_preview_server.max_preview_size_mb`, or whose pixel count exceeds `preview.max_render_pixels`, is refused instead of rendered. Download the file to view it. See [Configuration](/reference/configuration#rich-previews).

### Video And Audio

Video and audio stream from the encrypted vault with seeking, the same way a media server would serve them. Whether a file plays depends on your browser's codecs. When it can't decode a format, the sheet says "This format can't play in your browser" and offers Download and, when the server has the optional `vaulthalla-preview-media` package, **Convert for playback**. Conversion produces an H.264/AAC MP4 on the server (once per file version, then cached encrypted) and plays it; long videos take a while.

### 3D Models

GLB, glTF, STL and OBJ files open in an interactive viewer: drag to orbit, right-drag or Ctrl-drag to pan, scroll or pinch to zoom, with Fit, Reset, a ground grid, a wireframe toggle and a readout of meshes, triangles, vertices, materials and size. glTF files with separate buffers and textures, and OBJ files with a `.mtl` material library, load those files from the same folder. Draco and meshopt compression work offline, and the viewer never contacts another host.

The viewer refuses models over 512 MiB, over 20 million triangles, and glTF files that require KTX2/Basis textures, with an explanation instead of freezing the tab.

STEP and STP files are converted to glTF on the server by the optional `vaulthalla-preview-cad` helper, once per file version. Without that package the sheet says the 3D converter isn't installed and offers Download. See [Install On Linux](/linux/installation#optional-preview-packages).

### Text And Markdown

Text files up to 2 MiB open as text. Larger files, and files that are not valid UTF-8 (or contain NUL bytes), show "This file is too large to preview" or "Binary or unsupported encoding" with a Download button. Markdown is rendered without embedded HTML and without loading remote images.

In the console (not on share links) you can **Edit** a text file in place and save it with the Save button or Ctrl+S (Cmd+S). Saving needs your vault **Overwrite** permission for the file; without it the save is refused and the editor turns read-only. Unsaved edits are guarded when you switch files, close the sheet or leave the page.

:::callout[Conflicts are never silent]{variant="info"}
A save only succeeds if the file is still the version you opened. If someone saved it in the meantime, or the file is open through the mounted filesystem at `/mnt/vaulthalla`, the console says "This file changed since you opened it" and lets you reload their version, overwrite it with yours, or copy your text first.
:::

The server limit for saved text is `preview.text.max_edit_bytes` (2 MiB by default). The console opens text files up to 2 MiB regardless of that setting.

## Share Links

A share link carries its own operations. The two that matter for previews:

| Link allows | Recipients can see |
| --- | --- |
| Preview only | Image previews, PDF pages and thumbnails (server-rendered JPEGs). Nothing else: no original bytes. |
| Download | Everything in the table above except editing: originals, SVG/WebP, video and audio, 3D models, STEP conversions, text and Markdown. |

On a preview-only link, opening a video, model or text file shows "Preview not available with this link's permissions" with the file details; the browser never receives the original. The **Browse & download** preset grants both. Share links never allow editing text in place.

See [Sharing](/sharing) for download counting and link limits.

## Downloads

Downloading a file streams it directly at any size; the console checks the download with a lightweight request first instead of starting it twice. Folders download as a ZIP that streams the same way, at any size: files are stored uncompressed (most content is already compressed), names keep their Unicode characters, and the browser shows the archive's exact size and progress from the start. A folder with more than 50,000 files and subfolders is refused as one archive; download its subfolders instead. If a file in the folder can't be read while the archive streams (for example a cloud file the server may not fetch), the download stops and the browser reports it as failed rather than saving an incomplete archive as finished.

## When A Preview Fails

| Message or symptom | Meaning |
| --- | --- |
| The 3D converter isn't installed / Server-side conversion isn't available | The optional helper package is not installed on the server. |
| This model could not be converted / The conversion failed | The converter rejected or could not finish this file. It is not retried until the file changes or the failure expires. |
| The server is busy | Too many renders or conversions at once, or the HTTP connection limit was reached. Try again shortly. |
| A remote-only file in a cloud vault won't open | The server policy does not allow fetching it for a preview, or a request or price budget refused the fetch. |

See [General Troubleshooting](/troubleshooting/general-troubleshooting#previews-and-media) for the operator side.
