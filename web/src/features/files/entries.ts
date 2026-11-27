import { parseDate } from '@/lib/format'
import type { PreviewCapability, PreviewKind } from '@/models/file'
import { baseName, joinPath, normalizePath } from '@/features/files/paths'

// Path helpers live in paths.ts so the console shell (transfers) doesn't pull this module into every route.
export { baseName, joinPath, normalizePath, parentOf, pathSegments } from '@/features/files/paths'

// One normalized filesystem entry for both the authenticated browser and public shares.
export interface Entry {
  key: string
  id: number
  name: string
  path: string
  kind: 'file' | 'dir'
  size: number | null
  mime: string | null
  modified: number // epoch ms, 0 when unknown
  fileCount?: number
  dirCount?: number
  // The server's preview plan (absent from older daemons: then preview/plan.ts falls back to isPreviewable).
  plan?: PreviewPlan
  // A detached mirror's file whose contents never arrived: listed with its size, but it can't be opened.
  missing?: boolean
}

// Normalized server preview plan. `derived` is always a list here.
export interface PreviewPlan {
  kind: PreviewKind
  renderer: string
  requires: PreviewCapability
  thumbnail: boolean
  derived: string[]
}

const num = (value: unknown): number | null => (typeof value === 'number' && Number.isFinite(value) ? value : null)

type Wire = Record<string, unknown>

const toPlan = (raw: unknown): PreviewPlan | undefined => {
  if (!raw || typeof raw !== 'object') return undefined
  const wire = raw as Wire
  if (typeof wire.renderer !== 'string' || !wire.renderer) return undefined
  const derived = Array.isArray(wire.derived) ? wire.derived : typeof wire.derived === 'string' ? [wire.derived] : []
  return {
    kind: (typeof wire.kind === 'string' ? wire.kind : 'unsupported') as PreviewKind,
    renderer: wire.renderer,
    // Anything but an explicit "preview" needs the stronger capability.
    requires: wire.requires === 'preview' ? 'preview' : 'download',
    thumbnail: wire.thumbnail === true,
    derived: derived.filter((d): d is string => typeof d === 'string' && d.length > 0),
  }
}

export const toEntry = (raw: unknown, parentPath: string): Entry => {
  const wire = (raw ?? {}) as Wire
  const name = typeof wire.name === 'string' ? wire.name : ''
  const path = typeof wire.path === 'string' && wire.path ? normalizePath(wire.path) : joinPath(parentPath, name)
  const isDir = wire.type === 'directory' || 'file_count' in wire || 'subdirectory_count' in wire
  const modified =
    parseDate(wire.updated_at ?? wire.last_modified ?? wire.modified_at ?? wire.updatedAt ?? wire.created_at)?.getTime() ?? 0
  return {
    key: path,
    id: num(wire.id) ?? 0,
    name: name || baseName(path),
    path,
    kind: isDir ? 'dir' : 'file',
    size: num(wire.size_bytes),
    mime: typeof wire.mime_type === 'string' && wire.mime_type ? wire.mime_type : null,
    modified,
    fileCount: num(wire.file_count) ?? undefined,
    dirCount: num(wire.subdirectory_count) ?? undefined,
    plan: isDir ? undefined : toPlan(wire.preview),
    missing: !isDir && wire.contents_missing === true ? true : undefined,
  }
}

export const sortEntries = (entries: Entry[], key: 'name' | 'size' | 'modified', dir: 'asc' | 'desc') => {
  const m = dir === 'asc' ? 1 : -1
  const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' })
  return [...entries].sort((a, b) => {
    if (a.kind !== b.kind) return a.kind === 'dir' ? -1 : 1
    if (key === 'size') return ((a.size ?? -1) - (b.size ?? -1)) * m || collator.compare(a.name, b.name)
    if (key === 'modified') return (a.modified - b.modified) * m || collator.compare(a.name, b.name)
    return collator.compare(a.name, b.name) * m
  })
}

const IMAGE = /^image\//
// Fallback only (older daemons send no plan): the server renders images and PDFs as JPEG.
export const isPreviewable = (entry: Entry) =>
  entry.kind === 'file' && Boolean(entry.mime) && (IMAGE.test(entry.mime as string) || entry.mime === 'application/pdf')

// Whether the grid/list should ask `/preview/batch` for a thumbnail.
export const hasThumbnail = (entry: Entry) => entry.kind === 'file' && (entry.plan ? entry.plan.thumbnail : isPreviewable(entry))

export const isImage = (entry: Entry) => entry.kind === 'file' && Boolean(entry.mime) && IMAGE.test(entry.mime as string)

export type FileCategory = 'dir' | 'image' | 'video' | 'audio' | 'pdf' | 'model' | 'archive' | 'code' | 'text' | 'other'

const EXT: Record<string, FileCategory> = {
  zip: 'archive', gz: 'archive', tgz: 'archive', tar: 'archive', xz: 'archive', zst: 'archive', '7z': 'archive', rar: 'archive', bz2: 'archive',
  js: 'code', ts: 'code', tsx: 'code', jsx: 'code', py: 'code', rs: 'code', go: 'code', c: 'code', h: 'code', cpp: 'code', hpp: 'code',
  java: 'code', rb: 'code', sh: 'code', json: 'code', yaml: 'code', yml: 'code', toml: 'code', sql: 'code', css: 'code', html: 'code',
  txt: 'text', md: 'text', log: 'text', csv: 'text', ini: 'text', conf: 'text',
  mp4: 'video', mkv: 'video', mov: 'video', webm: 'video', avi: 'video',
  mp3: 'audio', flac: 'audio', wav: 'audio', ogg: 'audio', m4a: 'audio',
  pdf: 'pdf',
  glb: 'model', gltf: 'model', stl: 'model', obj: 'model', step: 'model', stp: 'model',
  png: 'image', jpg: 'image', jpeg: 'image', gif: 'image', webp: 'image', svg: 'image', avif: 'image', heic: 'image',
}

const extOf = (name: string) => (name.includes('.') ? name.split('.').pop()!.toLowerCase() : '')

const RENDERER_CATEGORY: Record<string, FileCategory> = {
  image: 'image', svg: 'image', 'image-native': 'image', pdf: 'pdf', video: 'video', audio: 'audio', markdown: 'text',
}

export const categoryOf = (entry: Entry): FileCategory => {
  if (entry.kind === 'dir') return 'dir'
  const renderer = entry.plan?.renderer
  if (renderer) {
    if (renderer.startsWith('model:') || renderer.startsWith('derived:step')) return 'model'
    if (renderer === 'text') return EXT[extOf(entry.name)] === 'code' ? 'code' : 'text'
    if (RENDERER_CATEGORY[renderer]) return RENDERER_CATEGORY[renderer]
  }
  const mime = entry.mime ?? ''
  if (mime.startsWith('image/')) return 'image'
  if (mime.startsWith('video/')) return 'video'
  if (mime.startsWith('audio/')) return 'audio'
  if (mime === 'application/pdf') return 'pdf'
  return EXT[extOf(entry.name)] ?? (mime.startsWith('text/') ? 'text' : 'other')
}
