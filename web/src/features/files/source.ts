import { api } from '@/lib/session'
import { shareApi } from '@/features/share/shareSession'
import { shareOperations } from '@/util/shareOperations'
import type { PublicShare } from '@/models/linkShare'
import { normalizePath, toEntry, type Entry } from '@/features/files/entries'

export interface Listing {
  path: string
  dir: Entry | null
  entries: Entry[]
}

export interface Capabilities {
  list: boolean
  preview: boolean // lossy server renders (JPEG thumbnails, image/PDF pages)
  download: boolean // original bytes: downloads, native media, 3D, text, derived interactive artifacts
  edit: boolean // save text files in place (the server still enforces RBAC)
  upload: boolean
  folders: boolean // upload nested folders / create directories
  mutate: boolean // rename, move, copy, delete
  share: boolean // create share links
}

// Everything the browser needs from "where the files are". The UI renders from capabilities, never from the mode.
export interface FsSource {
  key: string
  mode: 'auth' | 'share'
  vaultId: number | null
  rootLabel: string
  caps: Capabilities
  list: (path: string, signal?: AbortSignal) => Promise<Listing>
  mkdir: (path: string) => Promise<void>
  rename: (from: string, to: string) => Promise<void>
  move: (from: string, to: string) => Promise<void>
  copy: (from: string, to: string) => Promise<void>
  remove: (path: string) => Promise<void>
  // File lanes address an entry by its opaque id (`entry=<id>`) whenever the id is known, so file names and paths
  // never appear in URLs, proxy access logs or browser history (#327). A bare path (a sibling resource of a 3D model,
  // an entry without an id) still works.
  previewUrl: (target: EntryRef, size?: number, page?: number) => string
  downloadUrl: (target: EntryRef) => string
  // Range-capable original bytes for in-browser viewers.
  contentUrl: (target: EntryRef, disposition?: 'inline' | 'attachment') => string
  // A server-derived artifact (STEP → GLB, transcodes): 200 bytes, 202 queued, 422 failed, 503 helper missing.
  derivedUrl: (target: EntryRef, kind: string) => string
  // Text save target (`PUT` with If-Match); null where editing isn't offered.
  textSaveUrl: ((target: EntryRef) => string) | null
  uploadQuery: string
  uploadSessionBody: (vaultFields: { path: string; filename: string; size: number; mime: string | null; fileId: string }[]) => unknown
}

const query = (params: Record<string, string | number>) => new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString()

export type EntryRef = string | { id?: number; path: string }

// `entry=<id>` when the id is known, else the normalized path.
export const addressOf = (target: EntryRef): Record<string, string | number> =>
  typeof target !== 'string' && target.id && target.id > 0 ? { entry: target.id } : { path: normalizePath(typeof target === 'string' ? target : target.path) }

export const authSource = (vault: { id: number; name: string }): FsSource => ({
  key: `vault:${vault.id}`,
  mode: 'auth',
  vaultId: vault.id,
  rootLabel: vault.name,
  caps: { list: true, preview: true, download: true, edit: true, upload: true, folders: true, mutate: true, share: true },
  list: async (path, signal) => {
    const res = await api.send('fs.dir.list', { vault_id: vault.id, path: normalizePath(path) }, { signal })
    const listed = normalizePath(res.path ?? path)
    return {
      path: listed,
      dir: res.entry ? toEntry(res.entry, listed) : null,
      entries: (res.files ?? []).map(entry => toEntry(entry, listed)),
    }
  },
  mkdir: async path => {
    await api.send('fs.dir.create', { vault_id: vault.id, path: normalizePath(path) })
  },
  rename: async (from, to) => {
    await api.send('fs.entry.rename', { vault_id: vault.id, from, to })
  },
  move: async (from, to) => {
    await api.send('fs.entry.move', { vault_id: vault.id, from, to })
  },
  copy: async (from, to) => {
    await api.send('fs.entry.copy', { vault_id: vault.id, from, to })
  },
  remove: async path => {
    await api.send('fs.entry.delete', { vault_id: vault.id, path })
  },
  previewUrl: (target, size = 128, page) => `/preview?${query({ vault_id: vault.id, ...addressOf(target), size, ...(page ? { page } : {}) })}`,
  downloadUrl: target => `/download?${query({ vault_id: vault.id, ...addressOf(target) })}`,
  contentUrl: (target, disposition = 'inline') => `/download/content?${query({ vault_id: vault.id, ...addressOf(target), disposition })}`,
  derivedUrl: (target, kind) => `/preview/derived?${query({ vault_id: vault.id, ...addressOf(target), kind })}`,
  textSaveUrl: target => `/upload/text?${query({ vault_id: vault.id, ...addressOf(target) })}`,
  uploadQuery: '',
  uploadSessionBody: files => ({
    vault_id: vault.id,
    files: files.map(f => ({ file_id: f.fileId, mime_type: f.mime, duplicate_policy: 'reject', path: normalizePath(`${f.path}/${f.filename}`), size: f.size })),
  }),
})

const notInShares = async () => {
  throw new Error('Not available on a share link')
}

export const shareSource = (publicToken: string, share: PublicShare): FsSource => {
  const ops = new Set(shareOperations(share.effective_allowed_ops ?? share.allowed_ops))
  return {
    key: `share:${publicToken}`,
    mode: 'share',
    vaultId: null,
    rootLabel: share.public_label || (share.root_path ? share.root_path.split('/').filter(Boolean).at(-1) : null) || 'Shared files',
    caps: {
      list: ops.has('list'),
      preview: ops.has('preview'),
      download: ops.has('download'),
      edit: false, // no share editing yet
      upload: ops.has('upload'),
      folders: ops.has('mkdir'),
      mutate: false,
      share: false,
    },
    list: async (path, signal) => {
      // A file share (or a share without list) exposes exactly its root entry through metadata.
      if (share.target_type === 'file' || !ops.has('list')) {
        if (!ops.has('metadata') && !ops.has('download') && !ops.has('preview')) return { path: '/', dir: null, entries: [] }
        const res = await shareApi.send('fs.metadata', { path: '/' }, { signal })
        const entry = toEntry(res.entry, '/')
        return entry.kind === 'file' ? { path: '/', dir: null, entries: [entry] } : { path: '/', dir: entry, entries: [] }
      }
      const res = await shareApi.send('fs.list', { path: normalizePath(path) }, { signal })
      const listed = normalizePath(res.path ?? path)
      return {
        path: listed,
        dir: res.entry ? toEntry(res.entry, listed) : null,
        entries: (res.files ?? []).map(entry => toEntry(entry, listed)),
      }
    },
    mkdir: notInShares,
    rename: notInShares,
    move: notInShares,
    copy: notInShares,
    remove: notInShares,
    previewUrl: (target, size = 128, page) => `/preview?${query({ share: 1, ...addressOf(target), size, ...(page ? { page } : {}) })}`,
    downloadUrl: target => `/download?${query({ share: 1, ...addressOf(target) })}`,
    contentUrl: (target, disposition = 'inline') => `/download/content?${query({ share: 1, ...addressOf(target), disposition })}`,
    derivedUrl: (target, kind) => `/preview/derived?${query({ share: 1, ...addressOf(target), kind })}`,
    textSaveUrl: null,
    uploadQuery: '?share=1',
    uploadSessionBody: files => ({
      files: files.map(f => ({ file_id: f.fileId, mime_type: f.mime, duplicate_policy: 'reject', path: normalizePath(f.path), filename: f.filename, size_bytes: f.size })),
    }),
  }
}
