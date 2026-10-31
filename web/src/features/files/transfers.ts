'use client'

import { create } from 'zustand'
import { queryClient } from '@/lib/query'
import { onSessionReset } from '@/lib/session'
import { randomId } from '@/lib/randomId'
import { formatBytes } from '@/lib/format'
import { normalizePath, parentOf } from '@/features/files/paths'
import type { FsSource } from '@/features/files/source'
import { RESUME_STORAGE_KEY } from '@/features/files/upload/resumeStore'

export interface PickedFile {
  file: File
  // Path relative to the drop/upload target, including any folder structure ("photos/2024/a.jpg").
  relativePath: string
}

export type TaskStatus = 'queued' | 'running' | 'finishing' | 'done' | 'failed' | 'cancelled'

export interface TransferTask {
  id: string
  kind: 'upload' | 'download'
  label: string
  detail: string
  status: TaskStatus
  bytesTotal: number
  bytesDone: number
  filesTotal: number
  filesDone: number
  startedAt: number
  finishedAt: number | null
  error: string | null
  sourceKey: string
  // Shown under an active upload (e.g. resuming an earlier session).
  note?: string | null
  // Per-file errors of a batch that partly failed ("path: reason").
  failures?: string[]
}

interface TransferState {
  tasks: TransferTask[]
  open: boolean
  setOpen: (open: boolean) => void
  clearFinished: () => void
}

export const useTransfers = create<TransferState>(set => ({
  tasks: [],
  open: false,
  setOpen: open => set({ open }),
  clearFinished: () => set(state => ({ tasks: state.tasks.filter(isActive) })),
}))

export const isActive = (task: TransferTask) => task.status === 'queued' || task.status === 'running' || task.status === 'finishing'

const patch = (id: string, update: Partial<TransferTask> | ((task: TransferTask) => Partial<TransferTask>)) =>
  useTransfers.setState(state => ({
    tasks: state.tasks.map(task => (task.id === id ? { ...task, ...(typeof update === 'function' ? update(task) : update) } : task)),
  }))

const addTask = (task: TransferTask) =>
  useTransfers.setState(state => ({ tasks: [task, ...state.tasks.filter(t => isActive(t) || Date.now() - (t.finishedAt ?? 0) < 30 * 60_000)].slice(0, 50) }))

const controllers = new Map<string, AbortController>()

export const cancelTask = (id: string) => controllers.get(id)?.abort()

onSessionReset(() => {
  for (const controller of controllers.values()) controller.abort()
  useTransfers.setState({ tasks: [], open: false })
  try {
    sessionStorage.removeItem(RESUME_STORAGE_KEY)
  } catch {}
})

// Never let a tab close silently drop an upload.
if (typeof window !== 'undefined') {
  window.addEventListener('beforeunload', event => {
    if (useTransfers.getState().tasks.some(task => task.kind === 'upload' && isActive(task))) {
      event.preventDefault()
      event.returnValue = ''
    }
  })
}

const SESSION_MAX_FILES = 500
const SESSION_MAX_BYTES = 4 * 1024 ** 3
const CONCURRENCY = 3
const RETRIES = 3

// A message already written for the user (a resumable batch's summary): shown as is.
class UploadReport extends Error {}

class HttpError extends Error {
  constructor(
    public status: number,
    message: string,
  ) {
    super(message)
  }
}

const readError = async (response: Response, fallback: string) => {
  const text = (await response.text().catch(() => '')).trim()
  return new HttpError(response.status, text.length && text.length < 400 ? text : fallback)
}

const headRefusal = (status: number, isDir: boolean) => {
  if (status === 401) return 'Your session has ended. Sign in again to download.'
  if (status === 403) return isDir ? 'You don’t have permission to download everything in this folder.' : 'You don’t have permission to download this.'
  if (status === 404) return 'This item no longer exists.'
  // Folder archives have no size cap, only an entry-count limit for the up-front listing.
  if (status === 413) return isDir ? 'This folder has too many items to download as one archive. Download its subfolders instead.' : 'This is too large to download.'
  if (status === 429 || status === 503) return 'The server is busy. Try again in a moment.'
  return `Download failed (HTTP ${status})`
}

const friendly = (error: unknown) => {
  if (error instanceof UploadReport) return error.message
  const message = error instanceof Error ? error.message : String(error)
  const lower = message.toLowerCase()
  if (lower.includes('already exists')) return 'A file with that name already exists here.'
  if (lower.includes('exceeds') && (lower.includes('quota') || lower.includes('available vault storage'))) return 'This upload is larger than the vault has room for.'
  if (lower.includes('session not found')) return 'The upload session expired on the server. Try again.'
  return message
}

const retryable = (error: unknown) =>
  !(error instanceof DOMException && error.name === 'AbortError') &&
  (!(error instanceof HttpError) || error.status >= 500 || error.status === 408 || error.status === 429)

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    const timer = setTimeout(resolve, ms)
    signal.addEventListener('abort', () => {
      clearTimeout(timer)
      reject(new DOMException('Cancelled', 'AbortError'))
    })
  })

const putFile = (url: string, file: File, signal: AbortSignal, onBytes: (delta: number) => void) =>
  new Promise<void>((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    let seen = 0
    const abort = () => xhr.abort()
    signal.addEventListener('abort', abort, { once: true })
    xhr.open('PUT', url)
    xhr.withCredentials = true
    xhr.setRequestHeader('Content-Type', file.type || 'application/octet-stream')
    xhr.upload.onprogress = event => {
      const loaded = Math.min(file.size, event.loaded)
      if (loaded > seen) {
        onBytes(loaded - seen)
        seen = loaded
      }
    }
    const done = (error?: Error) => {
      signal.removeEventListener('abort', abort)
      if (error) {
        // Roll back this attempt's progress so a retry doesn't double count.
        if (seen) onBytes(-seen)
        reject(error)
      } else {
        if (file.size > seen) onBytes(file.size - seen)
        resolve()
      }
    }
    xhr.onload = () =>
      xhr.status >= 200 && xhr.status < 300
        ? done()
        : done(new HttpError(xhr.status, xhr.responseText?.trim() || `Upload failed (HTTP ${xhr.status})`))
    xhr.onerror = () => done(new HttpError(0, 'Network error while uploading'))
    xhr.onabort = () => done(new DOMException('Cancelled', 'AbortError'))
    xhr.send(file)
  })

const chunkFiles = (files: PickedFile[]) => {
  const chunks: PickedFile[][] = []
  let current: PickedFile[] = []
  let bytes = 0
  for (const item of files) {
    if (current.length && (current.length >= SESSION_MAX_FILES || bytes + item.file.size > SESSION_MAX_BYTES)) {
      chunks.push(current)
      current = []
      bytes = 0
    }
    current.push(item)
    bytes += item.file.size
  }
  if (current.length) chunks.push(current)
  return chunks
}

const runBounded = async <T,>(items: T[], limit: number, signal: AbortSignal, worker: (item: T) => Promise<void>) => {
  let next = 0
  let failure: unknown = null
  await Promise.all(
    Array.from({ length: Math.min(limit, items.length) }, async () => {
      while (next < items.length && !failure && !signal.aborted) {
        const item = items[next++]
        try {
          await worker(item)
        } catch (error) {
          failure ??= error
        }
      }
    }),
  )
  if (failure) throw failure
  if (signal.aborted) throw new DOMException('Cancelled', 'AbortError')
}

const refreshListing = (source: FsSource, dirs: Set<string>) => {
  for (const dir of dirs) void queryClient.invalidateQueries({ queryKey: ['fs', source.key, dir] })
  void queryClient.invalidateQueries({ queryKey: ['fs', source.key], refetchType: 'none' })
}

// Uploads into `targetDir`. Large drops are split into several server sessions so no session holds thousands of
// files or runs for hours; each file retries transient failures; cancelling aborts in-flight PUTs and discards
// the staged session on the server.
export const startUpload = (source: FsSource, targetDir: string, files: PickedFile[]) => {
  if (!files.length) return
  const target = normalizePath(targetDir)
  const nested = files.some(f => f.relativePath.includes('/'))
  if (nested && !source.caps.folders) throw new Error('Folders can’t be uploaded here. Upload individual files instead.')

  const id = randomId()
  const controller = new AbortController()
  controllers.set(id, controller)
  const bytesTotal = files.reduce((sum, f) => sum + f.file.size, 0)
  const label = files.length === 1 ? files[0].file.name : `${files.length} files`
  addTask({
    id,
    kind: 'upload',
    label,
    detail: `to ${target === '/' ? source.rootLabel : target}`,
    status: 'queued',
    bytesTotal,
    bytesDone: 0,
    filesTotal: files.length,
    filesDone: 0,
    startedAt: Date.now(),
    finishedAt: null,
    error: null,
    sourceKey: source.key,
  })
  useTransfers.getState().setOpen(true)

  const touchedDirs = new Set<string>([target])
  const onBytes = (delta: number) => patch(id, task => ({ bytesDone: Math.max(0, task.bytesDone + delta) }))

  const fullPath = (item: PickedFile) => normalizePath(`${target}/${item.relativePath || item.file.name}`)
  for (const item of files) touchedDirs.add(parentOf(fullPath(item)))

  // Servers with `http.upload.resumable` take parts through /upload/sessions (upload/resumable.ts, loaded on demand);
  // false means "use the whole-file flow below".
  const uploadResumably = async () => {
    let resumable: typeof import('@/features/files/upload/resumable')
    try {
      resumable = await import('@/features/files/upload/resumable')
    } catch {
      return false
    }
    const outcome = await resumable.uploadResumable({
      source,
      items: files.map(item => ({ file: item.file, path: fullPath(item) })),
      signal: controller.signal,
      onBytes,
      onFileDone: () => patch(id, task => ({ filesDone: task.filesDone + 1 })),
      onFinishing: finishing => patch(id, { status: finishing ? 'finishing' : 'running' }),
      onNote: note => patch(id, { note }),
    })
    if (outcome === 'unsupported') return false
    refreshListing(source, touchedDirs)
    if (outcome.error) {
      patch(id, { failures: outcome.failures })
      throw new UploadReport(outcome.error)
    }
    return true
  }

  const run = async () => {
    patch(id, { status: 'running' })
    if (await uploadResumably()) return
    for (const chunk of chunkFiles(files)) {
      const prepared = chunk.map((item, index) => {
        const full = fullPath(item)
        return { item, fileId: `f${index}`, path: parentOf(full), filename: full.split('/').at(-1) as string }
      })
      const start = await fetch(`/upload/session${source.uploadQuery}`, {
        method: 'POST',
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        signal: controller.signal,
        body: JSON.stringify(
          source.uploadSessionBody(prepared.map(p => ({ path: p.path, filename: p.filename, size: p.item.file.size, mime: p.item.file.type || null, fileId: p.fileId }))),
        ),
      })
      if (!start.ok) throw await readError(start, 'The server refused the upload')
      const session = (await start.json()) as { upload_id?: string }
      const uploadId = session.upload_id
      if (!uploadId) throw new Error('The server did not open an upload session')
      const base = `/upload/${encodeURIComponent(uploadId)}`

      try {
        await runBounded(prepared, CONCURRENCY, controller.signal, async p => {
          for (let attempt = 0; ; attempt++) {
            try {
              await putFile(`${base}/files/${encodeURIComponent(p.fileId)}${source.uploadQuery}`, p.item.file, controller.signal, onBytes)
              break
            } catch (error) {
              if (attempt >= RETRIES || !retryable(error)) throw error
              await sleep(800 * 2 ** attempt, controller.signal)
            }
          }
          patch(id, task => ({ filesDone: task.filesDone + 1 }))
        })
        patch(id, { status: 'finishing' })
        const finish = await fetch(`${base}/finish${source.uploadQuery}`, { method: 'POST', credentials: 'same-origin' })
        if (!finish.ok) throw await readError(finish, 'The server could not finish the upload')
        patch(id, { status: 'running' })
        refreshListing(source, touchedDirs)
      } catch (error) {
        void fetch(`${base}${source.uploadQuery}`, { method: 'DELETE', credentials: 'same-origin' }).catch(() => undefined)
        throw error
      }
    }
  }

  void run()
    .then(() => patch(id, { status: 'done', finishedAt: Date.now(), bytesDone: bytesTotal }))
    .catch(error => {
      const cancelled = error instanceof DOMException && error.name === 'AbortError'
      patch(id, { status: cancelled ? 'cancelled' : 'failed', finishedAt: Date.now(), error: cancelled ? null : friendly(error) })
      refreshListing(source, touchedDirs)
    })
    .finally(() => controllers.delete(id))
  return id
}

// Asks the server first with a HEAD (same URL, same authorization, no body), so a refusal (too many entries, gone, no
// permission) becomes a failed task instead of the browser navigating to an error page; then hands the URL to the
// browser's own download manager, which the server streams to. Files and folder ZIPs have no size cap, and both
// answer HEAD with their exact length (a folder's is computed from its listing, without reading any file).
export const startDownload = async (source: FsSource, path: string, label: string, isDir: boolean) => {
  const id = randomId()
  const url = source.downloadUrl(path)
  addTask({
    id,
    kind: 'download',
    label: isDir ? `${label}.zip` : label,
    detail: isDir ? 'Listing folder' : 'Starting',
    status: 'running',
    bytesTotal: 0,
    bytesDone: 0,
    filesTotal: 1,
    filesDone: 0,
    startedAt: Date.now(),
    finishedAt: null,
    error: null,
    sourceKey: source.key,
  })
  try {
    const probe = await fetch(url, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store' })
    // A HEAD carries no body: name the refusal from the status alone.
    if (!probe.ok) throw new HttpError(probe.status, headRefusal(probe.status, isDir))
    const size = Number(probe.headers.get('content-length') ?? '')
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = isDir ? `${label}.zip` : label
    anchor.rel = 'noopener'
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    patch(id, {
      status: 'done',
      finishedAt: Date.now(),
      filesDone: 1,
      detail:
        Number.isFinite(size) && size > 0 ?
          `${formatBytes(size)}${isDir ? ' ZIP' : ''} · handed to your browser`
        : 'Handed to your browser',
    })
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') return
    patch(id, { status: 'failed', finishedAt: Date.now(), error: friendly(error), detail: '' })
    useTransfers.getState().setOpen(true)
  }
}
