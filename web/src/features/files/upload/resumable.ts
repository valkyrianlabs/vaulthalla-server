// Browser entry point for resumable uploads, loaded with `import()` from transfers.ts when an upload starts, so none
// of this is in a route's first-load JS. Decides whether the server speaks /upload/sessions and runs the engine.
import { api } from '@/lib/session'
import { queryClient, wsKey } from '@/lib/query'
import { formatBytes } from '@/lib/format'
import type { FsSource } from '@/features/files/source'
import { uploadBatch, type ItemResult, type UploadItem } from './engine.ts'
import { browserHttp } from './http.ts'
import { contentDigest } from './digest.ts'
import { createResumeStore, resumeKey } from './resumeStore.ts'

// meta.hello capability for /upload/sessions (transfer-protocol.md §3); listed in WS_CAPABILITIES (wsContract.ts).
// Spelled here so this lazy chunk does not pull in the generated contract.
export const RESUMABLE_UPLOADS_CAPABILITY = 'http.upload.resumable'

const HELLO = { client: { name: 'Vaulthalla Web' } } as const

// Console sessions ask meta.hello (no protocol range, so the session keeps speaking the server's minimum, as before).
// Share sessions may not say hello: there the first create is the probe, and an older daemon's plain 404 means "no".
const supported = async (source: FsSource): Promise<boolean | 'probe'> => {
  if (source.mode === 'share') return 'probe'
  try {
    const hello = await queryClient.fetchQuery({
      queryKey: wsKey('meta.hello', HELLO),
      queryFn: ({ signal }) => api.send('meta.hello', HELLO, { signal }),
      staleTime: 10 * 60_000,
    })
    return hello.capabilities.includes(RESUMABLE_UPLOADS_CAPABILITY)
  } catch {
    // An older daemon answers "Unknown command": no capabilities.
    return false
  }
}

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal.aborted) return reject(new DOMException('Cancelled', 'AbortError'))
    const abort = () => {
      clearTimeout(timer)
      reject(new DOMException('Cancelled', 'AbortError'))
    }
    const timer = setTimeout(() => {
      signal.removeEventListener('abort', abort)
      resolve()
    }, ms)
    signal.addEventListener('abort', abort, { once: true })
  })

const store = createResumeStore(
  () => (typeof window === 'undefined' ? null : window.sessionStorage),
  () => Math.floor(Date.now() / 1000),
)

export interface ResumableRequest {
  source: FsSource
  // Full target paths.
  items: { file: File; path: string }[]
  signal: AbortSignal
  onBytes: (delta: number) => void
  onFileDone: () => void
  onFinishing: (finishing: boolean) => void
  onNote: (note: string | null) => void
}

export type ResumableOutcome = 'unsupported' | { error: string | null; failures: string[] }

const MAX_LISTED_FAILURES = 20

export const uploadResumable = async (request: ResumableRequest): Promise<ResumableOutcome> => {
  const { source } = request
  const mode = await supported(source)
  if (mode === false) return 'unsupported'

  let resumedFiles = 0
  let resumedBytes = 0
  const items: UploadItem[] = request.items.map(({ file, path }) => ({
    file,
    path,
    name: file.name,
    mime: file.type || null,
    resumeKey: resumeKey(source.key, path, file.size, file.lastModified),
  }))
  const outcome = await uploadBatch(items, {
    http: browserHttp,
    query: source.uploadQuery,
    vaultId: source.mode === 'auth' ? source.vaultId : null,
    store,
    digest: data => contentDigest(data),
    sleep,
    random: Math.random,
    now: Date.now,
    signal: request.signal,
    onBytes: request.onBytes,
    onFileSettled: result => {
      if (result.ok) request.onFileDone()
    },
    onFinishing: request.onFinishing,
    onResume: (_item, stored) => {
      resumedFiles += 1
      resumedBytes += stored
      request.onNote(`Resuming ${resumedFiles === 1 ? 'an earlier upload' : `${resumedFiles} earlier uploads`}: ${formatBytes(resumedBytes)} already on the server`)
    },
  })
  if (outcome.kind === 'unsupported') return 'unsupported'

  const failed = outcome.results.filter((r): r is Extract<ItemResult, { ok: false }> => !r.ok)
  if (!failed.length) return { error: null, failures: [] }
  if (items.length === 1) return { error: failed[0].error, failures: [] }
  const resumable = failed.some(r => r.resumable)
  return {
    error: `${failed.length} of ${items.length} files didn’t upload.${resumable ? ' Choose the same files again to resume.' : ''}`,
    failures: failed.slice(0, MAX_LISTED_FAILURES).map(r => `${r.item.path}: ${r.error}`),
  }
}
