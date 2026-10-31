// Which server session holds an unfinished upload of a file, so choosing the same file again after a reload (a File
// handle can't survive one) resumes instead of starting over. One sessionStorage entry per tab, keyed by where the
// file goes and what it is: (source, target path, size, lastModified). Pure over a Storage-like; see resumeStore.test.ts.

export interface ResumeRecord {
  upload_id: string
  file_id: string
  // Unix seconds; the record is ignored after it (the server's janitor has the session by then).
  expires_at: number | null
}

export interface KeyValueStorage {
  getItem(key: string): string | null
  setItem(key: string, value: string): void
  removeItem(key: string): void
}

export const RESUME_STORAGE_KEY = 'vaulthalla-upload-resume'
const MAX_RECORDS = 4096

export const resumeKey = (sourceKey: string, path: string, size: number, lastModified: number) => JSON.stringify([sourceKey, path, size, lastModified])

export interface ResumeStore {
  get(key: string): ResumeRecord | null
  put(entries: [string, ResumeRecord][]): void
  remove(keys: string[]): void
  removeUpload(uploadId: string): void
}

const isRecord = (value: unknown): value is ResumeRecord =>
  typeof value === 'object' && value !== null && typeof (value as ResumeRecord).upload_id === 'string' && typeof (value as ResumeRecord).file_id === 'string'

// `storage` may be null or throw (private windows, disabled storage): every operation then does nothing.
export const createResumeStore = (storage: () => KeyValueStorage | null, nowSeconds: () => number): ResumeStore => {
  const load = (): Record<string, ResumeRecord> => {
    try {
      const raw = storage()?.getItem(RESUME_STORAGE_KEY)
      const parsed: unknown = raw ? JSON.parse(raw) : null
      if (typeof parsed !== 'object' || parsed === null) return {}
      const now = nowSeconds()
      return Object.fromEntries(Object.entries(parsed).filter(([, r]) => isRecord(r) && (r.expires_at === null || r.expires_at > now)))
    } catch {
      return {}
    }
  }
  const save = (records: Record<string, ResumeRecord>) => {
    try {
      const entries = Object.entries(records).slice(-MAX_RECORDS)
      if (entries.length) storage()?.setItem(RESUME_STORAGE_KEY, JSON.stringify(Object.fromEntries(entries)))
      else storage()?.removeItem(RESUME_STORAGE_KEY)
    } catch {
      // Quota or disabled storage: resuming after a reload just isn't offered.
    }
  }
  const update = (change: (records: Record<string, ResumeRecord>) => void) => {
    const records = load()
    change(records)
    save(records)
  }
  return {
    get: key => load()[key] ?? null,
    put: entries =>
      update(records => {
        for (const [key, record] of entries) {
          delete records[key]
          records[key] = record
        }
      }),
    remove: keys =>
      update(records => {
        for (const key of keys) delete records[key]
      }),
    removeUpload: uploadId =>
      update(records => {
        for (const [key, record] of Object.entries(records)) if (record.upload_id === uploadId) delete records[key]
      }),
  }
}
