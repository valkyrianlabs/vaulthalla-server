'use client'

import React, { useCallback, useEffect, useRef, useState } from 'react'
import dynamic from 'next/dynamic'
import { queryClient } from '@/lib/query'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { Dialog, DialogContent } from '@/components/ui/Dialog'
import { Segmented } from '@/components/ui/Tabs'
import { Spinner } from '@/components/ui/Spinner'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import { CircleExclamationIcon, CopyIcon, FileLinesIcon, FloppyDiskIcon, LockIcon, PenIcon, RotateLeftIcon } from '@/components/ui/icons'
import { parentOf } from '@/features/files/entries'
import { Notice, Stage } from '@/features/files/preview/Frame'
import { describeStatus, errorText, isAbort, PreviewHttpError, readBytes } from '@/features/files/preview/http'
import type { EditorHandle } from '@/features/files/preview/TextEditor'
import type { RendererProps } from '@/features/files/preview/types'

const editorLoading = () => (
  <div className="grid h-full place-items-center">
    <Spinner className="size-6" label="Loading editor" />
  </div>
)
const TextEditor = dynamic(() => import('@/features/files/preview/TextEditor'), { ssr: false, loading: editorLoading })
const MarkdownView = dynamic(() => import('@/features/files/preview/MarkdownView'), { ssr: false, loading: editorLoading })

// Matches the server's default `preview.text.max_edit_bytes`.
export const MAX_TEXT_BYTES = 2 * 1024 ** 2

type Doc = { text: string; etag: string | null }
type Load = { status: 'loading' } | { status: 'ready'; doc: Doc } | { status: 'too-large' } | { status: 'binary' } | { status: 'error'; message: string }

class NotText extends Error {}

// The original bytes, uncached (`no-store`: the ETag must describe exactly what the editor starts from). Refuses
// anything over the edit limit, any NUL byte and any invalid UTF-8.
const fetchText = async (url: string, signal: AbortSignal): Promise<Doc> => {
  const response = await fetch(url, { credentials: 'same-origin', cache: 'no-store', signal })
  if (!response.ok) throw new PreviewHttpError(response.status, 'http', describeStatus(response.status))
  const bytes = new Uint8Array(await readBytes(response, MAX_TEXT_BYTES))
  if (bytes.includes(0)) throw new NotText()
  let text: string
  try {
    text = new TextDecoder('utf-8', { fatal: true }).decode(bytes)
  } catch {
    throw new NotText()
  }
  return { text, etag: response.headers.get('etag') }
}

// `text` / `markdown`: view by default; the console can edit in place (CodeMirror, lazy) and saves with
// `PUT /upload/text` + `If-Match` so a concurrent change is a 412 conflict, never a silent overwrite.
export default function TextRenderer({ source, entry, plan, onDownload, setDirty }: RendererProps) {
  const markdown = plan.renderer === 'markdown'
  const contentUrl = source.contentUrl(entry, 'inline')
  const [load, setLoad] = useState<Load>(() => (entry.size !== null && entry.size > MAX_TEXT_BYTES ? { status: 'too-large' } : { status: 'loading' }))
  const [view, setView] = useState<'rendered' | 'source'>(markdown ? 'rendered' : 'source')
  const [editing, setEditing] = useState(false)
  const [dirty, setLocalDirty] = useState(false)
  const [saving, setSaving] = useState(false)
  const [readOnly, setReadOnly] = useState<string | null>(null)
  const [conflict, setConflict] = useState<{ etag: string | null } | null>(null)
  const editor = useRef<EditorHandle | null>(null)

  const reload = useCallback(
    async (signal: AbortSignal) => {
      try {
        const doc = await fetchText(contentUrl, signal)
        setLoad({ status: 'ready', doc })
        return doc
      } catch (error) {
        if (isAbort(error)) return null
        if (error instanceof NotText) setLoad({ status: 'binary' })
        else if (error instanceof PreviewHttpError && error.code === 'too_large') setLoad({ status: 'too-large' })
        else setLoad({ status: 'error', message: errorText(error) })
        return null
      }
    },
    [contentUrl],
  )

  useEffect(() => {
    if (entry.size !== null && entry.size > MAX_TEXT_BYTES) return
    const controller = new AbortController()
    void reload(controller.signal)
    return () => controller.abort()
  }, [reload, entry.size])

  // Report unsaved work to the sheet, and to the browser if the tab closes.
  useEffect(() => {
    setDirty(editing && dirty)
    if (!(editing && dirty)) return
    const onUnload = (event: BeforeUnloadEvent) => {
      event.preventDefault()
      event.returnValue = ''
    }
    window.addEventListener('beforeunload', onUnload)
    return () => window.removeEventListener('beforeunload', onUnload)
  }, [editing, dirty, setDirty])
  useEffect(() => () => setDirty(false), [setDirty])

  const doc = load.status === 'ready' ? load.doc : null
  const saveUrl = source.caps.edit && source.textSaveUrl ? source.textSaveUrl(entry) : null
  const canEdit = Boolean(saveUrl && doc?.etag && !readOnly)

  const save = useCallback(
    async (etagOverride?: string | null) => {
      const handle = editor.current
      if (!saveUrl || !doc || !handle || saving) return
      const etag = etagOverride ?? doc.etag
      if (!etag) {
        setReadOnly('The server did not send a version tag for this file, so it can’t be saved safely. Reopen it to try again.')
        return
      }
      const text = handle.getText()
      setSaving(true)
      try {
        const response = await fetch(saveUrl, {
          method: 'PUT',
          credentials: 'same-origin',
          headers: { 'If-Match': etag, 'Content-Type': 'text/plain; charset=utf-8' },
          body: text,
        })
        if (response.ok) {
          const body = (await response.json().catch(() => null)) as { etag?: unknown } | null
          const next = typeof body?.etag === 'string' ? body.etag : response.headers.get('etag')
          handle.markSaved()
          setLoad({ status: 'ready', doc: { text, etag: next } })
          setConflict(null)
          notify.success('Saved', entry.name)
          void queryClient.invalidateQueries({ queryKey: ['fs', source.key, parentOf(entry.path)] })
          return
        }
        if (response.status === 412) {
          setConflict({ etag: response.headers.get('etag') })
          return
        }
        if (response.status === 403) {
          setReadOnly('You don’t have permission to change this file. Copy your text if you want to keep it.')
          notify.error(new Error('You don’t have permission to change this file.'))
          return
        }
        if (response.status === 413) {
          notify.error(new Error(`This text is too large to save here (limit ${formatBytes(MAX_TEXT_BYTES)}).`))
          return
        }
        if (response.status === 428) {
          notify.error(new Error('The server needs the file’s version to save it. Reopen the file and try again.'))
          return
        }
        if (response.status === 404 || response.status === 405 || response.status === 501) {
          notify.error(new Error(response.status === 404 ? 'This file no longer exists, or this server can’t save text files.' : 'This server can’t save text files yet.'))
          return
        }
        notify.error(new Error(`Saving failed (HTTP ${response.status}).`))
      } catch (error) {
        notify.error(error, 'Saving failed: the server could not be reached.')
      } finally {
        setSaving(false)
      }
    },
    [saveUrl, doc, saving, entry.name, entry.path, source.key],
  )

  const stopEditing = async () => {
    if (dirty && !(await confirm({ title: 'Discard unsaved changes?', confirmLabel: 'Discard changes', tone: 'danger' }))) return
    setEditing(false)
    setLocalDirty(false)
  }

  // Conflict: theirs wins (reload), mine wins (save against the current version), or keep a copy of mine.
  const takeTheirs = async () => {
    const controller = new AbortController()
    const fresh = await reload(controller.signal)
    if (fresh) editor.current?.reset(fresh.text)
    setConflict(null)
  }
  const overwrite = async () => {
    let etag = conflict?.etag ?? null
    if (!etag) {
      const head = await fetch(contentUrl, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store' }).catch(() => null)
      etag = head?.ok ? head.headers.get('etag') : null
    }
    setConflict(null)
    if (!etag) return notify.error(new Error('Could not read the file’s current version. Try again.'))
    await save(etag)
  }
  const copyMine = async () => {
    const text = editor.current?.getText() ?? ''
    try {
      await navigator.clipboard.writeText(text)
      notify.success('Your text is on the clipboard')
    } catch {
      notify.error(new Error('The browser refused clipboard access.'))
    }
  }

  if (load.status === 'too-large')
    return (
      <Notice
        icon={FileLinesIcon}
        title="This file is too large to preview"
        description={`Text files up to ${formatBytes(MAX_TEXT_BYTES)} open here. Download it to read the rest.`}
        onDownload={onDownload}
      />
    )
  if (load.status === 'binary')
    return <Notice icon={FileLinesIcon} title="Binary or unsupported encoding" description="This file isn’t valid UTF-8 text, so it isn’t shown here." onDownload={onDownload} />
  if (load.status === 'error') return <Notice icon={CircleExclamationIcon} title="This file could not be loaded" description={load.message} onDownload={onDownload} />
  if (!doc)
    return (
      <Stage>
        <Spinner className="size-6" label="Loading file" />
      </Stage>
    )

  return (
    <div className="flex flex-col gap-2">
      <div className="flex min-h-9 flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          {markdown && !editing ?
            <Segmented
              label="Markdown view"
              value={view}
              onChange={setView}
              options={[
                { value: 'rendered', label: 'Preview' },
                { value: 'source', label: 'Source' },
              ]}
            />
          : null}
          {editing ?
            <span className="text-xs text-fg-subtle" aria-live="polite">
              {saving ? 'Saving…' : dirty ? 'Unsaved changes' : 'No changes'}
            </span>
          : null}
        </div>
        <div className="flex items-center gap-2">
          {editing ?
            <>
              <Button variant="ghost" size="sm" onClick={() => void stopEditing()} disabled={saving}>
                Done
              </Button>
              <Button variant="primary" size="sm" onClick={() => void save()} loading={saving} disabled={!dirty || Boolean(readOnly)}>
                <FloppyDiskIcon aria-hidden /> Save
              </Button>
            </>
          : canEdit ?
            <Button variant="secondary" size="sm" onClick={() => setEditing(true)}>
              <PenIcon aria-hidden /> Edit
            </Button>
          : null}
        </div>
      </div>

      {readOnly ?
        <p className="flex items-center gap-2 rounded-control border border-warn-line bg-warn-soft px-3 py-2 text-xs text-warn" role="alert">
          <LockIcon className="size-3.5 shrink-0" aria-hidden /> {readOnly}
        </p>
      : null}

      {editing ?
        <div className="h-[60dvh] overflow-hidden rounded-card border border-line bg-surface-1">
          <TextEditor initial={doc.text} fileName={entry.name} onDirty={setLocalDirty} onSave={() => { if (dirty) void save() }} handleRef={editor} />
        </div>
      : <div className="max-h-[60dvh] overflow-auto rounded-card border border-line bg-surface-1 p-4" tabIndex={0} aria-label={`Contents of ${entry.name}`}>
          {markdown && view === 'rendered' ?
            <MarkdownView text={doc.text} />
          : <pre className="font-mono text-xs leading-relaxed break-words whitespace-pre-wrap text-fg" data-testid="text-view">
              {doc.text}
            </pre>
          }
        </div>
      }

      <Dialog open={conflict !== null} onOpenChange={open => !open && setConflict(null)}>
        {conflict ?
          <DialogContent
            title="This file changed since you opened it"
            description="Someone saved a newer version while you were editing. Choose which version to keep."
            footer={
              <>
                <Button variant="ghost" onClick={() => void copyMine()}>
                  <CopyIcon aria-hidden /> Copy your text
                </Button>
                <Button variant="secondary" onClick={() => void takeTheirs()}>
                  <RotateLeftIcon aria-hidden /> Reload their version
                </Button>
                <Button variant="danger" onClick={() => void overwrite()}>
                  Overwrite with yours
                </Button>
              </>
            }>
            <p className="text-sm text-fg-muted">Reloading discards your edits. Overwriting replaces their changes with your text.</p>
          </DialogContent>
        : null}
      </Dialog>
    </div>
  )
}
