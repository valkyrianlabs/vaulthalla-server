'use client'

import React, { useCallback, useEffect, useRef } from 'react'
import { Dialog, SheetContent } from '@/components/ui/Dialog'
import { Button } from '@/components/ui/Button'
import { DefinitionList } from '@/components/ui/Panel'
import { confirm } from '@/components/ui/Confirm'
import { ChevronLeftIcon, ChevronRightIcon, ClockIcon, DownloadIcon, LockIcon, ShareNodesIcon } from '@/components/ui/icons'
import { formatBytes, formatDateTime } from '@/lib/format'
import type { Entry } from '@/features/files/entries'
import { FileIcon } from '@/features/files/FileIcon'
import type { FsSource } from '@/features/files/source'
import { Notice, Stage } from '@/features/files/preview/Frame'
import { planOf } from '@/features/files/preview/plan'
import { rendererFor, wideRenderer } from '@/features/files/preview/registry'

// Keys typed into an editor, a media element's controls or a 3D canvas belong to that element, not to file navigation.
const ownsKeys = (target: EventTarget | null) =>
  target instanceof Element &&
  Boolean(target.closest('input, textarea, select, video, audio, canvas, [contenteditable=""], [contenteditable="true"], [data-preview-keys]'))

export const PreviewSheet = ({
  source,
  entry,
  siblings,
  onOpenChange,
  onSelect,
  onDownload,
  onShare,
  onRecoveryHistory,
}: {
  source: FsSource
  entry: Entry | null
  siblings: Entry[]
  onOpenChange: (open: boolean) => void
  onSelect: (entry: Entry) => void
  onDownload: (entry: Entry) => void
  onShare?: (entry: Entry) => void
  onRecoveryHistory?: (entry: Entry) => void
}) => {
  const files = siblings.filter(e => e.kind === 'file')
  const index = entry ? files.findIndex(e => e.key === entry.key) : -1
  const dirty = useRef(false)
  const setDirty = useCallback((value: boolean) => {
    dirty.current = value
  }, [])

  // Unsaved edits survive neither a file switch nor a close without an explicit discard.
  const leave = useCallback(async () => {
    if (!dirty.current) return true
    const ok = await confirm({
      title: 'Discard unsaved changes?',
      description: 'Your edits to this file haven’t been saved.',
      confirmLabel: 'Discard changes',
      tone: 'danger',
    })
    if (ok) dirty.current = false
    return ok
  }, [])

  const select = useCallback(
    async (next: Entry | undefined) => {
      if (next && (await leave())) onSelect(next)
    },
    [leave, onSelect],
  )

  const openChange = useCallback(
    async (open: boolean) => {
      if (open || (await leave())) onOpenChange(open)
    },
    [leave, onOpenChange],
  )

  useEffect(() => {
    if (!entry) return
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey || ownsKeys(event.target)) return
      if (event.key === 'ArrowRight' && index < files.length - 1) void select(files[index + 1])
      if (event.key === 'ArrowLeft' && index > 0) void select(files[index - 1])
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [entry, files, index, select])

  if (!entry) return null
  const plan = planOf(entry)
  const Renderer = rendererFor(plan.renderer)
  const allowed = plan.requires === 'download' ? source.caps.download : source.caps.preview
  const download = source.caps.download ? () => onDownload(entry) : null

  return (
    <Dialog open onOpenChange={o => void openChange(o)}>
      <SheetContent
        title={entry.name}
        width={wideRenderer(plan.renderer) ? 'max-w-4xl' : 'max-w-xl'}
        footer={
          <>
            {onRecoveryHistory ?
              <Button variant="ghost" onClick={() => onRecoveryHistory(entry)}>
                <ClockIcon aria-hidden /> History
              </Button>
            : null}
            {onShare && source.caps.share ?
              <Button variant="ghost" onClick={() => onShare(entry)}>
                <ShareNodesIcon aria-hidden /> Share
              </Button>
            : null}
            {download ?
              <Button variant="primary" onClick={download}>
                <DownloadIcon aria-hidden /> Download
              </Button>
            : null}
          </>
        }>
        <div data-preview-renderer={plan.renderer}>
          {!Renderer ?
            <Stage>
              <div className="flex flex-col items-center gap-3 py-16 text-fg-subtle">
                <FileIcon entry={entry} className="size-10" />
                <span className="text-sm">No preview for this file type</span>
              </div>
            </Stage>
          : !allowed ?
            <Notice
              icon={LockIcon}
              title={source.mode === 'share' ? 'Preview not available with this link’s permissions' : 'You don’t have permission to view this file'}
              description={
                plan.requires === 'download' ?
                  'Showing this file type needs the original file, which this access doesn’t include.'
                : 'This access doesn’t include previews.'
              }
            />
          : <Renderer key={entry.key} source={source} entry={entry} plan={plan} onDownload={download} setDirty={setDirty} />}
        </div>

        {files.length > 1 ?
          <div className="mt-3 flex items-center justify-between text-xs text-fg-subtle">
            <Button variant="ghost" size="sm" disabled={index <= 0} onClick={() => void select(files[index - 1])}>
              <ChevronLeftIcon aria-hidden /> Previous
            </Button>
            <span className="tabular">
              {index + 1} of {files.length}
            </span>
            <Button variant="ghost" size="sm" disabled={index >= files.length - 1} onClick={() => void select(files[index + 1])}>
              Next <ChevronRightIcon aria-hidden />
            </Button>
          </div>
        : null}

        <DefinitionList
          className="mt-5"
          items={[
            ['Size', formatBytes(entry.size)],
            ['Type', entry.mime ?? 'Unknown'],
            ['Modified', formatDateTime(entry.modified || null)],
            ['Location', <span key="loc" className="font-mono text-xs break-all">{entry.path}</span>],
          ]}
        />
      </SheetContent>
    </Dialog>
  )
}
