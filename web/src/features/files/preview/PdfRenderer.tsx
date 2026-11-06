'use client'

import React, { useEffect, useRef, useState } from 'react'
import { cn } from '@/util/cn'
import { IconButton } from '@/components/ui/IconButton'
import { Segmented } from '@/components/ui/Tabs'
import { Spinner } from '@/components/ui/Spinner'
import { ChevronLeftIcon, ChevronRightIcon, CircleExclamationIcon } from '@/components/ui/icons'
import { Notice, Stage } from '@/features/files/preview/Frame'
import { describeStatus, errorText, isAbort } from '@/features/files/preview/http'
import type { RendererProps } from '@/features/files/preview/types'

type Fit = 'page' | 'width'

// One server-rendered JPEG per page (`/preview?…&page=N&size=S`, 0-based pages). The page count arrives in
// `X-Vaulthalla-Page-Count`. Pages are fetched with credentials and shown as blob URLs (revoked when replaced).
// PageUp/PageDown turn pages; the sheet keeps ←/→ for switching files.
export default function PdfRenderer({ source, entry }: RendererProps) {
  const [page, setPage] = useState(0)
  const [count, setCount] = useState<number | null>(null)
  const [fit, setFit] = useState<Fit>('page')
  const [url, setUrl] = useState<string | null>(null)
  const [busy, setBusy] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const current = useRef<string | null>(null)
  // Sharp on high-density screens without asking for more than the sheet can show.
  const [size] = useState(() => (typeof window !== 'undefined' && window.devicePixelRatio > 1.25 ? 2048 : 1536))

  useEffect(() => {
    const controller = new AbortController()
    setBusy(true)
    setError(null)
    void (async () => {
      try {
        const response = await fetch(source.previewUrl({ id: entry.id, path: entry.path }, size, page), { credentials: 'same-origin', signal: controller.signal })
        if (!response.ok) throw new Error(describeStatus(response.status, 'this document'))
        const pages = Number(response.headers.get('x-vaulthalla-page-count') ?? '')
        if (Number.isInteger(pages) && pages > 0) setCount(pages)
        const blob = await response.blob()
        const next = URL.createObjectURL(blob)
        if (current.current) URL.revokeObjectURL(current.current)
        current.current = next
        setUrl(next)
        setBusy(false)
      } catch (err) {
        if (isAbort(err)) return
        setError(errorText(err))
        setBusy(false)
      }
    })()
    return () => controller.abort()
  }, [source, entry.id, entry.path, page, size])

  useEffect(
    () => () => {
      if (current.current) URL.revokeObjectURL(current.current)
      current.current = null
    },
    [],
  )

  const last = count === null ? null : count - 1
  const canPrev = page > 0
  const canNext = last === null ? false : page < last
  const go = (next: number) => setPage(Math.max(0, last === null ? next : Math.min(last, next)))

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (event.defaultPrevented || event.altKey || event.ctrlKey || event.metaKey) return
      if (event.target instanceof Element && event.target.closest('input, textarea, select, [contenteditable="true"]')) return
      if (event.key === 'PageDown' && canNext) {
        event.preventDefault()
        setPage(p => p + 1)
      } else if (event.key === 'PageUp' && canPrev) {
        event.preventDefault()
        setPage(p => Math.max(0, p - 1))
      }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [canNext, canPrev])

  if (error && !url) return <Notice icon={CircleExclamationIcon} title="This document could not be shown" description={error} />

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex items-center gap-1">
          <IconButton label="Previous page" icon={ChevronLeftIcon} size="icon-sm" disabled={!canPrev} onClick={() => go(page - 1)} />
          <span className="tabular min-w-24 text-center text-xs text-fg-muted" aria-live="polite" data-testid="pdf-page-indicator">
            Page {page + 1}
            {count !== null ? ` of ${count}` : ''}
          </span>
          <IconButton label="Next page" icon={ChevronRightIcon} size="icon-sm" disabled={!canNext} onClick={() => go(page + 1)} />
        </div>
        <Segmented
          label="Page fit"
          value={fit}
          onChange={setFit}
          options={[
            { value: 'page', label: 'Fit page' },
            { value: 'width', label: 'Fit width' },
          ]}
        />
      </div>
      <Stage className={cn(fit === 'width' && 'block max-h-[70dvh] overflow-auto')}>
        {busy ? <Spinner className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2" label="Loading page" /> : null}
        {url ?
          // eslint-disable-next-line @next/next/no-img-element -- blob URL of an authenticated server render
          <img
            src={url}
            alt={`${entry.name}, page ${page + 1}`}
            className={cn(fit === 'page' ? 'max-h-[70dvh] w-auto max-w-full object-contain' : 'h-auto w-full', busy && 'opacity-60')}
            data-testid="pdf-page"
          />
        : null}
        {error && url ?
          <p className="absolute bottom-2 left-1/2 -translate-x-1/2 rounded-md bg-surface-solid px-3 py-1.5 text-xs text-danger" role="alert">
            {error}
          </p>
        : null}
      </Stage>
    </div>
  )
}
