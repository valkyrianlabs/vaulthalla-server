'use client'

import { useEffect, useRef, useSyncExternalStore } from 'react'
import { hasThumbnail, type Entry } from '@/features/files/entries'
import type { FsSource } from '@/features/files/source'

// Thumbnails for the rows on screen only. Requests go out in batches of at most 100; only items the server reports
// as still rendering are polled again, with backoff. Only entries whose server plan says a thumbnail exists are asked
// for (MIME rules when an older daemon sends no plan). `failed` (the source doesn't render: invalid or over a limit)
// is final, like `unsupported`: no polling and no fallback request.
type ThumbState = { status: 'ready' | 'queued' | 'missing' | 'unsupported' | 'failed' | 'error'; url: string | null }

// The thumbnail size for a tile: list icons are 32 px (128 covers them at any density); grid tiles are at least
// 176 px wide and 112 px tall, cropped to cover, so they need 256 px, or 512 px on high-density screens.
export const thumbnailSizeFor = (view: 'list' | 'grid', tileWidth: number) => {
  if (view === 'list') return 128
  const dpr = typeof window !== 'undefined' ? window.devicePixelRatio || 1 : 1
  return tileWidth * dpr > 256 ? 512 : 256
}

const cache = new Map<string, ThumbState>()
const inflight = new Set<string>()
const listeners = new Set<() => void>()
let version = 0
const emit = () => {
  version++
  for (const listener of listeners) listener()
}

const BATCH = 100
const MAX_POLLS = 12

const signature = (source: FsSource, entry: Entry, size: number) =>
  `${source.key}\x1f${entry.path}\x1f${entry.modified}\x1f${entry.size ?? ''}\x1f${size}`

async function request(source: FsSource, entries: Entry[], size: number, attempt: number) {
  const sigs = entries.map(entry => signature(source, entry, size))
  sigs.forEach(sig => inflight.add(sig))
  try {
    const response = await fetch(`/preview/batch${source.mode === 'share' ? '?share=1' : ''}`, {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        size,
        ...(source.vaultId ? { vault_id: source.vaultId } : {}),
        items: entries.map((entry, index) => ({ key: sigs[index], path: entry.path, ...(source.vaultId ? { vault_id: source.vaultId } : {}) })),
      }),
    })
    if (!response.ok) throw new Error(String(response.status))
    const data = (await response.json()) as { items?: { key?: string; status: ThumbState['status']; url?: string }[] }
    const requeue: Entry[] = []
    for (const item of data.items ?? []) {
      if (!item.key) continue
      cache.set(item.key, { status: item.status, url: item.status === 'ready' && item.url ? item.url : null })
      if (item.status === 'queued') {
        const entry = entries[sigs.indexOf(item.key)]
        if (entry) requeue.push(entry)
      }
    }
    emit()
    if (requeue.length && attempt < MAX_POLLS) setTimeout(() => void request(source, requeue, size, attempt + 1), Math.min(5000, 250 * 2 ** attempt))
  } catch {
    // Fall back to the direct preview URL for these rows.
    for (const sig of sigs) if (!cache.has(sig)) cache.set(sig, { status: 'error', url: null })
    emit()
  } finally {
    sigs.forEach(sig => inflight.delete(sig))
  }
}

export const useThumbnails = (source: FsSource, visible: Entry[], enabled: boolean, size = 128) => {
  const wanted = enabled && source.caps.preview ? visible.filter(hasThumbnail) : []
  // A string key keeps the effect stable across renders that show the same rows.
  const wantedKey = wanted.map(entry => signature(source, entry, size)).join('\n')
  const latest = useRef(wanted)
  latest.current = wanted

  useEffect(() => {
    if (!wantedKey) return
    const timer = setTimeout(() => {
      const missing = latest.current.filter(entry => {
        const sig = signature(source, entry, size)
        return !cache.has(sig) && !inflight.has(sig)
      })
      for (let i = 0; i < missing.length; i += BATCH) void request(source, missing.slice(i, i + BATCH), size, 0)
    }, 120)
    return () => clearTimeout(timer)
  }, [source, wantedKey, size])

  useSyncExternalStore(
    listener => {
      listeners.add(listener)
      return () => listeners.delete(listener)
    },
    () => version,
    () => version,
  )

  return (entry: Entry): string | null => {
    if (!source.caps.preview || !hasThumbnail(entry)) return null
    const state = cache.get(signature(source, entry, size))
    if (!state) return null
    if (state.status === 'ready') return state.url
    if (state.status === 'error') return source.previewUrl(entry.path, size)
    return null
  }
}
