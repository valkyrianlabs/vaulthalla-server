'use client'

import React, { useCallback, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useWindowVirtualizer } from '@tanstack/react-virtual'
import { cn } from '@/util/cn'
import { queryClient } from '@/lib/query'
import { formatBytes, formatDateTime, formatRelative } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { IconButton } from '@/components/ui/IconButton'
import { Input } from '@/components/ui/Field'
import { Checkbox } from '@/components/ui/Choice'
import { ContextMenu, DropdownMenu, type MenuEntry } from '@/components/ui/Menu'
import { EmptyState, ErrorState } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { confirm } from '@/components/ui/Confirm'
import { notify } from '@/components/ui/Toast'
import {
  ArrowsRotateIcon,
  ArrowsUpDownLeftRightIcon,
  ChevronRightIcon,
  CopyIcon,
  DownloadIcon,
  EllipsisIcon,
  EyeIcon,
  FileArrowUpIcon,
  FolderOpenIcon,
  FolderPlusIcon,
  Grid2Icon,
  HouseIcon,
  ListIcon,
  MagnifyingGlassIcon,
  PenIcon,
  ShareNodesIcon,
  TrashIcon,
  UploadIcon,
  XmarkIcon,
} from '@/components/ui/icons'
import { useUiPrefs } from '@/components/shell/uiPrefs'
import {
  baseName,
  joinPath,
  normalizePath,
  parentOf,
  pathSegments,
  sortEntries,
  type Entry,
} from '@/features/files/entries'
import type { FsSource, Listing } from '@/features/files/source'
import { FileIcon } from '@/features/files/FileIcon'
import { thumbnailSizeFor, useThumbnails } from '@/features/files/thumbnails'
import { startDownload, startUpload, type PickedFile } from '@/features/files/transfers'
import { collectDropped, collectPicked } from '@/features/files/drop'
import dynamic from 'next/dynamic'

// Dialogs load the first time they're needed.
const NameDialog = dynamic(() => import('@/features/files/dialogs').then(m => m.NameDialog), { ssr: false })
const DestinationDialog = dynamic(() => import('@/features/files/dialogs').then(m => m.DestinationDialog), {
  ssr: false,
})
const PreviewSheet = dynamic(() => import('@/features/files/PreviewSheet').then(m => m.PreviewSheet), { ssr: false })

type SortKey = 'name' | 'size' | 'modified'

export interface FileBrowserProps {
  source: FsSource
  path: string
  onNavigate: (path: string) => void
  // Rendered left of the breadcrumbs (e.g. the vault switcher).
  leading?: React.ReactNode
  onShare?: (target: Entry) => void
  className?: string
}

export const listingKey = (source: FsSource, path: string) => ['fs', source.key, normalizePath(path)] as const

const ROW_HEIGHT = 52

const countLabel = (n: number, noun: string) => `${n} ${noun}${n === 1 ? '' : 's'}`

export function FileBrowser({ source, path, onNavigate, leading, onShare, className }: FileBrowserProps) {
  const current = normalizePath(path)
  const listing = useQuery<Listing>({
    queryKey: listingKey(source, current),
    queryFn: ({ signal }) => source.list(current, signal),
    staleTime: 10_000,
    // Keep the previous folder on screen while the next loads — but only within the same source, and actions are
    // disabled until the new listing arrives so nothing can target the wrong folder.
    placeholderData: (previous, previousQuery) => (previousQuery?.queryKey[1] === source.key ? previous : undefined),
    enabled: source.caps.list || source.mode === 'share',
  })
  const stale = listing.isPlaceholderData

  const view = useUiPrefs(state => state.fileView)
  const setView = useUiPrefs(state => state.setFileView)
  const [filter, setFilter] = useState('')
  const [sort, setSort] = useState<{ key: SortKey; dir: 'asc' | 'desc' }>({ key: 'name', dir: 'asc' })
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [focus, setFocus] = useState(0)
  const anchor = useRef<number | null>(null)
  const [preview, setPreview] = useState<Entry | null>(null)
  const [naming, setNaming] = useState<{ mode: 'mkdir' } | { mode: 'rename'; entry: Entry } | null>(null)
  const [destination, setDestination] = useState<{ mode: 'move' | 'copy'; entries: Entry[] } | null>(null)
  const [menuTarget, setMenuTarget] = useState<Entry | null>(null)
  const [dragging, setDragging] = useState(false)
  const dragDepth = useRef(0)
  const fileInput = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  // Reset view state when the folder changes.
  useEffect(() => {
    setSelected(new Set())
    setFocus(0)
    setFilter('')
    anchor.current = null
  }, [source.key, current])

  const entries = useMemo(() => {
    const all = listing.data?.entries ?? []
    const q = filter.trim().toLowerCase()
    return sortEntries(q ? all.filter(e => e.name.toLowerCase().includes(q)) : all, sort.key, sort.dir)
  }, [listing.data, filter, sort])

  const selectedEntries = useMemo(() => entries.filter(e => selected.has(e.key)), [entries, selected])

  // ---------- actions ----------

  const refresh = useCallback(
    (...dirs: string[]) =>
      Promise.all([current, ...dirs].map(dir => queryClient.invalidateQueries({ queryKey: listingKey(source, dir) }))),
    [source, current],
  )

  const open = useCallback(
    (entry: Entry) => {
      if (entry.kind === 'dir') onNavigate(entry.path)
      else if (source.caps.preview || source.caps.download) setPreview(entry)
    },
    [onNavigate, source.caps.download, source.caps.preview],
  )

  const download = useCallback(
    (entry: Entry) =>
      void startDownload(
        source,
        entry.path,
        entry.kind === 'dir' ? entry.name || source.rootLabel : entry.name,
        entry.kind === 'dir',
      ),
    [source],
  )

  const upload = useCallback(
    (files: PickedFile[]) => {
      if (!files.length) return
      try {
        startUpload(source, current, files)
      } catch (error) {
        notify.error(error)
      }
    },
    [source, current],
  )

  const remove = useCallback(
    async (targets: Entry[]) => {
      if (!targets.length) return
      const dirs = targets.filter(t => t.kind === 'dir').length
      const ok = await confirm({
        title: targets.length === 1 ? `Delete “${targets[0].name}”?` : `Delete ${targets.length} items?`,
        description:
          dirs > 0 ?
            'Folders are deleted with everything inside them. Deleted items move to the vault’s trash retention.'
          : 'Deleted items move to the vault’s trash retention.',
        confirmLabel: 'Delete',
      })
      if (!ok) return
      let failed = 0
      for (const target of targets) {
        try {
          await source.remove(target.path)
        } catch (error) {
          failed++
          notify.error(error, `Could not delete ${target.name}`)
        }
      }
      setSelected(new Set())
      await refresh()
      if (!failed)
        notify.success(targets.length === 1 ? `Deleted ${targets[0].name}` : `Deleted ${targets.length} items`)
    },
    [refresh, source],
  )

  const transfer = useCallback(
    async (mode: 'move' | 'copy', targets: Entry[], dir: string) => {
      for (const target of targets) {
        const to = joinPath(dir, target.name)
        if (to === target.path) continue
        if (mode === 'move') await source.move(target.path, to)
        else await source.copy(target.path, to)
      }
      setSelected(new Set())
      await refresh(dir)
      notify.success(
        `${mode === 'move' ? 'Moved' : 'Copied'} ${targets.length === 1 ? targets[0].name : `${targets.length} items`}`,
      )
    },
    [refresh, source],
  )

  const entryActions = useCallback(
    (entry: Entry, many: Entry[] = [entry]): MenuEntry[] => {
      const multi = many.length > 1
      const list: MenuEntry[] = []
      if (!multi)
        list.push({
          key: 'open',
          label: entry.kind === 'dir' ? 'Open' : 'Preview',
          icon: entry.kind === 'dir' ? FolderOpenIcon : EyeIcon,
          onSelect: () => open(entry),
          shortcut: '↵',
        })
      if (source.caps.download)
        list.push({
          key: 'download',
          label:
            multi ? `Download ${many.length} items`
            : entry.kind === 'dir' ? 'Download as zip'
            : 'Download',
          icon: DownloadIcon,
          onSelect: () => many.forEach(download),
        })
      if (!multi && source.caps.share && onShare)
        list.push({ key: 'share', label: 'Share link…', icon: ShareNodesIcon, onSelect: () => onShare(entry) })
      if (source.caps.mutate) {
        list.push('separator')
        if (!multi)
          list.push({
            key: 'rename',
            label: 'Rename…',
            icon: PenIcon,
            onSelect: () => setNaming({ mode: 'rename', entry }),
            shortcut: 'F2',
          })
        list.push({
          key: 'move',
          label: 'Move to…',
          icon: ArrowsUpDownLeftRightIcon,
          onSelect: () => setDestination({ mode: 'move', entries: many }),
        })
        list.push({
          key: 'copy',
          label: 'Copy to…',
          icon: CopyIcon,
          onSelect: () => setDestination({ mode: 'copy', entries: many }),
        })
        list.push('separator')
        list.push({
          key: 'delete',
          label: multi ? `Delete ${many.length} items` : 'Delete',
          icon: TrashIcon,
          danger: true,
          onSelect: () => void remove(many),
          shortcut: 'Del',
        })
      }
      return list
    },
    [download, onShare, open, remove, source.caps.download, source.caps.mutate, source.caps.share],
  )

  // ---------- selection & keyboard ----------

  const selectIndex = (index: number, event?: { shiftKey?: boolean; metaKey?: boolean; ctrlKey?: boolean }) => {
    const entry = entries[index]
    if (!entry) return
    setFocus(index)
    if (event?.shiftKey && anchor.current !== null) {
      const [a, b] = [Math.min(anchor.current, index), Math.max(anchor.current, index)]
      setSelected(new Set(entries.slice(a, b + 1).map(e => e.key)))
    } else if (event?.metaKey || event?.ctrlKey) {
      setSelected(prev => {
        const next = new Set(prev)
        if (next.has(entry.key)) next.delete(entry.key)
        else next.add(entry.key)
        return next
      })
      anchor.current = index
    } else {
      setSelected(new Set([entry.key]))
      anchor.current = index
    }
  }

  const toggle = (entry: Entry, index: number) => {
    setFocus(index)
    anchor.current = index
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(entry.key)) next.delete(entry.key)
      else next.add(entry.key)
      return next
    })
  }

  const onKeyDown = (event: React.KeyboardEvent) => {
    if (stale || !entries.length) return
    const cols = view === 'grid' ? gridCols : 1
    const move = (delta: number) => {
      event.preventDefault()
      const index = Math.max(0, Math.min(entries.length - 1, focus + delta))
      selectIndex(index, { shiftKey: event.shiftKey })
      virtualizer.scrollToIndex(view === 'grid' ? Math.floor(index / cols) : index, { align: 'auto' })
    }
    const target = entries[focus]
    switch (event.key) {
      case 'ArrowDown':
        return move(cols)
      case 'ArrowUp':
        return move(-cols)
      case 'ArrowRight':
        return view === 'grid' ? move(1) : undefined
      case 'ArrowLeft':
        return view === 'grid' ? move(-1) : undefined
      case 'Home':
        return move(-entries.length)
      case 'End':
        return move(entries.length)
      case 'Enter':
        if (target) {
          event.preventDefault()
          open(target)
        }
        return
      case 'Backspace':
        // ⌘⌫ deletes, like Finder; plain Backspace goes up a folder.
        if (event.metaKey) {
          if (source.caps.mutate && selectedEntries.length) {
            event.preventDefault()
            void remove(selectedEntries)
          }
          return
        }
        if (current !== '/') {
          event.preventDefault()
          onNavigate(parentOf(current))
        }
        return
      case 'Delete':
        if (source.caps.mutate && selectedEntries.length) {
          event.preventDefault()
          void remove(selectedEntries)
        }
        return
      case 'F2':
        if (source.caps.mutate && target) {
          event.preventDefault()
          setNaming({ mode: 'rename', entry: target })
        }
        return
      case 'Escape':
        setSelected(new Set())
        return
      case 'a':
        if (event.metaKey || event.ctrlKey) {
          event.preventDefault()
          setSelected(new Set(entries.map(e => e.key)))
        }
        return
    }
  }

  // ---------- drag & drop ----------

  const canUpload = source.caps.upload && !stale
  const dropProps =
    canUpload ?
      {
        onDragEnter: (event: React.DragEvent) => {
          if (!event.dataTransfer.types.includes('Files')) return
          event.preventDefault()
          dragDepth.current++
          setDragging(true)
        },
        onDragLeave: (event: React.DragEvent) => {
          if (!event.dataTransfer.types.includes('Files')) return
          dragDepth.current = Math.max(0, dragDepth.current - 1)
          if (!dragDepth.current) setDragging(false)
        },
        onDragOver: (event: React.DragEvent) => {
          if (!event.dataTransfer.types.includes('Files')) return
          event.preventDefault()
          event.dataTransfer.dropEffect = 'copy'
        },
        onDrop: (event: React.DragEvent) => {
          if (!event.dataTransfer.types.includes('Files')) return
          event.preventDefault()
          dragDepth.current = 0
          setDragging(false)
          void collectDropped(event.dataTransfer).then(upload, error =>
            notify.error(error, 'Could not read the dropped files'),
          )
        },
      }
    : {}

  // ---------- virtualization ----------

  const [gridCols, setGridCols] = useState(4)
  const [tileWidth, setTileWidth] = useState(176)
  const [scrollMargin, setScrollMargin] = useState(0)
  useLayoutEffect(() => {
    const el = listRef.current
    if (!el) return
    const measure = () => {
      setScrollMargin(el.getBoundingClientRect().top + window.scrollY)
      const cols = Math.max(2, Math.floor(el.clientWidth / 176))
      setGridCols(cols)
      setTileWidth(el.clientWidth / cols)
    }
    measure()
    const observer = new ResizeObserver(measure)
    observer.observe(el)
    return () => observer.disconnect()
  }, [listing.isPending])

  const rowCount = view === 'grid' ? Math.ceil(entries.length / gridCols) : entries.length
  const virtualizer = useWindowVirtualizer({
    count: rowCount,
    estimateSize: () => (view === 'grid' ? 196 : ROW_HEIGHT),
    overscan: view === 'grid' ? 3 : 12,
    scrollMargin,
  })
  const items = virtualizer.getVirtualItems()
  const firstRow = items[0]?.index ?? 0
  const lastRow = items.length ? items[items.length - 1].index : -1
  const visibleEntries =
    view === 'grid' ?
      entries.slice(firstRow * gridCols, (lastRow + 1) * gridCols)
    : entries.slice(firstRow, lastRow + 1)
  const thumb = useThumbnails(source, visibleEntries, true, thumbnailSizeFor(view, tileWidth))

  const contextEntries =
    menuTarget ?
      selected.has(menuTarget.key) && selectedEntries.length > 1 ?
        entryActions(menuTarget, selectedEntries)
      : entryActions(menuTarget)
    : []

  // ---------- render ----------

  const segments = pathSegments(current)
  const allSelected = entries.length > 0 && selected.size === entries.length

  return (
    <div className={cn('relative', className)} {...dropProps}>
      {/* toolbar (the selection bar overlays it, so selecting never shifts the list under the pointer) */}
      <div className="relative mb-4">
        <div className="flex flex-wrap items-center gap-2">
          {leading}
          <nav aria-label="Folder path" className="flex min-w-0 flex-1 items-center gap-0.5 text-sm">
            <button
              type="button"
              onClick={() => onNavigate('/')}
              className={cn(
                'text-fg-muted hover:bg-surface-2 hover:text-fg inline-flex max-w-[16rem] items-center gap-1.5 rounded-md px-2 py-1',
                !segments.length && 'text-fg font-medium',
              )}>
              <HouseIcon className="size-3.5 shrink-0" aria-hidden />
              <span className={cn('truncate', leading && 'sr-only')}>{source.rootLabel}</span>
            </button>
            {segments.map((segment, index) => {
              const last = index === segments.length - 1
              return (
                <React.Fragment key={index}>
                  <ChevronRightIcon className="text-fg-faint size-3 shrink-0" aria-hidden />
                  <button
                    type="button"
                    aria-current={last ? 'page' : undefined}
                    onClick={() => onNavigate(`/${segments.slice(0, index + 1).join('/')}`)}
                    className={cn(
                      'text-fg-muted hover:bg-surface-2 hover:text-fg max-w-[14rem] truncate rounded-md px-2 py-1',
                      last && 'text-fg font-medium',
                    )}>
                    {segment}
                  </button>
                </React.Fragment>
              )
            })}
            {listing.isFetching ?
              <Spinner className="ml-2 size-3.5" />
            : null}
          </nav>
          <div className="flex items-center gap-1.5">
            <div className="relative hidden sm:block">
              <MagnifyingGlassIcon
                className="text-fg-faint pointer-events-none absolute top-1/2 left-2.5 size-3.5 -translate-y-1/2"
                aria-hidden
              />
              <Input
                value={filter}
                onChange={e => setFilter(e.target.value)}
                placeholder="Filter"
                aria-label="Filter this folder"
                className="h-8 w-40 pl-8"
              />
            </div>
            <IconButton label="Refresh" icon={ArrowsRotateIcon} size="icon-sm" onClick={() => void refresh()} />
            <IconButton
              label={view === 'list' ? 'Grid view' : 'List view'}
              icon={view === 'list' ? Grid2Icon : ListIcon}
              size="icon-sm"
              onClick={() => setView(view === 'list' ? 'grid' : 'list')}
            />
            {source.caps.mutate ?
              <IconButton
                label="New folder"
                icon={FolderPlusIcon}
                size="icon-sm"
                disabled={stale}
                onClick={() => setNaming({ mode: 'mkdir' })}
              />
            : null}
            {source.caps.upload ?
              <DropdownMenu
                label="Upload"
                trigger={
                  <Button variant="primary" size="sm" disabled={stale}>
                    <UploadIcon aria-hidden /> Upload
                  </Button>
                }
                entries={[
                  { key: 'files', label: 'Files…', icon: FileArrowUpIcon, onSelect: () => fileInput.current?.click() },
                  ...(source.caps.folders ?
                    [
                      {
                        key: 'folder',
                        label: 'Folder…',
                        icon: FolderOpenIcon,
                        onSelect: () => folderInput.current?.click(),
                      },
                    ]
                  : []),
                ]}
              />
            : null}
          </div>
          <input
            ref={fileInput}
            type="file"
            multiple
            hidden
            onChange={event => {
              upload(collectPicked(event.target.files))
              event.target.value = ''
            }}
          />
          <input
            ref={folderInput}
            type="file"
            hidden
            {...({ webkitdirectory: '', directory: '' } as Record<string, string>)}
            onChange={event => {
              upload(collectPicked(event.target.files))
              event.target.value = ''
            }}
          />
        </div>
        {/* selection bar */}
        {selectedEntries.length > 0 ?
          <div className="animate-fade-in rounded-card border-accent-line bg-bg-raised absolute inset-0 z-20 flex border shadow-[var(--shadow-pop)] flex-wrap items-center gap-2 overflow-hidden px-3 text-sm">
            <span className="text-fg tabular mr-1 font-medium">{selectedEntries.length} selected</span>
            {source.caps.download ?
              <Button size="sm" variant="ghost" onClick={() => selectedEntries.forEach(download)}>
                <DownloadIcon aria-hidden /> Download
              </Button>
            : null}
            {source.caps.mutate ?
              <>
                {selectedEntries.length === 1 ?
                  <Button
                    size="sm"
                    variant="ghost"
                    onClick={() => setNaming({ mode: 'rename', entry: selectedEntries[0] })}>
                    <PenIcon aria-hidden /> Rename
                  </Button>
                : null}
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setDestination({ mode: 'move', entries: selectedEntries })}>
                  <ArrowsUpDownLeftRightIcon aria-hidden /> Move
                </Button>
                <Button
                  size="sm"
                  variant="ghost"
                  onClick={() => setDestination({ mode: 'copy', entries: selectedEntries })}>
                  <CopyIcon aria-hidden /> Copy
                </Button>
                <Button size="sm" variant="danger" onClick={() => void remove(selectedEntries)}>
                  <TrashIcon aria-hidden /> Delete
                </Button>
              </>
            : null}
            <IconButton
              label="Clear selection"
              icon={XmarkIcon}
              size="icon-sm"
              className="ml-auto"
              onClick={() => setSelected(new Set())}
            />
          </div>
        : null}
      </div>

      {/* body */}
      <div className="panel relative overflow-hidden">
        {view === 'list' ?
          <div className="border-line text-fg-subtle grid grid-cols-[2rem_minmax(0,1fr)_6rem_10rem_2.5rem] items-center gap-3 border-b px-3 py-2 text-xs max-md:grid-cols-[2rem_minmax(0,1fr)_2.5rem]">
            <Checkbox
              aria-label="Select all"
              checked={
                allSelected ? true
                : selected.size ?
                  'indeterminate'
                : false
              }
              onCheckedChange={() => setSelected(allSelected ? new Set() : new Set(entries.map(e => e.key)))}
              disabled={!entries.length || stale}
            />
            {(['name', 'size', 'modified'] as SortKey[]).map(key => (
              <button
                key={key}
                type="button"
                onClick={() => setSort(s => ({ key, dir: s.key === key && s.dir === 'asc' ? 'desc' : 'asc' }))}
                aria-sort={
                  sort.key === key ?
                    sort.dir === 'asc' ?
                      'ascending'
                    : 'descending'
                  : undefined
                }
                className={cn(
                  'hover:text-fg flex items-center gap-1 text-left font-medium capitalize',
                  key !== 'name' && 'max-md:hidden',
                  key === 'size' && 'justify-end',
                )}>
                {key}
                <span aria-hidden className={cn('text-[9px]', sort.key !== key && 'opacity-0')}>
                  {sort.dir === 'asc' ? '▲' : '▼'}
                </span>
              </button>
            ))}
            <span />
          </div>
        : null}

        <ContextMenu entries={contextEntries} onOpenChange={o => !o && setMenuTarget(null)}>
          <div
            ref={listRef}
            role="listbox"
            aria-label={`Contents of ${current === '/' ? source.rootLabel : baseName(current)}`}
            aria-multiselectable="true"
            aria-busy={listing.isFetching || undefined}
            aria-activedescendant={entries[focus] ? `fs-row-${focus}` : undefined}
            tabIndex={0}
            onKeyDown={onKeyDown}
            className={cn(
              'relative min-h-64 outline-none focus-visible:shadow-[inset_0_0_0_1px_var(--accent-line)]',
              stale && 'pointer-events-none opacity-60 transition-opacity',
            )}
            style={{ height: entries.length ? virtualizer.getTotalSize() : undefined }}>
            {listing.isPending ?
              <div className="space-y-2 p-4">
                {Array.from({ length: 6 }, (_, i) => (
                  <div key={i} className="skeleton h-9" style={{ opacity: 1 - i * 0.14 }} />
                ))}
              </div>
            : listing.error && !listing.data ?
              <ErrorState error={listing.error} onRetry={() => void listing.refetch()} />
            : !entries.length ?
              filter ?
                <EmptyState title={`Nothing matches “${filter}”`} />
              : <EmptyState
                  icon={FolderOpenIcon}
                  title={source.caps.list ? 'This folder is empty' : 'Nothing to show'}
                  description={source.caps.upload ? 'Drop files anywhere on this page, or use Upload.' : undefined}
                  action={
                    source.caps.upload ?
                      <Button variant="secondary" onClick={() => fileInput.current?.click()}>
                        <UploadIcon aria-hidden /> Upload files
                      </Button>
                    : undefined
                  }
                />

            : items.map(row => {
                if (view === 'grid') {
                  const start = row.index * gridCols
                  return (
                    <div
                      key={row.key}
                      className="absolute inset-x-0 grid gap-3 px-3 pt-3"
                      style={{
                        transform: `translateY(${row.start - virtualizer.options.scrollMargin}px)`,
                        gridTemplateColumns: `repeat(${gridCols}, minmax(0, 1fr))`,
                      }}>
                      {entries.slice(start, start + gridCols).map((entry, offset) => (
                        <GridTile
                          key={entry.key}
                          id={`fs-row-${start + offset}`}
                          entry={entry}
                          thumb={thumb(entry)}
                          selected={selected.has(entry.key)}
                          focused={focus === start + offset}
                          onClick={event => selectIndex(start + offset, event)}
                          onOpen={() => open(entry)}
                          onContext={() => {
                            setMenuTarget(entry)
                            if (!selected.has(entry.key)) selectIndex(start + offset)
                          }}
                          menu={<RowMenu entries={entryActions(entry)} />}
                        />
                      ))}
                    </div>
                  )
                }
                const entry = entries[row.index]
                return (
                  <Row
                    key={entry.key}
                    id={`fs-row-${row.index}`}
                    entry={entry}
                    thumb={thumb(entry)}
                    selected={selected.has(entry.key)}
                    focused={focus === row.index}
                    top={row.start - virtualizer.options.scrollMargin}
                    onClick={event => selectIndex(row.index, event)}
                    onToggle={() => toggle(entry, row.index)}
                    onOpen={() => open(entry)}
                    onContext={() => {
                      setMenuTarget(entry)
                      if (!selected.has(entry.key)) selectIndex(row.index)
                    }}
                    menu={<RowMenu entries={entryActions(entry)} />}
                  />
                )
              })
            }
          </div>
        </ContextMenu>

        {entries.length ?
          <div className="border-line text-fg-subtle tabular flex items-center justify-between border-t px-4 py-2 text-xs">
            <span>
              {countLabel(entries.filter(e => e.kind === 'dir').length, 'folder')} ·{' '}
              {countLabel(entries.filter(e => e.kind === 'file').length, 'file')}
            </span>
            <span>{formatBytes(entries.reduce((sum, e) => sum + (e.kind === 'file' ? (e.size ?? 0) : 0), 0))}</span>
          </div>
        : null}
      </div>

      {dragging ?
        <div className="animate-fade-in bg-bg/70 pointer-events-none fixed inset-0 z-50 grid place-items-center backdrop-blur-sm">
          <div className="glass-strong rounded-panel border-accent-line flex flex-col items-center gap-3 border-2 border-dashed px-14 py-10 text-center">
            <UploadIcon className="text-accent-text size-8" aria-hidden />
            <p className="text-fg text-base font-medium">Drop to upload</p>
            <p className="text-fg-subtle text-sm">into {current === '/' ? source.rootLabel : baseName(current)}</p>
          </div>
        </div>
      : null}

      {preview ?
        <PreviewSheet
          source={source}
          entry={preview}
          siblings={entries}
          onOpenChange={o => !o && setPreview(null)}
          onSelect={setPreview}
          onDownload={download}
          onShare={onShare}
        />
      : null}

      {naming ?
        <NameDialog
          open={naming !== null}
          onOpenChange={o => !o && setNaming(null)}
          title={naming?.mode === 'rename' ? `Rename ${naming.entry.kind === 'dir' ? 'folder' : 'file'}` : 'New folder'}
          initial={naming?.mode === 'rename' ? naming.entry.name : ''}
          confirmLabel={naming?.mode === 'rename' ? 'Rename' : 'Create'}
          onSubmit={async name => {
            if (naming?.mode === 'rename') {
              if (name === naming.entry.name) return
              await source.rename(naming.entry.path, joinPath(parentOf(naming.entry.path), name))
              notify.success(`Renamed to ${name}`)
            } else {
              await source.mkdir(joinPath(current, name))
            }
            await refresh()
          }}
        />
      : null}

      {destination ?
        <DestinationDialog
          open
          onOpenChange={o => !o && setDestination(null)}
          source={source}
          title={`${destination.mode === 'move' ? 'Move' : 'Copy'} ${destination.entries.length === 1 ? `“${destination.entries[0].name}”` : `${destination.entries.length} items`}`}
          confirmLabel={destination.mode === 'move' ? 'Move' : 'Copy'}
          startPath={current}
          disabledPaths={destination.entries.filter(e => e.kind === 'dir').map(e => e.path)}
          onSubmit={dir => transfer(destination.mode, destination.entries, dir)}
        />
      : null}
    </div>
  )
}

const RowMenu = ({ entries }: { entries: MenuEntry[] }) => (
  <DropdownMenu
    label="Item actions"
    entries={entries}
    trigger={
      <button
        type="button"
        tabIndex={-1}
        aria-label="Item actions"
        className="text-fg-subtle hover:bg-surface-3 hover:text-fg grid size-8 place-items-center rounded-md opacity-100 transition data-[state=open]:opacity-100 pointer-fine:opacity-0 pointer-fine:group-hover:opacity-100 pointer-fine:group-aria-selected:opacity-100">
        <EllipsisIcon className="size-4" aria-hidden />
      </button>
    }
  />
)

interface ItemProps {
  id: string
  entry: Entry
  thumb: string | null
  selected: boolean
  focused: boolean
  onClick: (event: React.MouseEvent) => void
  onOpen: () => void
  onContext: () => void
  menu: React.ReactNode
}

const Thumb = ({ entry, thumb, large }: { entry: Entry; thumb: string | null; large?: boolean }) =>
  thumb ?
    // eslint-disable-next-line @next/next/no-img-element -- authenticated thumbnail route
    <img
      src={thumb}
      alt=""
      loading="lazy"
      decoding="async"
      className={cn('shrink-0 rounded object-cover', large ? 'h-28 w-full' : 'size-8')}
    />
  : <span className={cn('bg-surface-2 grid shrink-0 place-items-center rounded', large ? 'h-28 w-full' : 'size-8')}>
      <FileIcon entry={entry} className={large ? 'size-9' : undefined} />
    </span>

const Row = React.memo(function Row({
  id,
  entry,
  thumb,
  selected,
  focused,
  top,
  onClick,
  onToggle,
  onOpen,
  onContext,
  menu,
}: ItemProps & { top: number; onToggle: () => void }) {
  return (
    <div
      id={id}
      role="option"
      aria-selected={selected}
      onClick={onClick}
      onDoubleClick={onOpen}
      onContextMenu={onContext}
      className={cn(
        'group border-line/50 hover:bg-surface-2 absolute inset-x-0 grid cursor-default select-none grid-cols-[2rem_minmax(0,1fr)_6rem_10rem_2.5rem] items-center gap-3 border-b px-3 text-sm transition-colors max-md:grid-cols-[2rem_minmax(0,1fr)_2.5rem]',
        selected && 'bg-accent-soft hover:bg-accent-soft',
        focused && 'shadow-[inset_2px_0_0_var(--accent)]',
      )}
      style={{ height: ROW_HEIGHT, transform: `translateY(${top}px)` }}>
      <Checkbox
        tabIndex={-1}
        aria-label={`Select ${entry.name}`}
        checked={selected}
        onClick={event => event.stopPropagation()}
        onCheckedChange={onToggle}
        className={cn(
          'pointer-fine:opacity-0 pointer-fine:group-hover:opacity-100',
          selected && 'pointer-fine:opacity-100',
        )}
      />
      <div className="flex min-w-0 items-center gap-3">
        <Thumb entry={entry} thumb={thumb} />
        <div className="min-w-0">
          <button
            type="button"
            tabIndex={-1}
            onClick={event => {
              // The name works like a link; the row's own double-click handles the second click of a double-click.
              if (event.detail > 1) return
              event.stopPropagation()
              onOpen()
            }}
            className="text-fg hover:text-accent-text inline-block max-w-full truncate text-left align-middle">
            {entry.name}
          </button>
          <div className="text-fg-subtle truncate text-xs md:hidden">
            {entry.kind === 'dir' ? 'Folder' : formatBytes(entry.size)}
            {entry.modified ? ` · ${formatRelative(entry.modified)}` : ''}
          </div>
        </div>
      </div>
      <span className="text-fg-subtle tabular text-right max-md:hidden">
        {entry.kind === 'dir' ?
          entry.fileCount !== undefined ?
            countLabel(entry.fileCount + (entry.dirCount ?? 0), 'item')
          : '—'
        : formatBytes(entry.size)}
      </span>
      <span
        className="text-fg-subtle truncate max-md:hidden"
        title={entry.modified ? formatDateTime(entry.modified) : undefined}>
        {entry.modified ? formatRelative(entry.modified) : '—'}
      </span>
      <div onClick={event => event.stopPropagation()}>{menu}</div>
    </div>
  )
})

const GridTile = React.memo(function GridTile({
  id,
  entry,
  thumb,
  selected,
  focused,
  onClick,
  onOpen,
  onContext,
  menu,
}: ItemProps) {
  return (
    <div
      id={id}
      role="option"
      aria-selected={selected}
      onClick={onClick}
      onDoubleClick={onOpen}
      onContextMenu={onContext}
      className={cn(
        'group rounded-card border-line bg-surface-1 hover:border-line-strong hover:bg-surface-2 relative flex h-[184px] cursor-default select-none flex-col gap-2 border p-2 transition-colors',
        selected && 'border-accent-line bg-accent-soft hover:border-accent-line hover:bg-accent-soft',
        focused && 'shadow-[0_0_0_1px_var(--accent)]',
      )}>
      <Thumb entry={entry} thumb={thumb} large />
      <div className="flex min-w-0 items-start gap-1">
        <div className="min-w-0 flex-1">
          <button
            type="button"
            tabIndex={-1}
            onClick={event => {
              if (event.detail > 1) return
              event.stopPropagation()
              onOpen()
            }}
            className="text-fg hover:text-accent-text inline-block max-w-full truncate text-left text-sm">
            {entry.name}
          </button>
          <div className="text-fg-subtle tabular truncate text-xs">
            {entry.kind === 'dir' ? 'Folder' : formatBytes(entry.size)}
          </div>
        </div>
        <div onClick={event => event.stopPropagation()}>{menu}</div>
      </div>
    </div>
  )
})
