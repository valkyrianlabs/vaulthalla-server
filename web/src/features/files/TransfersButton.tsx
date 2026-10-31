'use client'

import React, { useEffect, useRef } from 'react'
import { Popover } from '@/components/ui/Popover'
import { cn } from '@/util/cn'
import { formatBytes } from '@/lib/format'
import { Button } from '@/components/ui/Button'
import { Meter } from '@/components/ui/Stat'
import { CircleCheckIcon, CircleExclamationIcon, DownloadIcon, UploadIcon, XmarkIcon, ArrowsUpDownLeftRightIcon } from '@/components/ui/icons'
import { cancelTask, isActive, useTransfers, type TransferTask } from '@/features/files/transfers'

// Bytes/second over the task's lifetime; good enough for an ETA without per-tick sampling.
const rate = (task: TransferTask) => {
  const seconds = (Date.now() - task.startedAt) / 1000
  return seconds > 1 ? task.bytesDone / seconds : 0
}

const TaskRow = ({ task }: { task: TransferTask }) => {
  const active = isActive(task)
  const ratio = task.bytesTotal ? task.bytesDone / task.bytesTotal : null
  const speed = rate(task)
  const eta = speed > 0 && task.bytesTotal ? (task.bytesTotal - task.bytesDone) / speed : null
  const Icon = task.status === 'failed' ? CircleExclamationIcon : task.status === 'done' ? CircleCheckIcon : task.kind === 'upload' ? UploadIcon : DownloadIcon
  return (
    <li className="px-3.5 py-3">
      <div className="flex items-start gap-2.5">
        <Icon
          aria-hidden
          className={cn('mt-0.5 size-4 shrink-0 text-fg-subtle', task.status === 'failed' && 'text-danger', task.status === 'done' && 'text-ok', active && 'text-accent-text')}
        />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm text-fg" title={task.label}>
            {task.label}
          </div>
          <div className="truncate text-xs text-fg-subtle">
            {task.status === 'failed'
              ? task.error
              : task.status === 'cancelled'
                ? 'Cancelled'
                : task.kind === 'upload' && active
                  ? `${formatBytes(task.bytesDone)} of ${formatBytes(task.bytesTotal)}${task.filesTotal > 1 ? ` · ${task.filesDone}/${task.filesTotal} files` : ''}${
                      task.status === 'finishing' ? ' · finishing' : eta !== null ? ` · ${eta < 60 ? `${Math.ceil(eta)}s` : `${Math.ceil(eta / 60)} min`} left` : ''
                    }`
                  : task.status === 'done' && task.kind === 'upload'
                    ? `${formatBytes(task.bytesTotal)} uploaded ${task.detail}`
                    : task.detail}
          </div>
          {active && task.note ? <div className="truncate text-xs text-fg-subtle">{task.note}</div> : null}
          {task.status === 'failed' && task.failures?.length ? (
            <ul className="mt-1 space-y-0.5 text-xs text-fg-subtle">
              {task.failures.slice(0, 3).map(line => (
                <li key={line} className="truncate" title={line}>
                  {line}
                </li>
              ))}
              {task.failures.length > 3 ? <li>and {task.failures.length - 3} more</li> : null}
            </ul>
          ) : null}
          {active && task.kind === 'upload' ? <Meter ratio={ratio} className="mt-2" label={`${task.label} progress`} /> : null}
        </div>
        {active && task.kind === 'upload' ? (
          <button type="button" aria-label={`Cancel ${task.label}`} onClick={() => cancelTask(task.id)} className="rounded p-1 text-fg-subtle hover:bg-surface-3 hover:text-fg">
            <XmarkIcon className="size-3.5" aria-hidden />
          </button>
        ) : null}
      </div>
    </li>
  )
}

export const TransfersButton = () => {
  const tasks = useTransfers(state => state.tasks)
  const open = useTransfers(state => state.open)
  const setOpen = useTransfers(state => state.setOpen)
  const clearFinished = useTransfers(state => state.clearFinished)
  const active = tasks.filter(isActive)
  const failed = tasks.some(t => t.status === 'failed')
  const totalBytes = active.reduce((s, t) => s + t.bytesTotal, 0)
  const doneBytes = active.reduce((s, t) => s + t.bytesDone, 0)
  const ratio = totalBytes ? doneBytes / totalBytes : 0

  // Re-render active tasks once a second so speed/ETA stay current.
  const [, tick] = React.useReducer((n: number) => n + 1, 0)
  const ticking = useRef<ReturnType<typeof setInterval> | null>(null)
  useEffect(() => {
    if (active.length && !ticking.current) ticking.current = setInterval(tick, 1000)
    if (!active.length && ticking.current) {
      clearInterval(ticking.current)
      ticking.current = null
    }
  }, [active.length])

  if (!tasks.length) return null

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      className="w-[min(24rem,calc(100vw-1rem))]"
      trigger={
        <button
          type="button"
          aria-label={active.length ? `${active.length} transfers in progress` : 'Transfers'}
          className="relative grid size-9 place-items-center rounded-control text-fg-muted transition-colors hover:bg-surface-2 hover:text-fg">
          {active.length ? (
            <svg viewBox="0 0 36 36" className="absolute inset-0.5 size-8 -rotate-90" aria-hidden>
              <circle cx="18" cy="18" r="15" fill="none" stroke="currentColor" strokeOpacity="0.15" strokeWidth="2.5" />
              <circle
                cx="18"
                cy="18"
                r="15"
                fill="none"
                stroke="var(--accent)"
                strokeWidth="2.5"
                strokeLinecap="round"
                strokeDasharray={`${Math.max(0.03, ratio) * 94.2} 94.2`}
                className="transition-[stroke-dasharray] duration-500"
              />
            </svg>
          ) : null}
          <ArrowsUpDownLeftRightIcon className="size-4 rotate-45" aria-hidden />
          {failed ? <span className="absolute top-1.5 right-1.5 size-2 rounded-full bg-danger" aria-hidden /> : null}
        </button>
      }>

          <div className="flex items-center justify-between border-b border-line px-3.5 py-2.5">
            <span className="text-sm font-medium text-fg">Transfers</span>
            {tasks.length > active.length ? (
              <Button size="sm" variant="ghost" onClick={clearFinished}>
                Clear finished
              </Button>
            ) : null}
          </div>
          <ul className="max-h-96 divide-y divide-line/60 overflow-y-auto scrollbar-thin">
            {tasks.map(task => (
              <TaskRow key={task.id} task={task} />
            ))}
          </ul>
            </Popover>
  )
}
