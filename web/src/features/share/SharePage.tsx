'use client'

import React, { useEffect, useMemo, useRef, useState } from 'react'
import NextImage from 'next/image'
import { useParams, useRouter } from 'next/navigation'
import { cn } from '@/util/cn'
import { Button } from '@/components/ui/Button'
import { Field, Input } from '@/components/ui/Field'
import { EmptyState, InlineError } from '@/components/ui/State'
import { Spinner } from '@/components/ui/Spinner'
import { Badge } from '@/components/ui/Badge'
import { BanIcon, CircleCheckIcon, ClockIcon, EnvelopeIcon, LockIcon, UploadIcon, FolderOpenIcon, FileArrowUpIcon } from '@/components/ui/icons'
import { formatBytes, formatDateTime } from '@/lib/format'
import { FileBrowser } from '@/features/files/FileBrowser'
import { shareSource } from '@/features/files/source'
import { normalizePath } from '@/features/files/entries'
import { collectDropped, collectPicked } from '@/features/files/drop'
import { startUpload, useTransfers } from '@/features/files/transfers'
import { TransfersButton } from '@/features/files/TransfersButton'
import { notify } from '@/components/ui/Toast'
import { confirmEmailChallenge, openShare, shareApi, startEmailChallenge, useShareSession } from '@/features/share/shareSession'
import { shareOperations } from '@/util/shareOperations'
import Logo from '@/public/vaulthalla-logo.png'

const sharePath = (token: string, path: string) => {
  const encoded = normalizePath(path).split('/').filter(Boolean).map(encodeURIComponent).join('/')
  return `/share/${encodeURIComponent(token)}${encoded ? `/${encoded}` : ''}`
}

// The anonymous recipient experience: shared primitives and the same file browser, without the console shell.
export function SharePage({ token }: { token: string }) {
  const router = useRouter()
  const params = useParams<{ path?: string[] }>()
  const segments = params.path
  const path = useMemo(() => normalizePath((segments ?? []).map(s => decodeURIComponent(s)).join('/')), [segments])
  const status = useShareSession(state => state.status)
  const share = useShareSession(state => state.share)
  const error = useShareSession(state => state.error)

  useEffect(() => {
    shareApi.connect()
    void openShare(token)
    return () => shareApi.close()
  }, [token])

  const source = useMemo(() => (share && status === 'ready' ? shareSource(token, share) : null), [share, status, token])
  const ops = useMemo(() => new Set(share ? shareOperations(share.effective_allowed_ops ?? share.allowed_ops) : []), [share])
  const uploadOnly = Boolean(share && share.target_type === 'directory' && ops.has('upload') && !ops.has('list'))

  return (
    <div className="flex min-h-dvh flex-col">
      <header className="glass sticky top-0 z-40 flex h-14 items-center gap-3 border-x-0 border-t-0 px-4 sm:px-6">
        <NextImage src={Logo} alt="" width={28} height={28} className="size-7" priority />
        <div className="min-w-0 flex-1">
          <div className="truncate text-sm font-semibold text-fg">{source?.rootLabel ?? 'Shared with you'}</div>
          <div className="truncate text-xs text-fg-subtle">Shared securely with Vaulthalla</div>
        </div>
        {share?.expires_at ? (
          <Badge tone="neutral" className="hidden sm:inline-flex">
            <ClockIcon className="size-3" aria-hidden /> Expires {formatDateTime(share.expires_at)}
          </Badge>
        ) : null}
        <TransfersButton />
      </header>

      <main className="mx-auto w-full max-w-[1200px] flex-1 px-4 py-6 sm:px-6">
        {status === 'idle' || status === 'opening' ? (
          <div className="grid min-h-[50vh] place-items-center">
            <div className="flex flex-col items-center gap-3 text-sm text-fg-subtle">
              <Spinner className="size-7" />
              Opening share…
            </div>
          </div>
        ) : status === 'email_required' ? (
          <EmailGate />
        ) : status === 'revoked' ? (
          <EmptyState icon={BanIcon} title="This link was revoked" description="Ask the person who shared it for a new link." />
        ) : status === 'expired' ? (
          <EmptyState icon={ClockIcon} title="This link has expired" description="Ask the person who shared it for a new link." />
        ) : status === 'error' || !source ? (
          <EmptyState icon={LockIcon} title="This link can’t be opened" description={error ?? 'It may be mistyped, revoked or expired.'} />
        ) : uploadOnly ? (
          <Dropbox source={source} />
        ) : (
          <FileBrowser source={source} path={path} onNavigate={next => router.push(sharePath(token, next))} />
        )}
      </main>
    </div>
  )
}

const EmailGate = () => {
  const challengeId = useShareSession(state => state.challengeId)
  const [email, setEmail] = useState('')
  const [code, setCode] = useState('')
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState<unknown>(null)

  const run = async (fn: () => Promise<void>) => {
    setBusy(true)
    setError(null)
    try {
      await fn()
    } catch (err) {
      setError(err)
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="mx-auto mt-10 max-w-sm">
      <div className="mb-6 flex flex-col items-center text-center">
        <div className="mb-4 grid size-12 place-items-center rounded-2xl border border-accent-line bg-accent-soft text-accent-text">
          <EnvelopeIcon className="size-5" aria-hidden />
        </div>
        <h1 className="text-lg font-semibold text-fg">Confirm your email</h1>
        <p className="mt-1 text-sm text-fg-subtle">
          {challengeId ? 'Enter the code we sent to your inbox.' : 'This share is limited to specific people. We’ll send you a one-time code.'}
        </p>
      </div>
      <form
        className="glass space-y-4 rounded-panel p-5"
        onSubmit={event => {
          event.preventDefault()
          void run(() => (challengeId ? confirmEmailChallenge(code.trim()) : startEmailChallenge(email.trim())))
        }}>
        {challengeId ? (
          <Field label="Code" htmlFor="share-code">
            <Input id="share-code" inputMode="numeric" autoComplete="one-time-code" autoFocus value={code} onChange={e => setCode(e.target.value)} required />
          </Field>
        ) : (
          <Field label="Email" htmlFor="share-email">
            <Input id="share-email" type="email" autoComplete="email" autoFocus value={email} onChange={e => setEmail(e.target.value)} required />
          </Field>
        )}
        <InlineError error={error} />
        <Button type="submit" variant="primary" className="w-full" loading={busy}>
          {challengeId ? 'Verify' : 'Send code'}
        </Button>
        {challengeId ? (
          <button type="button" className="w-full text-center text-xs text-fg-subtle hover:text-fg" onClick={() => void run(() => startEmailChallenge(email.trim()))}>
            Send a new code
          </button>
        ) : null}
      </form>
    </div>
  )
}

// Upload-only folder: recipients can add files but never see what's already there.
const Dropbox = ({ source }: { source: ReturnType<typeof shareSource> }) => {
  const input = useRef<HTMLInputElement>(null)
  const [over, setOver] = useState(false)
  const tasks = useTransfers(state => state.tasks).filter(t => t.kind === 'upload' && t.sourceKey === source.key)
  const upload = (files: ReturnType<typeof collectPicked>) => {
    if (!files.length) return
    try {
      startUpload(source, '/', files)
    } catch (err) {
      notify.error(err)
    }
  }
  return (
    <div className="mx-auto max-w-2xl">
      <h1 className="mb-1 text-xl font-semibold text-fg">Send files</h1>
      <p className="mb-5 text-sm text-fg-subtle">Files you add go straight to {source.rootLabel}. You won’t be able to see other people’s uploads.</p>
      <div
        onDragOver={event => {
          event.preventDefault()
          setOver(true)
        }}
        onDragLeave={() => setOver(false)}
        onDrop={event => {
          event.preventDefault()
          setOver(false)
          void collectDropped(event.dataTransfer).then(upload)
        }}
        className={cn(
          'flex flex-col items-center justify-center gap-3 rounded-panel border-2 border-dashed border-line-strong bg-surface-1 px-6 py-16 text-center transition-colors',
          over && 'border-accent bg-accent-soft',
        )}>
        <UploadIcon className="size-8 text-accent-text" aria-hidden />
        <p className="text-base font-medium text-fg">Drop files here</p>
        <Button variant="primary" onClick={() => input.current?.click()}>
          <FileArrowUpIcon aria-hidden /> Choose files
        </Button>
        <input
          ref={input}
          type="file"
          multiple
          hidden
          onChange={event => {
            upload(collectPicked(event.target.files))
            event.target.value = ''
          }}
        />
      </div>
      {tasks.length ? (
        <ul className="panel mt-5 divide-y divide-line/60">
          {tasks.map(task => (
            <li key={task.id} className="flex items-center gap-3 px-4 py-3 text-sm">
              {task.status === 'done' ? (
                <CircleCheckIcon className="size-4 text-ok" aria-hidden />
              ) : task.status === 'failed' ? (
                <BanIcon className="size-4 text-danger" aria-hidden />
              ) : (
                <Spinner className="size-4" />
              )}
              <span className="min-w-0 flex-1 truncate text-fg" title={task.failures?.join('\n')}>
                {task.label}
                {task.note && task.status !== 'done' && task.status !== 'failed' ? <span className="block truncate text-xs text-fg-subtle">{task.note}</span> : null}
              </span>
              <span className={cn('text-xs text-fg-subtle tabular', task.status === 'failed' && 'text-danger')}>
                {task.status === 'failed' ? task.error : task.status === 'done' ? `${formatBytes(task.bytesTotal)} sent` : `${formatBytes(task.bytesDone)} / ${formatBytes(task.bytesTotal)}`}
              </span>
            </li>
          ))}
        </ul>
      ) : (
        <p className="mt-5 flex items-center justify-center gap-2 text-xs text-fg-faint">
          <FolderOpenIcon className="size-3.5" aria-hidden /> Nothing sent yet
        </p>
      )}
    </div>
  )
}
