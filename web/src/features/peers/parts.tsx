'use client'

import React, { useState } from 'react'
import { IconButton } from '@/components/ui/IconButton'
import { notify } from '@/components/ui/Toast'
import { CheckIcon, CopyIcon, TriangleExclamationIcon } from '@/components/ui/icons'
import { errorMessage, WsError } from '@/lib/ws/errors'
import { cn } from '@/util/cn'
import { refusalText } from '@/features/peers/model'

// Small pieces the Linked servers page and its dialogs share.

export const CopyButton = ({ text, label, className }: { text: string; label: string; className?: string }) => {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      notify.info('Copy it manually', 'Clipboard access isn’t available here.')
    }
  }
  return <IconButton label={copied ? 'Copied' : label} icon={copied ? CheckIcon : CopyIcon} size="icon-sm" className={cn('size-7', className)} onClick={copy} />
}

// A server refusal with its reason: the daemon's words and its data.code (e.g. peer_forbidden), never swallowed.
export const PeerError = ({ error, fallback, className }: { error: unknown; fallback: string; className?: string }) => {
  if (!error) return null
  const { message, code } = refusalText(
    error instanceof WsError ? { message: error.message, code: error.code } : { message: errorMessage(error, fallback) },
    fallback,
  )
  return (
    <p
      role="alert"
      data-testid="peer-error"
      className={cn('flex items-start gap-2 rounded-control border border-danger-line bg-danger-soft px-3 py-2 text-sm text-danger', className)}>
      <TriangleExclamationIcon className="mt-0.5 size-4 shrink-0" aria-hidden />
      <span className="min-w-0 break-words">
        {message}
        {code ? (
          <code className="ml-1.5 font-mono text-xs opacity-80" data-testid="peer-error-code">
            ({code})
          </code>
        ) : null}
      </span>
    </p>
  )
}
