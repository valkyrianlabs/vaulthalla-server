'use client'

import React, { useCallback, useEffect, useRef, useState } from 'react'
import { Button } from '@/components/ui/Button'
import { Spinner } from '@/components/ui/Spinner'
import { ArrowsRotateIcon, CircleExclamationIcon, CircleInfoIcon, FileAudioIcon, LockIcon } from '@/components/ui/icons'
import { Notice, Stage } from '@/features/files/preview/Frame'
import { describeStatus, errorText, isAbort, pollDerived, PreviewHttpError } from '@/features/files/preview/http'
import type { RendererProps } from '@/features/files/preview/types'

type Kind = 'video' | 'audio'

type Failure = { kind: 'codec' | 'http' | 'network' | 'convert'; title: string; message: string }

// The default browser-friendly transcode when the plan only says "a transcode exists".
const DEFAULT_TRANSCODE = 'transcode-h264-720'

export const VideoRenderer = (props: RendererProps) => <MediaRenderer {...props} kind="video" />
export const AudioRenderer = (props: RendererProps) => <MediaRenderer {...props} kind="audio" />

// Pausing, dropping src and calling load() makes the browser close the ranged connection right away.
const release = (element: HTMLMediaElement) => {
  element.pause()
  element.removeAttribute('src')
  element.load()
}

// Native <video>/<audio> over the Range-capable original (`/download/content`, inline). Never autoplays. When the
// browser can't decode the format, offers the download and, if the plan lists a transcode, a server conversion
// (`/preview/derived`), then plays the converted stream instead.
function MediaRenderer({ source, entry, plan, onDownload, kind }: RendererProps & { kind: Kind }) {
  // The latest media element; kept after React detaches it so the unmount cleanup can still release it.
  const media = useRef<HTMLMediaElement | null>(null)
  const attach = useCallback((element: HTMLMediaElement | null) => {
    if (!element) return
    if (media.current && media.current !== element) release(media.current)
    media.current = element
  }, [])
  const original = source.contentUrl(entry, 'inline')
  const [src, setSrc] = useState(original)
  const [failure, setFailure] = useState<Failure | null>(null)
  const [converting, setConverting] = useState<number | null>(null)
  const conversion = useRef<AbortController | null>(null)
  const transcode = kind === 'video' ? plan.derived.find(d => d.startsWith('transcode')) : undefined
  const transcodeKind = transcode === 'transcode' ? DEFAULT_TRANSCODE : transcode
  const converted = src !== original

  // A hint only: canPlayType('') is common for containers the browser can still play (e.g. Matroska with VP9).
  const [doubtful] = useState(() => {
    if (!entry.mime || typeof document === 'undefined') return false
    return document.createElement(kind).canPlayType(entry.mime) === ''
  })

  // Stop playback and drop the connection when the file changes or the sheet closes.
  useEffect(
    () => () => {
      conversion.current?.abort()
      if (media.current) release(media.current)
    },
    [],
  )

  const onError = async () => {
    const code = media.current?.error?.code
    if (code === undefined || code === MediaError.MEDIA_ERR_ABORTED) return
    // An HTTP refusal also surfaces as "source not supported": ask the server before blaming the codec.
    try {
      const head = await fetch(src, { method: 'HEAD', credentials: 'same-origin', cache: 'no-store' })
      if (!head.ok) {
        setFailure({ kind: 'http', title: `This ${kind === 'video' ? 'video' : 'audio file'} could not be loaded`, message: describeStatus(head.status) })
        return
      }
    } catch {
      setFailure({ kind: 'network', title: 'The connection to the server dropped', message: 'Check your connection and try again.' })
      return
    }
    if (code === MediaError.MEDIA_ERR_NETWORK) {
      setFailure({ kind: 'network', title: 'Playback was interrupted', message: 'The connection dropped while loading. Try again.' })
      return
    }
    setFailure({
      kind: 'codec',
      title: converted ? 'The converted version can’t play either' : 'This format can’t play in your browser',
      message:
        converted ? 'Download the file to play it in a desktop player.'
        : transcodeKind ? 'Download it, or convert it on the server for playback here.'
        : 'Download it to play it in a desktop player.',
    })
  }

  const convert = async () => {
    if (!transcodeKind) return
    conversion.current?.abort()
    const controller = new AbortController()
    conversion.current = controller
    setConverting(0)
    try {
      const url = source.derivedUrl(entry, transcodeKind)
      const response = await pollDerived(url, { signal: controller.signal, probe: true, onQueued: setConverting })
      void response.body?.cancel().catch(() => undefined)
      setFailure(null)
      setSrc(url)
    } catch (error) {
      if (isAbort(error)) return
      const helper = error instanceof PreviewHttpError && error.code === 'converter_unavailable'
      setFailure({ kind: 'convert', title: helper ? 'Server-side conversion isn’t available' : 'The conversion failed', message: errorText(error) })
    } finally {
      if (conversion.current === controller) {
        conversion.current = null
        setConverting(null)
      }
    }
  }

  const retry = () => {
    setFailure(null)
    media.current?.load()
  }

  if (converting !== null)
    return (
      <Stage>
        <div className="flex flex-col items-center gap-3 px-6 py-14 text-center text-sm text-fg-subtle" role="status" aria-live="polite">
          <Spinner className="size-6" />
          <span>
            Converting for playback{converting > 4000 ? ` · ${Math.round(converting / 1000)} s` : '…'}
            <span className="mt-1 block text-xs text-fg-faint">Long videos can take a while. You can keep this open.</span>
          </span>
          <Button variant="ghost" size="sm" onClick={() => conversion.current?.abort()}>
            Cancel
          </Button>
        </div>
      </Stage>
    )

  if (failure)
    return (
      <div data-testid="media-fallback">
        <Notice
          icon={failure.kind === 'http' && failure.message.includes('permission') ? LockIcon : CircleExclamationIcon}
          title={failure.title}
          description={failure.message}
          onDownload={onDownload}
          action={
            failure.kind === 'network' ?
              <Button variant="secondary" onClick={retry}>
                <ArrowsRotateIcon aria-hidden /> Try again
              </Button>
            : (failure.kind === 'codec' || failure.kind === 'convert') && transcodeKind && !converted ?
              <Button variant="primary" onClick={() => void convert()}>
                <ArrowsRotateIcon aria-hidden /> Convert for playback
              </Button>
            : null
          }
        />
      </div>
    )

  return (
    <div className="flex flex-col gap-2">
      {kind === 'video' ?
        <Stage>
          <video
            ref={attach}
            src={src}
            controls
            preload="metadata"
            playsInline
            onError={() => void onError()}
            className="max-h-[65dvh] w-full bg-black"
            data-testid="preview-video">
            Your browser can’t play this video.
          </video>
        </Stage>
      : <Stage className="min-h-0 gap-6 px-6 py-10">
          <FileAudioIcon className="size-12 text-pink" aria-hidden />
          <audio ref={attach} src={src} controls preload="metadata" onError={() => void onError()} className="w-full max-w-md" data-testid="preview-audio">
            Your browser can’t play this audio file.
          </audio>
        </Stage>
      }
      {doubtful && !converted ?
        <p className="flex items-center gap-1.5 text-xs text-fg-subtle">
          <CircleInfoIcon className="size-3.5" aria-hidden />
          Your browser may not support {entry.mime}. If it doesn’t play, download it
          {transcodeKind ? ' or convert it for playback' : ''}.
        </p>
      : null}
      {converted ? <p className="text-xs text-fg-subtle">Playing a browser-friendly copy converted on the server.</p> : null}
    </div>
  )
}
