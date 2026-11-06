'use client'

import React, { useState } from 'react'
import { Spinner } from '@/components/ui/Spinner'
import { CircleExclamationIcon } from '@/components/ui/icons'
import { Notice, Stage } from '@/features/files/preview/Frame'
import type { RendererProps } from '@/features/files/preview/types'

// Small enough to ship with the sheet itself: no nested chunk for the common case.

// `image`: the server's lossy JPEG render (Preview capability).
export const ImageRenderer = ({ source, entry }: RendererProps) => <Img src={source.previewUrl(entry, 1024)} alt={entry.name} />

// `svg` / `image-native`: the original bytes (Download capability). SVG inside <img> never runs scripts, and the
// server adds a sandbox CSP to inline SVG responses as well.
export const NativeImageRenderer = ({ source, entry }: RendererProps) => <Img src={source.contentUrl(entry, 'inline')} alt={entry.name} />

const Img = ({ src, alt }: { src: string; alt: string }) => {
  const [state, setState] = useState<'loading' | 'ready' | 'error'>('loading')
  if (state === 'error') return <Notice icon={CircleExclamationIcon} title="This image could not be loaded" description="It may have been moved, or the server refused it." />
  return (
    <Stage>
      {state === 'loading' ? <Spinner className="absolute" label="Loading image" /> : null}
      {/* eslint-disable-next-line @next/next/no-img-element -- authenticated preview route, not optimizable */}
      <img
        src={src}
        alt={alt}
        onLoad={() => setState('ready')}
        onError={() => setState('error')}
        className="max-h-[60dvh] w-full object-contain"
        data-testid="preview-image"
      />
    </Stage>
  )
}
