'use client'

import React, { useCallback, useEffect, useState } from 'react'
import dynamic from 'next/dynamic'
import { Spinner } from '@/components/ui/Spinner'
import { CircleExclamationIcon, CubeIcon } from '@/components/ui/icons'
import { formatBytes } from '@/lib/format'
import { parentOf } from '@/features/files/entries'
import { Notice, Stage } from '@/features/files/preview/Frame'
import { describeStatus, errorText, isAbort, pollDerived, PreviewHttpError, readBytes } from '@/features/files/preview/http'
import type { RendererProps } from '@/features/files/preview/types'
// Type-only (erased): the viewer module itself is only ever loaded through the dynamic import below.
import type { ResolveInit } from '@/features/files/preview/ModelViewer'

// The 3D engine lives only in ModelViewer (and preview/model/**). This loader is the only way in, and it runs only
// after the model bytes are in hand, so no other preview ever downloads the engine.
const ModelViewer = dynamic(() => import('@/features/files/preview/ModelViewer'), {
  ssr: false,
  loading: () => (
    <Stage className="h-[60dvh]">
      <Spinner className="size-6" label="Loading 3D viewer" />
    </Stage>
  ),
})

type Format = 'glb' | 'gltf' | 'stl' | 'obj'

// The client holds the whole model (and its GPU buffers) in memory; refuse anything larger up front.
export const MAX_MODEL_BYTES = 512 * 1024 ** 2

const FORMATS: Record<string, Format> = { 'model:glb': 'glb', 'model:gltf': 'gltf', 'model:stl': 'stl', 'model:obj': 'obj', 'derived:step-glb': 'glb' }

type State =
  | { phase: 'converting'; elapsed: number }
  | { phase: 'loading'; loaded: number; total: number | null }
  | { phase: 'ready'; data: ArrayBuffer; format: Format }
  | { phase: 'error'; title: string; message: string }

// Resolves a glTF/OBJ side-file URI against the model's folder. Only plain relative references are followed, and
// never above the vault (or share) root; the server authorizes every fetch again.
export const resolveSibling = (baseDir: string, uri: string): string => {
  if (/^[a-z][a-z0-9+.-]*:/i.test(uri) || uri.startsWith('//')) throw new Error(`External resource refused: ${uri.slice(0, 80)}`)
  let decoded: string
  try {
    decoded = decodeURIComponent(uri.split(/[?#]/)[0])
  } catch {
    throw new Error(`Malformed resource reference: ${uri.slice(0, 80)}`)
  }
  decoded = decoded.replace(/\\/g, '/')
  if (decoded.startsWith('/')) throw new Error(`Absolute resource paths aren’t followed: ${decoded.slice(0, 80)}`)
  const parts = baseDir.split('/').filter(Boolean)
  for (const part of decoded.split('/')) {
    if (!part || part === '.') continue
    if (part === '..') {
      if (!parts.length) throw new Error('A resource reference points outside the shared folder.')
      parts.pop()
    } else parts.push(part)
  }
  if (!parts.length) throw new Error(`Empty resource reference: ${uri.slice(0, 80)}`)
  return `/${parts.join('/')}`
}

const numberStat = (stats: Record<string, unknown>, key: string) => (typeof stats[key] === 'number' && Number.isFinite(stats[key]) ? (stats[key] as number) : null)

export default function ModelRenderer({ source, entry, plan, onDownload }: RendererProps) {
  const [state, setState] = useState<State>({ phase: 'loading', loaded: 0, total: entry.size })
  const [stats, setStats] = useState<Record<string, unknown> | null>(null)
  const format = FORMATS[plan.renderer]
  const derivedKind = plan.renderer.startsWith('derived:') ? (plan.derived.find(kind => kind.startsWith('model-')) ?? 'model-glb') : null

  useEffect(() => {
    if (!format) {
      setState({ phase: 'error', title: 'This model format isn’t supported', message: `The server suggested “${plan.renderer}”, which this console doesn’t know.` })
      return
    }
    if (!derivedKind && entry.size !== null && entry.size > MAX_MODEL_BYTES) {
      setState({ phase: 'error', title: 'This model is too large to open here', message: `Models over ${formatBytes(MAX_MODEL_BYTES)} can’t be opened in the browser. Download it instead.` })
      return
    }
    const controller = new AbortController()
    void (async () => {
      try {
        let response: Response
        if (derivedKind) {
          setState({ phase: 'converting', elapsed: 0 })
          response = await pollDerived(source.derivedUrl({ id: entry.id, path: entry.path }, derivedKind), {
            signal: controller.signal,
            onQueued: elapsed => setState({ phase: 'converting', elapsed }),
          })
        } else {
          response = await fetch(source.contentUrl({ id: entry.id, path: entry.path }, 'inline'), { credentials: 'same-origin', signal: controller.signal })
          if (!response.ok) throw new PreviewHttpError(response.status, 'http', describeStatus(response.status, 'this model'))
        }
        setState({ phase: 'loading', loaded: 0, total: null })
        const data = await readBytes(response, MAX_MODEL_BYTES, (loaded, total) => setState({ phase: 'loading', loaded, total }))
        setState({ phase: 'ready', data, format })
      } catch (error) {
        if (isAbort(error)) return
        const converter = error instanceof PreviewHttpError && error.code === 'converter_unavailable'
        setState({
          phase: 'error',
          title: converter ? 'The 3D converter isn’t installed' : derivedKind ? 'This model could not be converted' : 'This model could not be loaded',
          message: errorText(error),
        })
      }
    })()
    return () => controller.abort()
  }, [source, entry.id, entry.path, entry.size, format, derivedKind, plan.renderer])

  // Side files (glTF buffers/textures, OBJ materials) come from the same folder through the same authorized route.
  // The viewer aborts `signal` when it closes (or the load fails) and caps the bytes left for the model as a whole.
  const resolveResource = useCallback(
    async (uri: string, { signal, maxBytes, onProgress }: ResolveInit): Promise<ArrayBuffer> => {
      const path = resolveSibling(parentOf(entry.path), uri)
      const response = await fetch(source.contentUrl(path, 'inline'), { credentials: 'same-origin', signal })
      if (!response.ok) {
        void response.body?.cancel().catch(() => undefined)
        throw new Error(`${uri}: ${describeStatus(response.status, 'this resource')}`)
      }
      try {
        return await readBytes(response, Math.min(maxBytes, MAX_MODEL_BYTES), loaded => onProgress(loaded))
      } catch (error) {
        if (error instanceof PreviewHttpError && error.code === 'too_large') throw new RangeError(`${uri} is over the model’s size budget`)
        throw error
      }
    },
    [source, entry.path],
  )

  const onStats = useCallback((value: unknown) => {
    if (value && typeof value === 'object') setStats(value as Record<string, unknown>)
  }, [])
  const onError = useCallback((error: unknown) => {
    setState({ phase: 'error', title: 'This model could not be rendered', message: errorText(error) })
  }, [])

  if (state.phase === 'error')
    return <Notice icon={state.title.includes('converter') ? CubeIcon : CircleExclamationIcon} title={state.title} description={state.message} onDownload={onDownload} />

  if (state.phase !== 'ready')
    return (
      <Stage className="h-[60dvh]">
        <div className="flex flex-col items-center gap-3 text-sm text-fg-subtle" role="status" aria-live="polite">
          <Spinner className="size-6" />
          {state.phase === 'converting' ?
            <span>
              Converting for 3D preview{state.elapsed > 4000 ? ` · ${Math.round(state.elapsed / 1000)} s` : '…'}
              <span className="mt-1 block text-xs text-fg-faint">Large assemblies can take a few minutes.</span>
            </span>
          : <span className="tabular">
              Loading model
              {state.loaded > 0 ? ` · ${formatBytes(state.loaded)}${state.total ? ` of ${formatBytes(state.total)}` : ''}` : '…'}
            </span>
          }
          {state.phase === 'loading' && state.total ?
            <div className="h-1 w-48 overflow-hidden rounded-full bg-surface-3" aria-hidden>
              <div className="h-full bg-accent transition-[width]" style={{ width: `${Math.min(100, (state.loaded / state.total) * 100)}%` }} />
            </div>
          : null}
        </div>
      </Stage>
    )

  const triangles = stats ? numberStat(stats, 'triangles') : null
  const vertices = stats ? numberStat(stats, 'vertices') : null
  const meshes = stats ? numberStat(stats, 'meshes') : null

  return (
    <div className="flex flex-col gap-2">
      <Stage className="block h-[60dvh]" data-model-viewer="">
        <ModelViewer data={state.data} format={state.format} fileName={entry.name} resolveResource={resolveResource} onStats={onStats} onError={onError} />
      </Stage>
      {triangles !== null || vertices !== null || meshes !== null ?
        <p className="tabular text-xs text-fg-subtle" data-testid="model-stats">
          {[
            meshes !== null ? `${meshes.toLocaleString()} mesh${meshes === 1 ? '' : 'es'}` : null,
            triangles !== null ? `${triangles.toLocaleString()} triangles` : null,
            vertices !== null ? `${vertices.toLocaleString()} vertices` : null,
          ]
            .filter(Boolean)
            .join(' · ')}
        </p>
      : <p className="text-xs text-fg-faint">Drag to orbit, right-drag to pan, scroll to zoom.</p>}
    </div>
  )
}
