import { FSEntry, FSEntryWire, normalizeFsEntryTimestamps } from '@/models/fsEntry'

// Server-authoritative preview plan attached to every file entry (`preview` in the file JSON). The web renders from
// it and only falls back to its own MIME rules when an older daemon omits it.
export type PreviewKind = 'rendered_image' | 'native_media' | 'client_model' | 'text_document' | 'derived_artifact' | 'unsupported'

// `preview` = lossy server renders only (JPEG thumbnails/pages); `download` = original bytes or a full-fidelity derivative.
export type PreviewCapability = 'preview' | 'download'

// Known renderers; the server may add more, so unknown strings are kept and rendered as "no preview".
export type PreviewRendererName =
  | 'image'
  | 'pdf'
  | 'svg'
  | 'image-native'
  | 'video'
  | 'audio'
  | 'model:glb'
  | 'model:gltf'
  | 'model:stl'
  | 'model:obj'
  | 'derived:step-glb'
  | 'text'
  | 'markdown'
  | 'none'

export interface IPreviewPlan {
  kind: PreviewKind
  renderer: PreviewRendererName | (string & {})
  requires: PreviewCapability
  thumbnail: boolean
  // Derived artifact kind(s) the renderer can ask `/preview/derived` for (e.g. "model-glb", "transcode-h264-720").
  derived?: string | string[] | null
  pages?: number | null
}

export interface IFile extends FSEntry {
  size_bytes: number
  mime_type?: string
  preview?: IPreviewPlan
  // The strong ETag /download/content serves for the current bytes (quotes included). Absent from older daemons.
  content_version?: string
}

export class File implements IFile {
  id: number = 0
  vault_id: number = 0
  parent_id?: number
  name: string = ''
  created_by: number = 0
  created_at: number = 0
  updated_at: number = 0
  last_modified_by?: number
  size_bytes: number = 0
  path?: string
  mime_type?: string
  preview?: IPreviewPlan
  content_version?: string
  metadata_version?: string

  constructor(data?: FSEntryWire<Partial<IFile>>) {
    if (data) Object.assign(this, normalizeFsEntryTimestamps(data))
  }
}

export interface IFileUpload {
  vault_id: number
  path: string
  size?: number
}
