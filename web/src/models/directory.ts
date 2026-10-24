import { FSEntry, FSEntryWire, normalizeFsEntryTimestamps } from '@/models/fsEntry'

export interface IDirectory extends FSEntry {
  size_bytes: number
  file_count: number
  subdirectory_count: number
  last_modified: Date
}

export class Directory implements IDirectory {
  id: number = 0
  vault_id: number = 0
  parent_id?: number
  name: string = ''
  created_by: number = 0
  created_at: number = 0
  updated_at: number = 0
  last_modified_by?: number
  path?: string
  size_bytes: number = 0
  file_count: number = 0
  subdirectory_count: number = 0
  last_modified: Date = new Date()
  metadata_version?: string

  constructor(data?: FSEntryWire<Partial<IDirectory>>) {
    if (data) Object.assign(this, normalizeFsEntryTimestamps(data))
  }
}
