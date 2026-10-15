'use client'

import React from 'react'
import { DASH, formatBytes, formatInt } from '@/lib/format'
import { Badge } from '@/components/ui/Badge'
import { DefinitionList } from '@/components/ui/Panel'
import type { AdmissionReport } from '@/models/upstream'

const versioningLabel: Record<string, string> = {
  unversioned: 'Off',
  enabled: 'Enabled',
  suspended: 'Suspended',
  unknown: 'Unknown',
}

// The daemon's read-only admission report for adopting an existing bucket (bounded LIST + a few HEADs).
export const AdmissionReportView = ({ report }: { report: AdmissionReport }) => (
  <div className="space-y-4 text-sm">
    {report.blockers.length ?
      <div role="alert" className="rounded-control border-danger-line bg-danger-soft text-danger border px-3 py-2">
        <p className="font-medium">This bucket can’t be adopted:</p>
        <ul className="mt-1 list-disc pl-5">
          {report.blockers.map(b => (
            <li key={b}>{b}</li>
          ))}
        </ul>
      </div>
    : null}
    {report.warnings.length ?
      <div className="rounded-control border-warn-line bg-warn-soft text-warn border px-3 py-2">
        <ul className="list-disc pl-5">
          {report.warnings.map(w => (
            <li key={w}>{w}</li>
          ))}
        </ul>
      </div>
    : null}
    <DefinitionList
      items={[
        [
          'Objects scanned',
          <span key="o" className="tabular">
            {formatInt(report.objects_scanned)}
            {report.truncated ? ' (more not scanned)' : ''}
          </span>,
        ],
        [
          'Size scanned',
          <span key="b" className="tabular">
            {formatBytes(report.bytes_scanned)}
          </span>,
        ],
        [
          'Sampled objects',
          <span key="s" className="tabular">
            {formatInt(report.sampled)}: {formatInt(report.sampled_vaulthalla_encrypted)} Vaulthalla-encrypted,{' '}
            {formatInt(report.sampled_plaintext)} plain
          </span>,
        ],
        [
          'Vaulthalla manifest',
          report.has_vaulthalla_manifest ?
            <Badge key="m" tone="warn">
              Present{report.manifest_vault_id ? ` (vault ${report.manifest_vault_id})` : ''}
            </Badge>
          : <span key="m" className="text-fg-subtle">
              None
            </span>,
        ],
        ['Versioning', <span key="v">{versioningLabel[report.versioning] ?? report.versioning}</span>],
        [
          'Object lock',
          <span key="l">
            {report.object_lock === null || report.object_lock === undefined ?
              'Unknown'
            : report.object_lock ?
              'On'
            : 'Off'}
          </span>,
        ],
        [
          'Recommended',
          <span key="r">
            {report.recommended_encrypt_upstream === null || report.recommended_encrypt_upstream === undefined ?
              DASH
            : report.recommended_encrypt_upstream ?
              'Encrypt objects before upload'
            : 'Keep objects as plain files (the bucket already holds plain data)'}
          </span>,
        ],
      ]}
    />
    {report.sample_keys.length ?
      <details className="rounded-card border-line border">
        <summary className="text-fg-muted cursor-pointer px-3 py-2 text-xs select-none">Sample keys</summary>
        <ul className="border-line text-fg-subtle max-h-40 overflow-y-auto border-t px-3 py-2 font-mono text-xs">
          {report.sample_keys.map(k => (
            <li key={k} className="truncate">
              {k}
            </li>
          ))}
        </ul>
      </details>
    : null}
    <p className="text-fg-subtle text-xs">
      Adoption never deletes, overwrites or re-encrypts objects already in the bucket; they stay as they are upstream.
      Only what Vaulthalla writes afterwards follows the vault’s encryption setting.
    </p>
  </div>
)

export default AdmissionReportView
