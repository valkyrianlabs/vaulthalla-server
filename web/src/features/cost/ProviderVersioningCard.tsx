'use client'

import React from 'react'
import Link from 'next/link'
import { Section } from '@/features/cost/bits'
import type { VaultLite } from '@/features/cost/queries'

// Provider versioning costs are per vault and per bucket, each an estimate with its own basis and confidence, so
// they are not added up here: this links to each S3 vault's recovery cost panel instead.
export const ProviderVersioningCard = ({ vaults, pending }: { vaults: VaultLite[]; pending: boolean }) => (
  <Section
    id="provider-versioning"
    title="Provider versioning"
    description="What keeping object versions in S3 buckets costs or would cost. Each vault's panel shows its own estimate; they aren't summed because each has its own basis and confidence.">
    <div className="panel px-5 py-4" data-testid="cost-provider-versioning">
      {pending ?
        <div className="skeleton h-10" />
      : vaults.length ?
        <ul className="flex flex-wrap gap-2">
          {vaults.map(v => (
            <li key={v.id}>
              <Link
                href={`/vaults/${v.id}/sync#recovery-costs`}
                className="rounded-control border-line text-fg hover:border-accent-line inline-flex h-8 items-center border px-3 text-sm transition-colors">
                {v.name}
              </Link>
            </li>
          ))}
        </ul>
      : <p className="text-fg-subtle text-sm">
          No S3 vaults. Provider versioning applies to vaults backed by a bucket.
        </p>
      }
    </div>
  </Section>
)
