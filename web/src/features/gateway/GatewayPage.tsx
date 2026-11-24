'use client'

import { replaceQuery } from '@/lib/url'
import React, { useState } from 'react'
import dynamic from 'next/dynamic'
import { useSearchParams } from 'next/navigation'
import { useIsFetching } from '@tanstack/react-query'
import { PageHeader } from '@/components/ui/Panel'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/State'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/Tabs'
import { ArrowsRotateIcon, PlusIcon } from '@/components/ui/icons'
import type { GatewayCredential, UpstreamProfile } from '@/features/gateway/model'
import { refreshGateway, useGatewayCredentials, useGatewayPerms, useGatewayStatus } from '@/features/gateway/queries'
import { ServicePanel } from '@/features/gateway/ServicePanel'
import { CredentialsTab } from '@/features/gateway/CredentialsTab'
import { BucketsTab, BudgetsTab, ClientSetupTab } from '@/features/gateway/tabs'
import { UpstreamProfilesTab } from '@/features/gateway/UpstreamProfilesTab'
import type { BucketDialogKind } from '@/features/gateway/BucketDialogs'

// Editors load only when opened.
const CreateCredentialDialog = dynamic(() => import('@/features/gateway/CreateCredentialDialog'), { ssr: false })
const CredentialSheet = dynamic(() => import('@/features/gateway/CredentialSheet'), { ssr: false })
const BucketDialog = dynamic(() => import('@/features/gateway/BucketDialogs'), { ssr: false })
const UpstreamProfileDialog = dynamic(() => import('@/features/gateway/UpstreamProfileDialog'), { ssr: false })

const TABS = ['keys', 'buckets', 'upstream', 'budgets', 'clients'] as const
type Tab = (typeof TABS)[number]

export const GatewayPage = () => {
  const can = useGatewayPerms()
  const params = useSearchParams()
  const requested = params.get('tab') as Tab | null
  const tab: Tab = requested && TABS.includes(requested) ? requested : 'keys'
  const status = useGatewayStatus(can.view)
  const credentials = useGatewayCredentials(can.any)
  const [creating, setCreating] = useState(false)
  const [openId, setOpenId] = useState<number | null>(null)
  const [bucketDialog, setBucketDialog] = useState<BucketDialogKind | null>(null)
  // The profile being edited; { profile: null } is a new one.
  const [profileDialog, setProfileDialog] = useState<{ profile: UpstreamProfile | null } | null>(null)
  const fetching = useIsFetching({ predicate: q => String(q.queryKey[0]).startsWith('s3.gateway.') })
  const open = openId !== null ? ((credentials.data ?? []).find(c => c.id === openId) ?? null) : null

  const setTab = (next: string) => replaceQuery({ tab: next })
  const openCredential = (c: GatewayCredential) => setOpenId(c.id)

  const header = (
    <PageHeader
      title="S3 gateway"
      description="Let S3 clients (aws, rclone, mc, backup tools) use Vaulthalla vaults as buckets, with scoped keys and per-key budgets."
      actions={
        can.any ?
          <>
            <Button variant="secondary" onClick={() => void refreshGateway()} loading={fetching > 0}>
              {fetching > 0 ? null : <ArrowsRotateIcon aria-hidden />}
              Refresh
            </Button>
            <Button variant="primary" data-testid="s3-gateway-open-create-credential" onClick={() => setCreating(true)}>
              <PlusIcon aria-hidden />
              Create key
            </Button>
          </>
        : null
      }
    />
  )

  if (!can.any)
    return (
      <>
        {header}
        <EmptyState
          className="panel"
          title="You don't have access to this"
          description="The S3 gateway needs an admin.s3_gateway permission."
        />
      </>
    )

  return (
    <>
      {header}
      <div data-testid="s3-gateway-section-service" className="mb-6">
        {can.view ?
          <ServicePanel query={status} />
        : null}
      </div>

      <Tabs value={tab} onValueChange={setTab}>
        <TabsList aria-label="S3 gateway sections">
          <TabsTrigger value="keys">Keys</TabsTrigger>
          <TabsTrigger value="buckets">Buckets</TabsTrigger>
          <TabsTrigger value="upstream">Upstream</TabsTrigger>
          <TabsTrigger value="budgets">Budgets</TabsTrigger>
          <TabsTrigger value="clients">Client setup</TabsTrigger>
        </TabsList>
        <TabsContent value="keys" data-testid="s3-gateway-section-credentials">
          <CredentialsTab onCreate={() => setCreating(true)} onOpen={openCredential} />
        </TabsContent>
        <TabsContent value="buckets">
          <BucketsTab onDialog={setBucketDialog} />
        </TabsContent>
        <TabsContent value="upstream">
          <UpstreamProfilesTab onEdit={profile => setProfileDialog({ profile })} />
        </TabsContent>
        <TabsContent value="budgets">
          <BudgetsTab onOpenCredential={openCredential} />
        </TabsContent>
        <TabsContent value="clients">
          <ClientSetupTab status={status.data ?? null} />
        </TabsContent>
      </Tabs>

      {creating ?
        <CreateCredentialDialog onClose={() => setCreating(false)} onCreated={() => setTab('keys')} />
      : null}
      {open ?
        <CredentialSheet credential={open} onClose={() => setOpenId(null)} />
      : null}
      {bucketDialog ?
        <BucketDialog kind={bucketDialog} onClose={() => setBucketDialog(null)} />
      : null}
      {profileDialog ?
        <UpstreamProfileDialog profile={profileDialog.profile} onClose={() => setProfileDialog(null)} />
      : null}
    </>
  )
}
