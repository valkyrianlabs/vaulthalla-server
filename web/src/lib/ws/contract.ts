import { notify } from '@/components/ui/Toast'
import type { WsClient } from '@/lib/ws/client'
import { WS_CONTRACT_HASH } from '@/util/generated/wsContract'

// The console's ws types are generated from the daemon's usage module (core/usage). After every connect, ask the
// daemon which contract it was built from; a different one means it was upgraded (or rolled back) under this open
// page, and commands may not have the shape this page expects. Say so once per server contract, never block.
let notifiedFor: string | null = null

export const checkServerContract = async (client: WsClient) => {
  try {
    const { ws_hash } = await client.send('meta.contract.get', null, { timeoutMs: 10_000 })
    if (!ws_hash || ws_hash === WS_CONTRACT_HASH || notifiedFor === ws_hash) return
    notifiedFor = ws_hash
    notify.info('The Vaulthalla server was upgraded', 'Reload this page to load the matching console.')
  } catch {
    // Daemons before the contract answer "Unknown command"; a dropped socket retries on the next connect.
  }
}
