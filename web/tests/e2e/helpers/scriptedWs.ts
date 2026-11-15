import { test, type Page } from '@playwright/test'

// Scripted answers on the console socket (page.routeWebSocket), shared by the specs that prove the console's own rules
// against any daemon (devices.spec.ts, cloud.spec.ts). Offline (VAULTHALLA_E2E_OFFLINE=1) no daemon is needed: a dummy
// `refresh` cookie passes the middleware, auth.refresh signs in a scripted user and every command the spec doesn't
// script is refused. Online, unscripted commands reach the real daemon and only the session user's role is patched to
// a super admin when asked (UI gating only; the daemon still decides).

export const OFFLINE = process.env.VAULTHALLA_E2E_OFFLINE === '1' || process.env.VAULTHALLA_E2E_OFFLINE === 'true'

export type Frame = { command: string; payload: Record<string, unknown> | null; requestId: string }
// `errorData` joins `code` in the refusal's data (a step-up refusal carries its family and methods there).
export type Answer = { data?: unknown; error?: string; code?: string; errorData?: Record<string, unknown> }

export const NOW = Math.floor(Date.now() / 1000)
const SUPER_ADMIN_PERMISSIONS = ['admin.identities.admins.delete', 'admin.vaults.admin.remove', 'admin.keys.encryption.rotate']

export const superAdminRole = (role: Record<string, unknown> | undefined) => ({
  ...(role ?? {}),
  id: (role?.id as number | undefined) ?? 1,
  name: 'super_admin',
  permissions: [
    ...(((role?.permissions as { qualified: string }[] | undefined) ?? []).filter(p => !SUPER_ADMIN_PERMISSIONS.includes(p.qualified))),
    ...SUPER_ADMIN_PERMISSIONS.map(qualified => ({ qualified, value: true })),
  ],
})

// `role`: a super admin, a plain user, or a user whose admin role holds exactly these permission bits.
export type ScriptedRole = boolean | string[]

const adminRole = (role: ScriptedRole) =>
  role === true ? superAdminRole(undefined)
  : role === false ? { id: 2, name: 'user', permissions: [] }
  : { id: 3, name: 'scripted', permissions: role.map(qualified => ({ qualified, value: true })) }

export const offlineUser = (role: ScriptedRole) => ({
  id: 7,
  name: 'e2e-user',
  email: 'e2e@example.invalid',
  permissions: {},
  created_at: new Date((NOW - 86_400 * 30) * 1000).toISOString(),
  last_login: new Date(NOW * 1000).toISOString(),
  is_active: true,
  admin_role: adminRole(role),
  vault_roles: [],
})

export const reply = (frame: Frame, a: Answer) =>
  JSON.stringify(
    a.error ?
      { command: frame.command, requestId: frame.requestId, status: 'ERROR', error: a.error, data: { ...a.errorData, code: a.code } }
    : { command: frame.command, requestId: frame.requestId, status: 'OK', data: a.data },
  )

// Scripts the commands `owns` claims and records every frame of theirs the console sent; an owned command `answer`
// returns nothing for is refused `invalid` ("not scripted").
export const scriptWs = async (
  page: Page,
  owns: (command: string) => boolean,
  answer: (frame: Frame) => Answer | undefined,
  { superAdmin = false as ScriptedRole } = {},
) => {
  const sent: Frame[] = []
  if (OFFLINE) {
    const base = new URL(test.info().project.use.baseURL ?? 'http://127.0.0.1:3000')
    await page.context().addCookies([{ name: 'refresh', value: 'e2e-offline', url: base.origin }])
  }
  await page.routeWebSocket(
    url => url.pathname === '/ws',
    ws => {
      const server = OFFLINE ? null : ws.connectToServer()
      const refreshes = new Set<string>()
      ws.onMessage(message => {
        let frame: Frame | null = null
        if (typeof message === 'string') {
          try {
            frame = JSON.parse(message)
          } catch {
            frame = null
          }
        }
        if (frame && owns(frame.command)) {
          sent.push(frame)
          ws.send(reply(frame, answer(frame) ?? { error: 'not scripted', code: 'invalid' }))
          return
        }
        if (!server) {
          if (frame?.command === 'auth.refresh')
            ws.send(JSON.stringify({ ...JSON.parse(reply(frame, { data: { user: offlineUser(superAdmin) } })), token: 'e2e-token' }))
          else if (frame) ws.send(reply(frame, { error: 'Unknown command (offline e2e)', code: 'denied' }))
          return
        }
        if (frame?.command === 'auth.refresh' || frame?.command === 'auth.login') refreshes.add(frame.requestId)
        server.send(message)
      })
      server?.onMessage(message => {
        if (superAdmin === true && typeof message === 'string' && refreshes.size) {
          try {
            const frame = JSON.parse(message)
            if (refreshes.has(frame.requestId) && frame.data?.user) {
              refreshes.delete(frame.requestId)
              frame.data.user.admin_role = superAdminRole(frame.data.user.admin_role)
              message = JSON.stringify(frame)
            }
          } catch {
            // not JSON: pass through
          }
        }
        ws.send(message)
      })
    },
  )
  return sent
}

export const count = (sent: Frame[], command: string) => sent.filter(f => f.command === command).length
