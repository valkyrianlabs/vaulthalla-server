// Step-up (#359; core auth/stepup/StepUp.hpp, MFA design note section 5.4). A sensitive command (its contract entry
// carries step_up: <family>) may refuse with data.code step_up_required and the data below; the console confirms the
// person with auth.stepup.begin / auth.stepup.finish (a passkey, or the password with an authenticator code, or for an
// account without MFA the password alone) and resends the request. The server decides everything: which methods count,
// how long a grant lasts, and that a grant for one session, family or target never serves another.

export type StepUpFamily =
  | 'keys'
  | 'device.trust'
  | 'account.credentials'
  | 'identity.admin'
  | 'secrets'
  | 'settings'
  | 'data.destroy'

export type StepUpMethod = 'webauthn' | 'password_totp' | 'password'

export interface StepUpRequest {
  family: StepUpFamily
  target: string | null
  methods: StepUpMethod[] // empty: nothing this session can answer with (a device, an agent, or no factor for it)
  max_age_seconds: number
}

const FAMILIES: readonly StepUpFamily[] = [
  'keys',
  'device.trust',
  'account.credentials',
  'identity.admin',
  'secrets',
  'settings',
  'data.destroy',
]
const METHODS: readonly StepUpMethod[] = ['webauthn', 'password_totp', 'password']

// The refusal's data, when it is a step-up refusal (a narrow guard: refusal data is not in the generated contract).
export const readStepUp = (code: string | undefined, data: unknown): StepUpRequest | null => {
  if (code !== 'step_up_required' || !data || typeof data !== 'object') return null
  const r = data as Record<string, unknown>
  if (!FAMILIES.includes(r.family as StepUpFamily)) return null
  const methods = Array.isArray(r.methods) ? r.methods.filter((m): m is StepUpMethod => METHODS.includes(m as StepUpMethod)) : []
  return {
    family: r.family as StepUpFamily,
    target: typeof r.target === 'string' ? r.target : null,
    methods,
    max_age_seconds: typeof r.max_age_seconds === 'number' ? r.max_age_seconds : 300,
  }
}

// What the person is confirming, in the console's words.
export const STEP_UP_ACTION: Readonly<Record<StepUpFamily, string>> = {
  keys: 'Handle vault encryption keys',
  'device.trust': 'Trust a device',
  'account.credentials': 'Change sign-in credentials',
  'identity.admin': 'Change accounts, roles or groups',
  secrets: 'Change stored secrets and credentials',
  settings: 'Change server settings',
  'data.destroy': 'Permanently remove data',
}

// Target-bound families confirm one exact action, once; the others hold for the grant window.
export const isTargetBound = (family: StepUpFamily): boolean =>
  family === 'keys' || family === 'device.trust' || family === 'data.destroy'

export const stepUpWindowText = (request: StepUpRequest): string => {
  if (isTargetBound(request.family)) return 'This confirms this one change.'
  const minutes = Math.max(1, Math.round(request.max_age_seconds / 60))
  return `Similar changes in the next ${minutes} minute${minutes === 1 ? '' : 's'} won’t ask again.`
}
