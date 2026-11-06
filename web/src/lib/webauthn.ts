// WebAuthn L3 JSON forms in and out of the browser (#357). The daemon speaks PublicKeyCredential{Creation,Request}
// OptionsJSON and the toJSON() forms of the result (base64url everywhere). Browsers with
// PublicKeyCredential.parseCreationOptionsFromJSON / toJSON use them; this is the small polyfill for the rest.
// Pure (no DOM types at module level), so it runs under `node --test`.

export const bytesToBase64url = (bytes: ArrayBuffer | ArrayBufferView): string => {
  const view = bytes instanceof ArrayBuffer ? new Uint8Array(bytes) : new Uint8Array(bytes.buffer, bytes.byteOffset, bytes.byteLength)
  let binary = ''
  for (const b of view) binary += String.fromCharCode(b)
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const base64urlToBytes = (text: string): Uint8Array<ArrayBuffer> => {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new Error('not base64url')
  const padded = text.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (text.length % 4)) % 4)
  const binary = atob(padded)
  const out = new Uint8Array(new ArrayBuffer(binary.length))
  for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i)
  return out
}

interface DescriptorJson {
  type: 'public-key'
  id: string
  transports?: string[]
}

export interface CreationOptionsJson {
  rp: { id: string; name: string }
  user: { id: string; name: string; displayName: string }
  challenge: string
  pubKeyCredParams: { type: 'public-key'; alg: number }[]
  timeout: number
  excludeCredentials: DescriptorJson[]
  authenticatorSelection: { residentKey: string; requireResidentKey: boolean; userVerification: string }
  attestation: string
  extensions: { credProps: boolean }
}

export interface RequestOptionsJson {
  challenge: string
  rpId: string
  timeout: number
  userVerification: string
  allowCredentials: DescriptorJson[]
}

const descriptor = (d: DescriptorJson) => ({
  type: d.type,
  id: base64urlToBytes(d.id),
  ...(d.transports?.length ? { transports: d.transports } : {}),
})

// The options navigator.credentials.create() takes (binary fields decoded).
export const creationOptionsFromJson = (json: CreationOptionsJson) => ({
  rp: json.rp,
  user: { ...json.user, id: base64urlToBytes(json.user.id) },
  challenge: base64urlToBytes(json.challenge),
  pubKeyCredParams: json.pubKeyCredParams,
  timeout: json.timeout,
  excludeCredentials: json.excludeCredentials.map(descriptor),
  authenticatorSelection: json.authenticatorSelection,
  attestation: json.attestation,
  extensions: json.extensions,
})

// The options navigator.credentials.get() takes.
export const requestOptionsFromJson = (json: RequestOptionsJson) => ({
  challenge: base64urlToBytes(json.challenge),
  rpId: json.rpId,
  timeout: json.timeout,
  userVerification: json.userVerification,
  allowCredentials: json.allowCredentials.map(descriptor),
})

// A browser credential, as far as the conversion reads it (PublicKeyCredential with either response kind).
export interface CredentialLike {
  id: string
  rawId: ArrayBuffer
  type: string
  authenticatorAttachment?: string | null
  response: {
    clientDataJSON: ArrayBuffer
    attestationObject?: ArrayBuffer
    getTransports?: () => string[]
    authenticatorData?: ArrayBuffer
    signature?: ArrayBuffer
    userHandle?: ArrayBuffer | null
  }
  getClientExtensionResults?: () => { credProps?: { rk?: boolean } }
  toJSON?: () => unknown
}

export interface RegistrationJson {
  id: string
  rawId: string
  type: 'public-key'
  response: { clientDataJSON: string; attestationObject: string; transports?: string[] }
  authenticatorAttachment?: string | null
  clientExtensionResults?: { credProps?: { rk?: boolean } }
}

export interface AssertionJson {
  id: string
  rawId: string
  type: 'public-key'
  response: { clientDataJSON: string; authenticatorData: string; signature: string; userHandle?: string | null }
  authenticatorAttachment?: string | null
  clientExtensionResults?: { credProps?: { rk?: boolean } }
}

const extensions = (c: CredentialLike) => {
  const credProps = c.getClientExtensionResults?.().credProps
  return credProps && typeof credProps.rk === 'boolean' ? { credProps: { rk: credProps.rk } } : {}
}

// Only the members the daemon reads: toJSON() also carries derived fields (publicKey, ...) that it ignores, and a
// hand-built object is the same in every browser.
export const registrationToJson = (c: CredentialLike): RegistrationJson => {
  const r = c.response
  if (!r.attestationObject) throw new Error('not a registration')
  const transports = r.getTransports?.() ?? []
  return {
    id: c.id,
    rawId: bytesToBase64url(c.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: bytesToBase64url(r.clientDataJSON),
      attestationObject: bytesToBase64url(r.attestationObject),
      ...(transports.length ? { transports } : {}),
    },
    authenticatorAttachment: c.authenticatorAttachment ?? null,
    clientExtensionResults: extensions(c),
  }
}

export const assertionToJson = (c: CredentialLike): AssertionJson => {
  const r = c.response
  if (!r.authenticatorData || !r.signature) throw new Error('not an assertion')
  return {
    id: c.id,
    rawId: bytesToBase64url(c.rawId),
    type: 'public-key',
    response: {
      clientDataJSON: bytesToBase64url(r.clientDataJSON),
      authenticatorData: bytesToBase64url(r.authenticatorData),
      signature: bytesToBase64url(r.signature),
      userHandle: r.userHandle ? bytesToBase64url(r.userHandle) : null,
    },
    authenticatorAttachment: c.authenticatorAttachment ?? null,
    clientExtensionResults: extensions(c),
  }
}

// What a ceremony that didn't produce a credential means to the person: they closed the prompt, or the browser
// refused (wrong origin, no authenticator). Never a server failure.
export const ceremonyMessage = (error: unknown): string => {
  const name = error && typeof error === 'object' && 'name' in error ? String((error as { name: unknown }).name) : ''
  if (name === 'NotAllowedError') return 'The passkey prompt was closed or timed out. Try again.'
  if (name === 'InvalidStateError') return 'This passkey is already registered to your account.'
  if (name === 'SecurityError') return 'This browser refused the passkey for this address. Ask an administrator to check the passkey settings.'
  if (name === 'NotSupportedError') return 'This browser or authenticator does not support the passkey settings this server needs.'
  return error instanceof Error && error.message ? error.message : 'The passkey could not be used.'
}

export const webauthnSupported = (): boolean =>
  typeof window !== 'undefined' && typeof window.PublicKeyCredential === 'function' && !!navigator.credentials
