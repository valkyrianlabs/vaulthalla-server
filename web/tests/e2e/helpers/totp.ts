import { createHmac } from 'node:crypto'

// RFC 6238 (SHA-1, 6 digits, 30 s) computed in the test with node:crypto, the way an authenticator app does.

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'

export const base32Decode = (text: string) => {
  const clean = text.replace(/[\s=]/g, '').toUpperCase()
  let bits = 0
  let value = 0
  const out: number[] = []
  for (const c of clean) {
    const v = ALPHABET.indexOf(c)
    if (v < 0) throw new Error(`not base32: ${c}`)
    value = (value << 5) | v
    bits += 5
    if (bits >= 8) {
      bits -= 8
      out.push((value >>> bits) & 0xff)
    }
  }
  return Buffer.from(out)
}

export const totpStep = (at = Date.now()) => Math.floor(at / 1000 / 30)

export const totpCode = (secretBase32: string, step = totpStep()) => {
  const counter = Buffer.alloc(8)
  counter.writeBigUInt64BE(BigInt(step))
  const mac = createHmac('sha1', base32Decode(secretBase32)).update(counter).digest()
  const offset = mac[mac.length - 1] & 0x0f
  const binary = ((mac[offset] & 0x7f) << 24) | (mac[offset + 1] << 16) | (mac[offset + 2] << 8) | mac[offset + 3]
  return String(binary % 1_000_000).padStart(6, '0')
}

// Each step is accepted once per factor (the replay guard): wait for a step after `step`.
export const nextTotpStep = async (step: number) => {
  while (totpStep() <= step) await new Promise(resolve => setTimeout(resolve, 250))
  return totpStep()
}
