import { createHmac } from 'node:crypto'
import { mkdir, readFile, rename, rm, stat, writeFile } from 'node:fs/promises'
import { dirname } from 'node:path'

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

// A factor's private file, shared by every worker of a run, in tools/lab/mfa.py's TotpStore format:
// {"secret_base32", "last_step", "recovery_codes"?}, 0600. tools/e2e/enroll_totp.py writes the e2e account's at
// provisioning (#405); signIn writes one for an account it enrolls through the console. Never printed or logged.
type TotpDoc = { secret_base32: string; last_step: number; [key: string]: unknown }

const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms))

const writePrivate = async (file: string, doc: TotpDoc, flag: 'w' | 'wx') => {
  if (flag === 'wx') {
    await writeFile(file, JSON.stringify(doc), { mode: 0o600, flag })
    return
  }
  const tmp = `${file}.${process.pid}.tmp`
  await writeFile(tmp, JSON.stringify(doc), { mode: 0o600, flag: 'w' })
  await rename(tmp, file)
}

// Keeps a factor that was just enrolled; refuses to overwrite one already on disk.
export const saveEnrolledTotp = async (file: string, secretBase32: string, step: number) => {
  await mkdir(dirname(file), { recursive: true, mode: 0o700 })
  await writePrivate(file, { secret_base32: secretBase32, last_step: step }, 'wx')
}

// One worker at a time spends a step of the factor in `file` (a lock directory beside it). The daemon refuses a step
// at or below the last one it accepted, so a code is computed, submitted and answered inside the lock: steps reach
// the daemon in order and none is used twice. A lock older than two minutes (a turn takes under one) belongs to a
// worker that died holding it.
const lock = async (file: string) => {
  const dir = `${file}.lock`
  const deadline = Date.now() + 300_000
  for (;;) {
    try {
      await mkdir(dir)
      return () => rm(dir, { recursive: true, force: true })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
      const held = await stat(dir).catch(() => null)
      if (held && Date.now() - held.mtimeMs > 120_000) await rm(dir, { recursive: true, force: true })
      if (Date.now() > deadline) throw new Error(`timed out waiting for the TOTP lock ${dir}`)
      await sleep(100)
    }
  }
}

// Runs `submit` with the next code of the factor in `file`. The daemon accepts the step before the current one, the
// current one and the next (core/auth/mfa/Totp): the earliest of those after the last step spent is used (the previous
// one only while 3 s of the current step are left, so it can't age out on the way), anything later is waited for.
// `submit` sends the code and waits for the daemon's answer. With one factor shared by every worker, that is three
// sign-ins at once and then one per 30 s: callers that queue behind others give themselves time (signIn, confirmStepUp).
export const withTotpCode = async <T>(file: string, submit: (code: string) => Promise<T>): Promise<T> => {
  const release = await lock(file)
  try {
    const doc = JSON.parse(await readFile(file, 'utf8')) as TotpDoc
    const now = Date.now()
    const earliest = (totpStep(now) + 1) * 30_000 - now >= 3_000 ? totpStep(now) - 1 : totpStep(now)
    const step = Math.max(earliest, Number(doc.last_step ?? -1) + 1)
    while (step > totpStep() + 1) await sleep(250)
    await writePrivate(file, { ...doc, last_step: step }, 'w')
    return await submit(totpCode(doc.secret_base32, step))
  } finally {
    await release()
  }
}
