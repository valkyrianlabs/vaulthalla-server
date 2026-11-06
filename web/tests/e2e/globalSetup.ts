import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'

function explicitSkipRequested() {
  return process.env.VAULTHALLA_E2E_SKIP === '1' ||
    process.env.VAULTHALLA_E2E_SKIP === 'true'
}

function decodeProvisionExports(exportsText: string, repoRoot: string) {
  const output = execFileSync('bash', [
    '-lc',
    `${exportsText}\nprintf '%s\\0%s\\0%s\\0' "$VAULTHALLA_E2E_USER" "$VAULTHALLA_E2E_PASSWORD" "$VAULTHALLA_E2E_TOTP_FILE"`,
  ], {
    cwd: repoRoot,
    env: process.env,
    encoding: 'buffer',
    stdio: ['ignore', 'pipe', 'inherit'],
  }).toString('utf8')

  const [user, password, totpFile] = output.split('\0')
  if (!user || !password) {
    throw new Error('E2E credential provisioning completed without returning user and password exports.')
  }
  return { user, password, totpFile: totpFile ?? '' }
}

// VAULTHALLA_E2E_OFFLINE=1: specs that script every ws answer themselves (devices.spec.ts) run against `pnpm dev:e2e`
// alone, with no daemon and no provisioned account.
function offlineRequested() {
  return process.env.VAULTHALLA_E2E_OFFLINE === '1' ||
    process.env.VAULTHALLA_E2E_OFFLINE === 'true'
}

function globalSetup() {
  if (explicitSkipRequested() || offlineRequested()) return

  const repoRoot = resolve(__dirname, '../../..')
  const provisionScript = resolve(repoRoot, 'tools/e2e/provision_e2e_user.sh')
  const provisionEnv = {
    ...process.env,
    VAULTHALLA_E2E_USER: '',
    VAULTHALLA_E2E_PASSWORD: '',
    VAULTHALLA_E2E_EMAIL: '',
    VAULTHALLA_E2E_TOTP_FILE: '',
  }
  const exportsText = execFileSync(provisionScript, ['--force', '--fresh-user', '--print-exports'], {
    cwd: repoRoot,
    env: provisionEnv,
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'inherit'],
  })
  // The account and its second factor (#357, #405): provisioning enrolls an authenticator app for an account that needs
  // one, once, before any worker signs in, and names the private file that holds it (helpers/totp.ts reads it).
  const { user, password, totpFile } = decodeProvisionExports(exportsText, repoRoot)

  process.env.VAULTHALLA_E2E_USER = user
  process.env.VAULTHALLA_E2E_PASSWORD = password
  process.env.VAULTHALLA_E2E_TOTP_FILE = totpFile ? resolve(repoRoot, totpFile) : ''
}

export default globalSetup
