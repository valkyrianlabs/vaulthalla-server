// One of the signed-in user's web sessions (ws auth.sessions.list; core's ops::sessions::to_json). A session is one
// refresh token row, shared by every tab of one browser. `id` is an opaque handle for auth.sessions.revoke (never the
// refresh token's id) and changes when the daemon restarts. Times are Unix seconds.
export interface AuthSession {
  id: string
  current: boolean
  // Authenticator assurance level of the sign-in: 1 a password, 2 a second factor or a passkey.
  aal: number
  // How the sign-in was proven: pwd, hwk / swk (device-bound / synced passkey), otp, rec.
  amr: string[]
  auth_time: number
  last_activity_at: number
  ip_address: string
  user_agent: string
}
