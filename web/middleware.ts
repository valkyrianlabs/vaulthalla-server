import { NextRequest, NextResponse } from 'next/server'
import { parseLegacySharePath, shareHref } from './src/features/share/shareLocation.ts'

export const config = {
  matcher: ['/((?!api|_next|favicon.ico|robots.txt|sitemap.xml).*)'],
}

const PUBLIC_PATH_PREFIXES = ['/login', '/share']
const PUBLIC_FILES = new Set(['/favicon.ico', '/robots.txt', '/sitemap.xml'])
const STATIC_ASSET_PATTERN = /\.(?:avif|css|gif|ico|jpeg|jpg|js|json|map|png|svg|txt|webmanifest|webp|woff|woff2)$/i

const isPublic = (req: NextRequest) => {
  const { pathname } = req.nextUrl
  if (PUBLIC_FILES.has(pathname)) return true
  if (pathname.startsWith('/_next') || pathname.startsWith('/api')) return true
  if (PUBLIC_PATH_PREFIXES.some(path => pathname === path || pathname.startsWith(`${path}/`))) return true
  return STATIC_ASSET_PATTERN.test(pathname)
}

const redirectToLogin = (req: NextRequest) => {
  const redir = new URL('/login', req.url)
  redir.searchParams.set('next', req.nextUrl.pathname + req.nextUrl.search)
  return NextResponse.redirect(redir)
}

// Presence only: no refresh cookie means login. Whether the cookie is still valid is the websocket session gate's
// call (SessionGate → auth.refresh), which sends a refused session to /login and shows its reconnect state when the
// daemon is down. Pages carry no data (everything loads over the socket after the gate), so there is nothing to
// protect here, and an upstream check per navigation only added a round trip (#171).
export function middleware(req: NextRequest) {
  // Links issued before #327 put the share token (and folder names) in the path, where access logs and `Referer`
  // see them. Answer them with one redirect to the fragment form, which never leaves the browser again.
  if (req.nextUrl.pathname.startsWith('/share/')) {
    const location = parseLegacySharePath(req.nextUrl.pathname)
    const target = new URL(location ? shareHref(location) : '/share', req.url)
    const res = NextResponse.redirect(target, 308)
    res.headers.set('Referrer-Policy', 'no-referrer')
    res.headers.set('Cache-Control', 'no-store')
    return res
  }
  if (isPublic(req) || req.cookies.get('refresh')?.value) return NextResponse.next()
  return redirectToLogin(req)
}
