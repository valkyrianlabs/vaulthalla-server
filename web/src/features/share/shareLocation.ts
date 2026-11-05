// Where a share recipient is: the link's token and the folder they are browsing. Both live in the URL fragment
// (`/share#<token>/<path>`, #327). Browsers never send the fragment to the server and never put it in `Referer`, so
// neither the bearer token nor file and folder names reach nginx access logs, proxies or other sites. Links issued
// before #327 (`/share/<token>/<path>`) land on a page that rewrites them to this form at once.
// Pure: see shareLocation.test.ts.

import { normalizePath } from '../files/paths.ts'

export interface ShareLocation {
  token: string
  path: string
}

const decode = (segment: string) => {
  try {
    return decodeURIComponent(segment)
  } catch {
    return null
  }
}

const fromSegments = (segments: string[]): ShareLocation | null => {
  const [rawToken, ...rest] = segments
  const token = rawToken ? decode(rawToken) : null
  if (!token) return null
  const parts = rest.filter(Boolean).map(decode)
  if (parts.some(part => part === null)) return null
  try {
    return { token, path: normalizePath(parts.join('/')) }
  } catch {
    return null
  }
}

// `#<token>[/<encoded path segments>]`, with or without the leading `#`.
export const parseShareHash = (hash: string): ShareLocation | null =>
  fromSegments((hash.startsWith('#') ? hash.slice(1) : hash).split('/'))

// A pre-#327 pathname, `/share/<token>[/<path>]`.
export const parseLegacySharePath = (pathname: string): ShareLocation | null => {
  const match = /^\/share\/(.+)$/.exec(pathname)
  return match ? fromSegments(match[1].split('/')) : null
}

export const shareHash = ({ token, path }: ShareLocation) => {
  const encoded = normalizePath(path).split('/').filter(Boolean).map(encodeURIComponent).join('/')
  return `#${encodeURIComponent(token)}${encoded ? `/${encoded}` : ''}`
}

export const shareHref = (location: ShareLocation) => `/share${shareHash(location)}`
