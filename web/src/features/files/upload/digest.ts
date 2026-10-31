// RFC 9530 Content-Digest for part bodies (transfer-protocol.md §3.3). Pure; see digest.test.ts.

const toBase64 = (bytes: Uint8Array): string => {
  let binary = ''
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000))
  return btoa(binary)
}

// `sha-256=:<base64>:` from a raw 32-byte SHA-256.
export const formatContentDigest = (sha256: ArrayBuffer | Uint8Array): string =>
  `sha-256=:${toBase64(sha256 instanceof Uint8Array ? sha256 : new Uint8Array(sha256))}:`

// The header value for `data`, or null where Web Crypto isn't available. crypto.subtle exists only in secure
// contexts, and the package's default site is plain HTTP: the header is optional, so parts go without it there.
// `subtle` defaults to the global one; null stands for "not available" (tests).
export const contentDigest = async (data: ArrayBuffer, subtle?: SubtleCrypto | null): Promise<string | null> => {
  const crypto = subtle === undefined ? globalThis.crypto?.subtle : subtle
  if (!crypto) return null
  return formatContentDigest(await crypto.digest('SHA-256', data))
}
