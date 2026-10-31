// The browser's UploadHttp: same-origin fetch for JSON requests (the cookie, or `share_refresh` on links, rides
// along) and XMLHttpRequest for part bodies, the only browser API with upload progress events.
import { TransportError, type HttpAnswer, type UploadHttp } from './engine.ts'

// JSON requests: finish waits up to 5 s on the server, so a minute without an answer is a dead connection.
const REQUEST_TIMEOUT_MS = 60_000
// Parts: no progress for this long while sending, or no answer this long after the last byte (the server encrypts,
// writes and syncs before answering), and the attempt is abandoned and retried.
const STALL_TIMEOUT_MS = 120_000

const parse = (text: string): unknown => {
  if (!text) return null
  try {
    return JSON.parse(text)
  } catch {
    return null
  }
}

const abortError = () => new DOMException('Cancelled', 'AbortError')

export const browserHttp: UploadHttp = {
  async request(method, url, body, signal) {
    if (signal?.aborted) throw abortError()
    const controller = new AbortController()
    let timedOut = false
    const timer = setTimeout(() => {
      timedOut = true
      controller.abort()
    }, REQUEST_TIMEOUT_MS)
    const forward = () => controller.abort()
    signal?.addEventListener('abort', forward, { once: true })
    try {
      const response = await fetch(url, {
        method,
        credentials: 'same-origin',
        cache: 'no-store',
        headers: body === undefined ? undefined : { 'Content-Type': 'application/json' },
        body: body === undefined ? undefined : JSON.stringify(body),
        signal: controller.signal,
      })
      const text = await response.text()
      return { status: response.status, header: (name: string) => response.headers.get(name), body: parse(text) } satisfies HttpAnswer
    } catch {
      if (signal?.aborted) throw abortError()
      throw new TransportError(timedOut ? 'timeout' : 'network')
    } finally {
      clearTimeout(timer)
      signal?.removeEventListener('abort', forward)
    }
  },

  putPart(url, data, headers, signal, onProgress) {
    return new Promise<HttpAnswer>((resolve, reject) => {
      if (signal.aborted) return reject(abortError())
      const xhr = new XMLHttpRequest()
      let stall: ReturnType<typeof setTimeout> | null = null
      let timedOut = false
      const arm = () => {
        if (stall) clearTimeout(stall)
        stall = setTimeout(() => {
          timedOut = true
          xhr.abort()
        }, STALL_TIMEOUT_MS)
      }
      const abort = () => xhr.abort()
      const done = () => {
        if (stall) clearTimeout(stall)
        signal.removeEventListener('abort', abort)
      }
      signal.addEventListener('abort', abort, { once: true })
      xhr.open('PUT', url)
      xhr.withCredentials = true
      for (const [name, value] of Object.entries(headers)) xhr.setRequestHeader(name, value)
      xhr.upload.onprogress = event => {
        arm()
        onProgress(event.loaded)
      }
      xhr.upload.onload = arm
      xhr.onload = () => {
        done()
        resolve({ status: xhr.status, header: name => xhr.getResponseHeader(name), body: parse(xhr.responseText) })
      }
      xhr.onerror = () => {
        done()
        reject(new TransportError('network'))
      }
      xhr.onabort = () => {
        done()
        reject(signal.aborted ? abortError() : new TransportError(timedOut ? 'timeout' : 'network'))
      }
      arm()
      xhr.send(data)
    })
  },
}
