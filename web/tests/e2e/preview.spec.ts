import { expect, test, type Locator, type Page } from '@playwright/test'
import { join } from 'node:path'
import { armStepUp, authenticateAndSaveState, authStatePath, explicitSkipRequested } from './helpers/auth'

// Rich previews end to end: server preview plans, ranged /download/content for native media, PDF paging, text
// view/edit/save with ETag conflicts, 3D models through the lazy viewer, and share-link capability gating
// (preview-only links never fetch original bytes). Uploads the fixtures under fixtures/preview (regenerate with
// fixtures/preview/generate.mjs) into a run folder in the first vault, and removes it and its links at the end.
//   VAULTHALLA_E2E_BASE_URL=https://localhost VAULTHALLA_E2E_NO_WEB_SERVER=1 pnpm exec playwright test tests/e2e/preview.spec.ts
// Needs the reverse proxy (nginx/Caddy) in front of both the console and the daemon's HTTP routes.

test.skip(explicitSkipRequested(), 'VAULTHALLA_E2E_SKIP set')
test.use({ storageState: authStatePath, ignoreHTTPSErrors: true })
// Step-up dialogs (#359) are answered with the e2e account's password and TOTP code.
test.beforeEach(({ page }) => armStepUp(page))

test.beforeAll(async ({ browser }) => {
  await authenticateAndSaveState(browser)
})

const RUN = `pv-${Date.now().toString(36)}`
const FOLDER = `${RUN} previews`
const FIXTURES = join(__dirname, 'fixtures', 'preview')
// No name is a substring of another: rows are found by text.
const FILES = ['image.png', 'doc.pdf', 'clip.webm', 'tone.ogg', 'unsupported.avi', 'notes.txt', 'readme.md', 'cube.glb', 'cube.gltf', 'cube.bin', 'cube.stl', 'cube.obj']
const MODELS = ['cube.glb', 'cube.gltf', 'cube.stl', 'cube.obj']
// Strings only the Babylon engine bundle carries (its version banner, its package scope).
const BABYLON = /Babylon\.js v|@babylonjs/

let folderUrl = ''
let vaultId = 0

const filePath = (name: string) => `/${FOLDER}/${name}`
const query = (params: Record<string, string | number>) => new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)])).toString()

const watchErrors = (page: Page) => {
  const problems: string[] = []
  page.on('pageerror', error => problems.push(`pageerror: ${error.message}`))
  page.on('console', message => {
    if (message.type() === 'error') problems.push(`console.error: ${message.text().slice(0, 240)}`)
  })
  return problems
}

const gotoFiles = async (page: Page) => {
  await page.goto('/files')
  await page.waitForURL(/\/files\/\d+/)
  await expect(page.getByRole('listbox', { name: /contents of/i })).toBeVisible()
}

const gotoFolder = async (page: Page) => {
  await page.goto(folderUrl)
  await expect(page.getByRole('listbox', { name: /contents of/i })).toBeVisible()
}

const row = (page: Page, name: string) => page.getByRole('option').filter({ hasText: name })

const openPreview = async (page: Page, name: string) => {
  await row(page, name).dblclick()
  const sheet = page.getByRole('dialog', { name, exact: true })
  await expect(sheet).toBeVisible()
  return sheet
}

const closeSheet = async (page: Page, sheet: Locator) => {
  // The close button, not Escape: a focused canvas or editor may own the key.
  await sheet.getByRole('button', { name: 'Close' }).first().click()
  await expect(sheet).toHaveCount(0)
}

// Whether the element's on-screen pixels show something besides a flat background. Uses a compositor screenshot,
// so it works whatever the WebGL context's preserveDrawingBuffer setting is.
const isDrawn = async (page: Page, target: Locator) => {
  const png = await target.screenshot()
  return page.evaluate(async b64 => {
    const img = new Image()
    img.src = `data:image/png;base64,${b64}`
    await img.decode()
    const canvas = document.createElement('canvas')
    canvas.width = img.width
    canvas.height = img.height
    const ctx = canvas.getContext('2d')
    if (!ctx) return false
    ctx.drawImage(img, 0, 0)
    const { data } = ctx.getImageData(0, 0, canvas.width, canvas.height)
    const [r, g, b] = [data[0], data[1], data[2]]
    let differing = 0
    for (let i = 0; i < data.length; i += 4) if (Math.abs(data[i] - r) + Math.abs(data[i + 1] - g) + Math.abs(data[i + 2] - b) > 48) differing++
    return differing / (data.length / 4) > 0.01
  }, png.toString('base64'))
}

const playMuted = (media: Locator) =>
  media.evaluate(async (element: HTMLMediaElement) => {
    element.muted = true // muted playback needs no user gesture
    await element.play()
  })

const currentTime = (media: Locator) => media.evaluate((element: HTMLMediaElement) => element.currentTime)

// Creates a share link for the run folder through the console's share dialog; returns the public URL.
const createFolderLink = async (page: Page) => {
  await gotoFiles(page)
  await row(page, FOLDER).click({ button: 'right' })
  await page.getByRole('menuitem', { name: 'Share link…' }).click()
  await page.getByRole('button', { name: 'Create link' }).click()
  const url = ((await page.locator('code').first().textContent()) ?? '').trim()
  expect(url).toMatch(/\/share#vhs_/)
  await page.keyboard.press('Escape')
  return url
}

test.describe.serial('rich previews', () => {
  test('setup: upload the preview fixtures into a run folder', async ({ page }) => {
    await gotoFiles(page)
    vaultId = Number(/\/files\/(\d+)/.exec(page.url())?.[1] ?? 0)
    expect(vaultId).toBeGreaterThan(0)
    await page.getByRole('button', { name: 'New folder' }).click()
    await page.getByRole('textbox', { name: 'Name', exact: true }).fill(FOLDER)
    await page.getByRole('button', { name: 'Create' }).click()
    await row(page, FOLDER).dblclick()
    await expect(page.getByRole('listbox', { name: new RegExp(`contents of ${FOLDER}`, 'i') })).toBeVisible()
    folderUrl = page.url()
    await page.locator('input[type=file][multiple]').setInputFiles(FILES.map(name => join(FIXTURES, name)))
    for (const name of FILES) await expect(row(page, name)).toBeVisible({ timeout: 30_000 })
  })

  test('the server plan reaches the listing', async ({ page }) => {
    const plans = new Map<string, { renderer?: string; requires?: string }>()
    page.on('websocket', ws => {
      if (new URL(ws.url()).pathname !== '/ws') return
      ws.on('framereceived', frame => {
        if (typeof frame.payload !== 'string' || !frame.payload.includes('"preview"')) return
        try {
          const files = (JSON.parse(frame.payload)?.data?.files ?? []) as { name?: string; preview?: { renderer?: string; requires?: string } }[]
          for (const file of files) if (file.name && file.preview) plans.set(file.name, file.preview)
        } catch {
          // not a listing frame
        }
      })
    })
    await gotoFolder(page)
    await expect.poll(() => plans.size, { timeout: 15_000 }).toBeGreaterThanOrEqual(FILES.length - 1)
    expect(plans.get('image.png')).toMatchObject({ renderer: 'image', requires: 'preview' })
    expect(plans.get('doc.pdf')).toMatchObject({ renderer: 'pdf', requires: 'preview' })
    expect(plans.get('clip.webm')).toMatchObject({ renderer: 'video', requires: 'download' })
    expect(plans.get('tone.ogg')).toMatchObject({ renderer: 'audio', requires: 'download' })
    expect(plans.get('notes.txt')).toMatchObject({ renderer: 'text', requires: 'download' })
    expect(plans.get('readme.md')).toMatchObject({ renderer: 'markdown', requires: 'download' })
    // libmagic calls these text/plain or application/json: the server must classify 3D by extension.
    expect(plans.get('cube.glb')).toMatchObject({ renderer: 'model:glb', requires: 'download' })
    expect(plans.get('cube.gltf')).toMatchObject({ renderer: 'model:gltf' })
    expect(plans.get('cube.stl')).toMatchObject({ renderer: 'model:stl' })
    expect(plans.get('cube.obj')).toMatchObject({ renderer: 'model:obj' })
  })

  test('an image opens in the preview sheet', async ({ page }) => {
    const problems = watchErrors(page)
    await gotoFolder(page)
    const sheet = await openPreview(page, 'image.png')
    const image = sheet.getByTestId('preview-image')
    await expect(image).toBeVisible()
    await expect.poll(() => image.evaluate((img: HTMLImageElement) => img.naturalWidth)).toBeGreaterThan(0)
    expect(await image.getAttribute('src')).toMatch(/^\/preview\?/)
    await closeSheet(page, sheet)
    expect(problems).toEqual([])
  })

  test('a PDF pages through server renders', async ({ page }) => {
    const pages: string[] = []
    page.on('response', response => {
      const url = new URL(response.url())
      if (url.pathname === '/preview' && url.searchParams.get('path') === filePath('doc.pdf')) pages.push(`${url.searchParams.get('page') ?? '0'}:${response.status()}`)
    })
    await gotoFolder(page)
    const sheet = await openPreview(page, 'doc.pdf')
    const indicator = sheet.getByTestId('pdf-page-indicator')
    await expect(indicator).toHaveText('Page 1 of 2')
    await expect(sheet.getByTestId('pdf-page')).toBeVisible()
    await expect(sheet.getByRole('button', { name: 'Previous page' })).toBeDisabled()
    await sheet.getByRole('button', { name: 'Next page' }).click()
    await expect(indicator).toHaveText('Page 2 of 2')
    await expect(sheet.getByRole('button', { name: 'Next page' })).toBeDisabled()
    // PageUp goes back; ←/→ stay with the sheet's file navigation.
    await page.keyboard.press('PageUp')
    await expect(indicator).toHaveText('Page 1 of 2')
    await sheet.getByRole('radio', { name: 'Fit width' }).click()
    await expect(sheet.getByTestId('pdf-page')).toBeVisible()
    expect(pages).toContain('0:200')
    expect(pages).toContain('1:200')
    await closeSheet(page, sheet)
  })

  test('video plays from ranged reads and seeks near the end', async ({ page }) => {
    const problems = watchErrors(page)
    const reads: { status: number; range: string | undefined }[] = []
    page.on('response', response => {
      if (new URL(response.url()).pathname === '/download/content') reads.push({ status: response.status(), range: response.headers()['content-range'] })
    })
    await gotoFolder(page)
    const sheet = await openPreview(page, 'clip.webm')
    const video = sheet.getByTestId('preview-video')
    await expect(video).toBeVisible()
    expect(await video.evaluate((element: HTMLVideoElement) => element.autoplay || !element.paused)).toBe(false)
    await playMuted(video)
    await expect.poll(() => currentTime(video), { timeout: 15_000 }).toBeGreaterThan(0.2)
    const target = await video.evaluate(
      (element: HTMLVideoElement) =>
        new Promise<number>((resolve, reject) => {
          const seekTo = Math.max(0, element.duration - 0.75)
          if (!Number.isFinite(seekTo)) return reject(new Error(`duration is ${element.duration}`))
          element.addEventListener('seeked', () => resolve(seekTo), { once: true })
          element.currentTime = seekTo
        }),
    )
    expect(target).toBeGreaterThan(5)
    await expect.poll(() => currentTime(video)).toBeGreaterThanOrEqual(target - 0.05)
    expect(reads.length).toBeGreaterThan(0)
    expect(reads.every(read => read.status === 200 || read.status === 206), JSON.stringify(reads)).toBe(true)
    expect(reads.some(read => read.status === 206 && /^bytes \d+-\d+\/\d+$/.test(read.range ?? '')), JSON.stringify(reads)).toBe(true)
    await closeSheet(page, sheet)
    expect(problems).toEqual([])
  })

  test('audio plays', async ({ page }) => {
    await gotoFolder(page)
    const sheet = await openPreview(page, 'tone.ogg')
    const audio = sheet.getByTestId('preview-audio')
    await expect(audio).toBeAttached()
    await playMuted(audio)
    await expect.poll(() => currentTime(audio), { timeout: 15_000 }).toBeGreaterThan(0.2)
    await closeSheet(page, sheet)
  })

  test('a format the browser cannot decode falls back to download', async ({ page }) => {
    await gotoFolder(page)
    const sheet = await openPreview(page, 'unsupported.avi')
    const fallback = sheet.getByTestId('media-fallback')
    await expect(fallback).toBeVisible({ timeout: 15_000 })
    await expect(fallback.getByText(/can.t play in your browser/i)).toBeVisible()
    await expect(fallback.getByRole('button', { name: 'Download' })).toBeVisible()
    await closeSheet(page, sheet)
  })

  test('a text file can be viewed, edited, saved and reloaded', async ({ page }) => {
    const problems = watchErrors(page)
    const edited = `edited by ${RUN}`
    await gotoFolder(page)
    let sheet = await openPreview(page, 'notes.txt')
    await expect(sheet.getByTestId('text-view')).toContainText('Vaulthalla preview notes')
    await sheet.getByRole('button', { name: 'Edit' }).click()
    const editor = sheet.locator('.cm-content')
    await expect(editor).toBeVisible()
    await editor.click()
    await page.keyboard.press('ControlOrMeta+a')
    await page.keyboard.type(edited)
    await expect(sheet.getByText('Unsaved changes')).toBeVisible()
    const saved = page.waitForResponse(response => new URL(response.url()).pathname === '/upload/text' && response.request().method() === 'PUT')
    await sheet.getByRole('button', { name: 'Save' }).click()
    const response = await saved
    expect(response.status()).toBe(200)
    expect(response.request().headers()['if-match']).toBeTruthy()
    await expect(sheet.getByText('No changes')).toBeVisible()
    await sheet.getByRole('button', { name: 'Done' }).click()
    await expect(sheet.getByTestId('text-view')).toHaveText(edited)
    await closeSheet(page, sheet)

    await page.reload()
    await expect(row(page, 'notes.txt')).toBeVisible()
    sheet = await openPreview(page, 'notes.txt')
    await expect(sheet.getByTestId('text-view')).toHaveText(edited)
    await closeSheet(page, sheet)
    const stored = await page.request.get(`/download/content?${query({ vault_id: vaultId, path: filePath('notes.txt') })}`)
    expect(await stored.text()).toBe(edited)
    expect(problems).toEqual([])
  })

  test('a concurrent change turns the save into a conflict', async ({ page }) => {
    const theirs = `theirs from ${RUN}`
    await gotoFolder(page)
    const sheet = await openPreview(page, 'notes.txt')
    await sheet.getByRole('button', { name: 'Edit' }).click()
    const editor = sheet.locator('.cm-content')
    await editor.click()
    await page.keyboard.press('ControlOrMeta+End')
    await page.keyboard.type(' + mine')

    // Someone else saves first, through the same HTTP contract.
    const contentUrl = `/download/content?${query({ vault_id: vaultId, path: filePath('notes.txt') })}`
    const head = await page.request.head(contentUrl)
    expect(head.ok()).toBe(true)
    const etag = head.headers()['etag']
    expect(etag).toBeTruthy()
    const origin = new URL(page.url()).origin
    const put = await page.request.put(`/upload/text?${query({ vault_id: vaultId, path: filePath('notes.txt') })}`, {
      headers: { 'If-Match': etag, 'Content-Type': 'text/plain; charset=utf-8', Origin: origin },
      data: theirs,
    })
    expect(put.status()).toBe(200)

    const refused = page.waitForResponse(response => new URL(response.url()).pathname === '/upload/text' && response.request().method() === 'PUT')
    await sheet.getByRole('button', { name: 'Save' }).click()
    expect((await refused).status()).toBe(412)
    const conflict = page.getByRole('dialog', { name: /changed since you opened it/i })
    await expect(conflict).toBeVisible()
    await conflict.getByRole('button', { name: /reload their version/i }).click()
    await expect(conflict).toHaveCount(0)
    await expect(editor).toHaveText(theirs)
    await sheet.getByRole('button', { name: 'Done' }).click()
    await closeSheet(page, sheet)
  })

  test('markdown renders without raw HTML or remote images', async ({ page }) => {
    const remote: string[] = []
    page.on('request', request => {
      if (new URL(request.url()).hostname === 'example.com') remote.push(request.url())
    })
    await gotoFolder(page)
    const sheet = await openPreview(page, 'readme.md')
    const view = sheet.getByTestId('markdown-view')
    await expect(view.getByRole('heading', { name: 'Preview readme' })).toBeVisible()
    await expect(view.getByRole('link', { name: 'link' })).toHaveAttribute('rel', 'noopener noreferrer')
    await expect(view.locator('img')).toHaveCount(0)
    await expect(view.getByText('[image: remote]')).toBeVisible()
    await expect(view.getByRole('table')).toBeVisible()
    expect(await page.evaluate(() => (window as unknown as { __pwned?: boolean }).__pwned)).toBeUndefined()
    expect(remote).toEqual([])
    await sheet.getByRole('radio', { name: 'Source' }).click()
    await expect(sheet.getByTestId('text-view')).toContainText('<img src="x"')
    await closeSheet(page, sheet)
  })

  test('opening an image never downloads the 3D engine', async ({ page }) => {
    let phase: 'image' | 'model' = 'image'
    const scripts: { phase: 'image' | 'model'; url: string; body: Promise<string> }[] = []
    page.on('response', response => {
      if (response.request().resourceType() === 'script') scripts.push({ phase, url: response.url(), body: response.text().catch(() => '') })
    })
    await gotoFolder(page)
    const image = await openPreview(page, 'image.png')
    await expect(image.getByTestId('preview-image')).toBeVisible()
    await page.waitForLoadState('networkidle')
    await expect(page.locator('[data-model-viewer]')).toHaveCount(0)
    for (const script of scripts) expect(BABYLON.test(await script.body), `${script.url} carries the 3D engine`).toBe(false)
    const resources = await page.evaluate(() => performance.getEntriesByType('resource').map(entry => entry.name))
    expect(resources.filter(name => /babylon/i.test(name))).toEqual([])
    await closeSheet(page, image)

    // Positive control: the engine does arrive once a model opens, so the check above could have seen it.
    phase = 'model'
    const model = await openPreview(page, 'cube.glb')
    await expect(model.locator('[data-model-viewer] canvas')).toBeVisible({ timeout: 30_000 })
    const modelBodies = await Promise.all(scripts.filter(script => script.phase === 'model').map(script => script.body))
    expect(modelBodies.some(body => BABYLON.test(body))).toBe(true)
    await closeSheet(page, model)
  })

  test('3D models render to a non-blank canvas without console errors', async ({ page }) => {
    test.setTimeout(120_000)
    const problems = watchErrors(page)
    const reads: string[] = []
    page.on('response', response => {
      const url = new URL(response.url())
      if (url.pathname === '/download/content') reads.push(`${url.searchParams.get('path')}:${response.status()}`)
    })
    await gotoFolder(page)
    for (const name of MODELS) {
      const sheet = await openPreview(page, name)
      const canvas = sheet.locator('[data-model-viewer] canvas')
      await expect(canvas, name).toBeVisible({ timeout: 30_000 })
      await expect.poll(() => isDrawn(page, canvas), { message: `${name} draws something`, timeout: 20_000 }).toBe(true)
      await closeSheet(page, sheet)
    }
    // glTF side files resolve to sibling vault paths through the same authorized route.
    expect(reads).toContain(`${filePath('cube.bin')}:200`)
    expect(problems).toEqual([])
  })

  test('a preview-only share link cannot open the video', async ({ page, browser }) => {
    // The share dialog only offers presets; rewrite this one create call to drop "download".
    await page.routeWebSocket(
      url => url.pathname === '/ws',
      ws => {
        const server = ws.connectToServer()
        ws.onMessage(message => {
          if (typeof message === 'string' && message.includes('"share.link.create"')) {
            const frame = JSON.parse(message)
            frame.payload.allowed_ops = ['metadata', 'list', 'preview']
            message = JSON.stringify(frame)
          }
          server.send(message)
        })
      },
    )
    const url = await createFolderLink(page)

    const recipient = await browser.newContext({ ignoreHTTPSErrors: true, storageState: undefined })
    const anon = await recipient.newPage()
    const originals: string[] = []
    anon.on('request', request => {
      const path = new URL(request.url()).pathname
      if (path === '/download/content' || path === '/download') originals.push(request.url())
    })
    await anon.goto(url)
    await expect(anon.getByRole('listbox')).toBeVisible({ timeout: 15_000 })

    let sheet = await openPreview(anon, 'clip.webm')
    await expect(sheet.getByText(/preview not available with this link.s permissions/i)).toBeVisible()
    await expect(sheet.getByTestId('preview-video')).toHaveCount(0)
    await expect(sheet.getByRole('button', { name: 'Download' })).toHaveCount(0)
    await closeSheet(anon, sheet)

    // The lossy server render is still allowed.
    sheet = await openPreview(anon, 'image.png')
    await expect(sheet.getByTestId('preview-image')).toBeVisible()
    await closeSheet(anon, sheet)
    expect(originals).toEqual([])
    await recipient.close()
  })

  test('a share link with download plays the video', async ({ page, browser }) => {
    const url = await createFolderLink(page)
    const recipient = await browser.newContext({ ignoreHTTPSErrors: true, storageState: undefined })
    const anon = await recipient.newPage()
    const reads: string[] = []
    anon.on('response', response => {
      const parsed = new URL(response.url())
      if (parsed.pathname === '/download/content') reads.push(`${parsed.searchParams.get('share')}:${response.status()}`)
    })
    await anon.goto(url)
    await expect(anon.getByRole('listbox')).toBeVisible({ timeout: 15_000 })
    const sheet = await openPreview(anon, 'clip.webm')
    const video = sheet.getByTestId('preview-video')
    await expect(video).toBeVisible()
    await playMuted(video)
    await expect.poll(() => currentTime(video), { timeout: 15_000 }).toBeGreaterThan(0.2)
    expect(reads.length).toBeGreaterThan(0)
    expect(reads.every(read => read === '1:200' || read === '1:206'), JSON.stringify(reads)).toBe(true)
    await closeSheet(anon, sheet)
    await recipient.close()
  })

  test('cleanup: revoke the run folder links and delete it', async ({ page }) => {
    await gotoFiles(page)
    const folder = row(page, FOLDER)
    if (!(await folder.count())) return
    await folder.click({ button: 'right' })
    await page.getByRole('menuitem', { name: 'Share link…' }).click()
    await page.getByRole('tab', { name: 'Existing links' }).click()
    const dialog = page.getByRole('dialog')
    // Revoked links drop their actions menu.
    const actions = dialog.getByRole('button', { name: 'Link actions' })
    for (let remaining = await actions.count(); remaining > 0; remaining--) {
      await actions.first().click()
      await page.getByRole('menuitem', { name: /revoke/i }).click()
      await page.getByRole('button', { name: 'Revoke', exact: true }).click()
      await expect(actions).toHaveCount(remaining - 1, { timeout: 15_000 })
    }
    await page.keyboard.press('Escape')
    await expect(page.getByRole('dialog')).toHaveCount(0)
    await folder.click()
    await page.keyboard.press('Delete')
    await page.getByRole('button', { name: 'Delete', exact: true }).click()
    await expect(folder).toHaveCount(0, { timeout: 30_000 })
  })
})
