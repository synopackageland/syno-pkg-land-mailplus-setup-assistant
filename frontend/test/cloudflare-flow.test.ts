// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://nas.test"}
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {format} from '@synopackageland/sdk'
import {mount} from '../src/main'
import {dsmWindow} from './context'

const LOCALES = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it'] as const
const CATALOGS = Object.fromEntries(
 LOCALES.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]),
) as Record<(typeof LOCALES)[number], Record<string, string>>

const CF_FLOW_KEYS = Object.keys(CATALOGS.en).filter(k => k.startsWith('ui.cfFlow.'))

async function settle() {
 for(let i = 0; i < 20; i++) {
  await Promise.resolve()
  await nextTick()
 }
}

function mockMatchMedia(reduced: boolean) {
 const listeners = new Set<(e: MediaQueryListEvent) => void>()
 const mql = {
  matches: reduced,
  media: '(prefers-reduced-motion: reduce)',
  onchange: null,
  addEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.add(fn),
  removeEventListener: (_: string, fn: (e: MediaQueryListEvent) => void) => listeners.delete(fn),
  addListener: () => {},
  removeListener: () => {},
  dispatchEvent: () => true,
 } as unknown as MediaQueryList
 vi.stubGlobal('matchMedia', vi.fn((query: string) => (
  query === '(prefers-reduced-motion: reduce)'
   ? mql
   : ({matches: false, media: query, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {}, dispatchEvent: () => true} as unknown as MediaQueryList)
 )))
 return {
  setReduced(next: boolean) {
   Object.defineProperty(mql, 'matches', {value: next, configurable: true})
   for(const fn of listeners) fn({matches: next, media: mql.media} as MediaQueryListEvent)
  },
 }
}

function openOverview(locale: (typeof LOCALES)[number] = 'zh-TW') {
 const catalog = CATALOGS[locale]
 const t = (key: string, params?: Record<string, unknown>) =>
  catalog[key] === undefined ? key : params ? format(catalog[key]!, params as never) : catalog[key]!
 const call = vi.fn(async (method: string) => {
  if(method === 'app.status') return {package: 'Pkg', version: '1', user: 'admin', admin: true}
  if(method === 'mail.mailplus.status') return {state: 'running', version: '4.1', setUp: true}
  if(method === 'mail.relay.status') return {enabled: false, status: {running: false}}
  if(method === 'mail.setup.start') return {id: 'f1', resume: false}
  if(method === 'mail.inbound.status') return {setups: []}
  throw {code: 'unknown_method'}
 })
 const root = document.createElement('div')
 document.body.appendChild(root)
 const app = mount(root, dsmWindow({locale, t: t as never, call: call as never}))
 return {
  root,
  catalog,
  section: () => root.querySelector<HTMLElement>('[data-section="cloudflare-flow"]'),
  toggleBtn: () => root.querySelector<HTMLButtonElement>('[data-section="cloudflare-flow"] button[aria-expanded]'),
  flow: () => root.querySelector<HTMLElement>('[data-section="cloudflare-flow"] .msa-cf-flow'),
  close() {
   app.unmount()
   root.remove()
  },
 }
}

afterEach(() => {
 document.body.innerHTML = ''
 vi.unstubAllGlobals()
 vi.restoreAllMocks()
})

test('every ui.cfFlow key exists in all 9 locales and never ends with a trailing period', () => {
 expect(CF_FLOW_KEYS.length).toBeGreaterThanOrEqual(50)
 for(const loc of LOCALES) {
  const cat = CATALOGS[loc]
  for(const key of CF_FLOW_KEYS) {
   const val = cat[key]
   expect(val, `${loc}:${key}`).toBeTruthy()
   expect(val!.trim(), `${loc}:${key} has trailing period`).not.toMatch(/[.。]$/)
  }
 }
})

test('starts collapsed with no animation running, no subtitle, and stops animation on re-collapse', async () => {
 mockMatchMedia(false)
 const rafSpy = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 42)
 const cafSpy = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})

 const h = openOverview('zh-TW')
 try {
  await settle()
  const sec = h.section()
  expect(sec).not.toBeNull()
  expect(sec?.textContent).toContain(h.catalog['ui.cfFlow.title'])
  expect(sec?.textContent).not.toMatch(/方案\s*[ABC]/)
  // No section description element rendered for the flow card.
  expect(sec?.querySelector('[data-ui-section-description]')).toBeNull()

  const toggle = h.toggleBtn()
  expect(toggle?.getAttribute('aria-expanded')).toBe('false')
 expect(rafSpy.mock.calls.filter(([fn]) => fn.name === 'tick')).toHaveLength(0)
 rafSpy.mockClear()
 cafSpy.mockClear()

  // Expand -> plays and schedules animation frames.
  toggle!.click()
  await settle()
  expect(toggle?.getAttribute('aria-expanded')).toBe('true')
  expect(h.flow()?.dataset.playing).toBe('true')
  expect(h.flow()?.dataset.reduced).toBe('false')
 expect(rafSpy.mock.calls.some(([fn]) => fn.name === 'tick')).toBe(true)

  // Collapse -> cancels rAF and stops playback.
  toggle!.click()
  await settle()
  expect(toggle?.getAttribute('aria-expanded')).toBe('false')
  expect(cafSpy).toHaveBeenCalledWith(42)
 } finally {
  h.close()
 }
})

test('bottom stepper is split into inbound and outbound groups that follow the selected mode', async () => {
 mockMatchMedia(false)
 vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 1)
 vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})

 const h = openOverview('zh-TW')
 try {
  await settle()
  h.toggleBtn()!.click()
  await settle()

  // Default "both" mode shows both inbound (6) and outbound (4) groups.
  expect(h.root.querySelectorAll('[data-stepper-group="in"] [data-step-node]').length).toBe(6)
  expect(h.root.querySelectorAll('[data-stepper-group="out"] [data-step-node]').length).toBe(4)

  // Switch to receive-only -> only inbound group shown.
  h.root.querySelector<HTMLButtonElement>('[data-flow-mode="in"]')!.click()
  await settle()
  expect(h.root.querySelector('[data-stepper-group="in"]')).not.toBeNull()
  expect(h.root.querySelector('[data-stepper-group="out"]')).toBeNull()

  // Switch to send-only -> only outbound group shown.
  h.root.querySelector<HTMLButtonElement>('[data-flow-mode="out"]')!.click()
  await settle()
  expect(h.root.querySelector('[data-stepper-group="in"]')).toBeNull()
  expect(h.root.querySelector('[data-stepper-group="out"]')).not.toBeNull()

  // Switch back to both and jump directly to an outbound station chip.
  h.root.querySelector<HTMLButtonElement>('[data-flow-mode="both"]')!.click()
  await settle()
  h.root.querySelector<HTMLButtonElement>('[data-step-dir="out"][data-step-node="sending"]')!.click()
  await settle()
  expect(h.flow()?.dataset.activeDir).toBe('out')
 } finally {
  h.close()
 }
})

test('honors prefers-reduced-motion and skips requestAnimationFrame while keeping static controls', async () => {
 const mq = mockMatchMedia(true)
 const rafSpy = vi.spyOn(window, 'requestAnimationFrame').mockImplementation(() => 7)
 const cafSpy = vi.spyOn(window, 'cancelAnimationFrame').mockImplementation(() => {})

 const h = openOverview('en')
 try {
 await settle()
 rafSpy.mockClear()
 cafSpy.mockClear()
 h.toggleBtn()!.click()
  await settle()

  expect(h.flow()?.dataset.reduced).toBe('true')
  expect(h.flow()?.dataset.playing).toBe('false')
 expect(rafSpy.mock.calls.filter(([fn]) => fn.name === 'tick')).toHaveLength(0)
  expect(h.root.querySelector('[data-flow-pause]')).toBeNull()
  expect(h.root.querySelector('[data-flow-replay]')).toBeNull()
  // Station groups still work in reduced motion.
  expect(h.root.querySelector('[data-stepper-group="in"]')).not.toBeNull()
  expect(h.root.querySelector('[data-stepper-group="out"]')).not.toBeNull()

  // Toggling reduced-motion off starts playback; toggling back on cancels it.
  mq.setReduced(false)
  await settle()
  expect(h.flow()?.dataset.reduced).toBe('false')
  expect(h.flow()?.dataset.playing).toBe('true')
 expect(rafSpy.mock.calls.some(([fn]) => fn.name === 'tick')).toBe(true)

  mq.setReduced(true)
  await settle()
  expect(h.flow()?.dataset.reduced).toBe('true')
  expect(h.flow()?.dataset.playing).toBe('false')
  expect(cafSpy).toHaveBeenCalledWith(7)
 } finally {
  h.close()
 }
})

test.each(LOCALES)('renders translated flow copy with no raw keys in %s', async loc => {
 mockMatchMedia(true)
 const h = openOverview(loc)
 try {
  await settle()
  h.toggleBtn()!.click()
  await settle()
  const text = h.section()!.textContent ?? ''
  expect(text).toContain(h.catalog['ui.cfFlow.title'])
  expect(text).toContain(h.catalog['ui.cfFlow.zoneNas'])
  expect(text).toContain(h.catalog['ui.cfFlow.tag.connect'])
  expect(text).toContain(h.catalog['ui.cfFlow.dirIn'])
  expect(text).toContain(h.catalog['ui.cfFlow.dirOut'])
  expect(text).not.toMatch(/\bui\.cfFlow\./)
 } finally {
  h.close()
 }
})
