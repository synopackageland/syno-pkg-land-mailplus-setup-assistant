// @vitest-environment jsdom
// A removal that had to leave
// the MX records Cloudflare locks for Email Routing finishes, says so plainly,
// lists them and opens Cloudflare's Email Routing page of the setup's account
// in a new tab, with a warning about the whole domain; the relay card shows
// the relay's real state after a removal.
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {emailRoutingUrl} from '../src/api/cloudflare'
import {dsmWindow} from './context'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const ID = 'f'.repeat(32)
const ACCOUNT = 'a'.repeat(32)
const KEYS = ['ui.remove.locked.title', 'ui.remove.locked.body', 'ui.remove.locked.where', 'ui.remove.locked.whereAny', 'ui.remove.locked.warning', 'ui.remove.locked.open']
// Standard mail terms (MX, SPF) and Cloudflare's own page names stay; internal jargon and codes do not.
const JARGON = /journal|snapshot|ledger|unsafe|relay|Worker(?!s)|VPC|tunnel|catch-?all|1046|\b\d{3,4}\b/i
const LOCKED = [1, 2, 3].map(i => ({type: 'MX', name: 'mail.example.com', content: `route${i}.mx.cloudflare.net`}))

async function settle() {for(let i = 0; i < 30; i++) {await Promise.resolve(); await nextTick()}}
afterEach(() => {document.body.innerHTML = ''; vi.restoreAllMocks()})

function open(removal: Record<string, unknown>, locale = 'zh-TW') {
 const catalog = catalogs[locale]!
 let relayOn = true
 const calls: string[] = []
 const call = vi.fn(async (method: string) => {
  calls.push(method)
  if(method === 'app.status') return {package: 'SynoMailPlusSetupAssistant', version: '0.1.0', user: 'admin', admin: true}
  if(method === 'dsm.authority.status') return {capability: {state: 'ready'}, profiles: [
   {name: 'mail-read', profile: {purpose: '', apis: {}}, state: 'granted', canRevoke: true},
   {name: 'mail-write', profile: {purpose: '', apis: {}}, state: 'granted', canRevoke: true}], grants: []}
  if(method === 'mail.relay.status') return {id: 'mail.relay', enabled: relayOn, status: {running: relayOn, since: relayOn ? '2026-11-13T08:44:00Z' : undefined}}
  if(method === 'mail.mailplus.status') return {state: 'running', version: '3.3.0-21430'}
  if(method === 'mail.setup.start') return {id: '0'.repeat(32), phase: '', done: 0, total: 0, changes: [], findings: [], verified: false, resume: false}
  if(method === 'mail.inbound.status') return {setups: relayOn ? [{id: ID, domain: 'mail.example.com', intent: 'both', receive: 'addresses', token: true, relay: true,
   removes: ['ui.remove.item.receiveDNS', 'ui.remove.item.relay', 'ui.remove.item.token']}] : []}
  if(method === 'mail.cloudflare.remove') {
   relayOn = false // the removal turned the relay off
   return {id: ID, domain: 'mail.example.com', token: false, removes: [], removal: {state: 'done', done: 8, total: 8, ...removal}}
  }
  throw {code: 'unknown_method'}
 })
 const t = (key: string, params?: Record<string, unknown>) => (catalog[key] ?? key).replace(/\{(\w+)\}/g, (m, n) => params && n in params ? String(params[n]) : m)
 const root = document.createElement('div'); document.body.append(root)
 const app = mount(root, dsmWindow({locale, call: call as never, t}))
 const section = (name: string) => root.querySelector<HTMLElement>(`[data-section="${name}"]`)
 return {root, section, calls, catalog, t, close() {app.unmount(); root.remove()}}
}
function click(el: Element | null) {expect(el).not.toBeNull(); (el as HTMLElement).click()}
async function removeIt(h: ReturnType<typeof open>) {
 await settle()
 click(h.section('inbound')!.querySelector('[data-remove]')); await settle()
 click(document.querySelector('[data-confirm-remove]')); await settle()
}

test.each(locales)('the locked-record messages exist, are plain and keep their placeholders in %s', loc => {
 const c = catalogs[loc]!
 for(const key of KEYS) {
  expect(c[key], `${loc}: ${key}`).toBeTruthy()
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
  expect(c[key], `${loc}: ${key}`).not.toMatch(/[.。]$/)
 }
 expect(c['ui.remove.locked.body']).toContain('{domain}')
 expect(c['ui.remove.locked.body']).toMatch(/\bMX\b/)
 expect(c['ui.remove.locked.where']).toContain('{zone}')
 expect(c['ui.remove.locked.open']).toContain('Email Routing')
 expect(c['ui.remove.locked.warning']).toContain('Email Routing')
 // The old refusal (go to Settings first, then try again) is gone.
 expect(c['mail.remove.cause.locked']).toBeUndefined()
})

test('the Email Routing link is the documented page with the account filled in', () => {
 expect(emailRoutingUrl(ACCOUNT)).toBe(`https://dash.cloudflare.com/?to=/${ACCOUNT}/email-service/routing`)
 // Anything that is not an account ID leaves the documented placeholder.
 for(const bad of [undefined, '', 'x/../../evil', 'A'.repeat(32), 'a'.repeat(31)]) {
  expect(emailRoutingUrl(bad)).toBe('https://dash.cloudflare.com/?to=/:account/email-service/routing')
 }
})

test('a removal that left locked MX records finishes, lists them and links to Email Routing in a new tab', async () => {
 const opened = vi.spyOn(window, 'open').mockReturnValue(null)
 const h = open({locked: LOCKED, accountId: ACCOUNT, zone: 'example.com'})
 try {
  await removeIt(h)
  const inbound = h.section('inbound')!
  expect(inbound.querySelector('[data-remove-result]')?.textContent).toBe(h.t('ui.remove.done', {domain: 'mail.example.com'}))
  expect(inbound.querySelector('[data-remove-failed]')).toBeNull()
  const box = inbound.querySelector('[data-remove-locked]')!
  expect(box.textContent).toContain(h.catalog['ui.remove.locked.title'])
  expect(box.textContent).toContain(h.t('ui.remove.locked.body', {domain: 'mail.example.com'}))
  expect([...box.querySelectorAll('[data-locked-records] [role=listitem]')].map(li => li.textContent)).toEqual(LOCKED.map(l => `MX mail.example.com ${l.content}`))
  expect(box.textContent).toContain(h.t('ui.remove.locked.where', {zone: 'example.com'}))
  expect(box.querySelector('[data-locked-warning]')?.textContent).toBe(h.catalog['ui.remove.locked.warning'])
  click(box.querySelector('[data-open-routing]'))
  expect(opened).toHaveBeenCalledWith(`https://dash.cloudflare.com/?to=/${ACCOUNT}/email-service/routing`, '_blank', 'noopener,noreferrer')
 } finally {h.close()}
})

test('without the zone name the link still opens and the text says to select the domain', async () => {
 vi.spyOn(window, 'open').mockReturnValue(null)
 const h = open({locked: LOCKED, accountId: ACCOUNT})
 try {
  await removeIt(h)
  const box = h.section('inbound')!.querySelector('[data-remove-locked]')!
  expect(box.textContent).toContain(h.catalog['ui.remove.locked.whereAny'])
  expect(box.querySelector('[data-open-routing]')).not.toBeNull()
 } finally {h.close()}
})

test('a removal with nothing locked shows only the done line', async () => {
 const h = open({})
 try {
  await removeIt(h)
  expect(h.section('inbound')!.querySelector('[data-remove-result]')).not.toBeNull()
  expect(h.section('inbound')!.querySelector('[data-remove-locked]')).toBeNull()
 } finally {h.close()}
})

test('after a removal the relay card reads the relay again and shows that it is off', async () => {
 const h = open({})
 try {
  await settle()
  const relay = () => h.section('relay')!.textContent ?? ''
  expect(relay()).toContain(h.catalog['ui.services.running'])
  const reads = h.calls.filter(m => m === 'mail.relay.status').length
  await removeIt(h)
  expect(h.calls.filter(m => m === 'mail.relay.status').length).toBeGreaterThan(reads)
  expect(relay()).not.toContain(h.catalog['ui.services.running'])
  expect(relay()).toContain(h.catalog['ui.services.off'])
 } finally {h.close()}
})
