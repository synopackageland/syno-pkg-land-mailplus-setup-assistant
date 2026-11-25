// @vitest-environment jsdom
// A Cloudflare token deleted or rolled in Cloudflare's dashboard (
// owner request 2026-11-13): the Overview says so in one line with "Enter a
// new token", which opens the same guided entry as the setup (steps, the
// create-token link, the permission list); the diagnosis shows it as a
// problem with the same button. One new token replaces the old one
// everywhere; a missing permission is named in plain words.
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const ID = 'e'.repeat(32)
const KEYS = ['ui.token.invalid', 'ui.token.invalidNoRelay', 'ui.token.queued', 'ui.token.reenter', 'ui.token.title', 'ui.token.body', 'ui.token.save',
 'ui.token.cancel', 'ui.token.saved', 'ui.token.missing', 'mail.inbound.tokenMissing', 'ui.setup.tokenTitle', 'ui.setup.tokenBody', 'ui.setup.tokenSaved',
 'ui.diag.action.token', 'mail.diag.problem.token_invalid.title', 'mail.diag.problem.token_invalid.body', 'mail.diag.problem.token_invalid.action',
 'mail.diag.token_invalid.title', 'mail.diag.token.why', 'mail.diag.token.fix']
const JARGON = /\b401\b|\b535\b|journal|alias|SMTP|relay|Worker(?!s)|VPC|tunnel/i
const SECRET = 'fixture-replacement'

async function settle() {for(let i = 0; i < 30; i++) {await Promise.resolve(); await nextTick()}}
afterEach(() => {document.body.innerHTML = ''; vi.useRealTimers()})

type Reply = unknown | ((p: Record<string, unknown>) => unknown)
function open(replies: Record<string, Reply>, locale = 'zh-TW') {
 const catalog = catalogs[locale]!
 const calls: [string, Record<string, unknown>][] = []
 const call = vi.fn(async (method: string, params: Record<string, unknown> = {}) => {
  calls.push([method, params])
  if(method === 'app.status') return {package: 'SynoMailPlusSetupAssistant', version: '0.1.0', user: 'admin', admin: true}
  if(method === 'dsm.authority.status') return {capability: {state: 'ready'}, profiles: [
   {name: 'mail-read', profile: {purpose: '', apis: {}}, state: 'granted', canRevoke: true},
   {name: 'mail-write', profile: {purpose: '', apis: {}}, state: 'granted', canRevoke: true}], grants: []}
  if(method === 'mail.relay.status') return {id: 'mail.relay', enabled: true, status: {running: true}}
  if(method === 'mail.mailplus.status') return {state: 'running', version: '3.3.0-21430'}
  if(method === 'mail.setup.start') return {id: '0'.repeat(32), phase: '', done: 0, total: 0, changes: [], findings: [], verified: false, resume: false}
  if(!(method in replies)) throw {code: 'unknown_method'}
  const r = replies[method]
  const v = typeof r === 'function' ? (r as (p: Record<string, unknown>) => unknown)(params) : r
  if(v && typeof v === 'object' && '__throw' in v) throw (v as {__throw: unknown}).__throw
  return v
 })
 const t = (key: string, params?: Record<string, unknown>) => (catalog[key] ?? key).replace(/\{(\w+)\}/g, (m, n) => params && n in params ? String(params[n]) : m)
 const root = document.createElement('div'); document.body.append(root)
 const app = mount(root, dsmWindow({locale, call: call as never, t}))
 const section = () => root.querySelector<HTMLElement>('[data-section="inbound"]')
 const tokenDialog = () => document.querySelector<HTMLElement>('[data-token-dialog]')
 const params = (m: string) => calls.filter(c => c[0] === m).map(c => c[1])
 return {root, section, tokenDialog, params, catalog, close() {app.unmount(); root.remove()}}
}
const kept = (extra: Record<string, unknown> = {}) => ({id: ID, domain: 'example.com', intent: 'both', receive: 'addresses', token: true, relay: true, ...extra})
function click(el: Element | null) {expect(el).not.toBeNull(); (el as HTMLElement).click()}
async function type(el: HTMLInputElement, value: string) {el.value = value; el.dispatchEvent(new Event('input', {bubbles: true})); await settle()}
const tokenInput = () => document.querySelector<HTMLInputElement>('[data-new-token] input, input[data-new-token]')!

test.each(locales)('every token key exists, is plain and keeps its placeholders in %s', loc => {
 const c = catalogs[loc]!
 for(const key of KEYS) {
  expect(c[key], `${loc}: ${key}`).toBeTruthy()
  // The finding's own why/fix (under Show details) may name the relay; what the page and the problem say may not.
  if(!key.startsWith('mail.diag.token')) expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
  expect(c[key], `${loc}: ${key}`).not.toMatch(/[.。]$/)
 }
 expect(c['ui.token.title']).toContain('{domain}')
 expect(c['ui.token.saved']).toContain('{domain}')
 expect(c['ui.token.missing']).toContain('{permissions}')
 if(loc === 'zh-TW') {
  expect(c['ui.token.invalid']).toBe('Cloudflare 權杖已失效（可能已被刪除），寄信與同步暫停')
  expect(c['ui.token.reenter']).toBe('重新輸入權杖')
 }
})

test('the Overview says the token no longer works, with one button to enter a new one', async () => {
 let invalid = true
 const h = open({'mail.inbound.status': () => ({setups: [kept({tokenInvalid: invalid})]}),
  'mail.inbound.token': (p: Record<string, unknown>) => {invalid = !p.token; return kept({tokenInvalid: invalid})}})
 try {
  await settle()
  const line = h.section()!.querySelector('[data-token-invalid]')!
  expect(line.querySelector('[role=alert]')?.textContent).toBe('Cloudflare 權杖已失效（可能已被刪除），寄信與同步暫停')
  expect(line.querySelector('[data-token-queued]')).not.toBeNull()
  expect(line.querySelector('[data-reenter-token]')?.textContent?.trim()).toBe('重新輸入權杖')
  // Sync waits for the new token; the old "token needed" form is not shown twice.
  expect(h.section()!.querySelector<HTMLButtonElement>('[data-sync]')!.disabled).toBe(true)
  expect(h.section()!.querySelector('[data-token-ask]')).toBeNull()

  click(line.querySelector('[data-reenter-token]')); await settle()
  const d = h.tokenDialog()!
  expect(document.body.textContent).toContain(h.catalog['ui.token.title']!.replace('{domain}', 'example.com'))
  // The same guided entry as the setup: the steps, the create-token link, the permission list.
  expect(d.querySelector('[data-token-steps]')).not.toBeNull()
  expect(d.querySelector('[data-create-token]')?.textContent?.trim()).toBe(h.catalog['mail.setup.cloudflare.create'])
  expect(d.querySelector('[data-permissions]')).not.toBeNull()
  const opened = vi.spyOn(window, 'open').mockReturnValue(null)
  click(d.querySelector('[data-create-token]'))
  expect(String(opened.mock.calls[0]?.[0])).toContain('permissionGroupKeys=')

  await type(tokenInput(), SECRET)
  click(document.querySelector('[data-token-save]')); await settle()
  expect(h.params('mail.inbound.token')).toEqual([{id: ID, token: SECRET}])
  expect(h.tokenDialog()).toBeNull()
  expect(h.section()!.querySelector('[data-token-invalid]')).toBeNull()
  expect(h.section()!.querySelector('[data-token-saved]')?.textContent).toContain('example.com')
  expect(h.section()!.querySelector<HTMLButtonElement>('[data-sync]')!.disabled).toBe(false)
  expect(document.body.innerHTML).not.toContain(SECRET)
 } finally {h.close()}
})

test('a setup that does not send through Cloudflare says sync and removal are paused', async () => {
 const h = open({'mail.inbound.status': {setups: [kept({relay: false, tokenInvalid: true})]}})
 try {
  await settle()
  const line = h.section()!.querySelector('[data-token-invalid]')!
  expect(line.textContent).toContain(h.catalog['ui.token.invalidNoRelay'])
  expect(line.querySelector('[data-token-queued]')).toBeNull()
 } finally {h.close()}
})

test('a token missing permissions is refused with their names, and the field is emptied', async () => {
 const h = open({'mail.inbound.status': {setups: [kept({tokenInvalid: true})]},
  'mail.inbound.token': {__throw: {code: 'permission_refused', details: {reason: 'mail.inbound.tokenMissing', permissions: 'workersEdit,vpcAdmin'}}}})
 try {
  await settle()
  click(h.section()!.querySelector('[data-reenter-token]')); await settle()
  await type(tokenInput(), SECRET)
  click(document.querySelector('[data-token-save]')); await settle()
  const missing = h.tokenDialog()!.querySelector('[data-token-missing]')!
  expect(missing.textContent).toContain(h.catalog['mail.setup.cloudflare.permission.workersEdit'])
  expect(missing.textContent).toContain(h.catalog['mail.setup.cloudflare.permission.vpcAdmin'])
  expect(tokenInput().value).toBe('')
  expect(h.section()!.querySelector('[data-token-invalid]')).not.toBeNull()
  expect(document.body.innerHTML).not.toContain(SECRET)
 } finally {h.close()}
})

test('the diagnosis shows a refused token as a problem whose button opens the same entry', async () => {
 const h = open({
  'mail.inbound.status': {setups: [kept({tokenInvalid: true})]},
  'mail.diagnose.start': {id: 'run', symptom: 'cannot-send', done: 0, total: 1, checks: ['mail.diag.relay'], findings: [], complete: false},
  'mail.diagnose.next': {id: 'run', symptom: 'cannot-send', done: 1, total: 1, checks: ['mail.diag.relay'], findings: [], complete: true,
   summary: {verdict: 'problems', problems: [{key: 'token_invalid', severity: 'critical', action: 'token', targets: ['example.com'], findings: ['mail.diag.relay.token_invalid']}], others: []}},
  'mail.inbound.token': kept(),
 }, 'en')
 try {
  await settle()
  const start = [...h.root.querySelectorAll<HTMLButtonElement>('[data-section="diagnose"] button')].find(b => b.textContent?.trim() === h.catalog['ui.overview.start'])
  click(start ?? null); await settle()
  const radio = [...document.querySelectorAll<HTMLElement>('[role=radio],input[type=radio]')].find(r => (r.closest('label') ?? r).textContent?.includes(h.catalog['mail.diag.symptom.cannot-send']!))
  click(radio ?? null); await settle()
  click([...document.querySelectorAll('button')].find(b => b.textContent?.trim() === 'Next') ?? null); await settle()
  const card = document.querySelector('[data-problem="token_invalid"]')!
  expect(card.textContent).toContain(h.catalog['mail.diag.problem.token_invalid.title'])
  expect(card.textContent).toContain('example.com')
  const button = card.querySelector('[data-action="token"]')!
  expect(button.textContent?.trim()).toBe(h.catalog['ui.diag.action.token'])
  click(button); await settle()
  expect(h.tokenDialog()).not.toBeNull()
  await type(tokenInput(), SECRET)
  click(document.querySelector('[data-token-save]')); await settle()
  expect(h.params('mail.inbound.token')).toEqual([{id: ID, token: SECRET}])
  expect(document.querySelector('[data-token-saved]')?.textContent).toContain('example.com')
 } finally {h.close()}
})
