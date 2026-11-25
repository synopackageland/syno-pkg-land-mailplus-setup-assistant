// @vitest-environment jsdom
// Follow-ups from the sample-nas live test (owner decisions 2026-11-13):
// a new token given in the diagnosis clears the Overview's red line and the
// diagnosis's token card at once; a domain set up again drops its "removed"
// notice without a restart; the removal dialog names the subdomain's
// receiving records; the new messages exist, plainly, in all nine languages.
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const ID = 'f'.repeat(32)
const SECRET = 'fixture-replacement'
const UNSAFE = ['zoneMismatch', 'inboundExists', 'sendingDns', 'egressUnknown', 'dkimUnknown', 'dnsExists', 'relayInUse', 'mailplusReply', 'savedRecord', 'planCheck', 'secret']
const KEYS = ['ui.remove.item.receiveDNS', 'ui.setup.authority.failed', 'ui.setup.authority.rolledBack',
 'ui.setup.authority.someStep', 'ui.setup.authority.someAccess', ...UNSAFE.map(c => `mail.setup.unsafe.${c}`),
 // The MailPlus steps a missing grant can stop at are named in the message.
 'mail.setup.change.mailplus.delivery', 'mail.setup.change.relay.configure']
// Standard mail terms (MX, SPF, DKIM, DNS) stay; internal jargon and codes do not.
const JARGON = /journal|snapshot|ledger|unsafe|authority_required|relay|STARTTLS|loopback|Worker(?!s)|VPC|tunnel|catch-?all|\b\d{3,4}\b/i

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
 const params = (m: string) => calls.filter(c => c[0] === m).map(c => c[1])
 return {root, section, params, catalog, close() {app.unmount(); root.remove()}}
}
const kept = (extra: Record<string, unknown> = {}) => ({id: ID, domain: 'example.com', intent: 'both', receive: 'addresses', token: true, relay: true, ...extra})
function click(el: Element | null) {expect(el).not.toBeNull(); (el as HTMLElement).click()}
const buttonText = (label: string, scope: ParentNode = document) => [...scope.querySelectorAll<HTMLButtonElement>('button')].find(b => b.textContent?.trim() === label) ?? null

test.each(locales)('every new message exists, is plain, and keeps its placeholders in %s', loc => {
 const c = catalogs[loc]!
 for(const key of KEYS) {
  expect(c[key], `${loc}: ${key}`).toBeTruthy()
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
  expect(c[key], `${loc}: ${key}`).not.toMatch(/[.。]$/)
 }
 for(const key of ['ui.setup.authority.failed', 'ui.setup.authority.rolledBack']) {
  expect(c[key]).toContain('{step}')
  expect(c[key]).toContain('{access}')
 }
 // Each refusal reason says its own thing, never the generic sentence.
 const texts = UNSAFE.map(code => c[`mail.setup.unsafe.${code}`])
 expect(new Set(texts).size).toBe(UNSAFE.length)
 expect(texts).not.toContain(c['mail.setup.integrationUnavailable'])
 expect(c['ui.remove.item.receiveDNS']).toMatch(/MX/)
 expect(c['ui.remove.item.receiveDNS']).toMatch(/SPF/)
})

test('a new token given in the diagnosis clears the Overview line and the token card at once', async () => {
 let invalid = true
 const h = open({
  'mail.inbound.status': () => ({setups: [kept({tokenInvalid: invalid})]}),
  'mail.diagnose.start': {id: 'run', symptom: 'cannot-send', done: 0, total: 1, checks: ['mail.diag.relay'], findings: [], complete: false},
  'mail.diagnose.next': {id: 'run', symptom: 'cannot-send', done: 1, total: 1, checks: ['mail.diag.relay'], findings: [], complete: true,
   summary: {verdict: 'problems', problems: [{key: 'token_invalid', severity: 'critical', action: 'token', targets: ['example.com'], findings: ['mail.diag.relay.token_invalid']}], others: []}},
  'mail.inbound.token': (p: Record<string, unknown>) => {invalid = !p.token; return kept({tokenInvalid: invalid})},
 })
 try {
  await settle()
  expect(h.section()!.querySelector('[data-token-invalid]')).not.toBeNull()
  click(buttonText(h.catalog['ui.overview.start']!, h.root.querySelector('[data-section="diagnose"]')!)); await settle()
  const radio = [...document.querySelectorAll<HTMLElement>('[role=radio],input[type=radio]')].find(r => (r.closest('label') ?? r).textContent?.includes(h.catalog['mail.diag.symptom.cannot-send']!))
  click(radio ?? null); await settle()
  click(buttonText(h.catalog['ui.wizard.next'] ?? '下一步') ?? [...document.querySelectorAll('[role=dialog] button')].find(b => /下一步|Next/.test(b.textContent ?? '')) ?? null); await settle()
  const card = document.querySelector('[data-problem="token_invalid"]')!
  click(card.querySelector('[data-action="token"]')); await settle()
  const input = document.querySelector<HTMLInputElement>('[data-new-token] input, input[data-new-token]')!
  input.value = SECRET; input.dispatchEvent(new Event('input', {bubbles: true})); await settle()
  const reads = h.params('mail.inbound.status').length
  click(document.querySelector('[data-token-save]')); await settle()
  expect(h.params('mail.inbound.token')).toEqual([{id: ID, token: SECRET}])
  // The diagnosis: the card is gone, the saved line shows, the verdict is clear.
  expect(document.querySelector('[data-problem="token_invalid"]')).toBeNull()
  expect(document.querySelector('[role=dialog] [data-token-saved]')?.textContent).toContain('example.com')
  expect(document.querySelector('[role=dialog]')!.textContent).toContain(h.catalog['ui.diag.verdict.clear'])
  // The Overview read the kept setups again: its red line is gone, without a reload.
  expect(h.params('mail.inbound.status').length).toBeGreaterThan(reads)
  expect(h.section()!.querySelector('[data-token-invalid]')).toBeNull()
  expect(document.body.innerHTML).not.toContain(SECRET)
 } finally {h.close()}
})

test('a domain set up again drops its "removed" notice without a restart', async () => {
 const again = 'a'.repeat(32)
 let setups: unknown[] = [kept({removes: ['ui.remove.item.receiveAddresses', 'ui.remove.item.receiveDNS', 'ui.remove.item.token']})]
 const h = open({
  'mail.inbound.status': () => ({setups}),
  'mail.cloudflare.remove': () => {setups = []; return kept({removal: {state: 'done', done: 3, total: 3}})},
 })
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  // The confirm dialog names the subdomain's receiving records.
  expect(document.querySelector('[data-remove-confirm]')!.textContent).toContain(h.catalog['ui.remove.item.receiveDNS'])
  click(document.querySelector('[data-confirm-remove]')); await settle()
  const notice = h.catalog['ui.remove.done']!.replace('{domain}', 'example.com')
  expect(h.section()!.querySelector('[data-remove-result]')?.textContent).toBe(notice)

  // The same domain is set up again (a new kept setup); the Overview reads it after the wizard.
  setups = [kept({id: again})]
  click(buttonText(h.catalog['ui.overview.start']!, h.root.querySelector('[data-section="setup"]')!)); await settle()
  const dialog = document.querySelector('[role=dialog]')!
  click(dialog.querySelector('button[aria-label]:not([aria-label=""])')); await settle()
  expect(document.querySelector('[role=dialog]')).toBeNull()
  expect(h.section()!.querySelector('[data-remove-result]')).toBeNull()
  expect(h.section()!.querySelector(`[data-inbound="${again}"]`)).not.toBeNull()
 } finally {h.close()}
})
