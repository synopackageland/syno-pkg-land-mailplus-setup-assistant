// @vitest-environment jsdom
// "Remove Cloudflare setup" on the Overview (owner request 2026-11-13):
// a danger action per kept setup. The confirm dialog lists, in plain words,
// what is removed or put back; the option to also turn off Cloudflare
// receiving is offered (unticked) only when this setup turned it on. The
// removal runs in the worker: progress, then the result or why it stopped
// with Try again; a refused or missing token asks for one like the setup.
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const ID = 'd'.repeat(32)
const ITEMS = ['receiveDomain', 'receiveAddresses', 'sending', 'dns', 'mailplus', 'relay', 'token'].map(i => `ui.remove.item.${i}`)
const VISIBLE = ['ui.remove.action', 'ui.remove.title', 'ui.remove.body', 'ui.remove.kept', 'ui.remove.routing', 'ui.remove.routingBody',
 'ui.remove.cancel', 'ui.remove.confirm', 'ui.remove.running', 'ui.remove.done', 'ui.remove.failed', 'ui.remove.saveToken', 'ui.remove.uninstall', 'ui.remove.short',
 'ui.inbound.mode.send', ...ITEMS, 'ui.remove.access', ...['record', 'changed', 'nas', 'authority', 'admin', 'mailplus', 'relay'].map(c => `mail.remove.cause.${c}`)]
const JARGON = /catch-?all|Email Routing|Worker(?!s)|VPC|tunnel|relay|journal|snapshot|規則轉寄|全收/i

async function settle() {for(let i = 0; i < 30; i++) {await Promise.resolve(); await nextTick()}}
afterEach(() => {document.body.innerHTML = ''; vi.useRealTimers()})

type Reply = unknown | ((p: Record<string, unknown>) => unknown)
function open(replies: Record<string, Reply>) {
 const catalog = catalogs['zh-TW']!
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
 const app = mount(root, dsmWindow({locale: 'zh-TW', call: call as never, t}))
 const section = () => root.querySelector<HTMLElement>('[data-section="inbound"]')
 const dialog = () => document.querySelector<HTMLElement>('[data-remove-confirm]')
 const params = (m: string) => calls.filter(c => c[0] === m).map(c => c[1])
 return {root, section, dialog, params, close() {app.unmount(); root.remove()}}
}
const REMOVES = ['ui.remove.item.receiveAddresses', 'ui.remove.item.mailplus', 'ui.remove.item.relay', 'ui.remove.item.token']
const kept = (extra: Record<string, unknown> = {}) => ({id: ID, domain: 'example.com', intent: 'both', receive: 'addresses', token: true, removes: REMOVES, ...extra})
const run = (state: string, done: number, extra: Record<string, unknown> = {}) => ({state, done, total: 5, ...extra})
function click(el: Element | null) {expect(el).not.toBeNull(); (el as HTMLElement).click()}
function confirmButton() {return document.querySelector<HTMLButtonElement>('[data-confirm-remove]')}

test.each(locales)('every removal key exists and is plain in %s', loc => {
 const c = catalogs[loc]!
 for(const key of VISIBLE) {
  expect(c[key], `${loc}: ${key}`).toBeTruthy()
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
 }
 expect(c['ui.remove.title']).toContain('{domain}')
 expect(c['ui.remove.done']).toContain('{domain}')
 expect(c['ui.remove.running']).toContain('{done}')
 expect(c['ui.remove.running']).toContain('{total}')
 expect(c['ui.remove.failed']).toContain('{cause}')
 expect(c['ui.remove.access']).toContain('{profile}')
 expect(c['ui.remove.action']!.length).toBeLessThan(45)
 if(loc === 'zh-TW') {
  expect(c['ui.remove.action']).toBe('移除 Cloudflare 設定')
  expect(c['ui.remove.routing']).toBe('同時關閉此網域的 Cloudflare 收信')
  expect(c['ui.remove.uninstall']).toBe('解除安裝 App 不會移除 Cloudflare 上的這些設定；要撤銷只能在這裡移除')
  expect(c['ui.inbound.body']).toBe('透過 Cloudflare 收發信的網域。解除安裝不會移除這些設定；要撤銷請按「移除」')
  expect(c['ui.remove.short']).toBe('移除…')
 }
})

test('the confirm dialog lists what is removed; Cancel removes nothing', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]}})
 try {
  await settle()
  const s = h.section()!
  // The uninstall note is part of the section description (and the dialog), not a line of its own.
  expect(s.textContent).toContain('解除安裝不會移除這些設定；要撤銷請按「移除」')
  expect(s.querySelector('[data-uninstall-note]')).toBeNull()
  // A quiet "Remove…" in the row; the danger styling is in the confirm dialog.
  const removeButton = s.querySelector<HTMLElement>('[data-remove]')!
  expect(removeButton.textContent?.trim()).toBe('移除…')
  expect(removeButton.getAttribute('aria-label')).toBe('移除 Cloudflare 設定')
  expect(removeButton.className).not.toMatch(/danger/)
  click(s.querySelector('[data-remove]')); await settle()
  const d = h.dialog()!
  expect(document.body.textContent).toContain('要移除 example.com 的 Cloudflare 設定嗎？')
  expect([...d.querySelectorAll('[data-item]')].map(li => li.getAttribute('data-item'))).toEqual(REMOVES)
  expect(d.querySelector('[data-item="ui.remove.item.relay"]')?.textContent).toBe('關閉這個 App 的郵件轉發服務')
  expect(d.querySelector('[data-remove-kept]')?.textContent).toContain('Cloudflare 上的其他設定不會變動')
  expect(d.querySelector('[data-uninstall-note]')?.textContent).toBe('解除安裝 App 不會移除 Cloudflare 上的這些設定；要撤銷只能在這裡移除')
  expect(d.querySelector('[data-remove-routing]')).toBeNull()
  expect(d.textContent).not.toMatch(JARGON)
  click(document.querySelector('[data-remove-cancel]')); await settle()
  expect(h.dialog()).toBeNull()
  expect(h.params('mail.cloudflare.remove')).toEqual([])
 } finally {h.close()}
})

test('turning Cloudflare receiving off is offered only when this setup turned it on, unticked', async () => {
 const h = open({'mail.inbound.status': {setups: [kept({routingOwned: true})]},
  'mail.cloudflare.remove': kept({routingOwned: true, removal: run('done', 5)})})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  const box = h.dialog()!.querySelector<HTMLButtonElement>('[data-remove-routing][role=checkbox]')!
  expect(box.getAttribute('aria-checked')).toBe('false')
  expect(h.dialog()!.textContent).toContain('同時關閉此網域的 Cloudflare 收信')
  expect(h.dialog()!.textContent).toContain('MX 與 SPF')
  click(confirmButton()); await settle()
  expect(h.params('mail.cloudflare.remove')).toEqual([{id: ID}])
 } finally {h.close()}
 // Ticked: sent with the removal.
 const g = open({'mail.inbound.status': {setups: [kept({routingOwned: true})]},
  'mail.cloudflare.remove': kept({routingOwned: true, removal: run('done', 6)})})
 try {
  await settle()
  click(g.section()!.querySelector('[data-remove]')); await settle()
  const box = g.dialog()!.querySelector<HTMLButtonElement>('[data-remove-routing][role=checkbox]')!
  box.click(); await settle()
  click(confirmButton()); await settle()
  expect(g.params('mail.cloudflare.remove')).toEqual([{id: ID, routing: true}])
 } finally {g.close()}
})

test('a removal shows its progress, then the result; the setup leaves the list', async () => {
 let polls = 0
 let listed = true
 const h = open({'mail.inbound.status': () => ({setups: listed ? [kept()] : []}),
  'mail.cloudflare.remove': (p: Record<string, unknown>) => {
   if(!p.poll) return kept({removal: run('running', 1)})
   if(++polls < 2) return kept({removal: run('running', 3)})
   listed = false
   return kept({removal: run('done', 5)})
  }})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  vi.useFakeTimers()
  click(confirmButton()); await settle()
  expect(h.section()!.textContent).toContain('正在移除 Cloudflare 設定（1/5）')
  expect(h.section()!.querySelector('[data-remove-progress]')).not.toBeNull()
  expect(h.section()!.querySelector<HTMLButtonElement>('[data-remove]')!.disabled).toBe(true)
  await vi.advanceTimersByTimeAsync(2000); await settle()
  expect(h.section()!.textContent).toContain('（3/5）')
  await vi.advanceTimersByTimeAsync(2000); await settle()
  vi.useRealTimers(); await settle()
  expect(h.params('mail.cloudflare.remove')).toEqual([{id: ID}, {id: ID, poll: true}, {id: ID, poll: true}])
  expect(h.section()!.querySelector('[data-remove-result]')?.textContent).toBe('已移除 example.com 的 Cloudflare 設定，MailPlus Server 也已還原成設定前的樣子')
  expect(h.section()!.querySelector(`[data-inbound="${ID}"]`)).toBeNull()
 } finally {h.close()}
})

test('a stopped removal says why, and Try again goes on with the same choice', async () => {
 let runs = 0
 const h = open({'mail.inbound.status': {setups: [kept({routingOwned: true})]},
  'mail.cloudflare.remove': () => ++runs === 1 ? kept({routingOwned: true, removal: run('failed', 2, {causeKey: 'mail.remove.cause.nas'})})
   : kept({routingOwned: true, removal: run('done', 6)})})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  h.dialog()!.querySelector<HTMLButtonElement>('[data-remove-routing][role=checkbox]')!.click(); await settle()
  click(confirmButton()); await settle()
  const failed = h.section()!.querySelector('[data-remove-failed]')!
  expect(failed.textContent).toContain('這台 NAS 上的設定（MailPlus Server 或郵件轉發服務）無法還原')
  expect(failed.textContent).toContain('已完成的部分不會重做')
  click(failed.querySelector('[data-remove-retry]')); await settle()
  expect(h.params('mail.cloudflare.remove')).toEqual([{id: ID, routing: true}, {id: ID, routing: true}])
  expect(h.section()!.querySelector('[data-remove-result]')).not.toBeNull()
 } finally {h.close()}
})

// A MailPlus Server restore the executor refused for want of MailPlus change
// access: the line names the access, not the generic "NAS setting", and
// offers "Allow access" as the setup does; Try again then goes on.
test('a removal stopped for want of MailPlus change access offers Allow access, then goes on', async () => {
 let runs = 0
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.cloudflare.remove': () => ++runs === 1 ? kept({removal: run('failed', 0, {causeKey: 'mail.remove.cause.authority', profile: 'mail-write'})})
   : kept({removal: run('done', 5)})})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  click(confirmButton()); await settle()
  const failed = h.section()!.querySelector('[data-remove-failed]')!
  expect(failed.textContent).toContain('還原 MailPlus Server 需要「MailPlus 變更權」')
  expect(failed.textContent).not.toContain('MailPlus Server 或郵件轉發服務')
  const allow = failed.querySelector('[data-remove-access]')
  expect(allow?.textContent?.trim()).toBe('允許存取')
  click(allow); await settle()
  expect(document.body.textContent).toContain(catalogs['zh-TW']!['ui.authority.consentTitle']!)
  // Allowing access does not start the removal by itself.
  expect(h.params('mail.cloudflare.remove')).toHaveLength(1)
  click(failed.querySelector('[data-remove-retry]')); await settle()
  expect(h.params('mail.cloudflare.remove')).toEqual([{id: ID}, {id: ID}])
  expect(h.section()!.querySelector('[data-remove-result]')).not.toBeNull()
 } finally {h.close()}
})

test('a removal stopped by MailPlus Server or the forwarding service says which, with no Allow access', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.cloudflare.remove': kept({removal: run('failed', 1, {causeKey: 'mail.remove.cause.relay'})})})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  click(confirmButton()); await settle()
  const failed = h.section()!.querySelector('[data-remove-failed]')!
  expect(failed.textContent).toContain('這台 NAS 上的郵件轉發服務無法停止')
  expect(failed.querySelector('[data-remove-access]')).toBeNull()
 } finally {h.close()}
})

test('a refused permission asks for a token like the setup; after saving, Remove is pressed again', async () => {
 let sealed = false
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.cloudflare.remove': () => sealed ? kept({removal: run('done', 5)}) : kept({removal: run('failed', 0, {causeKey: 'mail.inbound.cause.token'})}),
  'mail.inbound.token': (p: Record<string, unknown>) => {sealed = !!p.token; return kept({token: sealed})}})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  click(confirmButton()); await settle()
  expect(h.section()!.querySelector('[data-remove-failed]')).toBeNull()
  const ask = h.section()!.querySelector('[data-token-ask]')!
  expect(ask.querySelector('[data-create-token]')).not.toBeNull()
  const input = h.section()!.querySelector<HTMLInputElement>('[data-inbound-token] input, input[data-inbound-token]')!
  input.value = 'fixture-token'; input.dispatchEvent(new Event('input', {bubbles: true})); await settle()
  expect(h.section()!.querySelector('[data-save-token]')?.textContent?.trim()).toBe('儲存權杖')
  click(h.section()!.querySelector('[data-save-token]')); await settle()
  expect(h.params('mail.inbound.token')).toEqual([{id: ID, token: 'fixture-token'}])
  // Saving does not start the removal by itself.
  expect(h.params('mail.cloudflare.remove')).toHaveLength(1)
  expect(h.section()!.querySelector('[data-token-ask]')).toBeNull()
  expect(h.root.textContent).not.toContain('fixture-token')
 } finally {h.close()}
})

test('without a sealed token the refusal asks for one', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.cloudflare.remove': {__throw: {code: 'unavailable', details: {reason: 'mail.inbound.tokenRequired'}}}})
 try {
  await settle()
  click(h.section()!.querySelector('[data-remove]')); await settle()
  click(confirmButton()); await settle()
  expect(h.section()!.querySelector('[data-token-ask]')).not.toBeNull()
  expect(h.section()!.querySelector('[data-sync-error]')).toBeNull()
 } finally {h.close()}
})
