// @vitest-environment jsdom
// The Overview's receiving section (owner decision 2026-11-13): how each
// kept setup receives through Cloudflare; for the listed mailboxes one "Sync
// mailboxes" button ("sync now"; build 50 also syncs in the worker by itself).
// Opening the Overview reads the package's records only. A pressed sync shows one result line, or the
// failure with Try again; a missing or refused token asks for one here.
import {afterEach, expect, test, vi} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const ID = 'd'.repeat(32)
const WHOLE = 'e'.repeat(32)

/** Visible copy: plain words, none of Cloudflare's product internals. */
const VISIBLE = ['ui.inbound.title', 'ui.inbound.body', 'ui.inbound.mode.domain', 'ui.inbound.mode.addresses', 'ui.inbound.hint', 'ui.inbound.lastSync', 'ui.inbound.autoSynced', 'ui.inbound.autoSyncedChanges',
 'ui.inbound.unsynced', 'ui.inbound.autoStopped', 'ui.inbound.held', 'ui.inbound.heldEmpty',
 ...['mailplus', 'stopped', 'changed', 'empty', 'approval'].map(c => `mail.inbound.auto.cause.${c}`),
 'ui.inbound.sync', 'ui.inbound.syncInfo', 'ui.inbound.syncInfoLabel', 'ui.inbound.syncing', 'ui.inbound.result', 'ui.inbound.inLine', 'ui.inbound.pending', 'ui.inbound.failed', 'ui.inbound.retry',
 'ui.inbound.tokenTitle', 'ui.inbound.tokenBody', 'ui.inbound.tokenHint', 'ui.inbound.saveToken',
 'mail.inbound.tokenRequired', ...['mailplus', 'token', 'gone', 'interrupted', 'cloudflare'].map(c => `mail.inbound.cause.${c}`),
 'mail.setup.receive.title', 'mail.setup.receive.domain', 'mail.setup.receive.domainBody', 'mail.setup.receive.addresses', 'mail.setup.receive.addressesBody',
 'mail.setup.receive.subdomain', 'mail.setup.receive.inUse', 'mail.setup.receive.domainUnsupported', 'mail.setup.receive.unknown',
 'mail.setup.receive.domainUnavailable', 'mail.setup.consequence.receiveDomain', 'mail.setup.mailboxesLater', 'mail.setup.cloudflare.oneRun']
const JARGON = /catch-?all|Email Routing|Worker(?!s)|VPC|tunnel|relay|規則轉寄|全收/i

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
 const ctx = dsmWindow({locale, call: call as never, t})
 const root = document.createElement('div'); document.body.append(root)
 const app = mount(root, ctx)
 const section = () => root.querySelector<HTMLElement>('[data-section="inbound"]')
 const methods = () => calls.map(c => c[0])
 const params = (m: string) => calls.filter(c => c[0] === m).map(c => c[1])
 return {root, section, methods, params, catalog, close() {app.unmount(); root.remove()}}
}
const kept = (extra: Record<string, unknown> = {}) => ({id: ID, domain: 'example.com', intent: 'both', receive: 'addresses', token: true, ...extra})
const whole = {id: WHOLE, domain: 'example.org', receive: 'domain', token: true}
function button(scope: ParentNode, sel: string) {return scope.querySelector<HTMLButtonElement>(sel)!}

test.each(locales)('every receiving key exists and is plain in %s', loc => {
 const c = catalogs[loc]!
 for(const key of VISIBLE) {
  expect(c[key], `${loc}: ${key}`).toBeTruthy()
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
 }
 expect(c['ui.inbound.result']).toContain('{added}')
 expect(c['ui.inbound.result']).toContain('{removed}')
 expect(c['ui.inbound.pending']).toContain('{list}')
 for(const k of ['ui.inbound.sync', 'ui.inbound.retry', 'mail.setup.receive.domain', 'mail.setup.receive.addresses']) expect(c[k]!.length, `${loc}: ${k}`).toBeLessThan(45)
 expect(c['ui.inbound.hint']!.length).toBeLessThan(110)
 expect(c['mail.setup.receive.subdomain']!.length).toBeLessThan(140)
 // The owner's own words in Traditional Chinese.
 if(loc === 'zh-TW') {
  expect(c['mail.setup.receive.domain']).toBe('整個網域自動收信')
  expect(c['mail.setup.receive.addresses']).toBe('指定信箱')
  expect(c['mail.setup.receive.subdomain']).toBe('需要使用主網域（例如 example.com），子網域無法整個代收')
  expect(c['ui.inbound.sync']).toBe('同步信箱')
  expect(c['ui.inbound.hint']).toBe('新增或刪除 MailPlus 使用者後，約 10 分鐘內會自動同步；按這裡可立即同步')
  expect(c['ui.inbound.retry']).toBe('再試一次')
 }
})

test('opening the Overview syncs nothing: it reads the records and shows each way of receiving', async () => {
 const h = open({'mail.inbound.status': {setups: [kept(), whole]}})
 try {
  await settle()
  const s = h.section()!
  expect(s.textContent).toContain('Cloudflare 上的設定')
  expect(h.methods()).toContain('mail.inbound.status')
  expect(h.methods()).not.toContain('mail.inbound.sync')
  expect(h.methods().filter(m => m === 'mail.inbound.status')).toHaveLength(1)
  const addresses = s.querySelector(`[data-inbound="${ID}"]`)!
  expect(addresses.querySelector('[data-mode]')?.textContent).toContain('指定信箱')
  // The hint is the Sync button's tooltip and description, not a line of its own.
  expect(button(addresses, '[data-sync]').getAttribute('aria-description')).toBe('新增或刪除 MailPlus 使用者後，約 10 分鐘內會自動同步；按這裡可立即同步')
  expect(s.textContent).not.toContain('新增或刪除 MailPlus 使用者後')
  expect(button(addresses, '[data-sync]').textContent).toBe('同步信箱')
  // Everything is fine: one row per domain, nothing under it.
  expect(addresses.querySelectorAll('[role=alert], [data-sync-pending], [data-sync-result]')).toHaveLength(0)
  const domain = s.querySelector(`[data-inbound="${WHOLE}"]`)!
  expect(domain.querySelector('[data-mode]')?.textContent).toContain('整個網域自動收信')
  expect(domain.querySelector('[data-sync]')).toBeNull()
  expect(s.textContent).not.toMatch(JARGON)
 } finally {h.close()}
})

test('a listed-mailbox row explains Sync mailboxes with an info mark: what it does, once, and when again', async () => {
 const h = open({'mail.inbound.status': {setups: [kept(), whole]}})
 try {
  await settle()
  const s = h.section()!
  const addresses = s.querySelector(`[data-inbound="${ID}"]`)!
  // The mark sits on the row's sync line and is named for screen readers.
  const mark = addresses.querySelector<HTMLElement>('.msa-kept-main [data-sync-info]')
  expect(mark).not.toBeNull()
  const trigger = mark!.matches('button') ? mark! : mark!.querySelector<HTMLElement>('button')!
  expect(trigger.getAttribute('aria-label')).toBe('關於同步信箱')
  // Hover or tap shows the plain explanation.
  trigger.focus(); trigger.dispatchEvent(new PointerEvent('pointerenter', {bubbles: true})); trigger.click()
  await new Promise(r => setTimeout(r, 400)); await settle()
  expect(document.body.textContent).toContain(h.catalog['ui.inbound.syncInfo'])
  // A whole-domain setup has nothing to sync, so no mark.
  expect(s.querySelector(`[data-inbound="${WHOLE}"] [data-sync-info]`)).toBeNull()
 } finally {h.close()}
})

test('the sync explanation says what syncing does, that once is enough, when to sync again, and that automatic sync does it', () => {
 const en = catalogs.en!['ui.inbound.syncInfo']!
 expect(en).toMatch(/tells Cloudflare which MailPlus mailboxes should receive mail/)
 expect(en).toMatch(/One sync is enough/)
 expect(en).toMatch(/only when mailbox accounts are added or removed/)
 expect(en).toMatch(/automatic sync is on, it does this for you/)
 const tw = catalogs['zh-TW']!['ui.inbound.syncInfo']!
 for(const part of ['哪些 MailPlus 信箱要收信', '同步一次就夠了', '新增或刪除信箱帳號', '自動同步']) expect(tw).toContain(part)
})

test('no kept setup on Cloudflare: no section', async () => {
 const h = open({'mail.inbound.status': {setups: []}})
 try {await settle(); expect(h.section()).toBeNull()}
 finally {h.close()}
})

test('a setup that only sends is listed for removal, without Sync', async () => {
 const h = open({'mail.inbound.status': {setups: [{id: ID, domain: 'example.com', token: true}]}})
 try {
  await settle()
  const row = h.section()!.querySelector(`[data-inbound="${ID}"]`)!
  expect(row.querySelector('[data-mode]')?.textContent).toContain('透過 Cloudflare 寄信')
  expect(row.querySelector('[data-sync]')).toBeNull()
  expect(row.querySelector('[data-remove]')).not.toBeNull()
 } finally {h.close()}
})

test('pressing Sync shows one result line', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': kept({last: {state: 'done', added: 2, removed: 1, pending: 0}})})
 try {
  await settle()
  button(h.section()!, '[data-sync]').click(); await settle()
  expect(h.params('mail.inbound.sync')).toEqual([{id: ID}])
  expect(h.section()!.querySelector('[data-sync-result]')?.textContent).toBe('已新增 2、移除 1 個信箱')
 } finally {h.close()}
})

test('a sync already in line says nothing changed; mailboxes still pending are named', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': kept({last: {state: 'done', added: 0, removed: 0, pending: 1, addresses: ['dave@example.com']}})})
 try {
  await settle()
  button(h.section()!, '[data-sync]').click(); await settle()
  expect(h.section()!.querySelector('[data-sync-result]')?.textContent).toBe('信箱都已同步，沒有需要變更的')
  expect(h.section()!.querySelector('[data-sync-pending]')?.textContent).toContain('dave@example.com')
 } finally {h.close()}
})

test('a run still going in the worker shows progress and is asked for again until it ends', async () => {
 let polls = 0
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': (p: Record<string, unknown>) => {
   if(!p.poll) return kept({last: {state: 'running', added: 0, removed: 0, pending: 0}})
   return ++polls < 2 ? kept({last: {state: 'running', added: 0, removed: 0, pending: 0}}) : kept({last: {state: 'done', added: 1, removed: 0, pending: 0}})
  }})
 try {
  await settle()
  vi.useFakeTimers()
  button(h.section()!, '[data-sync]').click(); await settle()
  expect(h.section()!.textContent).toContain('正在同步信箱')
  expect(button(h.section()!, '[data-sync]').disabled).toBe(true)
  await vi.advanceTimersByTimeAsync(2000); await settle()
  await vi.advanceTimersByTimeAsync(2000); await settle()
  vi.useRealTimers()
  expect(h.params('mail.inbound.sync')).toEqual([{id: ID}, {id: ID, poll: true}, {id: ID, poll: true}])
  expect(h.section()!.querySelector('[data-sync-result]')?.textContent).toBe('已新增 1、移除 0 個信箱')
 } finally {h.close()}
})

test('a failed run shows why, with Try again', async () => {
 let runs = 0
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': () => ++runs === 1 ? kept({last: {state: 'failed', added: 0, removed: 0, pending: 0, causeKey: 'mail.inbound.cause.mailplus'}})
   : kept({last: {state: 'done', added: 0, removed: 1, pending: 0}})})
 try {
  await settle()
  button(h.section()!, '[data-sync]').click(); await settle()
  const failed = h.section()!.querySelector('[data-sync-failed]')!
  expect(failed.textContent).toContain('讀不到 MailPlus Server 的使用者')
  expect(button(failed, '[data-retry]').textContent).toBe('再試一次')
  button(failed, '[data-retry]').click(); await settle()
  expect(h.section()!.querySelector('[data-sync-failed]')).toBeNull()
  expect(h.section()!.querySelector('[data-sync-result]')?.textContent).toBe('已新增 0、移除 1 個信箱')
 } finally {h.close()}
})

test('a refused call shows the error with Try again', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': {__throw: {code: 'unavailable', details: {reason: 'mail.setup.cloudflareUnavailable'}}}})
 try {
  await settle()
  button(h.section()!, '[data-sync]').click(); await settle()
  const e = h.section()!.querySelector('[data-sync-error]')!
  expect(e.textContent).not.toContain('mail.setup.')
  expect(button(e, '[data-retry]')).toBeTruthy()
 } finally {h.close()}
})

test('a missing or refused token asks for one; the pasted token is sent once, then the sync runs', async () => {
 let sealed = false
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': () => sealed ? kept({last: {state: 'done', added: 1, removed: 0, pending: 0}})
   : kept({last: {state: 'failed', added: 0, removed: 0, pending: 0, causeKey: 'mail.inbound.cause.token'}}),
  'mail.inbound.token': (p: Record<string, unknown>) => {sealed = !!p.token; return kept({token: sealed})}})
 try {
  await settle()
  expect(h.section()!.querySelector('[data-token-ask]')).toBeNull()
  button(h.section()!, '[data-sync]').click(); await settle()
  const ask = h.section()!.querySelector('[data-token-ask]')!
  expect(ask.textContent).toContain('需要 Cloudflare 權杖')
  expect(ask.querySelector('[data-create-token]')).not.toBeNull()
  expect(h.section()!.querySelector('[data-sync-failed]')).toBeNull()
  const input = h.section()!.querySelector<HTMLInputElement>('[data-inbound-token] input, input[data-inbound-token]')!
  expect(input.type).toBe('password')
  input.value = ' fixture-token '; input.dispatchEvent(new Event('input', {bubbles: true})); await settle()
  button(h.section()!, '[data-save-token]').click(); await settle()
  expect(h.params('mail.inbound.token')).toEqual([{id: ID, token: 'fixture-token'}])
  expect(h.params('mail.inbound.sync')).toHaveLength(2)
  expect(h.section()!.querySelector('[data-token-ask]')).toBeNull()
  expect(h.section()!.querySelector('[data-sync-result]')?.textContent).toBe('已新增 1、移除 0 個信箱')
  expect(h.root.textContent).not.toContain('fixture-token')
 } finally {h.close()}
})

test('the tokenRequired refusal asks for a token too; there is no Forget token on the Overview', async () => {
 const h = open({'mail.inbound.status': {setups: [kept()]},
  'mail.inbound.sync': {__throw: {code: 'unavailable', details: {reason: 'mail.inbound.tokenRequired'}}}})
 try {
  await settle()
  expect(h.section()!.querySelector('[data-forget-token]')).toBeNull()
  expect(h.section()!.textContent).not.toContain('忘記權杖')
  button(h.section()!, '[data-sync]').click(); await settle()
  expect(h.section()!.querySelector('[data-token-ask]')).not.toBeNull()
  expect(h.section()!.querySelector('[data-sync-error]')).toBeNull()
 } finally {h.close()}
})

test('the last sync shows as its time in the row; a fresh result goes back to the time after a while', async () => {
 const at = Math.floor(new Date(2026, 10, 13, 14, 5).getTime() / 1000)
 vi.useFakeTimers({toFake: ['setTimeout', 'clearTimeout', 'Date']}); vi.setSystemTime(new Date(2026, 10, 13, 15, 0))
 const h = open({'mail.inbound.status': {setups: [kept({last: {state: 'done', added: 0, removed: 0, pending: 0, at}})]},
  'mail.inbound.sync': kept({last: {state: 'done', added: 1, removed: 0, pending: 0, at}})})
 try {
  await settle()
  const row = () => h.section()!.querySelector(`[data-inbound="${ID}"]`)!
  expect(row().querySelector('[data-last-sync]')?.textContent).toBe('上次同步：14:05')
  expect(row().querySelector('[data-sync-result]')).toBeNull()
  button(h.section()!, '[data-sync]').click(); await settle()
  expect(row().querySelector('[data-sync-result]')?.textContent).toBe('已新增 1、移除 0 個信箱')
  await vi.advanceTimersByTimeAsync(10_000); await settle()
  expect(row().querySelector('[data-sync-result]')).toBeNull()
  expect(row().querySelector('[data-last-sync]')).not.toBeNull()
 } finally {h.close()}
})

// The row says how many mailboxes the setup syncs, from the
// stored record only; after a sync that changed something, what it added and
// removed; the whole-domain row says it receives for every address instead.
test('the row says how many mailboxes it syncs, with the last change, from the record only', async () => {
 const at = Math.floor(new Date(2026, 10, 16, 16, 47).getTime() / 1000)
 vi.useFakeTimers({toFake: ['setTimeout', 'clearTimeout', 'Date']}); vi.setSystemTime(new Date(2026, 10, 16, 17, 0))
 const h = open({'mail.inbound.status': {setups: [
  kept({synced: {mailboxes: 5, added: 2, removed: 1, at}}),
  {...kept({synced: {mailboxes: 3, at}}), id: 'f'.repeat(32), domain: 'example.net'},
  whole]}})
 try {
  await settle()
  // Nothing but the records is read: no sync, no Cloudflare call.
  expect(h.methods().filter(m => m.startsWith('mail.inbound.') || m.startsWith('mail.cloudflare.'))).toEqual(['mail.inbound.status'])
  const text = (id: string) => h.section()!.querySelector(`[data-inbound="${id}"] .msa-quiet`)!.textContent!.replace(/\s+/g, ' ').trim()
  expect(text(ID)).toBe('指定信箱 · 自動同步 5 個信箱（＋2／－1） · 上次同步：16:47')
  expect(text('f'.repeat(32))).toBe('指定信箱 · 自動同步 3 個信箱 · 上次同步：16:47')
  expect(text(WHOLE)).toBe('整個網域自動收信')
  expect(h.section()!.querySelector(`[data-inbound="${WHOLE}"] [data-synced]`)).toBeNull()
 } finally {h.close()}
})

test('only additions or only removals show alone; other locales word it too', async () => {
 const h = open({'mail.inbound.status': {setups: [kept({synced: {mailboxes: 1, removed: 2}})]}}, 'en')
 try {
  await settle()
  expect(h.section()!.querySelector('[data-synced]')?.textContent).toBe('Syncs 1 mailboxes automatically (−2)')
 } finally {h.close()}
})

test('just after a sync the count stays and the fresh result says what changed (no repeat)', async () => {
 const at = Math.floor(new Date(2026, 10, 16, 16, 47).getTime() / 1000)
 const h = open({'mail.inbound.status': {setups: [kept({synced: {mailboxes: 2, at}})]},
  'mail.inbound.sync': kept({last: {state: 'done', added: 1, removed: 0, pending: 0, at}, synced: {mailboxes: 3, added: 1, at}})})
 try {
  await settle()
  button(h.section()!, '[data-sync]').click(); await settle()
  const row = h.section()!.querySelector(`[data-inbound="${ID}"]`)!
  expect(row.querySelector('[data-synced]')?.textContent).toBe('自動同步 3 個信箱')
  expect(row.querySelector('[data-sync-result]')?.textContent).toBe('已新增 1、移除 0 個信箱')
 } finally {h.close()}
})

// The row says the sync is automatic, the
// last time is the latest automatic check, and what the automatic sync could
// not do shows as a warning with its reason.
test('the automatic check is the last sync time; failures and holds show as warnings', async () => {
 const at = Math.floor(new Date(2026, 10, 16, 16, 47).getTime() / 1000)
 const checked = Math.floor(new Date(2026, 10, 16, 17, 53).getTime() / 1000)
 vi.useFakeTimers({toFake: ['setTimeout', 'clearTimeout', 'Date']}); vi.setSystemTime(new Date(2026, 10, 16, 18, 0))
 const id = (c: string) => c.repeat(32)
 const h = open({'mail.inbound.status': {setups: [
  kept({synced: {mailboxes: 3, at}, auto: {state: 'ok', checkedAt: checked}}),
  {...kept({synced: {mailboxes: 3, at}, auto: {state: 'failing', causeKey: 'mail.inbound.auto.cause.stopped', unsynced: 1}}), id: id('1'), domain: 'a.example'},
  {...kept({synced: {mailboxes: 3, at}, auto: {state: 'failing', causeKey: 'mail.inbound.auto.cause.stopped'}}), id: id('2'), domain: 'b.example'},
  {...kept({synced: {mailboxes: 3, at}, auto: {state: 'stopped', causeKey: 'mail.inbound.auto.cause.changed'}}), id: id('3'), domain: 'c.example'},
  {...kept({synced: {mailboxes: 6, at}, auto: {state: 'ok', held: 3, checkedAt: checked}}), id: id('4'), domain: 'd.example'},
  {...kept({synced: {mailboxes: 2, at}, auto: {state: 'failing', causeKey: 'mail.inbound.auto.cause.empty', held: 2}}), id: id('5'), domain: 'e.example'},
 ]}})
 try {
  await settle()
  const row = (i: string) => h.section()!.querySelector(`[data-inbound="${i}"]`)!
  const notice = (i: string) => row(i).querySelector('[data-auto-notice]')?.textContent?.trim()
  expect(row(ID).querySelector('[data-last-sync]')?.textContent).toBe('上次同步：17:53')
  expect(notice(ID)).toBeUndefined()
  expect(notice(id('1'))).toBe('有 1 個信箱尚未同步：MailPlus Server 沒有在執行（可能正在更新或重新啟動）')
  // Failing with nothing waiting: nothing to say.
  expect(notice(id('2'))).toBeUndefined()
  expect(notice(id('3'))).toBe('自動同步已暫停：MailPlus Server 的回應和預期的格式不同（可能剛更新過）。確認 MailPlus Server 正常後，請按「同步信箱」')
  expect(notice(id('4'))).toContain('按「同步信箱」會刪除這 3 條規則')
  expect(notice(id('5'))).toBe('MailPlus Server 回報這個網域沒有任何信箱，所以自動同步沒有刪除任何規則。若確實如此，按「同步信箱」會刪除全部 2 條規則')
  for(const i of [id('1'), id('3'), id('4')]) expect(row(i).querySelector('[data-auto-notice]')!.closest('[class]')!.outerHTML).toMatch(/warning/)
 } finally {h.close()}
})

test('a refused token still says how many mailboxes wait', async () => {
 const h = open({'mail.inbound.status': {setups: [kept({tokenInvalid: true, relay: true, synced: {mailboxes: 2},
  auto: {state: 'failing', causeKey: 'mail.inbound.cause.token', unsynced: 2}})]}})
 try {
  await settle()
  expect(h.section()!.querySelector('[data-token-invalid]')).not.toBeNull()
  expect(h.section()!.querySelector('[data-auto-notice]')).toBeNull()
  expect(h.section()!.querySelector('[data-auto-unsynced]')?.textContent?.trim()).toBe('有 2 個信箱尚未同步：Cloudflare 不接受保存的權杖')
 } finally {h.close()}
})

test('the component never starts a sync by itself', () => {
 const src = readFileSync(join(__dirname, '../src/components/InboundSection.vue'), 'utf8')
 // The only sync call is inside sync(), reached from a button.
 expect(src.match(/'mail\.inbound\.sync'/g)).toHaveLength(2)
 expect(src).not.toMatch(/onMounted|setInterval|watch\(/)
 const page = readFileSync(join(__dirname, '../src/pages/OverviewPage.vue'), 'utf8')
 expect(page).not.toContain('mail.inbound.sync')
})
