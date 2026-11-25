// The facts and preview steps' copy: every key in the nine locales,
// placeholders kept, and the visible lines plain (no product internals); the
// details fold keeps the exact terms.
import {expect, test} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const SUMMARY = ['sendOn', 'sendVia', 'dkim', 'receiveOn', 'receiveProgram', 'receiveRules', 'receiveAll', 'smtpOn', 'dnsCloudflare', 'dnsExternal'].map(c => `mail.setup.summary.${c}`)
const PURPOSES = ['zoneRead', 'dnsEdit', 'sendingEdit', 'zoneSettingsEdit', 'routingRulesEdit', 'workersEdit', 'vpcAdmin', 'tunnelRead'].map(c => `mail.setup.purpose.${c}`)
const VISIBLE = ['mail.setup.previewFor', 'mail.setup.pathChanged.send', 'mail.setup.pathChanged.receive',
 'mail.setup.accountFor', 'mail.setup.account.found', 'mail.setup.account.foundParent', 'mail.setup.account.noMatch',
 'mail.setup.preview.permissions', 'mail.setup.preview.technical', ...SUMMARY, ...PURPOSES]
const FORMATS = ['mail.setup.preview.warning', 'mail.setup.preview.permission', 'mail.setup.inbound.relayNetworks', 'mail.setup.inbound.relayNetworksUnknown']
const JARGON = /relay|Worker|VPC|Tunnel|Email Routing|SPF|DKIM|softfail|catch-all|Workers (Paid|Free)|\bZone\b|STARTTLS/i
const PLACEHOLDERS: Record<string, string[]> = {
 'mail.setup.previewFor': ['{domain}'], 'mail.setup.summary.receiveRules': ['{count}'], 'mail.setup.summary.dnsCloudflare': ['{count}'],
 'mail.setup.summary.dnsExternal': ['{count}'], 'mail.setup.preview.warning': ['{text}', '{value}'], 'mail.setup.preview.permission': ['{purpose}', '{name}'],
 'mail.setup.accountFor': ['{domain}'], 'mail.setup.account.foundParent': ['{parent}'], 'mail.setup.inbound.relayNetworks': ['{count}'],
}

test.each(locales)('every facts/preview key exists in %s; the visible lines are plain and short', loc => {
 const c = catalogs[loc]!
 for(const key of [...VISIBLE, ...FORMATS]) expect(c[key], `${loc}: ${key}`).toBeTruthy()
 for(const key of VISIBLE) {
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
  expect(c[key]!.length, `${loc}: ${key}`).toBeLessThan(140)
 }
 for(const [key, names] of Object.entries(PLACEHOLDERS)) for(const name of names) expect(c[key], `${loc}: ${key}`).toContain(name)
 // A summary line names the system that changes, so the domain is never repeated per row.
 for(const key of SUMMARY) expect(c[key], `${loc}: ${key}`).not.toContain('{domain}')
 // The account step: the domain only in its headline, and no Cloudflare "zone" wording.
 for(const key of ['mail.setup.account.found', 'mail.setup.account.foundParent', 'mail.setup.account.noMatch']) {
  expect(c[key], `${loc}: ${key}`).not.toContain('{domain}')
  expect(c[key], `${loc}: ${key}`).not.toMatch(/zone\b|區域|区域|ゾーン|영역|Zone|zona/i)
 }
 // The relay client networks ask for no change (the inbound path cannot relay through them).
 for(const key of ['mail.setup.inbound.relayNetworks', 'mail.setup.inbound.relayNetworksUnknown']) expect(c[key], `${loc}: ${key}`).not.toMatch(/請確認|check that|vérifiez|prüfen|compruebe|verifica/i)
 expect(c['mail.setup.notice.relayNetworks'], loc).toBeUndefined()
})

const src = readFileSync(join(__dirname, '../src/wizards/SetupWizard.vue'), 'utf8')
const between = (from: string, to: string) => src.slice(src.indexOf(from), src.indexOf(to))

test('the facts step never echoes the chosen route', () => {
 const step = between('<WizardStep step-key="facts"', '<WizardStep v-if="stopShown')
 expect(step).not.toContain('PathList')
 expect(step).toContain('data-moved-paths')
 for(const echo of ['routeCloudflare', 'routeDirect', 'routeUnset']) expect(src).toContain(`'mail.setup.why.${echo}'`)
})

test('the preview step draws no raw FactList or ChangeList outside its details fold', () => {
 const step = between('<WizardStep step-key="preview"', '<WizardStep step-key="applying"')
 expect(step).not.toContain('FactList')
 const fold = step.slice(step.indexOf('<Accordion'), step.indexOf('</Accordion>'))
 expect(fold).toContain('<ChangeList')
 expect(step.replace(fold, '')).not.toContain('<ChangeList')
})

test('the configuration step no longer lists raw permissions', () => {
 const step = between('<WizardStep step-key="configuration"', '<WizardStep step-key="preview"')
 expect(step).not.toMatch(/permissionFacts|scope \/ resource/)
})
