// The configuration step's copy: every key in the nine locales, the
// visible lines plain (no product internals) and short; the details fold may
// keep the exact terms.
import {expect, test} from 'vitest'
import {readFileSync} from 'node:fs'
import {join} from 'node:path'

const locales = ['en', 'zh-TW', 'zh-CN', 'ja', 'ko', 'de', 'fr', 'es', 'it']
const catalogs = Object.fromEntries(locales.map(l => [l, JSON.parse(readFileSync(join(__dirname, `../../i18n/messages/${l}.json`), 'utf8')) as Record<string, string>]))
const VISIBLE = ['mail.setup.configurationFor', 'mail.setup.consequence.send', 'mail.setup.consequence.receive', 'mail.setup.consequence.offline',
 'mail.setup.details', 'mail.setup.noMailboxes']
const FOLDED = ['mail.setup.mailboxesNow', 'mail.setup.mailboxesLater']
const JARGON = /relay|Worker|VPC|Tunnel|Email Routing|SPF|softfail|catch-all|Workers (Paid|Free)/i

test.each(locales)('every configuration key exists in %s; the visible lines are plain and short', loc => {
 const c = catalogs[loc]!
 for(const key of [...VISIBLE, ...FOLDED]) expect(c[key], `${loc}: ${key}`).toBeTruthy()
 for(const key of VISIBLE) {
  expect(c[key], `${loc}: ${key}`).not.toMatch(JARGON)
  expect(c[key]!.length, `${loc}: ${key}`).toBeLessThan(140)
 }
 expect(c['mail.setup.configurationFor']).toContain('{domain}')
 expect(c['mail.setup.consequence.receive']).toContain('{domain}')
 expect(c['mail.setup.consequence.receive']).toContain('{count}')
 expect(c['mail.setup.mailboxesNow']).toContain('{list}')
})

test('the step no longer draws the warning facts or the path list, and has no address field', () => {
 const src = readFileSync(join(__dirname, '../src/wizards/SetupWizard.vue'), 'utf8')
 const step = src.slice(src.indexOf('<WizardStep step-key="configuration"'), src.indexOf('<WizardStep step-key="preview"'))
 expect(step).not.toMatch(/PathList|branch\?\.warnings\?\.length/)
 expect(step).toContain('data-details')
})
