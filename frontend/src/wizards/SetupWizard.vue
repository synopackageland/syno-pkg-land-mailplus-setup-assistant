<script setup lang="ts">
/**
 * mail.setup on the UI SDK Wizard.
 *
 * The browser owns the step flow; the worker owns detection, the exact plan,
 * the apply journal and the keep/rollback decision (mail.setup.* operations).
 * Branching after the facts follows the worker's BranchView.kind, so the
 * decision table stays in Go (backend/internal/mail/setup/branch.go).
 *
 *   [mailplus] → intent → start ─┬→ (A, own domain)  domain ───────────┐
 *                   └→ (B, Cloudflare)  cloudflare → zone ─┴→ detect → [prereq] → route → facts ─┬→ stop        (blocked | unavailable)
 *                                                                                                  ├→ already
 *                                                                                                  └→ [A: cloudflare → account]? → configuration → preview → applying → decision → result
 *   decision: one keep/roll-back choice + Confirm (roll back → applying → result)
 *   diagnose intent / branch → hands off to the diagnose wizard
 *
 * detect and applying are UI SDK progress steps: the wizard draws them, this
 * page watches the worker (one request at a time, only while the dialog is open
 * on that step) and moves on when the worker says the work ended. Terminal
 * steps are result steps whose tone follows the worker's outcome.
 *
 * start says where the domain comes from: A types its own domain (its DNS
 * managed by the administrator); B signs in to Cloudflare with one API token
 * (pasted once, sealed by the worker at once and dropped from the page) and
 * picks the account and the zone from Cloudflare's own lists. A reaches the
 * same token step and account step only when its branch needs Cloudflare;
 * nobody types an ID.
 *
 * The read-only detection starts as soon as the domain is chosen. prereq shows
 * only when MailPlus Server lacks something for this domain (the domain, a
 * licence, or an enabled mailbox for receiving): it says exactly what, opens
 * MailPlus Server and checks again when the administrator comes back. A
 * missing mailbox holds only receiving: with intent both, sending goes on and
 * receiving shows as pending (branch.receivePending).
 *
 * mailplus is the precondition: the wizard asks the worker whether MailPlus
 * Server is installed and running as soon as it opens (mail.mailplus.status,
 * DSM's package list only). Not installed, stopped or unknown, the wizard stops
 * there, at its start, with Open Package Center and Check again, and re-checks
 * when the administrator comes back; nothing that needs MailPlus Server is
 * asked before it says running.
 *
 * route asks how mail travels: Cloudflare receives and sends (recommended), or
 * the administrator's own IP, whose requirements (fixed public IP, inbound TCP
 * 25 forwarded; the detected outbound 25 and PTR) are shown and confirmed.
 * Nothing probes from outside: the outside SMTP test is only a link, and its
 * result is never read. The choice re-decides from the same detection; Go
 * decides each path and names why (paths). The source decides no path.
 */
import {computed, h, nextTick, onUnmounted, ref, watch} from 'vue'
import {Check, CircleCheck, Cloud, Globe, Inbox, Mail, MailCheck, Route as RouteIcon, Send, Server, Stethoscope, Undo2} from '@lucide/vue'
import {Accordion, Button, Callout, Checkbox, CopyButton, Form, FormItem, Input, Link, Progress, RadioGroup, Select, Space, StepList, Textarea, WizardDialog, WizardStep} from '@synopackageland/ui'
import type {AccordionEntry, FormRule, StepListItem, WizardGuardContext, WizardGuardResult, WizardProgress, WizardResultTone} from '@synopackageland/ui'
import {openApp, type DsmAppLaunchResult} from '@synopackageland/sdk'
import {pause, useAssistant} from '../api/assistant'
import {SLOW_AFTER, useElapsed} from '../api/elapsed'
import type {Answers, AssistantError, BranchView, CloudView, CloudZone, DetectView, Fact, FlowView, Intent, Permission, PreviewView, ReceiveMode, ReceiveModes, Route, Source, TunnelOption} from '../api/types'
import {isProfile, profileName} from '../api/authority'
import {cloudflareTokenUrl, openCloudflare, registerDomainUrl, tokenPermissionCodes} from '../api/cloudflare'
import {smtpTestUrl, SYNO_CONNECT_CATALOG_URL} from '../api/links'
import MailWayPicture from '../components/MailWayPicture.vue'
import PlanNote from '../components/PlanNote.vue'
import FactList from '../components/FactList.vue'
import MailPlusNotice from '../components/MailPlusNotice.vue'
import {MAILPLUS_CAUSES, useMailPlus} from '../api/mailplus'
import FactGroups from '../components/FactGroups.vue'
import ChangeList from '../components/ChangeList.vue'
import FindingCard from '../components/FindingCard.vue'
import PathList from '../components/PathList.vue'
import TokenDialog from '../components/TokenDialog.vue'

const open = defineModel<boolean>('open', {required: true})
/** Pre-selected intent (a finding's Fix passes params.intent). */
const props = defineProps<{intent?: Intent}>()
const emit = defineEmits<{diagnose: []; changed: []}>()
const k = useAssistant()
/** The MailPlus Server precondition, read on every opening. */
const mp = useMailPlus(k)
/** The read that runs for this opening (leaving intent waits for it). */
let mpRead: Promise<unknown> | undefined
/** Not running (or not known): the wizard stops on the mailplus step. */
const mpBlocked = computed(() => !!mp.status.value && mp.status.value.state !== 'running' && mp.status.value.state !== 'checking')
const mpReady = computed(() => mp.status.value?.state === 'running')

type StepKey = 'mailplus' | 'intent' | 'start' | 'cloudflare' | 'zone' | 'domain' | 'detect' | 'prereq' | 'route' | 'facts' | 'stop' | 'already' | 'account' | 'configuration' | 'preview' | 'applying' | 'decision' | 'result'
const step = ref<StepKey>('intent')
const flow = ref<FlowView>()
const choice = ref<Intent | 'diagnose'>('send')
const domain = ref('')
/** The route step's choice; '' until the administrator picks a card. */
const route = ref<Route | ''>('')
/** The own-IP route's "I have confirmed these requirements". */
const confirmed = ref(false)
const detection = ref<DetectView>()
/** A shown fact is unknown when its value is a cause key (mail.setup.cause.*,
 *  docs/CONTRACT.md); only then does the facts step ask for more evidence.
 *  Cause keys that are not missing evidence do not count: not checked by this
 *  version (unknown by design), and the certain negatives "DNS does not know
 *  this domain", "MailPlus Server has no such domain" and "the IP has no
 *  reverse DNS name". A worker that states each fact's state is
 *  read by that state: only a related fact still unknown counts, never one
 *  the plan creates (a new MailPlus Server domain's accounts and DKIM) or one
 *  the chosen route does not use. */
const NOT_UNKNOWN = new Set(['mail.setup.cause.notChecked', 'mail.setup.cause.noDomain', 'mail.setup.cause.notInMailPlus', 'mail.setup.cause.ptrNone'])
const factsUnknown = computed(() => {
 const list = detection.value?.facts ?? []
 if(list.some(f => f.state)) return list.some(f => !f.unrelated && f.state === 'unknown')
 return list.some(f => f.value.startsWith('mail.setup.cause.') && !NOT_UNKNOWN.has(f.value))
})
const branch = computed<BranchView | undefined>(() => detection.value?.branch)
/** The start step's choice; '' until the administrator picks a card. */
const source = ref<Source | ''>('')
const viaCloudflare = computed(() => source.value === 'cloudflare')
/** The pasted Cloudflare token: only until the worker sealed it (mail.setup.cloudflare). */
const token = ref('')
/** The worker's view of the sign-in: accounts, zones, the chosen ones, refused permissions. */
const cloud = ref<CloudView>()
const accountId = ref('')
const zoneId = ref('')
/** Path B: an optional mail name under the chosen zone (one label). */
const mailDomain = ref('')
const permissions = ref<Permission[]>([])
const values = ref<Record<string, string>>({})
const preview = ref<PreviewView>()
const error = ref<unknown>()
/** The domain this opening started with (kept from before, or the resumed flow's):
 * only what the user typed since then makes closing ask to discard. The account
 * fields and configuration values start empty in every opening. */
const domainAtOpen = ref('')
const typed = computed(() => domain.value !== domainAtOpen.value || accountId.value !== '' || zoneId.value !== '' || token.value !== '' || !!cloud.value
 || Object.values(values.value).some(v => v))
/** The MailPlus Server hand-off: the launcher's last answer and the running re-check. */
const launch = ref<DsmAppLaunchResult['status']>()
let rechecking: AbortController | undefined
/** The re-check's refresh call, so Check again can follow the job it started. */
let recheckStarted: Promise<unknown> | undefined
function stopRecheck() {rechecking?.abort(); rechecking = undefined}
/** The one watched round (detect or applying); a new round or leaving aborts it. */
let poll: {step: StepKey; ctl: AbortController} | undefined

const errorText = computed(() => error.value ? k.error(error.value) : '')
const refusal = computed(() => k.refusal(error.value))
// A step's error is drawn at the top of its body; the administrator may be
// scrolled down at the field they just used. Bring it into view.
watch(errorText, async text => {
 if(!text) return
 await nextTick()
 const alert = document.querySelector<HTMLElement>('[role="dialog"] section:not([aria-hidden="true"]) [role="alert"]')
 alert?.scrollIntoView?.({block: 'nearest', behavior: 'smooth'})
})

function stopPolling() {poll?.ctl.abort(); poll = undefined}
/** Starts watching `at`; returns undefined when a round for that step already runs. */
function watchRound(at: StepKey): AbortSignal | undefined {
 if(poll?.step === at && !poll.ctl.signal.aborted) return
 stopPolling()
 const ctl = new AbortController()
 poll = {step: at, ctl}
 return ctl.signal
}
/** A reply still matters only while its round, the open dialog and its step stand. */
const current = (signal: AbortSignal, at: StepKey) => !signal.aborted && open.value && step.value === at
onUnmounted(() => {stopPolling(); stopRecheck()})

// A shown error belongs to the step and the path it came from: any step
// change or source change clears it (synchronously, so code that moves to a
// step and then reports an error there keeps that error).
watch(step, () => {error.value = undefined}, {flush: 'sync'})
watch(source, () => {error.value = undefined}, {flush: 'sync'})

/** Runs a worker call for a step guard: false keeps the step and shows the error.
 * With the guard's signal, a failure that comes after the move was abandoned is dropped. */
async function guard(work: () => Promise<unknown>, signal?: AbortSignal): Promise<false | void> {
 error.value = undefined
 try {await work()} catch(e) {if(!signal?.aborted) error.value = e; return false}
}

// ---- Opening: start or resume the caller's flow.
/** Counts openings and closings: a mail.setup.start reply (or failure) that
 * arrives after the wizard closed, or was closed and opened again, is dropped. */
let opening = 0
watch(open, async value => {
 const round = ++opening
 stopPolling(); stopRecheck(); launch.value = undefined
 if(!value) return
 error.value = undefined; detection.value = undefined; preview.value = undefined; permissions.value = []
 values.value = {}; accountId.value = ''; zoneId.value = ''; mailDomain.value = ''; token.value = ''; cloud.value = undefined; source.value = ''
 route.value = ''; confirmed.value = false
 choice.value = props.intent ?? 'send'
 step.value = 'intent'
 domainAtOpen.value = domain.value
 mp.cancel(); mp.status.value = undefined; mp.error.value = undefined
 mpRead = mp.check().then(s => {
  // Still at the start of this opening: stop there when MailPlus Server does not run.
  if(round === opening && s && s.state !== 'running' && step.value === 'intent' && !flow.value?.resume) step.value = 'mailplus'
 })
 try {
  const f = await k.call('mail.setup.start')
  if(round !== opening) return
  flow.value = f
  if(f.resume) {
   choice.value = f.intent ?? choice.value; domain.value = domainAtOpen.value = f.domain ?? ''
   source.value = f.source === 'cloudflare' ? 'cloudflare' : 'own'
   resumeAt(f)
  }
 } catch(e) {if(round === opening) error.value = e}
}, {immediate: true})

/** A flow with applied changes resumes where its transaction stands. */
function resumeAt(f: FlowView) {
 if(f.phase === 'applying' || f.phase === 'verifying' || f.phase === 'rollingBack') {step.value = 'applying'; void follow()}
 else if(f.phase === 'decision' || f.phase === 'interrupted' || f.phase === 'failed') step.value = 'decision'
 else if(f.outcome) step.value = 'result'
}

// ---- intent → domain
const intents = computed(() => [
 {value: 'send', label: k.t('mail.setup.intent.send'), icon: Send},
 {value: 'receive', label: k.t('mail.setup.intent.receive'), icon: Inbox},
 {value: 'both', label: k.t('mail.setup.intent.both'), icon: Mail},
 {value: 'diagnose', label: k.t('ui.setup.handoffDiagnose'), description: k.t('ui.setup.diagnoseHint'), icon: Stethoscope},
])
async function leaveIntent(): Promise<WizardGuardResult> {
 if(choice.value === 'diagnose') {handOff(); return false}
 // Nothing that needs MailPlus Server is asked before the precondition says running.
 if(!mpReady.value) await mpRead
 if(!mpReady.value) return mp.error.value ? (error.value = mp.error.value, false) : {goTo: 'mailplus'}
}
/** The mailplus step's main action: check again; running goes on to the intent. */
async function leaveMailPlus(): Promise<false | void> {
 if(mpReady.value) return
 await (mpRead = mp.check())
 if(mp.error.value) {error.value = mp.error.value; return false}
 if(!mpReady.value) return false
}
function handOff() {open.value = false; emit('diagnose')}

// ---- route: how mail travels. The choice goes with every detection call
// once made; before it (the first detection, right after the domain) none.
const sends = computed(() => choice.value === 'send' || choice.value === 'both')
const receives = computed(() => choice.value === 'receive' || choice.value === 'both')
const answers = computed<Answers>(() => {
 // Both sources choose the same route; the source only says where the domain came from.
 const a: Answers = {source: viaCloudflare.value ? 'cloudflare' : 'own'}
 if(route.value) a.route = route.value
 return a
})
/** Each card's mini concept picture, drawn in the card's icon tile (widened in style.css). */
const CloudflareWay = () => h(MailWayPicture, {way: 'cloudflare'})
const DirectWay = () => h(MailWayPicture, {way: 'direct'})
const routes = computed(() => [
 {value: 'cloudflare', label: k.t('mail.setup.route.cloudflare'), description: k.t('mail.setup.route.cloudflareHint'), icon: CloudflareWay},
 {value: 'direct', label: k.t('mail.setup.route.direct'), description: k.t('mail.setup.route.directHint'), icon: DirectWay},
])
// A new choice asks for the confirmation again.
watch(route, () => {confirmed.value = false})
const routeReady = computed(() => route.value === 'cloudflare' || (route.value === 'direct' && confirmed.value))
/** The requirements of the own-IP route; inbound TCP 25 only when receiving. */
const requirements = computed<StepListItem[]>(() => [
 {title: k.t('mail.setup.route.fixedIp'), description: k.t('mail.setup.route.fixedIpHint')},
 ...(receives.value ? [{title: k.t('mail.setup.route.inbound'), description: k.t('mail.setup.route.inboundHint')}] : []),
])
const factOf = (label: string) => detection.value?.facts?.find(f => f.labelKey === `mail.setup.fact.${label}`)
/** The detected public IPv4 (only a value, never a cause), for the outside test link. */
const publicIp = computed(() => {
 const f = factOf('ip')
 return f?.value === 'mail.setup.value.text' ? f.params?.text : undefined
})
const smtpTest = computed(() => smtpTestUrl(publicIp.value))
/** What the NAS already detected for the own-IP route: the IP, and for sending outbound 25 and PTR. */
const routeFacts = computed<Fact[]>(() => ['ip', ...(sends.value ? ['outbound', 'ptr'] : [])].map(factOf).filter((f): f is Fact => !!f))
/** A detected result says the route will not hold (a problem, or unknown for sending): Go then takes Cloudflare for that direction. */
const checksDisagree = computed(() => routeFacts.value.some(f => f.state === 'problem' || f.state === 'unknown'))
function useCloudflare() {route.value = 'cloudflare'}
/** Leaving the route: the worker re-decides from the same detection (no new read). */
function leaveRoute({signal}: WizardGuardContext): Promise<false | void> | false {
 if(!routeReady.value) return false
 afterDetect.value = 'facts'
 return guard(() => startDetect(false, signal), signal)
}

// ---- start: own domain (A) or Cloudflare (B).
const sources = computed(() => [
 {value: 'own', label: k.t('mail.setup.start.own'), description: k.t('mail.setup.start.ownHint'), icon: Globe},
 {value: 'cloudflare', label: k.t('mail.setup.start.cloudflare'), description: k.t('mail.setup.start.cloudflareHint'), icon: Cloud},
])

// ---- cloudflare: sign in with one token. The worker seals it at once; the
// page drops it as soon as the reply comes, whatever the reply says.
const tokenUrl = cloudflareTokenUrl()
const permissionText = (codes: readonly string[]) => codes.map(c => k.t(`mail.setup.cloudflare.permission.${c}`)).join(', ')
const tokenSteps = computed<StepListItem[]>(() => [
 {title: k.t('mail.setup.cloudflare.step1')},
 {title: k.t('mail.setup.cloudflare.step2'), description: k.t('mail.setup.cloudflare.step2Hint')},
 {title: k.t('mail.setup.cloudflare.step3')},
])
/** The permissions the link fills in, one per line, folded under their count. */
const permissionLines = computed(() => tokenPermissionCodes.map(c => k.t(`mail.setup.cloudflare.permission.${c}`)))
const permissionFold = computed<AccordionEntry[]>(() => [{value: 'permissions', title: k.t('mail.setup.cloudflare.permissions', {count: tokenPermissionCodes.length})}])
/** The create-token button's own label, named by the texts that point at it. */
const createLabel = computed(() => k.t('mail.setup.cloudflare.create'))
const missingText = computed(() => cloud.value?.missing.length ? k.t('mail.setup.cloudflare.missing', {permissions: permissionText(cloud.value.missing), create: createLabel.value}) : '')
/** Signed in with nothing refused, and an account (or a token whose account shows with its first zone):
 * the token step may be left without a new token. */
const signedIn = computed(() => !!cloud.value && !cloud.value.missing.length && (cloud.value.accounts.length > 0 || !!cloud.value.accountUnknown))
function adopt(v: CloudView) {
 cloud.value = v
 accountId.value = v.accountId ?? ''
 if(v.zoneId !== zoneId.value) zoneId.value = v.zoneId ?? ''
}
async function signIn(signal?: AbortSignal): Promise<boolean> {
 const pasted = token.value.trim()
 token.value = ''
 const v = await k.call('mail.setup.cloudflare', {id: flow.value!.id, token: pasted})
 if(signal?.aborted) return false
 zoneId.value = ''
 adopt(v)
 return signedIn.value
}
async function leaveCloudflare({signal}: WizardGuardContext): Promise<false | void> {
 if(!token.value.trim()) return signedIn.value ? undefined : false
 let ok = false
 if(await guard(async () => {ok = await signIn(signal)}, signal) === false || !ok) return false
}

// ---- zone (B) and account (A): chosen from Cloudflare's lists.
const accountOptions = computed(() => (cloud.value?.accounts ?? []).map(a => ({value: a.id, label: a.name || a.id})))
function zoneLabel(z: CloudZone): string {
 if(z.status === 'active') return z.name
 return z.status === 'pending' ? k.t('mail.setup.zone.pending', {name: z.name}) : k.t('mail.setup.zone.inactive', {name: z.name, status: z.status})
}
const zoneOptions = computed(() => (cloud.value?.zones ?? []).map(z => ({value: z.id, label: zoneLabel(z), disabled: z.status !== 'active'})))
const anyPending = computed(() => cloud.value?.zones.some(z => z.status !== 'active') ?? false)
const chosenZone = computed(() => cloud.value?.zones.find(z => z.id === zoneId.value))
const listed = computed(() => !!cloud.value && cloud.value.accountId === accountId.value && accountId.value !== '')
/** No zone to choose: the chosen account has none, or the token's account shows only with its first zone. */
const noZones = computed(() => (listed.value && cloud.value!.zones.length === 0) || !!cloud.value?.accountUnknown)
/** Lists the chosen account's zones (choosing an account, or Check again). */
const listing = ref(false)
async function listZones() {
 const unknown = !!cloud.value?.accountUnknown
 if(!flow.value || (!accountId.value && !unknown) || choice.value === 'diagnose') return
 listing.value = true
 // An unknown account is read again with the sealed token (empty accountId).
 try {await guard(async () => adopt(await k.call('mail.setup.zones', {id: flow.value!.id, accountId: unknown ? '' : accountId.value})))}
 finally {listing.value = false}
}
watch(accountId, (id, before) => {if(id && id !== before && id !== cloud.value?.accountId && (step.value === 'zone' || step.value === 'account')) void listZones()})
// A: entering the account step lists the zones again, so the match is the one
// for the domain detected now (a view kept from the Cloudflare route, or from
// an earlier domain, holds no match or another one).
watch(step, (at, before) => {if(at === 'account' && before !== 'account' && cloud.value?.accountId) void listZones()})
/** Chooses the zone: the worker reads it the way the plan will (Email Sending
 * only once the decision takes the relay) and names refused permissions. */
async function chooseZone(id: string, signal?: AbortSignal): Promise<boolean> {
 const v = await k.call('mail.setup.zones', {id: flow.value!.id, accountId: accountId.value, zoneId: id})
 if(signal?.aborted) return false
 adopt(v)
 return v.zoneId === id && !v.missing.length
}
// B: choosing a zone reads it at once, with MailPlus Server's domains in it;
// the mail domain is picked from those (one is preselected), never the apex
// by default.
const choosing = ref(false)
const zoneRead = computed(() => !!cloud.value && cloud.value.zoneId === zoneId.value && zoneId.value !== '')
const mailDomainsKnown = computed(() => zoneRead.value && cloud.value!.mailDomainsState === 'read')
/** The Select value that asks the App to create a MailPlus Server mail domain. */
const NEW_DOMAIN = '\u0000new'
/** MailPlus Server finished its own setup and the setup sends: the App can
 * create a missing mail domain in the zone, as a previewed step. Receiving
 * alone needs mailboxes a new domain does not have yet: guidance stays. */
const canCreateDomain = computed(() => mailDomainsKnown.value && mp.status.value?.setUp === true && choice.value !== 'receive' && choice.value !== 'diagnose')
const mailDomainOptions = computed(() => [
 ...(zoneRead.value ? cloud.value!.mailDomains ?? [] : []).map(d => ({value: d, label: d})),
 ...(canCreateDomain.value ? [{value: NEW_DOMAIN, label: k.t('mail.setup.zone.newDomain')}] : []),
])
/** The new mail domain's name: the zone itself by default, or a name under it. */
const newDomain = ref('')
const newDomainName = computed(() => newDomain.value.trim().toLowerCase().replace(/\.$/, ''))
const newDomainProblem = computed(() => {
 const z = chosenZone.value?.name.toLowerCase()
 const n = newDomainName.value
 if(!z || mailDomain.value !== NEW_DOMAIN) return undefined
 if(!n || !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,61}[a-z0-9]$/.test(n)) return 'mail.setup.zone.newDomainInvalid'
 if(n !== z && !n.endsWith('.' + z)) return 'mail.setup.zone.newDomainOutside'
 if((cloud.value?.mailDomains ?? []).some(d => d.toLowerCase() === n)) return 'mail.setup.zone.newDomainExists'
 return undefined
})
watch(() => chosenZone.value?.name, name => {newDomain.value = name ?? ''}, {immediate: true})
const newDomainRule: FormRule = {trigger: 'change', validator: (_r, _v, done) => done(newDomainProblem.value ? k.t(newDomainProblem.value, {zone: chosenZone.value?.name ?? ''}) : undefined)}
/** The zone's domain read refused by the MailPlus Server precondition (it stopped since the start). */
const zoneMailPlus = computed(() => {
 const key = zoneRead.value && cloud.value!.mailDomainsState === 'unknown' ? cloud.value!.mailDomainsCauseKey : undefined
 if(!key || !MAILPLUS_CAUSES.has(key)) return undefined
 return {state: key === 'mail.setup.cause.mailplusNotInstalled' ? 'notInstalled' as const : 'stopped' as const}
})
async function readZone() {
 const z = chosenZone.value
 if(!flow.value || !z || z.status !== 'active') return
 choosing.value = true
 try {
  await guard(async () => {
   if(!await chooseZone(z.id) && cloud.value?.zoneId !== z.id) return
   // The worker reads MailPlus Server's domains in the background (a DSM
   // read may wait for an executor slot): poll while it reads.
   while(open.value && step.value === 'zone' && cloud.value?.zoneId === z.id && cloud.value.mailDomainsState === 'reading') {
    await pause(1000)
    if(!open.value || step.value !== 'zone' || zoneId.value !== z.id) return
    adopt(await k.call('mail.setup.zones', {id: flow.value!.id, poll: true}))
   }
  })
 } finally {choosing.value = false}
}
watch(zoneId, (id, before) => {if(id && id !== before && step.value === 'zone' && cloud.value?.zoneId !== id) void readZone()})
watch(() => [zoneRead.value, cloud.value?.mailDomains, canCreateDomain.value] as const, () => {
 const list = zoneRead.value ? cloud.value!.mailDomains ?? [] : []
 if(mailDomain.value === NEW_DOMAIN && canCreateDomain.value) return
 if(!list.includes(mailDomain.value)) mailDomain.value = list.length === 1 ? list[0]! : !list.length && canCreateDomain.value ? NEW_DOMAIN : ''
})
async function leaveZone({signal}: WizardGuardContext): Promise<false | void> {
 const z = chosenZone.value
 if(!z || !mailDomainsKnown.value || !mailDomainOptions.value.some(o => o.value === mailDomain.value) || newDomainProblem.value) return false
 if(cloud.value?.missing.length) {
  let ok = false
  if(await guard(async () => {ok = await chooseZone(z.id, signal)}, signal) === false || !ok) return false
 }
 domain.value = mailDomain.value === NEW_DOMAIN ? newDomainName.value : mailDomain.value
 afterDetect.value = 'route'
 return guard(() => startDetect(false, signal), signal)
}
/** The zone step's one Check again: reads the chosen zone (and MailPlus Server's domains in it) again, or lists the account's zones. */
function recheckZone() {
 if(zoneRead.value && chosenZone.value?.status === 'active') void readZone()
 else void listZones()
}
/** MailPlus Server has no mail domain in the chosen zone: the step says exactly
 * what to type in MailPlus Server (its first-run wizard when it was never set
 * up, else Domain → Create), opens it, and reads the zone again on coming back. */
const noMailDomain = computed(() => mailDomainsKnown.value && !(cloud.value?.mailDomains ?? []).length && !canCreateDomain.value)
/** true: MailPlus Server finished its first-run setup; false: not yet; undefined: unknown. */
const mailPlusSetUp = computed(() => mp.status.value?.setUp)
const zoneHost = computed(() => chosenZone.value ? `mail.${chosenZone.value.name}` : '')
const zoneHelpKey = computed(() => mailPlusSetUp.value === true ? 'addDomain' : mailPlusSetUp.value === false ? 'firstRun' : 'either')
/** Path A: the zone that holds the typed domain, decided by the worker. */
const matchedZone = computed(() => cloud.value?.zones.find(z => z.id === cloud.value?.match))
function replaceToken() {error.value = undefined; step.value = 'cloudflare'}

// ---- domain → detect: start the read-only detection, then poll it.
/** Where a finished detection goes when MailPlus Server lacks nothing: the
 * route step after a new domain or the prerequisite step, the facts after
 * Check again on the stop step or after the route step. */
const afterDetect = ref<'route' | 'facts'>('route')
/** MailPlus Server lacks something for the domain: it blocks (configureMailPlus) or only receiving waits. */
const blocking = computed(() => branch.value?.kind === 'configureMailPlus')
const pending = computed(() => !blocking.value && !!branch.value?.receivePending)
/** Receiving waits because the plan creates the mail domain: nothing
 * to do in MailPlus Server now, so the step offers no hand-off to it. */
const newDomainPending = computed(() => pending.value && !!branch.value?.createsDomain)
const prereqShown = computed(() => blocking.value || pending.value)
/** When the last detection job was started (refresh or first start); paces the focus re-check. */
let lastDetection = 0
function detectCall(refresh = false) {
 if(!flow.value || choice.value === 'diagnose') return Promise.resolve(undefined)
 return k.call('mail.setup.detect', {id: flow.value.id, intent: choice.value, domain: domain.value.trim(), answers: answers.value, refresh})
}
/** A guard's detection start. A reply that comes after the guard's move was abandoned
 * (Back, close, another step) is dropped. The last detection stays until the new
 * reply replaces it, so a stop step that checks again keeps its headline, body
 * and records while the check runs and after it fails. */
async function startDetect(refresh: boolean, signal?: AbortSignal) {
 lastDetection = Date.now()
 const reply = await detectCall(refresh)
 if(!signal?.aborted) detection.value = reply
}
/** A: leaving the domain starts the detection; the route is asked after it. */
function leaveDomain({signal}: WizardGuardContext): Promise<false | void> {
 afterDetect.value = 'route'
 return guard(() => startDetect(false, signal), signal)
}
/** The detect progress step: poll until the worker's detection is done. */
// Detection runs in the worker's background; the step shows the time waited.
const waited = useElapsed()
async function followDetect() {
 const signal = watchRound('detect')
 if(!signal) return
 const stopWait = waited.start()
 try {
  while(current(signal, 'detect') && !detection.value?.done) {
   await pause(1000, signal)
   if(!current(signal, 'detect')) return
   const reply = await detectCall()
   if(!current(signal, 'detect')) return
   detection.value = reply
  }
  if(current(signal, 'detect')) step.value = prereqShown.value ? 'prereq' : afterDetect.value
 } catch(e) {if(current(signal, 'detect')) {step.value = viaCloudflare.value ? 'zone' : 'domain'; error.value = e}}
 finally {stopWait()}
}

// The step counter counts only the chosen path: steps of the other source,
// the sign-in steps an own domain does not need, and the stop/already
// outcomes the branch did not take are not rendered (a step stays rendered
// while it shows, so the wizard never loses its current step).
// MailPlus Server's own gaps (configureMailPlus) show on the prerequisite step, never as a stop.
const stopShown = computed(() => !!branch.value && !['configure', 'already', 'diagnose', 'configureMailPlus'].includes(branch.value.kind))

// ---- facts: the rows that need attention first (problem, unknown), under
// their group; the rest folds away: fine and not-checked rows, and rows the
// chosen route and intent do not need. Every fact stays one click away.
const facts = computed(() => detection.value?.facts ?? [])
/** Facts from a worker that does not group them show as one list, as before. */
const grouped = computed(() => facts.value.some(f => f.state))
const needsAttention = (f: Fact) => f.state === 'problem' || f.state === 'unknown'
/** What the plan creates (planned) or only recommends (optional): shown, never as a problem. */
const handled = (f: Fact) => f.state === 'planned' || f.state === 'optional'
const attention = computed(() => facts.value.filter(f => !f.unrelated && needsAttention(f)))
const planned = computed(() => facts.value.filter(f => !f.unrelated && handled(f)))
/** The planned and optional facts by their reason, each reason said once under its facts. */
const plannedGroups = computed(() => {
 const map = new Map<string, Fact[]>()
 for(const f of planned.value) map.set(f.noteKey ?? '', [...(map.get(f.noteKey ?? '') ?? []), f])
 return [...map].map(([note, list]) => ({note, facts: list}))
})
const fine = computed(() => facts.value.filter(f => !f.unrelated && !needsAttention(f) && !handled(f)))
const unrelated = computed(() => facts.value.filter(f => f.unrelated))
const factFolds = computed<AccordionEntry[]>(() => [
 ...(fine.value.length ? [{value: 'fine', title: k.t('mail.setup.facts.others', {count: fine.value.length})}] : []),
 ...(unrelated.value.length ? [{value: 'unrelated', title: k.t('mail.setup.facts.unrelated', {count: unrelated.value.length})}] : []),
])

/** The facts step says only what the administrator did not state: a path that
 * follows the chosen route (and its "because you chose …" reason) is not
 * repeated. On the own-IP route, a direction the detection moved to Cloudflare
 * says so, with the checks that moved it. */
const ECHO = new Set(['mail.setup.why.routeCloudflare', 'mail.setup.why.routeDirect', 'mail.setup.why.routeUnset'])
const movedPaths = computed(() => route.value !== 'direct' ? [] : (branch.value?.paths ?? [])
 .filter(p => p.branch.startsWith('cloudflare-'))
 .map(p => ({direction: p.direction, why: p.why.filter(w => !ECHO.has(w))})))

/** The stop step explains its paths by the checks only: the echo of the chosen route is dropped. */
const stopPaths = computed(() => (branch.value?.paths ?? []).map(p => ({...p, why: p.why.filter(w => !ECHO.has(w))})).filter(p => p.why.length))

// ---- facts → the branch's next step
const nextAfterFacts = (): StepKey => {
 switch(branch.value?.kind) {
  // The own-domain source signs in to Cloudflare only when its branch needs it.
  case 'configure': return branch.value.needsAccount ? 'cloudflare' : 'configuration'
  case 'already': return 'already'
  default: return 'stop'
 }
}
function leaveFacts(): false | void {
 if(branch.value?.kind === 'diagnose') {handOff(); return false}
}
/** The stop step's main action: a fresh detection, shown on the detect step (next-step-key).
 * One detection at a time: when a focus re-check already started the worker's
 * job, Check again follows that job instead of starting another. */
async function retry({signal}: WizardGuardContext): Promise<false | void> {
 afterDetect.value = step.value === 'prereq' ? 'route' : 'facts'
 const started = rechecking ? recheckStarted : undefined
 stopRecheck()
 // Let the re-check's own start reach the worker first, so this poll follows its job.
 // When that start failed there is no job to follow: start a fresh one.
 const following = started ? await started.then(() => true, () => false) : false
 return guard(() => startDetect(!following, signal), signal)
}

// ---- prereq: say exactly what MailPlus Server lacks and hand off to it
// through the SDK DSM App launcher. `requested` only says DSM was asked: the
// step stays, the manual path stays visible, and coming back only triggers a
// read. The re-check's fresh detection replaces the shown one, so the step
// says at once what is still missing, or that MailPlus Server is ready.
const MAILPLUS_APP = {appId: 'SYNO.SDS.MailPlusServer.Instance'} as const
const handoff = computed(() => open.value && ((step.value === 'prereq' && !newDomainPending.value) || step.value === 'mailplus' || (step.value === 'zone' && noMailDomain.value)))
/** A re-check found MailPlus Server lacking nothing for the domain (the decision went past it). */
const prereqReady = computed(() => !pending.value && (branch.value?.kind === 'configure' || branch.value?.kind === 'already'))
const prereqTitle = computed(() => {
 const b = branch.value
 if(pending.value) return k.t(branch.value?.createsDomain ? 'mail.setup.prereq.receivePendingNew' : 'mail.setup.prereq.receivePending', {domain: domain.value})
 if(prereqReady.value) return k.t('mail.setup.prereq.ready')
 // Blocking, or another stop a re-check found (the facts and the stop step explain it).
 return b ? k.t(b.titleKey, b.params) : ''
})
const prereqBody = computed(() => {
 const b = branch.value
 if(pending.value) return k.t(branch.value?.createsDomain ? 'mail.setup.prereq.receivePendingNewBody' : 'mail.setup.prereq.receivePendingBody', {domain: domain.value})
 if(prereqReady.value) return k.t('mail.setup.prereq.readyBody')
 return b?.bodyKey ? k.t(b.bodyKey, b.params) : ''
})
/** The MailPlus Server facts that explain the gap (the domain list, the accounts, the licence). */
const prereqFacts = computed(() => (detection.value?.facts ?? []).filter(f => f.group === 'mailplus' && !f.unrelated && f.state === 'problem'))
/** What the plan creates in MailPlus Server (the new mail domain), said as planned. */
const prereqPlanned = computed(() => (detection.value?.facts ?? []).filter(f => f.group === 'mailplus' && !f.unrelated && f.state === 'planned'))
/** Where the prerequisite step's main action goes, fixed when it is pressed. */
const prereqNext = ref<'detect' | 'route'>('route')
/** Not blocking: go on to the route. Blocking: Check again. A fresh answer
 * that still lacks something, or now holds only receiving, stays on this step
 * and shows it; one still running is followed on the detect step; one that
 * lacks nothing goes on to the route. */
async function leavePrereq(ctx: WizardGuardContext): Promise<false | void> {
 prereqNext.value = 'route'
 if(!blocking.value) return
 if(await retry(ctx) === false) return false
 if(!detection.value?.done) {prereqNext.value = 'detect'; return}
 if(prereqShown.value) {recheck.value = recheckOf(detection.value) === 'unknown' ? 'unknown' : 'changed'; return false}
}
async function openMailPlus() {
 const result = await openApp(MAILPLUS_APP)
 if(!open.value || !handoff.value) return
 launch.value = result.status
 watchComeBack()
}
const launchText = computed(() => {
 if(!launch.value) return ''
 return k.t(launch.value === 'requested' ? 'ui.setup.launchRequested' : 'ui.setup.launchManual')
})

/** Re-check when the user comes back: a fresh read-only detection, shown as a
 * status line. It never moves the wizard; Check again does. */
type Recheck = 'checking' | 'still' | 'stillZone' | 'changed' | 'unknown'
const recheck = ref<Recheck>()
/** The least time between detections a focus re-check starts (each one reads DSM and writes the flow). */
const RECHECK_INTERVAL = 15_000
/** Only a decided, different branch is "changed"; anything unclear is unknown.
 * The same hand-off for another reason (a licence shortfall fixed, a domain
 * still missing) is a change too. */
function recheckOf(reply: DetectView | undefined): Recheck {
 const b = reply?.done ? reply.branch : undefined
 switch(b?.kind) {
  case 'configureMailPlus': return b.reason === branch.value?.reason && b.titleKey === branch.value?.titleKey ? 'still' : 'changed'
  case 'blocked': return b.reason === 'unknown' ? 'unknown' : 'changed'
  case 'configure': case 'already': case 'diagnose': return pending.value && b.receivePending ? 'still' : 'changed'
  default: return 'unknown' // unavailable, missing or an unknown kind
 }
}
/** A come-back inside the interval is not lost: one deferred re-check runs when the interval ends. */
let deferred: ReturnType<typeof setTimeout> | undefined
function clearDeferred() {if(deferred !== undefined) {clearTimeout(deferred); deferred = undefined}}
/** When the zone step last read the zone again on a come-back; paces those reads. */
let lastZoneRead = 0
/** The zone step: read the zone (MailPlus Server's domains in it) and the
 * first-run state again, at most once per interval. A domain now there ends
 * the guidance; still none says so. */
function recheckZoneSoon() {
 if(choosing.value) return
 const wait = lastZoneRead + RECHECK_INTERVAL - Date.now()
 if(wait > 0) {deferred ??= setTimeout(() => {deferred = undefined; comeBack()}, wait); return}
 clearDeferred()
 lastZoneRead = Date.now()
 recheck.value = 'checking'
 void Promise.all([readZone(), mp.check()]).finally(() => {
  if(step.value === 'zone' && recheck.value === 'checking') recheck.value = noMailDomain.value ? 'stillZone' : undefined
 })
}
/** The user came back: re-check now, or once the interval since the last detection ends. */
function comeBack() {
 if(!handoff.value) return
 // The precondition step re-reads only the package list (one call, at most once per 15 s).
 if(step.value === 'mailplus') {if(!mpReady.value) mp.recheckSoon(); return}
 if(step.value === 'zone') {recheckZoneSoon(); return}
 if(rechecking) return
 const wait = lastDetection + RECHECK_INTERVAL - Date.now()
 if(wait <= 0) {clearDeferred(); void recheckHandoff(); return}
 deferred ??= setTimeout(() => {deferred = undefined; comeBack()}, wait)
}
async function recheckHandoff() {
 // Only on the prerequisite step, one at a time, and not more often than the interval.
 if(!handoff.value || rechecking || Date.now() - lastDetection < RECHECK_INTERVAL) return
 const ctl = rechecking = new AbortController()
 lastDetection = Date.now()
 const live = () => !ctl.signal.aborted && open.value && handoff.value
 recheck.value = 'checking'
 try {
  const start = recheckStarted = detectCall(true)
  let reply = await start
  while(live() && !reply?.done) {
   await pause(1000, ctl.signal)
   if(!live()) return
   reply = await detectCall()
  }
  if(!live()) return
  recheck.value = recheckOf(reply)
  // A decided answer replaces the shown detection: the step names what is
  // still missing, or says MailPlus Server is ready.
  if(recheck.value !== 'unknown' && reply?.done) detection.value = reply
 } catch {if(live()) recheck.value = 'unknown'}
 finally {if(rechecking === ctl) rechecking = undefined}
}
const recheckText = computed(() => recheck.value === 'checking' && step.value === 'zone' ? k.t('mail.setup.zone.help.checking') : recheck.value === 'stillZone' ? k.t('mail.setup.zone.help.still', {zone: chosenZone.value?.name ?? ''}) : recheck.value ? k.t(`ui.setup.recheck.${recheck.value}`) : '')
// "Coming back": the host's `window-activated` event (SDK 0.53.16, CLI 0.52.11
// host) when it is supported. An older host answers unsupported; then the
// browser window regaining focus, or the focus returning into this wizard after
// it left it, stands in; the page becoming visible again counts too. Each is
// only a trigger for a read-only re-check. Watching starts when the
// prerequisite step shows and ends when it is left.
const handoffRoot = ref<HTMLElement>()
const mailplusRoot = ref<HTMLElement>()
const zoneHelpRoot = ref<HTMLElement>()
let away = false
let stopComeBack: (() => void) | undefined
const wizardDialog = () => (step.value === 'mailplus' ? mailplusRoot.value : step.value === 'zone' ? zoneHelpRoot.value : handoffRoot.value)?.closest('[role="dialog"]') ?? undefined
function onFocusOut(e: FocusEvent) {
 const d = wizardDialog()
 if(d && e.target instanceof Node && d.contains(e.target) && !(e.relatedTarget instanceof Node && d.contains(e.relatedTarget))) away = true
}
function onFocusIn(e: FocusEvent) {
 const d = wizardDialog()
 if(away && d && e.target instanceof Node && d.contains(e.target)) {away = false; comeBack()}
}
function onVisible() {if(document.visibilityState === 'visible') comeBack()}
function watchComeBack() {
 if(stopComeBack) return
 document.addEventListener('visibilitychange', onVisible)
 const sub = k.host.subscribe('window-activated', comeBack)
 if(sub.status === 'subscribed') {stopComeBack = () => {sub.dispose(); document.removeEventListener('visibilitychange', onVisible)}; return}
 document.addEventListener('focusout', onFocusOut, true)
 document.addEventListener('focusin', onFocusIn, true)
 window.addEventListener('focus', comeBack)
 stopComeBack = () => {
  document.removeEventListener('visibilitychange', onVisible)
  document.removeEventListener('focusout', onFocusOut, true)
  document.removeEventListener('focusin', onFocusIn, true)
  window.removeEventListener('focus', comeBack)
 }
}
function unwatchComeBack() {stopComeBack?.(); stopComeBack = undefined; clearDeferred(); away = false}
onUnmounted(unwatchComeBack)
watch(handoff, value => {
 if(value) {watchComeBack(); return}
 unwatchComeBack(); stopRecheck(); recheck.value = undefined; launch.value = undefined
})

// ---- account (A) → configuration → preview
async function leaveAccount({signal}: WizardGuardContext): Promise<false | void> {
 const z = matchedZone.value
 if(!z || z.status !== 'active') return false
 let ok = false
 if(await guard(async () => {ok = await chooseZone(z.id, signal)}, signal) === false || !ok) return false
 return guard(async () => {
  const r = await k.call('mail.setup.permissions', {id: flow.value!.id, accountId: accountId.value, zoneId: z.id})
  if(!signal.aborted) permissions.value = r.permissions
 }, signal)
}
// The plan is prepared in the worker's background (it reads MailPlus Server,
// minutes on a busy NAS); the step shows that it is reading and for how long.
const previewing = ref(false)
const previewWait = useElapsed()
/** The preview round being watched. Leaving the configuration step, closing
 * the wizard or a new round ends it, so its replies and errors never reach
 * another step. */
let previewRound: AbortController | undefined
function stopPreview() {previewRound?.abort(); previewRound = undefined}
watch([open, step], ([isOpen, at]) => {if(!isOpen || at !== 'configuration') stopPreview()})
onUnmounted(stopPreview)
// Inbound tunnel: offered only when the worker could not be certain of one.
// A single Syno Connect tunnel is preselected (the administrator confirms).
const tunnelOptions = ref<TunnelOption[]>([])
const tunnel = ref('')
watch(() => flow.value?.id, () => {tunnelOptions.value = []; tunnel.value = ''})
const tunnelCards = computed(() => tunnelOptions.value.map(o => ({value: o.id, label: o.name,
 description: [k.t(o.connect ? 'mail.setup.tunnel.connect' : 'mail.setup.tunnel.own'), o.match ? k.t('mail.setup.tunnel.match') : ''].filter(Boolean).join(' · ')})))
function offerTunnels(options: TunnelOption[]) {
 tunnelOptions.value = options
 if(!options.some(o => o.id === tunnel.value)) {
  const connect = options.filter(o => o.connect)
  tunnel.value = connect.length === 1 ? connect[0].id : ''
 }
}
/** Starts the preview and polls it until the plan is ready; true when it is. */
async function runPreview(outer?: AbortSignal): Promise<boolean> {
 stopPreview()
 const ctl = previewRound = new AbortController()
 outer?.addEventListener('abort', () => ctl.abort(), {once: true})
 const signal = ctl.signal
 let ready = false
 preview.value = undefined
 previewing.value = true
 previewWait.start()
 try {
  await guard(async () => {
   const v = values.value
   let reply = await k.call('mail.setup.preview', {id: flow.value!.id, addresses: v.addresses || undefined, members: v.members || undefined, tunnel: tunnel.value || undefined,
    receive: offerModes.value ? receive.value : undefined})
   while(reply.pending) {
    await pause(1000, signal)
    if(signal.aborted) return
    reply = await k.call('mail.setup.preview', {id: flow.value!.id, poll: true})
   }
   if(signal.aborted) return
   if(reply.tunnels?.length) {offerTunnels(reply.tunnels); return}
   preview.value = reply
   ready = true
  }, signal)
 } finally {
  if(previewRound === ctl) previewRound = undefined
  if(!previewRound) {previewing.value = false; previewWait.stop()}
 }
 return ready && !signal.aborted
}
async function leaveConfiguration({signal}: WizardGuardContext): Promise<false | void> {
 // B: once the decision takes the Cloudflare relay, read the zone again so a
 // refused Email Sending permission is named here, before any plan.
 if(viaCloudflare.value && branch.value?.paths?.some(p => p.branch === 'cloudflare-relay') && chosenZone.value) {
  let ok = false
  if(await guard(async () => {ok = await chooseZone(chosenZone.value!.id, signal)}, signal) === false || !ok) return false
 }
 if(!await runPreview(signal)) return false
}
/** Receiving through Cloudflare: the domain's mailboxes come from MailPlus Server (never typed). */
const routingReceive = computed(() => branch.value?.paths?.some(p => p.branch === 'cloudflare-routing') ?? false)
const noMailboxes = computed(() => routingReceive.value && !branch.value?.mailboxes?.length)
/** How mail is received through Cloudflare: the whole domain when
 * Cloudflare allows it (the zone itself, with no other receiving of its own;
 * then MailPlus users need nothing more), else the domain's mailboxes, kept in
 * line with the Overview's Sync mailboxes. Read on entering the step. */
const offerModes = computed(() => routingReceive.value && !noMailboxes.value)
const receive = ref<ReceiveMode>('addresses')
const modes = ref<ReceiveModes>()
const readingModes = ref(false)
async function readModes() {
 const id = flow.value?.id
 if(!id || !offerModes.value) return
 readingModes.value = true
 try {
  const m = await k.call('mail.setup.receivemodes', {id})
  if(flow.value?.id !== id) return
  modes.value = m
 } catch {
  if(flow.value?.id === id) modes.value = {domain: false, domainReason: 'mail.setup.receive.unknown'}
 } finally {readingModes.value = false}
 // The default: the whole domain when it is available.
 receive.value = modes.value?.domain ? 'domain' : 'addresses'
}
watch(step, (at, before) => {if(at === 'configuration' && before !== 'preview') void readModes()})
watch(() => flow.value?.id, () => {modes.value = undefined; receive.value = 'addresses'})
const receiveCards = computed(() => {
 const m = modes.value
 const count = branch.value?.mailboxes?.length ?? 0
 return [
  {value: 'domain', label: k.t('mail.setup.receive.domain'), disabled: !m?.domain,
   description: m && !m.domain ? k.t(m.domainReason || 'mail.setup.receive.unknown', {domain: domain.value}) : k.t('mail.setup.receive.domainBody', {domain: domain.value})},
  {value: 'addresses', label: k.t('mail.setup.receive.addresses'), description: k.t('mail.setup.receive.addressesBody', {count})},
 ]
})
const configurationTitle = computed(() => domain.value ? k.t('mail.setup.configurationFor', {domain: domain.value}) : k.t('mail.setup.configuration'))
/** What changes, in plain words: the send and receive consequences only. The
 * chosen path itself is not repeated (the route and facts steps said it). */
const consequences = computed(() => {
 const out: string[] = []
 if(branch.value?.paths?.some(p => p.branch === 'cloudflare-relay')) out.push(k.t('mail.setup.consequence.send'))
 if(offerModes.value) out.push(receive.value === 'domain' ? k.t('mail.setup.consequence.receiveDomain', {domain: domain.value})
  : k.t('mail.setup.consequence.receive', {domain: domain.value, count: branch.value?.mailboxes?.length ?? 0}), k.t('mail.setup.consequence.offline'))
 return out
})
/** The folded details: which mailboxes get a rule now, what later users need,
 * and the worker's limits and unknowns (restore, SPF, plan). The sender line
 * is already said above in plain words. */
const details = computed(() => {
 const out: string[] = []
 const boxes = branch.value?.mailboxes ?? []
 if(routingReceive.value && boxes.length && receive.value === 'addresses') out.push(k.t('mail.setup.mailboxesNow', {count: boxes.length, list: boxes.join(', ')}), k.t('mail.setup.mailboxesLater'))
 for(const w of branch.value?.warnings ?? []) if(w.labelKey !== 'mail.setup.globalDelivery') out.push(k.t(w.labelKey, w.params))
 return out
})
const detailFold = computed<AccordionEntry[]>(() => [{value: 'details', title: k.t('mail.setup.details')}])
const fieldsMissing = computed(() => (branch.value?.fields ?? []).some(f => f.required && !values.value[f.name]?.trim()) ||
 tunnelOptions.value.length > 0 && !tunnel.value || noMailboxes.value || offerModes.value && (readingModes.value || !modes.value))
/** The worker discarded the plan: answers or facts changed after it was prepared. */
const planChanged = computed(() => (error.value as AssistantError | undefined)?.details?.reason === 'mail.setup.planChanged')
/** The receive preview requires a healthy tunnel in the selected account. */
const tunnelHelp = computed(() => (error.value as AssistantError | undefined)?.details?.reason === 'mail.setup.tunnelRequired')
const tunnelHelpFold = computed<AccordionEntry[]>(() => [{value: 'manual-tunnel', title: k.t('mail.setup.tunnelAdvanced')}])
function openConnectCatalog() {window.open(SYNO_CONNECT_CATALOG_URL, '_blank', 'noopener,noreferrer')}
/** Generate the preview again: from the preview step, back to the configuration
 * (the fields may differ);
 * on the configuration step, prepare it now and show it. */
async function regenerate() {
 if(step.value === 'preview') {error.value = undefined; preview.value = undefined; step.value = 'configuration'; return}
 if(!fieldsMissing.value && await runPreview()) step.value = 'preview'
}

// ---- preview: what applying changes, in plain words, one line per thing the
// administrator would recognise (mail.setup.summary.*). Warnings the
// configuration step already gave are not repeated; at most two new ones
// show, the rest and the exact before/after values are folded.
const SUMMARY: Record<string, string> = {
 'cloudflare.sending': 'sendOn', 'cloudflare.sending.dns': 'sendOn',
 'relay.configure': 'sendVia', 'mailplus.delivery': 'sendVia',
 'mailplus.dkim.disable': 'dkim',
 'inbound.routing': 'receiveOn', 'cloudflare.routing': 'receiveOn',
 'inbound.worker': 'receiveProgram', 'inbound.vpc': 'receiveProgram', 'cloudflare.worker': 'receiveProgram', 'cloudflare.vpc': 'receiveProgram',
 'inbound.rules': 'receiveRules', 'inbound.catchall': 'receiveAll',
 'mailplus.smtp': 'smtpOn',
 'mailplus.domain': 'mailplusDomain',
}
const previewTitle = computed(() => domain.value ? k.t('mail.setup.previewFor', {domain: domain.value}) : k.t('mail.setup.preview'))
const summary = computed(() => {
 const lines = new Map<string, {key: string; count: number; fallback?: string; params?: Record<string, string>}>()
 for(const c of preview.value?.changes ?? []) {
  const code = SUMMARY[c.id] ?? (c.id.startsWith('dns.') ? (c.target === 'external.dns' ? 'dnsExternal' : 'dnsCloudflare') : undefined)
  const id = code ?? c.id
  const line = lines.get(id) ?? {key: code ? `mail.setup.summary.${code}` : '', count: 0, fallback: code ? undefined : k.t(c.actionKey, c.params), params: c.params}
  line.count++
  lines.set(id, line)
 }
 const boxes = branch.value?.mailboxes?.length ?? 0
 return [...lines.values()].map(l => l.key ? k.t(l.key, {...l.params, count: l.key.endsWith('receiveRules') ? boxes : l.count}) : l.fallback!)
})
/** Plan warnings that need no action: folded only. MailPlus's relay client
 * networks cannot open a relay through the inbound path: the Worker hands
 * MailPlus only recipients of the configured domain (docs/mail-rules.md,
 * Relay prevention), and a LAN range there is often deliberate (printers,
 * scanners). So neither the count nor an unread list asks for a change. */
const FOLD_ONLY = new Set(['mail.setup.inbound.relayNetworks', 'mail.setup.inbound.relayNetworksUnknown'])
/** Warnings whose text already carries their value (its params). */
const VALUE_IN_TEXT = new Set(['mail.setup.inbound.relayNetworks'])
/** A warning's exact text; its value only when it says more than the domain (shown once, in the headline). */
function warningText(w: Fact): string {
 const text = k.t(w.labelKey, w.params)
 if(VALUE_IN_TEXT.has(w.labelKey) || !/^mail\.[\w.]+$/.test(w.value) || !k.has(w.value)) return text
 return k.t('mail.setup.preview.warning', {text, value: k.t(w.value, w.params)})
}
const newWarnings = computed(() => {
 const said = new Set((branch.value?.warnings ?? []).map(w => w.labelKey))
 return (preview.value?.warnings ?? []).filter(w => !said.has(w.labelKey))
})
const notices = computed(() => newWarnings.value.filter(w => !FOLD_ONLY.has(w.labelKey)).slice(0, 2)
 .map(warningText))
/** Cloudflare's permission names, as plain purposes (mail.setup.purpose.*). */
const PURPOSE: Record<string, string> = {
 'Zone Read': 'zoneRead', 'DNS Write': 'dnsEdit', 'Email Sending Write': 'sendingEdit', 'Zone Settings Write': 'zoneSettingsEdit',
 'Email Routing Rules Write': 'routingRulesEdit', 'Workers Scripts Write': 'workersEdit', 'Connectivity Directory Admin': 'vpcAdmin', 'Cloudflare Tunnel Read': 'tunnelRead',
}
const purposes = computed(() => [...new Set((preview.value?.permissions ?? []).map(p => p.value.split(' / ').pop() ?? p.value))]
 .map(name => PURPOSE[name] ? k.t('mail.setup.preview.permission', {purpose: k.t(`mail.setup.purpose.${PURPOSE[name]}`), name}) : name))
const previewFold = computed<AccordionEntry[]>(() => [{value: 'details', title: k.t('mail.setup.details')}])

// ---- preview → applying (background) → decision
async function apply() {
 return guard(async () => {
  flow.value = await k.call('mail.setup.apply', {id: flow.value!.id})
  emit('changed')
 })
}
/** The applying progress step: watch the transaction until the worker reaches a decision or an outcome. */
const applyWait = useElapsed()
async function follow() {
 const signal = watchRound('applying')
 if(!signal) return
 error.value = undefined
 const stopWait = applyWait.start()
 try {
  for(;;) {
   const f = await k.call('mail.setup.status', {id: flow.value!.id})
   if(!current(signal, 'applying')) return
   flow.value = f
   if(f.phase === 'decision' || f.phase === 'interrupted' || f.phase === 'failed') {step.value = 'decision'; return}
   if(f.outcome) {step.value = 'result'; emit('changed'); return}
   await pause(1000, signal)
   if(!current(signal, 'applying')) return
  }
 } catch(e) {
  // The transaction is the worker's: a failed read only means the status is
  // not up to date. The last progress stays; Check again reads it again.
  if(current(signal, 'applying')) {error.value = e; stopPolling()}
 }
 finally {stopWait()}
}
// Watch only while the dialog is open on a progress step; leaving ends the round.
watch([open, step], ([isOpen, at]) => {
 if(!isOpen || (poll && poll.step !== at)) stopPolling()
 if(!isOpen) return
 if(at === 'detect') void followDetect()
 else if(at === 'applying') void follow()
})
/** A step ran out of time: what MailPlus now holds is not known. */
const unconfirmed = computed(() => flow.value?.error === 'mail.setup.unconfirmed')
/**
 * a MailPlus write refused for a missing DSM grant
 * (authority_required:<profile>) says which access is missing and which step
 * failed, with Allow access; never a DSM code.
 */
const missingAccess = computed(() => {
 const f = flow.value
 const m = /^authority_required:(.+)$/.exec(f?.error ?? '')
 if(!f || !m) return undefined
 const profile = isProfile(m[1]) ? m[1] : undefined
 const change = f.changes.find(c => c.id === f.failedStep)
 const text = k.t(f.outcome === 'rolledBack' ? 'ui.setup.authority.rolledBack' : 'ui.setup.authority.failed', {
  step: change ? k.t(change.actionKey, change.params) : k.t('ui.setup.authority.someStep'),
  access: profile ? k.t(profileName(profile)) : k.t('ui.setup.authority.someAccess')})
 return {profile, text}
})
/** Cloudflare refused the flow's token (deleted or rolled): a new one is entered here and replaces it in place. */
const tokenRefused = computed(() => {
 const e = flow.value?.error ?? ''
 return e === 'mail.setup.tokenInvalid' || e.startsWith('mail.setup.permissionRefused.')
})
const reentering = ref(false)
const tokenReplaced = ref(false)
// A later refusal (or another flow) asks again.
watch(() => [flow.value?.id, flow.value?.error], ([, e]) => {if(e) tokenReplaced.value = false})
async function flowTokenSaved() {
 tokenReplaced.value = true
 const f = flow.value
 if(f) try {flow.value = await k.call('mail.setup.status', {id: f.id})} catch {/* the next read shows it */}
}

const running = computed(() => flow.value?.phase === 'applying' || flow.value?.phase === 'verifying' || flow.value?.phase === 'rollingBack')
const progressLabel = computed(() => {
 const f = flow.value
 if(!f) return ''
 if(f.phase === 'verifying') return k.t('ui.setup.verifying')
 if(f.phase === 'rollingBack') return k.t('ui.wizard.rollingBack')
 return k.t('ui.setup.applyProgress', {done: f.done, total: f.total})
})
const applyProgress = computed<WizardProgress>(() => {
 const f = flow.value
 const status = errorText.value ? k.t('ui.setup.statusStale') : undefined
 if(f && f.total && f.phase === 'applying') return {mode: 'determinate', label: progressLabel.value, value: f.done, max: f.total, status}
 return {mode: 'indeterminate', label: progressLabel.value || k.t('ui.wizard.progressBusy'), status}
})
const detectProgress = computed<WizardProgress>(() => ({mode: 'indeterminate', label: k.t('ui.setup.detectProgress')}))

// ---- decision: one choice (keep | roll back) and one Confirm action.
// Keep is offered only in the decision phase; an interrupted or failed
// transaction can only be rolled back. Keep is pre-selected only once the
// changes were verified; otherwise nothing is selected and Confirm stays
// disabled until the administrator picks a card.
type Decision = 'keep' | 'rollback'
const canKeep = computed(() => flow.value?.phase === 'decision')
const decision = ref<Decision | ''>('')
// Opening the wizard, another transaction or a new phase starts the pick over.
watch(() => [open.value, flow.value?.id, flow.value?.phase, flow.value?.verified] as const, ([, , phase, verified]) => {
 decision.value = phase === 'decision' && verified ? 'keep' : ''
}, {immediate: true})
const decisions = computed(() => [
 {value: 'keep', label: k.t('mail.setup.keep'), description: k.t('mail.setup.keepHint'), icon: Check, disabled: !canKeep.value},
 {value: 'rollback', label: k.t('mail.setup.rollback'), description: k.t('mail.setup.rollbackHint'), icon: Undo2},
])
const decided = computed(() => decision.value === 'rollback' || (decision.value === 'keep' && canKeep.value))
/** Check again: inbound mail was not seen yet (for example the check mail the
 * administrator sends). Reads only; the decision stays open. */
const canCheckAgain = computed(() => flow.value?.phase === 'decision' && !flow.value.verified &&
 flow.value.findings.some(f => f.id === 'mail.setup.inbound'))
const checking = ref(false)
/**
 * Waiting for the administrator's check mail: readback passed and the only
 * open finding is "send a check mail" (plus the generic unverified line the
 * worker adds to any unverified result). Nothing failed yet, so the step shows
 * what to do in a neutral tone, not warnings. Any other open finding, or a
 * flow error (a timeout, a refused write), shows the findings as they are.
 */
const waitMail = computed(() => {
 const f = flow.value
 if(!f || f.phase !== 'decision' || f.verified || f.error) return undefined
 const mail = f.findings.find(x => x.id === 'mail.setup.inbound' && x.titleKey === 'mail.setup.inbound.checkMail')
 if(!mail || f.findings.some(x => x !== mail && x.severity !== 'ok' && x.id !== 'mail.setup.verification')) return undefined
 return {address: mail.params?.address ?? '', code: mail.params?.code ?? ''}
})
/** While waiting, the check mail's instructions replace its finding and the generic line; what passed still shows. */
const shownFindings = computed(() => waitMail.value ? flow.value!.findings.filter(x => x.severity === 'ok') : flow.value?.findings ?? [])
/** A Check again the administrator pressed found no check mail yet (still waiting, not failed). */
const notYet = ref(false)
watch(() => flow.value?.id, () => {notYet.value = false})
async function checkAgain() {
 checking.value = true
 notYet.value = false
 try {
  await guard(async () => {
   let f = await k.call('mail.setup.decide', {id: flow.value!.id, choice: 'verify'})
   flow.value = f
   while(f.phase === 'verifying') {
    await pause(2000)
    if(!open.value) return
    f = await k.call('mail.setup.status', {id: flow.value!.id})
    flow.value = f
   }
  })
 } finally {
  checking.value = false
  notYet.value = !!waitMail.value
 }
}
/** Confirm: Keep moves on to the result; Roll back goes to the applying step to follow the rollback. */
async function decide(): Promise<WizardGuardResult> {
 if(!decided.value) return false
 const choice = decision.value as Decision
 if(await guard(async () => {flow.value = await k.call('mail.setup.decide', {id: flow.value!.id, choice})}) === false) return false
 if(choice === 'rollback') return {goTo: 'applying'}
}
const decisionTitle = computed(() => {
 const f = flow.value
 if(f?.phase === 'interrupted') return k.t('ui.wizard.failedTitle')
 if(f?.phase === 'failed') return k.t('ui.wizard.failedTitle')
 if(waitMail.value) return k.t('mail.setup.waitMail.headline')
 return k.t(f?.verified ? 'mail.setup.verified' : 'mail.setup.verificationFailed')
})

// ---- result
const resultTitle = computed(() => {
 const f = flow.value
 if(f?.phase === 'kept') return k.t('mail.setup.kept')
 return k.t(f?.outcome === 'rolledBack' ? 'mail.setup.rolledback' : 'ui.wizard.failedTitle')
})
const resultBody = computed(() => {
 const f = flow.value
 if(f?.error === 'mail.setup.unconfirmed' && f.outcome !== 'rolledBack') return k.t('mail.setup.unconfirmedBody')
 // An automatic rollback says why, without blaming the verification.
 if(f?.outcome === 'rolledBack' && f.error === 'mail.setup.unconfirmed') return k.t('mail.setup.rolledBackAfterTimeout')
 if(missingAccess.value) return missingAccess.value.text
 if(f?.outcome === 'rolledBack') return k.t(f.error ? 'mail.setup.rolledBackAfterProblem' : 'ui.setup.rolledBackBody')
 if(f?.phase === 'kept') return k.t(f.verified ? 'ui.setup.keptBody' : 'mail.setup.keptUnverified')
 return k.t('ui.wizard.failedKeptBody')
})
/**
 * The outcome's tone: kept and verified is a success; a rollback the
 * administrator chose is neutral; kept unverified or rolled back after a
 * failed check is a warning; a failed transaction is a failure. Anything the
 * worker did not state is a warning, never a success.
 */
const resultTone = computed<WizardResultTone>(() => {
 const f = flow.value
 if(f?.phase === 'kept') return f.verified && f.outcome === 'ok' ? 'success' : 'warning'
 if(f?.outcome === 'rolledBack') return f.error ? 'warning' : 'neutral'
 if(f?.outcome === 'failed') return 'danger'
 return 'warning'
})
</script>

<template>
 <WizardDialog v-model:open="open" v-model:active-step-key="step" :title="k.t('mail.setup.title')" :confirm-close="typed && !flow?.outcome && !running">
  <!-- The precondition: MailPlus Server not installed, stopped or unknown stops the wizard at its start. -->
  <WizardStep v-if="mpBlocked || step === 'mailplus'" step-key="mailplus" :headline="k.t('ui.mailplus.title')" :icon="Server" :description="k.t('ui.mailplus.wizardBody')"
   next-step-key="intent" :next-label="mpReady ? undefined : k.t('ui.mailplus.recheck')" :next-disabled="mp.checking.value" :pre-enter-next-step="leaveMailPlus" :show-back="false">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span>
     <template v-if="refusal" #actions><Button variant="secondary" @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <div ref="mailplusRoot">
     <MailPlusNotice v-if="!mpReady" :status="mp.status.value" :checking="mp.checking.value" :recheck="false" @launched="watchComeBack" />
     <Callout v-else tone="success" :dismissible="false" data-mailplus-ready>{{ k.t('ui.mailplus.ready') }}</Callout>
    </div>
   </Space>
  </WizardStep>

  <!-- Errors and refusals show above the step's content, in every step. -->
  <WizardStep step-key="intent" :headline="k.t('mail.setup.intent')" :icon="MailCheck" :description="k.t('ui.overview.setupBody')"
   next-step-key="start" :pre-enter-next-step="leaveIntent" :show-back="false">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <RadioGroup v-model="choice" variant="card" orientation="horizontal" :options="intents" />
   </Space>
  </WizardStep>

  <WizardStep step-key="start" :headline="k.t('mail.setup.start')" :description="k.t('mail.setup.startBody')"
   previous-step-key="intent" :next-step-key="() => viaCloudflare ? 'cloudflare' : 'domain'" :next-disabled="!source">
   <RadioGroup v-model="source" variant="card" orientation="horizontal" :options="sources" data-sources />
  </WizardStep>

  <!-- One Cloudflare token, pasted once: B right after start, A when its branch needs Cloudflare.
       One line, three numbered steps, the button, the permissions folded, the field, short notes. -->
  <WizardStep v-if="viaCloudflare || branch?.needsAccount || step === 'cloudflare'" step-key="cloudflare" :headline="k.t('mail.setup.cloudflare')" :description="k.t('mail.setup.cloudflareBody')"
   :previous-step-key="() => viaCloudflare ? 'start' : 'facts'" :next-step-key="() => viaCloudflare ? 'zone' : 'account'"
   :next-disabled="!token.trim() && !signedIn" :pre-enter-next-step="leaveCloudflare">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <Callout v-if="missingText" tone="warning" :dismissible="false" data-missing-permissions>{{ missingText }}</Callout>
    <Callout v-else-if="cloud && !cloud.accounts.length && !cloud.accountUnknown" tone="warning" :dismissible="false" data-no-account>{{ k.t('mail.setup.zone.noAccount', {create: createLabel}) }}</Callout>
    <StepList :items="tokenSteps" data-token-steps />
    <div><Button variant="secondary" data-create-token @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button></div>
    <Accordion :items="permissionFold" data-permissions>
     <template #item-permissions>
      <Space direction="column" spacing="dense" role="list">
       <div v-for="line in permissionLines" :key="line" role="listitem" data-permission>{{ line }}</div>
      </Space>
     </template>
    </Accordion>
    <Form>
     <FormItem :label="k.t('mail.setup.cloudflare.token')" :description="k.t('mail.setup.cloudflare.tokenHint')" :required-mark="!signedIn">
      <Input v-model="token" type="password" autocomplete="off" spellcheck="false" data-token />
     </FormItem>
    </Form>
    <Space direction="column" spacing="dense" class="msa-quiet" data-token-notes>
     <div v-if="signedIn" data-signed-in>{{ k.t('mail.setup.cloudflare.connected') }}</div>
     <div data-relay-note>{{ k.t('mail.setup.cloudflare.relayNote') }}</div>
     <div data-read-only-check>{{ k.t('mail.setup.cloudflare.readOnlyCheck') }}</div>
     <div data-one-run>{{ k.t('mail.setup.cloudflare.oneRun') }}</div>
    </Space>
   </Space>
  </WizardStep>

  <!-- B: the account (only when there are several) and the zone, from Cloudflare's lists. One Check again, in the footer. -->
  <WizardStep v-if="viaCloudflare || step === 'zone'" step-key="zone" :headline="k.t('mail.setup.zone')" :description="k.t('mail.setup.zoneBody')" previous-step-key="cloudflare"
   next-step-key="detect" :next-disabled="!chosenZone || chosenZone.status !== 'active' || listing || choosing || !mailDomainsKnown || !mailDomain || !!newDomainProblem" :pre-enter-next-step="leaveZone">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span>
     <template v-if="refusal" #actions><Button variant="secondary" data-zone-access @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <Callout v-if="missingText" tone="warning" :dismissible="false" data-missing-permissions>{{ missingText }}
     <template #actions>
      <Button variant="secondary" @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button>
      <Button variant="secondary" data-replace-token @click="replaceToken">{{ k.t('mail.setup.cloudflare.replace') }}</Button>
     </template>
    </Callout>
    <Form>
     <FormItem v-if="accountOptions.length > 1" :label="k.t('mail.setup.zone.account')" required-mark data-account>
      <Select v-model="accountId" :options="accountOptions" />
     </FormItem>
     <FormItem v-if="listed && !noZones" :label="k.t('mail.setup.zone.domain')" required-mark data-zones>
      <Select v-model="zoneId" :options="zoneOptions" search />
     </FormItem>
     <FormItem v-if="mailDomainsKnown && mailDomainOptions.length" :label="k.t('mail.setup.zone.mailDomain')" :description="k.t('mail.setup.zone.mailDomainHint', {zone: chosenZone!.name})" required-mark data-mail-domains>
      <Select v-model="mailDomain" :options="mailDomainOptions" />
     </FormItem>
     <FormItem v-if="mailDomain === NEW_DOMAIN && canCreateDomain" :label="k.t('mail.setup.zone.newDomainName')" :description="k.t('mail.setup.zone.newDomainHint', {zone: chosenZone!.name})"
      :rules="newDomainRule" validate-message-display-mode="text" default-validate-trigger="change" required-mark data-new-domain>
      <Input v-model="newDomain" autocomplete="off" spellcheck="false" :placeholder="chosenZone!.name" />
     </FormItem>
    </Form>
    <Progress v-if="choosing" indeterminate :label="k.t('mail.setup.zone.reading')" />
    <Callout v-if="mailDomain === NEW_DOMAIN && canCreateDomain" tone="info" :dismissible="false" data-new-domain-note>{{ k.t('mail.setup.zone.newDomainNote', {domain: newDomainName || chosenZone!.name}) }}</Callout>
    <!-- No mail domain in the zone: exactly what to type in MailPlus Server, open it, read again on coming back. -->
    <Callout v-if="noMailDomain" tone="info" :dismissible="false" data-no-mail-domain :data-help="zoneHelpKey">
     <div ref="zoneHelpRoot" class="msa-zone-help">
      <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t(`mail.setup.zone.help.${zoneHelpKey}.title`, {zone: chosenZone!.name}) }}</div>
      <div>{{ k.t(`mail.setup.zone.help.${zoneHelpKey}.body`, {zone: chosenZone!.name}) }}</div>
      <div class="msa-copy-values">
       <div class="msa-copy-value" data-copy="domain">
        <span class="msa-copy-label">{{ k.t('mail.setup.zone.help.domainName') }}</span>
        <span class="msa-copy-text"><code>{{ chosenZone!.name }}</code><CopyButton :text="chosenZone!.name" :label="k.t('mail.setup.zone.help.copy')" :words="{copied: k.t('mail.setup.zone.help.copied')}" size="sm" /></span>
       </div>
       <div v-if="zoneHelpKey !== 'addDomain'" class="msa-copy-value" data-copy="host">
        <span class="msa-copy-label">{{ k.t('mail.setup.zone.help.hostName') }}</span>
        <span class="msa-copy-text"><code>{{ zoneHost }}</code><CopyButton :text="zoneHost" :label="k.t('mail.setup.zone.help.copy')" :words="{copied: k.t('mail.setup.zone.help.copied')}" size="sm" /></span>
       </div>
      </div>
      <div class="msa-quiet">{{ k.t('mail.setup.zone.help.after') }}</div>
      <div v-if="launchText" class="msa-quiet" data-launch>{{ launchText }}</div>
      <div role="status" class="msa-quiet" data-recheck>{{ recheckText }}</div>
     </div>
     <template #actions><Button variant="secondary" data-open-mailplus @click="openMailPlus">{{ k.t('ui.setup.openMailPlusButton') }}</Button></template>
    </Callout>
    <MailPlusNotice v-if="zoneMailPlus" :status="zoneMailPlus" :recheck="false" data-zone-mailplus />
    <Callout v-else-if="zoneRead && cloud?.mailDomainsState === 'unknown'" tone="warning" :dismissible="false" data-mail-domains-unknown>{{ k.t('mail.setup.zone.mailDomainsUnknown', {cause: cloud?.mailDomainsCauseKey ? k.t(cloud.mailDomainsCauseKey, cloud.mailDomainsCauseParams) : k.t('mail.setup.cause.unavailable')}) }}</Callout>
    <div v-if="anyPending" class="msa-quiet" data-pending-note>{{ k.t('mail.setup.zone.pendingNote') }}</div>
    <Callout v-if="noZones" tone="info" :dismissible="false" data-no-zones>
     <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.zone.none') }}</div>
     {{ k.t('mail.setup.zone.noneBody') }}
     <template #actions>
      <Button variant="secondary" data-register @click="openCloudflare(registerDomainUrl)">{{ k.t('mail.setup.zone.register') }}</Button>
     </template>
    </Callout>
   </Space>
   <template v-if="listed || cloud?.accountUnknown" #actions><Button variant="ghost" kind="tool" :disabled="listing || choosing" data-recheck-zones @click="recheckZone">{{ k.t('mail.setup.zone.recheck') }}</Button></template>
  </WizardStep>

  <WizardStep v-if="!viaCloudflare || step === 'domain'" step-key="domain" :headline="k.t('mail.setup.domain')" :description="k.t('mail.setup.domainHint')" previous-step-key="start"
   next-step-key="detect" :next-disabled="!domain.trim()" :pre-enter-next-step="leaveDomain">
   <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
   <Form>
    <FormItem :label="k.t('mail.setup.domain')" required-mark>
     <Input v-model="domain" autocomplete="off" spellcheck="false" placeholder="example.com" />
    </FormItem>
   </Form>
  </WizardStep>

  <!-- Read-only work, right after the domain: Back stops watching and returns to the domain. -->
  <WizardStep step-key="detect" type="progress" :headline="k.t('mail.setup.detect')" :description="k.t('mail.setup.detectBody')"
   :progress="detectProgress" :show-back="true" :previous-step-key="() => viaCloudflare ? 'zone' : 'domain'">
   <div class="msa-quiet" aria-live="polite">{{ k.t('ui.wait.elapsed', {seconds: waited.seconds.value}) }}</div>
   <div v-if="waited.seconds.value >= SLOW_AFTER" class="msa-quiet">{{ k.t('ui.wait.slow') }}</div>
  </WizardStep>

  <!-- MailPlus Server lacks something for this domain: say exactly what, open it, check again on coming back.
       Blocking: Check again is the main action. Receiving pending: sending goes on. -->
  <WizardStep v-if="prereqShown || step === 'prereq'" step-key="prereq" :headline="k.t('mail.setup.prereq')" :description="prereqTitle" :icon="Inbox"
   :previous-step-key="() => viaCloudflare ? 'zone' : 'domain'" :next-step-key="() => prereqNext"
   :next-label="blocking ? k.t('ui.setup.checkAgain') : pending ? k.t('mail.setup.prereq.continueSend') : undefined" :pre-enter-next-step="leavePrereq">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <Callout v-if="prereqBody" :tone="prereqReady ? 'success' : pending ? 'info' : 'warning'" :dismissible="false" data-prereq-body>{{ prereqBody }}</Callout>
    <FactList v-if="prereqFacts.length" :facts="prereqFacts" data-prereq-facts />
    <FactList v-if="prereqPlanned.length" :facts="prereqPlanned" show-state hide-notes data-prereq-planned />
    <div v-if="!newDomainPending" ref="handoffRoot" class="msa-handoff">
     <!-- The manual path always shows: the launcher cannot prove a window opened. -->
     <div class="msa-quiet">{{ k.t('ui.setup.openMailPlus') }}</div>
     <div><Button variant="secondary" data-open-mailplus @click="openMailPlus">{{ k.t('ui.setup.openMailPlusButton') }}</Button></div>
     <div v-if="launchText" class="msa-quiet" data-launch>{{ launchText }}</div>
     <div role="status" class="msa-quiet" data-recheck>{{ recheckText }}</div>
    </div>
   </Space>
   <template #actions><Button variant="ghost" kind="tool" @click="handOff">{{ k.t('ui.setup.handoffDiagnose') }}</Button></template>
  </WizardStep>

  <!-- How mail travels: Cloudflare (recommended) or the confirmed own IP. Nothing is tested from outside. -->
  <WizardStep step-key="route" :headline="k.t('mail.setup.route')" :description="k.t('mail.setup.routeBody')" :icon="RouteIcon"
   :previous-step-key="() => prereqShown ? 'prereq' : viaCloudflare ? 'zone' : 'domain'" :next-step-key="() => detection?.done ? 'facts' : 'detect'"
   :next-disabled="!routeReady" :pre-enter-next-step="leaveRoute">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <!-- The App's one promise, then the two ways as cards with their concept pictures (moved here from the Overview). -->
    <div class="msa-key" data-key-point><CircleCheck class="msa-key-icon" aria-hidden="true" />{{ k.t('mail.setup.route.headline') }}</div>
    <RadioGroup v-model="route" variant="card" orientation="horizontal" :options="routes" data-routes />
    <PlanNote v-if="route !== 'direct'" />
    <Space v-if="route === 'direct'" direction="column" spacing="regular" data-requirements>
     <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.route.requirements') }}</div>
     <StepList :items="requirements" />
     <div v-if="receives">
      <Link :href="smtpTest" external target="_blank" rel="noopener noreferrer" data-smtp-test>{{ publicIp ? k.t('mail.setup.route.test', {ip: publicIp}) : k.t('mail.setup.route.testNoIp') }}</Link>
      <div class="msa-quiet">{{ k.t('mail.setup.route.testNote') }}</div>
     </div>
     <template v-if="routeFacts.length">
      <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.route.detected') }}</div>
      <FactList :facts="routeFacts" show-state data-route-facts />
     </template>
     <Callout v-if="checksDisagree" tone="warning" :dismissible="false" data-checks-disagree>{{ k.t('mail.setup.route.checksDisagree') }}</Callout>
     <Checkbox v-model="confirmed" :label="k.t('mail.setup.route.confirm')" data-confirm />
     <Callout tone="info" variant="inline" :dismissible="false" data-not-eligible>{{ k.t('mail.setup.route.notEligible') }}
      <template #actions><Button variant="secondary" data-use-cloudflare @click="useCloudflare">{{ k.t('mail.setup.route.useCloudflare') }}</Button></template>
     </Callout>
    </Space>
   </Space>
  </WizardStep>

  <WizardStep step-key="facts" :headline="k.t('mail.setup.facts')" :description="factsUnknown ? k.t('mail.setup.factsBody') : undefined"
   :next-step-key="nextAfterFacts" previous-step-key="route" :pre-enter-next-step="leaveFacts"
   :next-label="branch?.kind === 'diagnose' ? k.t('ui.setup.handoffDiagnose') : undefined">
   <Space direction="column" spacing="regular">
    <Callout v-if="branch?.receivePending" tone="info" :dismissible="false" data-receive-pending>{{ k.t(branch.createsDomain ? 'mail.setup.prereq.receivePendingNew' : 'mail.setup.prereq.receivePending', {domain}) }}</Callout>
    <template v-if="grouped">
     <FactGroups v-if="attention.length" :facts="attention" show-state data-attention />
     <div v-else class="msa-quiet" data-all-fine>{{ k.t(planned.length ? 'mail.setup.facts.nothingToFix' : 'mail.setup.facts.allFine') }}</div>
     <Space v-if="planned.length" direction="column" spacing="dense" data-planned>
      <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.facts.planned', {count: planned.length}) }}</div>
      <div v-for="g in plannedGroups" :key="g.note" class="msa-planned-group" :data-planned-note="g.note">
       <FactList :facts="g.facts" show-state hide-notes />
       <div v-if="g.note" class="msa-fact-note" data-fact-note>{{ k.t(g.note) }}</div>
      </div>
     </Space>
     <Accordion v-if="factFolds.length" :items="factFolds" data-fact-folds>
      <template #item-fine><FactGroups :facts="fine" /></template>
      <template #item-unrelated><FactGroups :facts="unrelated" /></template>
     </Accordion>
    </template>
    <FactList v-else-if="facts.length" :facts="facts" />
    <!-- Only a direction the detection moved away from the chosen route; the choice itself is never echoed. -->
    <Callout v-if="movedPaths.length" tone="info" :dismissible="false" data-moved-paths>
     <Space direction="column" spacing="dense">
      <div v-for="p in movedPaths" :key="p.direction" :data-moved="p.direction">
       <div class="msa-subtitle">{{ k.t(`mail.setup.pathChanged.${p.direction}`) }}</div>
       <div v-for="why in p.why" :key="why">{{ k.t(why) }}</div>
      </div>
     </Space>
    </Callout>
   </Space>
  </WizardStep>

  <!-- A stop: a blocker or a missing integration (MailPlus Server's own gaps show on prereq). -->
  <WizardStep v-if="stopShown || step === 'stop'" step-key="stop" :headline="branch ? k.t(branch.titleKey, branch.params) : ''" previous-step-key="facts"
   :next-label="k.t('ui.setup.checkAgain')" next-step-key="detect" :pre-enter-next-step="retry">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <Callout v-if="branch?.bodyKey" tone="warning" :dismissible="false">{{ k.t(branch.bodyKey, branch.params) }}</Callout>
    <!-- Which facts the decision lacked, and why each is unknown. -->
    <FactList v-if="branch?.warnings?.length" :facts="branch.warnings" data-missing />
    <PathList v-if="stopPaths.length" :paths="stopPaths" />
    <template v-if="branch?.records?.length">
     <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('ui.setup.records') }}</div>
     <ChangeList :changes="branch.records" />
    </template>
   </Space>
   <template #actions><Button variant="ghost" kind="tool" @click="handOff">{{ k.t('ui.setup.handoffDiagnose') }}</Button></template>
  </WizardStep>

  <WizardStep v-if="branch?.kind === 'already' || step === 'already'" step-key="already" type="result" :result-tone="branch?.outcome === 'ok' ? 'success' : 'warning'" :headline="branch ? k.t(branch.titleKey) : ''"
   :description="branch?.bodyKey ? k.t(branch.bodyKey) : undefined">
   <Callout v-if="branch?.outcome !== 'ok'" tone="warning" :dismissible="false">{{ k.t('mail.setup.verificationFailedBody') }}</Callout>
   <Callout v-if="branch?.receivePending" tone="info" :dismissible="false" data-receive-pending>{{ k.t(branch.createsDomain ? 'mail.setup.prereq.receivePendingNewBody' : 'mail.setup.prereq.receivePendingBody', {domain}) }}</Callout>
   <template #actions><Button variant="ghost" kind="tool" @click="handOff">{{ k.t('ui.setup.handoffDiagnose') }}</Button></template>
  </WizardStep>

  <!-- A: the signed-in account (a choice only when there are several) and the zone that holds the domain. -->
  <WizardStep v-if="(!viaCloudflare && branch?.needsAccount) || step === 'account'" step-key="account" :headline="k.t('mail.setup.accountFor', {domain})" previous-step-key="cloudflare" next-step-key="configuration"
   :next-disabled="!matchedZone || matchedZone.status !== 'active' || listing" :pre-enter-next-step="leaveAccount">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span></Callout>
    <Callout v-if="missingText" tone="warning" :dismissible="false" data-missing-permissions>{{ missingText }}
     <template #actions>
      <Button variant="secondary" @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button>
      <Button variant="secondary" data-replace-token @click="replaceToken">{{ k.t('mail.setup.cloudflare.replace') }}</Button>
     </template>
    </Callout>
    <Form v-if="accountOptions.length > 1">
     <FormItem :label="k.t('mail.setup.zone.account')" required-mark data-account><Select v-model="accountId" :options="accountOptions" /></FormItem>
    </Form>
    <template v-if="listed">
     <!-- The domain is in the headline: say only whether the account holds it (and the parent domain when it is one). -->
     <div v-if="matchedZone" data-matched>{{ matchedZone.status !== 'active' ? zoneLabel(matchedZone)
      : matchedZone.name.toLowerCase() === domain.trim().toLowerCase() ? k.t('mail.setup.account.found') : k.t('mail.setup.account.foundParent', {parent: matchedZone.name}) }}</div>
     <Callout v-else tone="warning" :dismissible="false" data-no-match>{{ k.t('mail.setup.account.noMatch') }}</Callout>
     <div v-if="matchedZone && matchedZone.status !== 'active'" class="msa-quiet">{{ k.t('mail.setup.zone.pendingNote') }}</div>
     <div><Button variant="ghost" kind="tool" :disabled="listing" data-recheck-zones @click="listZones">{{ k.t('mail.setup.zone.recheck') }}</Button></div>
    </template>
   </Space>
  </WizardStep>

  <WizardStep step-key="configuration" :headline="configurationTitle" :description="branch?.bodyKey ? k.t(branch.bodyKey) : undefined"
   :previous-step-key="() => !viaCloudflare && branch?.needsAccount ? 'account' : 'facts'" next-step-key="preview"
   :next-disabled="fieldsMissing" :pre-enter-next-step="leaveConfiguration">
   <!-- The step stacks its blocks at one rhythm: WizardStep does not space its content. -->
   <Space direction="column" spacing="regular" data-configuration>
    <Callout v-if="tunnelHelp" tone="warning" :dismissible="false" data-tunnel-help>
     <Space direction="column" spacing="dense">
      <span role="alert">{{ k.t('mail.setup.tunnelRequiredBody') }}</span>
      <ol class="msa-tunnel-steps" data-tunnel-steps>
       <li>{{ k.t('mail.setup.tunnelStepInstall') }}</li>
       <li>{{ k.t('mail.setup.tunnelStepConnect') }}</li>
       <li>{{ k.t('mail.setup.tunnelStepPreview') }}</li>
      </ol>
      <span>{{ k.t('mail.setup.tunnelPublicDSM') }}</span>
      <span>{{ k.t('mail.setup.tunnelSendOnly', {send: k.t('mail.setup.intent.send')}) }}</span>
     </Space>
     <template #actions><Button variant="primary" data-open-connect-catalog @click="openConnectCatalog">{{ k.t('mail.setup.tunnelOpenConnect') }}</Button></template>
    </Callout>
    <Callout v-else-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span>
     <template v-if="planChanged" #actions><Button variant="secondary" data-regenerate :disabled="fieldsMissing || previewing" @click="regenerate">{{ k.t('ui.setup.regeneratePreview') }}</Button></template>
     <template v-else-if="refusal" #actions><Button variant="secondary" @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <Callout v-if="missingText" tone="warning" :dismissible="false" data-missing-permissions>{{ missingText }}
     <template #actions>
      <Button variant="secondary" @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button>
      <Button variant="secondary" data-replace-token @click="replaceToken">{{ k.t('mail.setup.cloudflare.replace') }}</Button>
     </template>
    </Callout>
    <Accordion v-if="tunnelHelp" :items="tunnelHelpFold" data-tunnel-advanced>
     <template #item-manual-tunnel>{{ k.t('mail.setup.tunnelAdvancedBody') }}</template>
    </Accordion>
    <!-- Only what the administrator must know: at most three plain lines; the rest is folded. -->
    <div v-if="consequences.length" class="msa-lines" role="list" data-consequences>
     <div v-for="line in consequences" :key="line" role="listitem">{{ line }}</div>
    </div>
    <Callout v-if="noMailboxes" tone="warning" :dismissible="false" data-no-mailboxes>{{ k.t('mail.setup.noMailboxes', {domain}) }}
     <template #actions><Button variant="secondary" data-open-mailplus @click="openApp(MAILPLUS_APP)">{{ k.t('ui.setup.openMailPlusButton') }}</Button></template>
    </Callout>
    <Callout v-if="tunnelOptions.length" tone="info" :dismissible="false">{{ k.t('mail.setup.tunnelChoice') }}</Callout>
    <Accordion v-if="details.length" :items="detailFold" data-details>
     <template #item-details>
      <Space direction="column" spacing="dense" role="list">
       <div v-for="line in details" :key="line" role="listitem" data-detail>{{ line }}</div>
      </Space>
     </template>
    </Accordion>
    <Form v-if="branch?.fields?.length">
     <FormItem v-for="f in branch.fields" :key="f.name" :label="k.t(f.labelKey)" :description="f.hintKey ? k.t(f.hintKey) : undefined" :required-mark="f.required">
      <Input v-if="f.kind === 'secret'" v-model="values[f.name]" type="password" autocomplete="off" />
      <Textarea v-else v-model="values[f.name]" />
     </FormItem>
    </Form>
    <!-- Choice cards span the step under a heading, side by side, as on the start, route and decision steps;
         as a FormItem beside the label column they sat far right of the lines above. -->
    <div v-if="offerModes" class="msa-choice" data-receive-mode>
     <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.receive.title') }}</div>
     <RadioGroup v-model="receive" variant="card" orientation="horizontal" :options="receiveCards" :disabled="readingModes" :aria-label="k.t('mail.setup.receive.title')" />
    </div>
    <div v-if="tunnelOptions.length" class="msa-choice" data-tunnel-choice>
     <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.tunnel') }}</div>
     <div class="msa-quiet">{{ k.t('mail.setup.tunnelHint') }}</div>
     <RadioGroup v-model="tunnel" variant="card" :options="tunnelCards" :aria-label="k.t('mail.setup.tunnel')" />
    </div>
    <div v-if="branch?.fields?.some(f => f.kind === 'secret')" class="msa-quiet">{{ k.t('ui.setup.secretNote') }}</div>
    <template v-if="previewing">
     <Progress indeterminate :label="k.t('ui.setup.previewProgress')" />
     <div class="msa-quiet" aria-live="polite" data-preview-wait>{{ k.t('ui.wait.elapsed', {seconds: previewWait.seconds.value}) }}</div>
     <div v-if="previewWait.seconds.value >= SLOW_AFTER" class="msa-quiet">{{ k.t('ui.wait.slow') }}</div>
    </template>
   </Space>
  </WizardStep>

  <WizardStep step-key="preview" :headline="previewTitle"
   previous-step-key="configuration" next-step-key="applying" :next-label="k.t('ui.wizard.apply')" :pre-enter-next-step="apply">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span>
     <template v-if="planChanged" #actions><Button variant="secondary" data-regenerate @click="regenerate">{{ k.t('ui.setup.regeneratePreview') }}</Button></template>
     <template v-else-if="refusal" #actions><Button variant="secondary" @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <Space v-if="preview" direction="column" spacing="regular">
     <!-- One plain line per change; the exact values, every warning and the token's permissions are folded. -->
     <div class="msa-lines" role="list" data-summary>
      <div v-for="(line, i) in summary" :key="i" role="listitem">{{ line }}</div>
     </div>
     <Callout v-if="notices.length" tone="warning" :dismissible="false" data-notices>
      <div v-for="(line, i) in notices" :key="i">{{ line }}</div>
     </Callout>
     <Accordion :items="previewFold" data-preview-details>
      <template #item-details>
       <Space direction="column" spacing="regular">
        <Space v-if="newWarnings.length" direction="column" spacing="dense" role="list" data-preview-warnings>
         <div v-for="(w, i) in newWarnings" :key="i" role="listitem">{{ warningText(w) }}</div>
        </Space>
        <template v-if="purposes.length">
         <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.preview.permissions') }}</div>
         <Space direction="column" spacing="dense" role="list" data-purposes>
          <div v-for="(line, i) in purposes" :key="i" role="listitem">{{ line }}</div>
         </Space>
        </template>
        <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.preview.technical') }}</div>
        <ChangeList :changes="preview.changes" data-technical />
       </Space>
      </template>
     </Accordion>
     <div class="msa-quiet">{{ k.t('ui.wizard.previewNote') }}</div>
    </Space>
   </Space>
  </WizardStep>

  <!-- Changes data: no Back and no stop; closing only stops watching, and reopening resumes. -->
  <WizardStep step-key="applying" type="progress" :headline="flow?.phase === 'rollingBack' ? k.t('ui.wizard.rollingBack') : k.t('ui.wizard.applying')"
   :progress="applyProgress">
   <Callout v-if="errorText" tone="warning" :dismissible="false"><span role="alert">{{ errorText }}</span>
    <template #actions><Button variant="secondary" @click="follow">{{ k.t('ui.setup.checkAgain') }}</Button></template>
   </Callout>
   <div class="msa-quiet" aria-live="polite" data-apply-wait>{{ k.t('ui.wait.elapsed', {seconds: applyWait.seconds.value}) }}</div>
   <div v-if="applyWait.seconds.value >= SLOW_AFTER" class="msa-quiet">{{ k.t('ui.wait.slow') }}</div>
  </WizardStep>

  <WizardStep step-key="decision" :headline="decisionTitle" :show-back="false" next-step-key="result"
   :next-label="k.t('ui.setup.confirmDecision')" :next-disabled="!decided" :pre-enter-next-step="decide">
   <Space direction="column" spacing="regular">
    <Callout v-if="errorText" tone="danger" :dismissible="false"><span role="alert">{{ errorText }}</span>
     <template v-if="refusal" #actions><Button variant="secondary" @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <Callout v-if="unconfirmed" tone="warning" :dismissible="false" data-unconfirmed>{{ k.t('mail.setup.unconfirmedBody') }}</Callout>
    <Callout v-else-if="flow?.error?.startsWith('mail.setup.')" tone="warning" :dismissible="false" data-flow-error>{{ k.t(flow.error) }}</Callout>
    <Callout v-else-if="missingAccess" tone="warning" :dismissible="false" data-flow-access><span role="alert">{{ missingAccess.text }}</span>
     <template #actions><Button variant="secondary" @click="k.askAccess(missingAccess.profile ? [missingAccess.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button></template>
    </Callout>
    <Callout v-if="tokenRefused && !tokenReplaced" tone="danger" :dismissible="false" :title="k.t('ui.setup.tokenTitle')" data-flow-token>
     {{ k.t('ui.setup.tokenBody') }}
     <template #actions><Button variant="primary" data-reenter-token @click="reentering = true">{{ k.t('ui.token.reenter') }}</Button></template>
    </Callout>
    <Callout v-else-if="tokenReplaced" tone="success" :dismissible="false" data-flow-token-saved><span role="status">{{ k.t('ui.setup.tokenSaved') }}</span></Callout>
    <TokenDialog v-if="flow" v-model:open="reentering" :id="flow.id" :domain="flow.domain ?? ''" mode="flow" @saved="flowTokenSaved" />
    <Callout v-if="flow?.phase === 'interrupted'" tone="warning" :dismissible="false">{{ k.t('ui.setup.interruptedBody') }}</Callout>
    <Callout v-else-if="flow?.phase === 'failed'" tone="danger" :dismissible="false">{{ k.t('ui.wizard.failedKeptBody') }}</Callout>
    <!-- Three blocks, one rhythm, a rule between them: what was applied, what the verification found (Check again is its header action), the choice. -->
    <section v-if="flow?.changes.length" class="msa-block" data-applied>
     <ChangeList :changes="flow.changes" />
    </section>
    <section v-if="flow?.findings.length || canCheckAgain || checking" class="msa-block" data-verify :data-waiting="waitMail ? '' : undefined">
     <div class="msa-block-head">
      <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('ui.setup.verifyFindings') }}</div>
      <Button v-if="canCheckAgain || checking" variant="secondary" data-check-again :disabled="checking" @click="checkAgain">{{ k.t('ui.setup.checkAgain') }}</Button>
     </div>
     <Progress v-if="checking" indeterminate :label="k.t('ui.setup.verifying')" />
     <!-- Waiting for the check mail: what to send, where, and what then; no warning until a check really fails. -->
     <Callout v-if="waitMail" tone="info" :dismissible="false" :title="k.t('mail.setup.waitMail.title')" data-wait-mail>
      <div class="msa-zone-help">
       <div>{{ k.t('mail.setup.waitMail.body') }}</div>
       <div class="msa-copy-values">
        <div class="msa-copy-value" data-copy="address">
         <span class="msa-copy-label">{{ k.t('mail.setup.waitMail.to') }}</span>
         <span class="msa-copy-text"><code>{{ waitMail.address }}</code><CopyButton :text="waitMail.address" :label="k.t('mail.setup.zone.help.copy')" :words="{copied: k.t('mail.setup.zone.help.copied')}" size="sm" /></span>
        </div>
        <div class="msa-copy-value" data-copy="code">
         <span class="msa-copy-label">{{ k.t('mail.setup.waitMail.subject') }}</span>
         <span class="msa-copy-text"><code>{{ waitMail.code }}</code><CopyButton :text="waitMail.code" :label="k.t('mail.setup.zone.help.copy')" :words="{copied: k.t('mail.setup.zone.help.copied')}" size="sm" /></span>
        </div>
       </div>
       <div>{{ k.t('mail.setup.waitMail.after') }}</div>
       <div v-if="notYet && !checking" role="status" data-not-yet>{{ k.t('mail.setup.waitMail.notYet') }}</div>
       <div class="msa-quiet">{{ k.t('mail.setup.waitMail.decide') }}</div>
      </div>
     </Callout>
     <div v-if="shownFindings.length" class="msa-findings">
      <FindingCard v-for="f in shownFindings" :key="f.id" :finding="f" />
     </div>
    </section>
    <section class="msa-block" data-decide>
     <div class="msa-block-head"><div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('ui.setup.decideTitle') }}</div></div>
     <RadioGroup v-model="decision" variant="card" orientation="horizontal" :options="decisions" />
    </section>
   </Space>
  </WizardStep>

  <WizardStep step-key="result" type="result" :result-tone="resultTone" :headline="resultTitle" :description="resultBody">
   <template #actions>
    <Button v-if="missingAccess" variant="secondary" data-flow-access @click="k.askAccess(missingAccess.profile ? [missingAccess.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button>
    <Button v-if="flow?.outcome !== 'rolledBack'" variant="ghost" kind="tool" @click="handOff">{{ k.t('ui.setup.handoffDiagnose') }}</Button>
   </template>
  </WizardStep>
 </WizardDialog>
</template>

<style scoped>
.msa-tunnel-steps {
 margin: 0;
 padding-inline-start: var(--ui-space-5);
 list-style: decimal;
}
.msa-tunnel-steps > li + li {
 margin-block-start: var(--ui-space-2);
}
</style>
