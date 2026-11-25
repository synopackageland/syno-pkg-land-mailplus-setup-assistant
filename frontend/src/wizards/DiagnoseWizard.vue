<script setup lang="ts">
/**
 * mail.diagnose on the UI SDK Wizard: symptom → running (one read-only check
 * per call, real progress) → result (findings ranked by the worker for the
 * symptom). A missing DSM grant pauses the run in place; after the grant the
 * same run continues with the same check. `running` is a UI SDK progress step
 * (read-only: Back stops it); `result` is a result step whose tone says
 * whether the checks found something.
 *
 * MailPlus Server not installed or stopped is the run's first and only cause
 * (the worker skips every check that needs it); the result then says so with
 * Open Package Center instead of a setup Fix.
 *
 * The result shows the worker's summary, never the raw findings one by one:
 * a one-line verdict, at most three problems (each with one action), the
 * rest behind "Show more", and every other check as one line in a folded
 * "Other checks". With no problem it says what to try next. The dialog grows
 * with the DSM window (up to 1040 x 900) so a maximised window reads it all.
 *
 * A Cloudflare token refused for a kept setup is a problem whose
 * button opens the same guided token entry as the Overview (TokenDialog) for
 * the kept setup of that domain.
 */
import {computed, onUnmounted, ref, watch} from 'vue'
import {CircleCheck, CircleHelp, Info, Stethoscope} from '@lucide/vue'
import {Button, Callout, RadioGroup, SettingsSection, Space, WizardDialog, WizardStep} from '@synopackageland/ui'
import type {WizardProgress, WizardResultTone} from '@synopackageland/ui'
import {pause, useAssistant} from '../api/assistant'
import {SLOW_AFTER, useElapsed} from '../api/elapsed'
import {listText} from '../api/evidence'
import type {DiagnoseRun, Finding, KeptView, OtherCheck, Problem, Symptom} from '../api/types'
import FindingCard from '../components/FindingCard.vue'
import ProblemCard from '../components/ProblemCard.vue'
import TokenDialog from '../components/TokenDialog.vue'
import MailPlusNotice from '../components/MailPlusNotice.vue'
import type {MailPlusStatus} from '../api/types'

const open = defineModel<boolean>('open', {required: true})
const emit = defineEmits<{setup: [from?: Finding]; changed: []}>()
const k = useAssistant()

/**
 * The UI SDK's own sizes (clamp(560px, 75%, 860px) wide, at most 600px high)
 * with higher caps: in the default DSM window it is the same, maximised it
 * grows to show the results without scrolling inside a small box.
 */
const DIALOG_WIDTH = 'clamp(min(560px, 100%), 80%, 1040px)'
const DIALOG_HEIGHT = 'clamp(min(420px, 100%), calc(100% - 48px), 900px)'
const SYMPTOMS: Symptom[] = ['cannot-send', 'bounce-or-spam', 'cannot-receive', 'phone-connect', 'not-sure']
const step = ref<'symptom' | 'running' | 'result'>('symptom')
const symptom = ref<Symptom>('cannot-send')
const run = ref<DiagnoseRun>()
const error = ref<unknown>()
let stop: AbortController | undefined
onUnmounted(() => stop?.abort())

const options = computed(() => SYMPTOMS.map(s => ({value: s, label: k.t(`mail.diag.symptom.${s}`)})))
const refusal = computed(() => k.refusal(error.value))
/** The precondition cause (the run's only finding): MailPlus Server not installed or stopped. */
const mailplus = computed<MailPlusStatus | undefined>(() => {
 const f = run.value?.complete && run.value.findings.length === 1 ? run.value.findings[0] : undefined
 if(f?.id === 'mail.diag.mailplus.missing') return {state: 'notInstalled'}
 if(f?.id === 'mail.diag.mailplus.stopped') return {state: 'stopped'}
 return undefined
})
const summary = computed(() => run.value?.complete ? run.value.summary : undefined)
/**
 * A token problem of a domain given a new token here is solved (the worker
 * checked the new token before saving it): it leaves the result at once,
 * without running the checks again.
 */
const solved = (p: Problem) => p.action === 'token' && (p.targets?.length
 ? p.targets.every(t => replaced.value.some(d => d.toLowerCase() === t.toLowerCase()))
 : replaced.value.length > 0)
const problems = computed(() => (summary.value?.problems ?? []).filter(p => !solved(p)))
const more = computed(() => (summary.value?.more ?? []).filter(p => !solved(p)))
/** The kept setup whose refused token the problem names, and the domains given a new token. */
const replacing = ref<KeptView>()
const replaced = ref<string[]>([])
const showMore = ref(false)
const others = computed(() => summary.value?.others ?? [])
const othersOpen = ref(false)
/** Problems are a warning; checks that could not read what they need leave it unclear (neutral); nothing found is a success. */
/** The worker's verdict, clear once every problem it found was solved here. */
const verdictKey = computed(() => summary.value?.verdict === 'problems' && !problems.value.length && !more.value.length ? 'clear' : summary.value?.verdict)
const tone = computed<WizardResultTone>(() => {
 switch(verdictKey.value) {
  case 'problems': case 'unreadable': return 'warning'
  case 'clear': return 'success'
  default: return 'neutral'
 }
})
const verdict = computed(() => {
 const s = summary.value
 const count = problems.value.length + more.value.length
 switch(s && verdictKey.value) {
  case 'problems': return count === 1 ? k.t('ui.diag.verdict.one') : k.t('ui.diag.verdict.many', {count})
  case 'unreadable': return k.t('mail.setup.unreadable')
  case 'clear': return k.t('ui.diag.verdict.clear')
  case 'unclear': return k.t('ui.diag.verdict.unclear')
  default: return ''
 }
})
const OTHER_ICON = {ok: CircleCheck, note: Info, unknown: CircleHelp} as const
function otherText(o: OtherCheck): string {
 const targets = (o.targets ?? []).map(t => o.key === 'not_checked' ? k.t(`mail.diag.area.${t}`) : t)
 return k.t(`mail.diag.other.${o.key}`, {check: o.check ? k.t(`mail.diag.check.${o.check}`) : '', targets: listText(k.locale, targets), count: o.count ?? 0})
}
const progress = computed<WizardProgress>(() => run.value?.total
 ? {mode: 'determinate', label: k.t('ui.diag.progress', {done: run.value.done, total: run.value.total}), value: run.value.done, max: run.value.total}
 : {mode: 'indeterminate', label: k.t('mail.diag.wizard.running')})

watch(open, value => {
 stop?.abort()
 if(value) {step.value = 'symptom'; run.value = undefined; error.value = undefined; showMore.value = false; othersOpen.value = false; replaced.value = []}
}, {immediate: true})

async function start() {
 error.value = undefined
 try {run.value = await k.call('mail.diagnose.start', {symptom: symptom.value})}
 catch(e) {error.value = e; return false}
}

/**
 * Polls the run until it completes; stops on a refusal or error. The worker
 * reads MailPlus Server once and runs each check in its background, and each
 * call returns within seconds (pending while work continues), so no request
 * waits for a slow NAS. The step shows what runs and the time waited.
 */
const waited = useElapsed()
async function proceed() {
 stop?.abort()
 const signal = (stop = new AbortController()).signal
 error.value = undefined
 const stopWait = waited.start()
 try {
  while(run.value && !run.value.complete && !signal.aborted) {
   const next = await k.call('mail.diagnose.next', {id: run.value.id})
   if(signal.aborted) return
   run.value = next
   // The worker already waited up to 15 s; a pending reply never spins.
   if(next.pending) await pause(1000, signal)
  }
  if(run.value?.complete && !signal.aborted && open.value && step.value === 'running') step.value = 'result'
 } catch(e) {if(!signal.aborted) error.value = e}
 finally {stopWait()}
}
watch(step, value => {if(value === 'running') void proceed(); else stop?.abort()})

// A grant given while the run waits continues it.
watch(() => k.authority.status.value, () => {if(step.value === 'running' && refusal.value && open.value) void proceed()})

function fix(p: Problem) {
 open.value = false
 // The setup wizard takes its intent from the finding it starts from.
 const f: Finding = {id: p.findings[0] ?? p.key, module: 'mail', check: '', severity: p.severity, titleKey: `mail.diag.problem.${p.key}.title`,
  fixWizard: 'mail.setup', params: p.intent ? {intent: p.intent} : {}}
 emit('setup', f)
}
const tokenError = ref<unknown>()
async function newToken(p: Problem) {
 tokenError.value = undefined
 try {
  const {setups} = await k.call('mail.inbound.status')
  const targets = (p.targets ?? []).map(t => t.toLowerCase())
  replacing.value = setups.find(s => s.tokenInvalid && targets.includes(s.domain.toLowerCase()) && !replaced.value.includes(s.domain))
   ?? setups.find(s => s.tokenInvalid)
 } catch(e) {tokenError.value = e}
}
/** The Overview reads the kept setups again (its red line clears); the result drops the solved problem. */
function tokenSaved() {
 if(replacing.value) replaced.value = [...replaced.value, replacing.value.domain]
 emit('changed')
}

function chooseAgain() {run.value = undefined; step.value = 'symptom'}
async function again() {
 showMore.value = false; othersOpen.value = false; replaced.value = []
 if(await start() === false) return
 step.value = 'running'
}
</script>

<template>
 <WizardDialog v-model:open="open" v-model:active-step-key="step" :title="k.t('mail.diag.wizard.title')" :width="DIALOG_WIDTH" :height="DIALOG_HEIGHT">
  <WizardStep step-key="symptom" :headline="k.t('mail.diag.wizard.symptom')" :description="k.t('mail.diag.wizard.readonly')" :icon="Stethoscope"
   next-step-key="running" :pre-enter-next-step="start" :show-back="false">
   <Space direction="column" spacing="regular">
    <Callout v-if="error" tone="danger" :dismissible="false"><span role="alert">{{ k.error(error) }}</span></Callout>
    <RadioGroup v-model="symptom" :options="options" />
   </Space>
  </WizardStep>

  <WizardStep step-key="running" type="progress" :headline="k.t('mail.diag.wizard.running')" :description="k.t('mail.diag.wizard.readonly')"
   :progress="progress" :show-back="true" previous-step-key="symptom">
   <Callout v-if="error" :tone="refusal ? 'warning' : 'danger'" :dismissible="false"><span role="alert">{{ k.error(error) }}</span>
    <template #actions>
     <Button v-if="refusal" variant="secondary" @click="k.askAccess(refusal.code === 'authority_required' && refusal.profile ? [refusal.profile] : undefined)">{{ k.t('ui.access.needed') }}</Button>
     <Button v-else variant="secondary" @click="proceed">{{ k.t('ui.diag.again') }}</Button>
    </template>
   </Callout>
   <template v-if="run && !error">
    <div class="msa-quiet" aria-live="polite">{{ k.t(run.phase === 'reading' ? 'ui.diag.reading' : 'ui.diag.checking', {n: Math.min(run.done + 1, run.total)}) }}
     · {{ k.t('ui.wait.elapsed', {seconds: waited.seconds.value}) }}</div>
    <div v-if="waited.seconds.value >= SLOW_AFTER" class="msa-quiet">{{ k.t('ui.wait.slow') }}</div>
   </template>
  </WizardStep>

  <WizardStep step-key="result" type="result" :result-tone="tone" :headline="k.t('mail.diag.wizard.result')" :description="verdict">
   <div class="msa-diag-result" data-diagnose-result :data-verdict="summary?.verdict">
    <!-- MailPlus Server not installed or stopped is the only cause: the notice says it and what to do. -->
    <MailPlusNotice v-if="mailplus" :status="mailplus" :recheck="false" data-diagnose-mailplus />
    <!-- MailPlus Server could not be read: the one finding says why. -->
    <div v-else-if="summary?.verdict === 'unreadable'" class="msa-findings">
     <FindingCard v-for="f in run?.findings ?? []" :key="f.id" :finding="f" />
    </div>
    <template v-else>
     <Callout v-for="d in replaced" :key="d" tone="success" :dismissible="false" data-token-saved>
      <span role="status">{{ k.t('ui.token.saved', {domain: d}) }}</span>
     </Callout>
     <Callout v-if="tokenError" tone="danger" :dismissible="false"><span role="alert">{{ k.error(tokenError) }}</span></Callout>
     <div v-if="problems.length" class="msa-findings" data-problems>
      <ProblemCard v-for="p in problems" :key="p.key" :problem="p" @setup="fix" @token="newToken" />
      <template v-if="showMore">
       <ProblemCard v-for="p in more" :key="p.key" :problem="p" @setup="fix" @token="newToken" />
      </template>
     </div>
     <div v-if="more.length && !showMore">
      <Button variant="ghost" data-more @click="showMore = true">{{ more.length === 1 ? k.t('ui.diag.moreOne') : k.t('ui.diag.more', {count: more.length}) }}</Button>
     </div>
     <Callout v-if="summary && !problems.length" tone="info" :dismissible="false" :title="k.t('ui.diag.next.title')" data-next>
      {{ k.t(`ui.diag.next.${run?.symptom}`) }}
      <template v-if="run?.symptom === 'not-sure'" #actions><Button variant="secondary" data-choose-again @click="chooseAgain">{{ k.t('ui.diag.chooseAgain') }}</Button></template>
     </Callout>
    </template>
    <SettingsSection v-if="others.length" v-model:open="othersOpen" collapsible :title="k.t('ui.diag.others', {count: others.length})" data-others>
     <div class="msa-others" role="list">
      <div role="listitem" v-for="o in others" :key="`${o.key}|${o.check ?? ''}`" class="msa-other" :data-state="o.state" :data-other="o.key">
       <component :is="OTHER_ICON[o.state] ?? CircleHelp" class="msa-other-icon" aria-hidden="true" />
       <span>{{ otherText(o) }}</span>
      </div>
     </div>
    </SettingsSection>
    <div v-if="summary" class="msa-quiet">{{ k.t('ui.diag.limits') }}</div>
    <TokenDialog :open="!!replacing" :id="replacing?.id ?? ''" :domain="replacing?.domain ?? ''" mode="kept"
     @update:open="o => {if(!o) replacing = undefined}" @saved="tokenSaved" />
   </div>
   <template #actions><Button variant="ghost" kind="tool" @click="again">{{ k.t('ui.diag.again') }}</Button></template>
  </WizardStep>
 </WizardDialog>
</template>
