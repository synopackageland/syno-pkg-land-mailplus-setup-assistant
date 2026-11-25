<script setup lang="ts">
/**
 * Overview: whether MailPlus Server is installed and running (the App's
 * precondition, shown first with what to do), the two wizards, an unfinished
 * transaction to resume, the relay and the access notice. Opening the page
 * reads the relay state, the caller's flow and the precondition (one DSM
 * package-list read); coming back to the window re-reads the precondition
 * while MailPlus Server does not run (at most once per 15 s). Nothing else
 * runs until the user starts a wizard (the receiving section reads only the
 * package's own records; a mailbox sync runs only when its button is pressed).
 * There is no header Refresh: each
 * section that can go stale has its own Check again.
 */
import {computed, onMounted, onUnmounted, ref, watch} from 'vue'
import {Badge, Button, Callout, KeyValueRow, SettingsSection} from '@synopackageland/ui'
import {formatTime, useAssistant} from '../api/assistant'
import {useMailPlus} from '../api/mailplus'
import type {FlowView, ServiceView} from '../api/types'
import MailPlusNotice from '../components/MailPlusNotice.vue'
import InboundSection from '../components/InboundSection.vue'

const k = useAssistant()
const mp = useMailPlus(k)
const mpState = computed(() => mp.status.value?.state)
const mpBadge = computed(() => {
 switch(mpState.value) {
  case 'running': return {tone: 'success' as const, key: 'ui.mailplus.running'}
  case 'notInstalled': return {tone: 'danger' as const, key: 'ui.mailplus.notInstalled.badge'}
  case 'stopped': return {tone: 'warning' as const, key: 'ui.mailplus.stopped.badge'}
  case 'unknown': return {tone: 'neutral' as const, key: 'ui.mailplus.unknown.badge'}
  default: return undefined
 }
})
function comeBack() {if(mpState.value !== 'running') mp.recheckSoon()}
// Coming back is listened for only while MailPlus Server is known not to run.
let unsubscribe: (() => void) | undefined
function listen(on: boolean) {
 if(!on) {unsubscribe?.(); unsubscribe = undefined; return}
 if(unsubscribe) return
 const sub = k.host.subscribe('window-activated', comeBack)
 const visible = () => {if(document.visibilityState === 'visible') comeBack()}
 document.addEventListener('visibilitychange', visible)
 unsubscribe = () => {if(sub.status === 'subscribed') sub.dispose(); document.removeEventListener('visibilitychange', visible)}
}
watch(mpState, s => listen(s === 'notInstalled' || s === 'stopped' || s === 'unknown'))
onUnmounted(() => {listen(false); mp.cancel()})
const a = k.authority
const relay = ref<ServiceView>()
const pending = ref<FlowView>()
const error = ref<unknown>()
const busy = ref(false)
const reading = ref(false)
const inbound = ref<InstanceType<typeof InboundSection>>()

async function refresh() {
 error.value = undefined
 reading.value = true
 void inbound.value?.read()
 try {
  void mp.check()
  const [r, f] = await Promise.all([k.call('mail.relay.status'), k.call('mail.setup.start')])
  relay.value = r
  pending.value = f.resume ? f : undefined
 } catch(e) {error.value = e}
 finally {reading.value = false}
}
/** After a removal (which may turn the relay off): the relay's state only, read again. */
async function readRelay() {
 try {relay.value = await k.call('mail.relay.status')}
 catch(e) {error.value = e}
}
async function turnOff() {
 busy.value = true
 try {await k.call('mail.relay.set', {enabled: false}); await refresh()}
 catch(e) {error.value = e}
 finally {busy.value = false}
}
defineExpose({refresh})
onMounted(() => void refresh())
</script>

<template>
 <div class="msa-page" data-page="overview">
  <Callout v-if="error" tone="danger" :dismissible="false"><span role="alert">{{ k.error(error) }}</span></Callout>
  <Callout v-if="a.status.value && (a.needsApproval.value || a.readsMissing.value)" tone="info" :dismissible="false"
   :title="k.t('ui.authority.noticeTitle')">
   {{ k.t(a.needsApproval.value ? 'ui.authority.noticeApproval' : 'ui.authority.noticeBody') }}
   <template #actions><Button variant="secondary" @click="k.askAccess()">{{ k.t(a.needsApproval.value ? 'ui.authority.openSettings' : 'ui.access.needed') }}</Button></template>
  </Callout>
  <SettingsSection :title="k.t('ui.mailplus.title')" :description="k.t('ui.mailplus.overviewBody')" :collapsible="false" :loading="!mp.status.value && !mp.error.value" data-section="mailplus">
   <KeyValueRow v-if="mpBadge" :label="k.t('ui.services.status')">
    <Badge :tone="mpBadge.tone" :data-mailplus-state="mpState">{{ k.t(mpBadge.key) }}</Badge>
   </KeyValueRow>
   <KeyValueRow v-if="mp.status.value?.version" :label="k.t('ui.mailplus.version')" :value="mp.status.value.version" />
   <!-- Running but never set up: its own first-run wizard asks for the domain; this App says what to type. -->
   <div v-if="mpState === 'running' && mp.status.value?.setUp === false" class="msa-quiet" data-mailplus-not-set-up>{{ k.t('ui.mailplus.notSetUp') }}</div>
   <MailPlusNotice :status="mp.status.value" :checking="mp.checking.value" @recheck="mp.check()" />
   <Callout v-if="mp.error.value && !k.refusal(mp.error.value)" tone="danger" :dismissible="false"><span role="alert">{{ k.error(mp.error.value) }}</span></Callout>
   <template v-if="mp.error.value || mpState === 'running'" #actions>
    <Button variant="ghost" kind="tool" :disabled="mp.checking.value" data-mailplus-recheck @click="mp.check()">{{ k.t(mp.checking.value ? 'ui.mailplus.checking' : 'ui.mailplus.recheck') }}</Button>
   </template>
  </SettingsSection>
  <Callout v-if="pending" tone="warning" :dismissible="false" :title="k.t('ui.overview.resumeTitle')" data-resume>
   {{ k.t('ui.overview.resumeBody') }}
   <template #actions><Button variant="primary" @click="k.openWizard('mail.setup')">{{ k.t('ui.overview.resume') }}</Button></template>
  </Callout>

  <SettingsSection :title="k.t('mail.setup.title')" :description="k.t('ui.overview.setupBody')" :collapsible="false" data-section="setup">
   <template #actions><Button variant="primary" data-open="mail.setup" @click="k.openWizard('mail.setup')">{{ k.t('ui.overview.start') }}</Button></template>
  </SettingsSection>

  <InboundSection ref="inbound" @removed="readRelay()" />

  <SettingsSection :title="k.t('mail.diag.wizard.title')" :description="k.t('ui.overview.diagnoseBody')" :collapsible="false" data-section="diagnose">
   <template #actions><Button variant="secondary" data-open="mail.diagnose" @click="k.openWizard('mail.diagnose')">{{ k.t('ui.overview.start') }}</Button></template>
  </SettingsSection>

  <SettingsSection :title="k.t('ui.relay.title')" :description="k.t('ui.relay.body')" :collapsible="false" :loading="!relay && !error" data-section="relay">
   <template v-if="relay">
    <KeyValueRow :label="k.t('ui.services.status')">
     <Badge :tone="relay.status.running ? 'success' : relay.enabled ? 'warning' : 'neutral'">
      {{ k.t(relay.status.running ? 'ui.services.running' : relay.enabled ? 'ui.services.stopped' : 'ui.services.off') }}
     </Badge>
    </KeyValueRow>
    <KeyValueRow v-if="relay.status.running && formatTime(k.locale, relay.status.since)" :label="k.t('ui.services.since')" :value="formatTime(k.locale, relay.status.since)" />
    <KeyValueRow v-if="relay.status.lastError" :label="k.t('ui.services.lastError')" :value="k.t(relay.status.lastError)" />
   </template>
   <template v-if="relay || error" #actions>
    <Button variant="ghost" kind="tool" :disabled="reading || busy" data-relay-recheck @click="refresh()">{{ k.t('ui.relay.recheck') }}</Button>
    <Button v-if="relay?.enabled" variant="secondary" :disabled="busy" @click="turnOff">{{ k.t('ui.relay.turnOff') }}</Button>
   </template>
  </SettingsSection>
 </div>
</template>
