<script setup lang="ts">
import {computed, inject, onMounted, onUnmounted, provide, ref, watch} from 'vue'
import {LayoutDashboard, Settings as SettingsIcon} from '@lucide/vue'
import {KeyValueRow, SettingsSection} from '@synopackageland/ui'
import type {AppStatus, Context} from '@synopackageland/sdk'
import {AppShell, ExecutorSetupKey, LoginPage, createSession, type AppShellPageEntry} from '@synopackageland/sdk/vue'
import {createAssistant, provideAssistant} from './api/assistant'
import type {AuthorityProfileName, Finding, Intent} from './api/types'
import CapabilityPanels from './CapabilityPanels.vue'
import ExecutorGate, {holdsPages} from './ExecutorGate.vue'
import OverviewPage from './pages/OverviewPage.vue'
import AccessSettings from './pages/AccessSettings.vue'
import SetupWizard from './wizards/SetupWizard.vue'
import DiagnoseWizard from './wizards/DiagnoseWizard.vue'
import AuthorityConsent from './components/AuthorityConsent.vue'

type ExecutorSetup = NonNullable<Context['executor']>
const props = defineProps<{ctx: Context}>()
// The DSM window's own session; this App has no separate sign-in.
const login = createSession(props.ctx)
/** The executor as the shell's approval dialog uses it, telling this App when
 * an approval made it ready: the Overview's access notice then reads
 * the access state again instead of waiting for a reload. */
function approvalAware(e: ExecutorSetup | undefined): ExecutorSetup | undefined {
 if(!e) return e
 return {
  ...e,
  status: () => e.status(),
  async authorize(password, scope) {
   const status = await e.authorize(password, scope)
   if(status.state === 'ready') approved()
   return status
  },
  control: action => e.control(action),
  ...(e.subscribe ? {subscribe: (listener: Parameters<NonNullable<ExecutorSetup['subscribe']>>[0]) => e.subscribe!(listener)} : {}),
  ...(e.call ? {call: <T,>(method: string, params?: Record<string, unknown>) => e.call!<T>(method, params)} : {}),
 }
}
// The shell's approval dialog takes the executor main.ts provides: provide it
// again, approval-aware, for everything this App renders.
const injected = inject(ExecutorSetupKey, undefined)
if(injected) provide(ExecutorSetupKey, approvalAware(injected)!)
const shellCtx = holdsPages ? {...props.ctx, executor: undefined} : {...props.ctx, executor: approvalAware(props.ctx.executor)}
const page = ref<string>('overview')

// ---- Wizards: one of each, opened from any page or from a finding's Fix.
const setupOpen = ref(false)
const setupIntent = ref<Intent>()
const diagnoseOpen = ref(false)
const consentOpen = ref(false)
const consentFocus = ref<AuthorityProfileName[]>([])
const assistant = createAssistant(props.ctx, {
 openWizard(id, from?: Finding) {
  if(id === 'mail.diagnose') {setupOpen.value = false; diagnoseOpen.value = true; return}
  const intent = from?.params?.intent
  setupIntent.value = intent === 'send' || intent === 'receive' || intent === 'both' ? intent : undefined
  diagnoseOpen.value = false; setupOpen.value = true
 },
 openConsent(profiles) {consentFocus.value = profiles ?? []; consentOpen.value = true},
 openSettings() {setupOpen.value = false; diagnoseOpen.value = false; page.value = 'settings'},
})
provideAssistant(assistant)
const t = assistant.t
const authority = assistant.authority

// No Background tab: jobs: true only hosts the worker (relay, setup
// transactions, diagnose runs), and none of that is a bg job. The SDK
// BackgroundPanel lists imported-file jobs, which this App never submits, so
// the tab was always blank. The worker's work shows on the Overview instead.
const pages = computed<AppShellPageEntry[]>(() => [
 {id: 'overview', title: t('ui.nav.overview'), icon: LayoutDashboard},
 {id: 'settings', title: t('ui.nav.settings'), icon: SettingsIcon, placement: 'bottom'},
])
const current = ref<{refresh(): unknown}>()
const panels = ref<{refresh(): unknown}>()

// ---- Session and package status run in the background; the shell shows at once.
const app = ref<AppStatus>()
let disposed = false
let unsubscribe: (() => void) | undefined
const signIn = computed(() => login.ready.value && login.enabled.value && !login.subject.value && {header: false as const})
async function refreshStatus() {
 if(disposed || (login.enabled.value && !login.subject.value)) return
 const early = !login.ready.value
 const call: typeof login.call = early ? (method, params) => props.ctx.call(method, params) : login.call
 try {const status = await call<AppStatus>('app.status'); if(!disposed) app.value = status} catch {/* each page reports its own failure */}
}
// No header Refresh: reopening the window re-reads everything, each page reads
// when it is shown and has its own Check again where data can go stale.
async function refreshAll() {
 await Promise.all([refreshStatus(), current.value?.refresh(), panels.value?.refresh(), authority.refresh()])
}
// An approval on the Settings page ends the Overview's access notice without a
// reload: the executor's confirmation reads the access state again,
// and so does coming back to the Overview while the notice still shows.
function approved() {void authority.refresh()}
watch(page, p => {if(p === 'overview' && (authority.needsApproval.value || authority.readsMissing.value)) void authority.refresh()})
// A new grant or a closed wizard changes what the overview shows.
watch([consentOpen, setupOpen], ([consent, setup]) => {if(!consent && !setup) void current.value?.refresh()})
watch(login.subject, (subject, previous) => {
 if(!subject) app.value = undefined
 else if(!previous || previous.user !== subject.user) void refreshStatus()
})
onMounted(() => {
 unsubscribe = props.ctx.reopen(() => {if(!disposed) void refreshAll()})
 void login.start()
 void refreshStatus()
 void authority.refresh()
})
onUnmounted(() => {disposed = true; unsubscribe?.(); login.dispose()})
const admin = computed(() => props.ctx.user?.isAdmin ?? !!app.value?.admin)
</script>

<template>
 <!-- A DSM window stays light: no color-scheme binding. -->
 <AppShell app-root v-model="page" :ctx="shellCtx" :locale="ctx.locale" :pages="pages" :denied="signIn" sidebar-storage-key="SynoMailPlusSetupAssistant">
  <template #denied><LoginPage :session="login" :locale="ctx.locale" /></template>
  <ExecutorGate :ctx="ctx" :admin="admin">
   <div class="integration-app msa-app">
    <OverviewPage v-if="page === 'overview'" ref="current" />
    <div v-else-if="page === 'settings'" class="msa-page" data-page="settings">
     <CapabilityPanels v-if="app" ref="panels" :key="app.user" :ctx="ctx" :admin="app.admin" @confirmed="approved" />
     <AccessSettings v-if="app" />
     <SettingsSection v-if="app" :title="t('ui.settings.about')" :collapsible="false">
      <KeyValueRow :label="t('ui.settings.version')" :value="app.version" />
      <KeyValueRow :label="t('ui.settings.signedIn')" :value="app.user" />
     </SettingsSection>
    </div>
   </div>
  </ExecutorGate>
  <SetupWizard v-model:open="setupOpen" :intent="setupIntent" @diagnose="diagnoseOpen = true" @changed="current?.refresh()" />
  <DiagnoseWizard v-model:open="diagnoseOpen" @setup="f => assistant.openWizard('mail.setup', f)" @changed="current?.refresh()" />
  <AuthorityConsent v-model:open="consentOpen" :profiles="consentFocus" />
 </AppShell>
</template>
