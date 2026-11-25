<script setup lang="ts">
/**
 * One problem of a diagnosis: what is wrong, what it does, the one thing to
 * do and the button that does it (the setup wizard, a new Cloudflare
 * token, MailPlus Server or
 * Package Center through the SDK DSM App launcher). The affected domains or
 * addresses are listed once; the raw evidence stays folded under Show
 * details, never with a DSM code.
 */
import {computed, ref} from 'vue'
import {Badge, Button, Card} from '@synopackageland/ui'
import {openApp, type DsmAppLaunchResult} from '@synopackageland/sdk'
import {severityTone, useAssistant} from '../api/assistant'
import {evidenceText, listText} from '../api/evidence'
import {openPackageCenter} from '../api/mailplus'
import type {Problem} from '../api/types'

const props = defineProps<{problem: Problem}>()
const emit = defineEmits<{setup: [problem: Problem]; token: [problem: Problem]}>()
const k = useAssistant()
const MAILPLUS_APP = {appId: 'SYNO.SDS.MailPlusServer.Instance'} as const
const base = computed(() => `mail.diag.problem.${props.problem.key}`)
const targets = computed(() => props.problem.targets?.length ? listText(k.locale, props.problem.targets) : '')
const showDetails = ref(false)
const details = computed(() => (props.problem.details ?? [])
 .map(d => ({target: d.target ?? '', text: evidenceText(k.t, d.evidence)}))
 .filter(d => d.text))
const launch = ref<DsmAppLaunchResult['status']>()
async function act() {
 switch(props.problem.action) {
  case 'setup': emit('setup', props.problem); return
  case 'token': emit('token', props.problem); return
  case 'mailplus': launch.value = (await openApp(MAILPLUS_APP)).status; return
  case 'packages': launch.value = await openPackageCenter(); return
 }
}
</script>

<template>
 <Card class="msa-finding" :data-problem="problem.key" :data-severity="problem.severity" layout-type="compact">
  <template #title>
   <span class="msa-finding-title">
    <Badge :tone="severityTone(problem.severity)">{{ k.t(`ui.severity.${problem.severity}`) }}</Badge>
    <span>{{ k.t(`${base}.title`) }}</span>
   </span>
  </template>
  <div class="msa-finding-body">
   <span>{{ k.t(`${base}.body`) }}</span>
   <div v-if="targets" class="msa-quiet" data-targets>{{ k.t('ui.diag.targets', {targets}) }}</div>
   <div class="msa-finding-part">
    <strong>{{ k.t('ui.finding.fix') }}</strong>
    <span>{{ k.t(`${base}.action`) }}</span>
   </div>
   <span v-if="launch && launch !== 'requested'" class="msa-quiet" role="status">{{ k.t('ui.diag.launchManual') }}</span>
   <div v-if="showDetails" class="msa-evidence">
    <template v-for="(d, i) in details" :key="i">{{ d.target ? `${d.target}\n` : '' }}{{ d.text }}{{ i < details.length - 1 ? '\n\n' : '' }}</template>
   </div>
  </div>
  <template v-if="problem.action || details.length" #footer>
   <div class="msa-row-actions">
    <Button v-if="problem.action" variant="secondary" :data-action="problem.action" @click="act">{{ k.t(`ui.diag.action.${problem.action}`) }}</Button>
    <Button v-if="details.length" variant="ghost" :aria-expanded="showDetails" @click="showDetails = !showDetails">{{ k.t(showDetails ? 'ui.finding.hideDetails' : 'ui.finding.showDetails') }}</Button>
   </div>
  </template>
 </Card>
</template>
