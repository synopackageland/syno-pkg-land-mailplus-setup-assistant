<script setup lang="ts">
import {computed, ref} from 'vue'
import {Badge, Button, Card} from '@synopackageland/ui'
import type {Finding} from '../api/types'
import {severityTone, useAssistant} from '../api/assistant'
import {evidenceText} from '../api/evidence'
/**
 * actions: Overview controls (Fix opens the fixing wizard, Acknowledge).
 * fix: only the Fix control, reported to the parent (a running wizard hands off itself).
 */
const props = defineProps<{finding: Finding; actions?: boolean; acknowledged?: boolean; fix?: boolean}>()
const emit = defineEmits<{ack: [id: string]; fix: [finding: Finding]}>()
const k = useAssistant()
const showEvidence = ref(false)
/** The folded details: a cause key (mail.setup.cause.*) shows in words, never a DSM code. */
const evidence = computed(() => evidenceText(k.t, props.finding.evidence))
const canFix = computed(() => (props.finding.fixWizard === 'mail.setup' || props.finding.fixWizard === 'mail.diagnose') && (props.actions || props.fix))
function onFix() {
 if(props.fix) emit('fix', props.finding)
 else if(props.finding.fixWizard === 'mail.setup' || props.finding.fixWizard === 'mail.diagnose') k.openWizard(props.finding.fixWizard, props.finding)
}
</script>

<template>
 <Card class="msa-finding" :data-severity="finding.severity" layout-type="compact">
  <template #title>
   <span class="msa-finding-title">
    <Badge :tone="severityTone(finding.severity)">{{ k.t(`ui.severity.${finding.severity}`) }}</Badge>
    <span>{{ k.t(finding.titleKey, finding.params) }}</span>
   </span>
  </template>
  <div class="msa-finding-body">
   <div v-if="finding.whyKey" class="msa-finding-part">
    <strong>{{ k.t('ui.finding.why') }}</strong>
    <span>{{ k.t(finding.whyKey, finding.params) }}</span>
   </div>
   <div v-if="finding.fixKey" class="msa-finding-part">
    <strong>{{ k.t('ui.finding.fix') }}</strong>
    <span>{{ k.t(finding.fixKey, finding.params) }}</span>
   </div>
   <div v-if="showEvidence && evidence" class="msa-evidence">{{ evidence }}</div>
  </div>
  <template v-if="actions || canFix || evidence" #footer>
   <div class="msa-row-actions">
    <Button v-if="canFix" variant="secondary" :data-fix="finding.fixWizard" @click="onFix">{{ k.t('ui.finding.fixAction') }}</Button>
    <Button v-if="actions && !acknowledged" variant="secondary" @click="emit('ack', finding.id)">{{ k.t('ui.finding.ack') }}</Button>
    <Button v-if="evidence" variant="ghost" :aria-expanded="showEvidence" @click="showEvidence = !showEvidence">{{ k.t(showEvidence ? 'ui.finding.hideDetails' : 'ui.finding.showDetails') }}</Button>
   </div>
  </template>
 </Card>
</template>
