<script setup lang="ts">
import {Badge, StatusDot} from '@synopackageland/ui'
import type {Fact} from '../api/types'
import {severityTone, useAssistant} from '../api/assistant'
/** showState: a fact that needs attention (state problem or unknown), or none (planned: the setup creates it; optional), carries a badge saying which. */
/** hideNotes: the caller says the facts' reason (noteKey) once, under the list. */
defineProps<{facts: Fact[]; showState?: boolean; hideNotes?: boolean}>()
const k = useAssistant()
const BADGE: Record<string, 'warning' | 'neutral' | 'info'> = {problem: 'warning', unknown: 'neutral', planned: 'info', optional: 'neutral'}
</script>

<template>
 <div class="msa-facts" role="list" :aria-label="k.t('ui.wizard.facts')">
  <div v-for="fact in facts" :key="fact.labelKey" class="msa-fact" role="listitem" :data-status="fact.status || 'none'" :data-state="fact.state">
   <StatusDot :tone="severityTone(fact.status)" :label="fact.status ? k.t(`ui.severity.${fact.status}`) : undefined" />
   <span class="msa-fact-label">{{ k.t(fact.labelKey) }}
    <Badge v-if="showState && fact.state && BADGE[fact.state]" :tone="BADGE[fact.state]" data-fact-badge>{{ k.t(`mail.setup.facts.state.${fact.state}`) }}</Badge>
   </span>
   <span class="msa-fact-value">{{ /^(mail)\.[\w.]+$/.test(fact.value) && k.has(fact.value) ? k.t(fact.value, fact.params) : fact.value }}</span>
   <span v-if="fact.noteKey && !hideNotes" class="msa-fact-note" data-fact-note>{{ k.t(fact.noteKey) }}</span>
  </div>
 </div>
</template>
