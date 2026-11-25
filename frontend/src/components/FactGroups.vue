<script setup lang="ts">
import {computed} from 'vue'
import {Space} from '@synopackageland/ui'
import type {Fact, FactGroup} from '../api/types'
import {useAssistant} from '../api/assistant'
import FactList from './FactList.vue'
/** Facts under their group's heading (MailPlus Server, network, DNS, Cloudflare), in that order; empty groups are left out. */
const props = defineProps<{facts: Fact[]; showState?: boolean}>()
const k = useAssistant()
const ORDER: FactGroup[] = ['mailplus', 'network', 'dns', 'cloudflare']
const groups = computed(() => {
 const known = ORDER.map(g => ({key: g as string, facts: props.facts.filter(f => f.group === g)}))
 const other = props.facts.filter(f => !f.group || !ORDER.includes(f.group))
 return [...known, {key: 'other', facts: other}].filter(g => g.facts.length)
})
</script>

<template>
 <Space direction="column" spacing="regular" data-fact-groups>
  <Space v-for="g in groups" :key="g.key" direction="column" spacing="dense" :data-fact-group="g.key">
   <div v-if="g.key !== 'other'" role="heading" aria-level="3" class="msa-subtitle">{{ k.t(`mail.setup.facts.group.${g.key}`) }}</div>
   <FactList :facts="g.facts" :show-state="showState" />
  </Space>
 </Space>
</template>
