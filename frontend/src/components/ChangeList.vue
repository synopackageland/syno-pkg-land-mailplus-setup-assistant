<script setup lang="ts">
import {computed} from 'vue'
import type {Change} from '../api/types'
import {useAssistant} from '../api/assistant'
const props = defineProps<{changes: Change[]}>()
const k = useAssistant()
// Group by target so the user sees each system that changes once, in order.
const groups = computed(() => {
 const map = new Map<string, Change[]>()
 for(const change of props.changes) {
  const list = map.get(change.target) ?? []
  list.push(change); map.set(change.target, list)
 }
 return [...map].map(([target, items]) => ({target, items}))
})
function targetLabel(target: string) {
 const key = `ui.target.${target}`
 return k.has(key) ? k.t(key) : target
}
</script>

<template>
 <div class="msa-changes">
  <section v-for="group in groups" :key="group.target" class="msa-change-group">
   <div class="msa-change-target" role="heading" aria-level="3">{{ targetLabel(group.target) }}</div>
   <div class="msa-change-list" role="list">
    <div v-for="change in group.items" :key="change.id" class="msa-change" role="listitem">
     <div class="msa-change-action">{{ k.t(change.actionKey, change.params) }}</div>
     <div v-if="change.before || change.after" class="msa-change-diff">
      <span class="msa-diff-label">{{ k.t('ui.wizard.before') }}</span>
      <span class="msa-before">{{ change.before || k.t('ui.wizard.none') }}</span>
      <span class="msa-diff-label">{{ k.t('ui.wizard.after') }}</span>
      <span class="msa-after">{{ change.after || k.t('ui.wizard.removed') }}</span>
     </div>
    </div>
   </div>
  </section>
 </div>
</template>
