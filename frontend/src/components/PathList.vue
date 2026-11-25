<script setup lang="ts">
import type {PathView} from '../api/types'
import {useAssistant} from '../api/assistant'
/** Each decided direction's recommended path and the reasons it rests on. */
defineProps<{paths: PathView[]}>()
const k = useAssistant()
</script>

<template>
 <div class="msa-paths" data-paths>
  <div role="heading" aria-level="3" class="msa-subtitle">{{ k.t('mail.setup.paths') }}</div>
  <div v-for="p in paths" :key="p.direction" class="msa-path" :data-path="p.branch">
   <div class="msa-path-title">{{ k.t(p.titleKey) }}</div>
   <div class="msa-path-why" role="list">
    <div v-for="why in p.why" :key="why" role="listitem">{{ k.t(why) }}</div>
   </div>
  </div>
 </div>
</template>
