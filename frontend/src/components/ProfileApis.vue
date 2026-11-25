<script setup lang="ts">
import {computed} from 'vue'
import type {AuthorityProfile} from '../api/types'
import {profileKey} from '../api/authority'
import {useAssistant} from '../api/assistant'

/** The exact DSM API methods and versions a profile pins, as declared by the backend. */
const props = defineProps<{profile: AuthorityProfile; titled?: boolean}>()
const k = useAssistant()
const lines = computed(() => Object.entries(props.profile.profile.apis)
 .sort(([x], [y]) => x.localeCompare(y))
 .flatMap(([api, methods]) => Object.entries(methods).sort(([x], [y]) => x.localeCompare(y)).map(([method, versions]) => `${api} · ${method} · v${versions.join(', v')}`)))
</script>

<template>
 <div class="msa-apis">
  <div v-if="titled" class="msa-apis-title" role="heading" aria-level="3">{{ k.t(profileKey(profile.name)) }}</div>
  <div class="msa-apis-list" role="list"><div v-for="line in lines" :key="line" role="listitem">{{ line }}</div></div>
 </div>
</template>
