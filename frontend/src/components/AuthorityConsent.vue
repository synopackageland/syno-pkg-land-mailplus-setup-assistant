<script setup lang="ts">
import {computed, ref, watch} from 'vue'
import {Button, Callout, CheckboxGroup, Dialog} from '@synopackageland/ui'
import type {AuthorityProfile, AuthorityProfileName} from '../api/types'
import {OPT_IN_PROFILES, READ_PROFILES, WRITE_PROFILES, profileKey} from '../api/authority'
import {useAssistant} from '../api/assistant'
import ProfileApis from './ProfileApis.vue'

/**
 * First-run access consent: one decision, which DSM access the assistant may use.
 * Reads are preselected; changing MailPlus is a separate, unticked choice.
 * Each ticked profile becomes one confirmed dsm.authority.grant call.
 */
const open = defineModel<boolean>('open', {required: true})
/** Set when a refusal named exact profiles: only those are offered, and they are ticked because the user asked for them. */
const props = defineProps<{profiles?: AuthorityProfileName[]}>()
const focused = computed(() => !!props.profiles?.length)
const k = useAssistant()
const a = k.authority
const selected = ref<AuthorityProfileName[]>([])
const busy = ref(false)
const error = ref('')
const showApis = ref(false)

const pending = computed<AuthorityProfile[]>(() => (a.status.value?.profiles ?? []).filter(p => p.state !== 'granted' && !OPT_IN_PROFILES.includes(p.name) && (!focused.value || props.profiles!.includes(p.name))))
const options = computed(() => pending.value.map(p => ({
 value: p.name,
 label: k.t(profileKey(p.name)),
 description: k.t(WRITE_PROFILES.includes(p.name) ? 'ui.authority.changes' : 'ui.authority.readsOnly'),
})))

watch(open, value => {
 if(!value) return
 error.value = ''; showApis.value = false
 select()
 void a.refresh()
}, {immediate: true})
function select() {
 selected.value = pending.value.filter(p => focused.value || READ_PROFILES.includes(p.name)).map(p => p.name)
}
// A fresh status can drop a profile that was granted meanwhile, or bring the first one.
let seeded = false
watch(open, value => {seeded = value && !!a.status.value})
watch(pending, list => {
 if(!seeded && open.value && a.status.value) {seeded = true; select(); return}
 selected.value = selected.value.filter(n => list.some(p => p.name === n))
})

async function allow() {
 if(!selected.value.length || busy.value) return
 busy.value = true; error.value = ''
 try {
  const failure = await a.grant([...selected.value])
  if(failure) error.value = k.error(failure)
  else open.value = false
 } finally {busy.value = false}
}
function toSettings() {open.value = false; k.openSettings()}
</script>

<template>
 <Dialog v-model:open="open" :title="k.t('ui.authority.consentTitle')" size="md" :close-on-outside="false">
  <div class="msa-consent" :aria-busy="busy || a.loading.value">
   <Callout v-if="error" tone="danger" dismiss-scope="occurrence" :dismissible="false"><span role="alert">{{ error }}</span></Callout>
   <div>{{ k.t(focused ? 'ui.authority.focusBody' : 'ui.authority.consentBody') }}</div>
   <template v-if="!a.status.value">
    <Callout v-if="a.error.value" tone="danger" dismiss-scope="occurrence" :dismissible="false"><span role="alert">{{ k.error(a.error.value) }}</span></Callout>
    <div v-else class="msa-quiet" role="status">{{ k.t('ui.common.loading') }}</div>
   </template>
   <Callout v-else-if="a.needsApproval.value" tone="info" dismiss-scope="occurrence" :dismissible="false" :title="k.t('ui.authority.approvalTitle')">{{ k.t('ui.authority.approvalBody') }}</Callout>
   <div v-else-if="!pending.length" class="msa-quiet" role="status">{{ k.t('ui.authority.allGranted') }}</div>
   <template v-else>
    <CheckboxGroup v-model="selected" :options="options" orientation="vertical" :aria-label="k.t('ui.authority.consentTitle')" />
    <div class="msa-quiet">{{ k.t('ui.authority.consentNote') }}</div>
    <div><Button variant="ghost" :aria-expanded="showApis" @click="showApis = !showApis">{{ k.t(showApis ? 'ui.authority.hideApis' : 'ui.authority.showApis') }}</Button></div>
    <div v-if="showApis" class="msa-consent-apis">
     <ProfileApis v-for="p in pending" :key="p.name" :profile="p" titled />
    </div>
   </template>
  </div>
  <template #footer>
   <Button variant="secondary" :disabled="busy" @click="open = false">{{ k.t('ui.authority.notNow') }}</Button>
   <Button v-if="a.needsApproval.value" variant="primary" @click="toSettings">{{ k.t('ui.authority.openSettings') }}</Button>
   <Button v-else-if="pending.length" variant="primary" :disabled="busy || !selected.length" @click="allow">{{ k.t('ui.authority.allow') }}</Button>
  </template>
 </Dialog>
</template>
