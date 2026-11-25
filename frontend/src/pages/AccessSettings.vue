<script setup lang="ts">
import {computed, onMounted, ref} from 'vue'
import {Badge, Button, Callout, Dialog, SettingsSection, useToast} from '@synopackageland/ui'
import type {AuthorityGrant, AuthorityProfile, AuthorityProfileName, AuthorityState} from '../api/types'
import {OPT_IN_PROFILES, WRITE_PROFILES, profileKey} from '../api/authority'
import {formatTime, useAssistant, type Tone} from '../api/assistant'
import ProfileApis from '../components/ProfileApis.vue'

/** Settings > DSM access: each profile's state, Authorize and the caller's own Revoke. */
const k = useAssistant()
const a = k.authority
const toast = useToast({optional: true})
const busy = ref<string>()
const expanded = ref<string[]>([])
const confirm = ref<{profile: AuthorityProfileName; id: string}>()

const tones: Record<AuthorityState, Tone> = {
 'granted': 'success',
 'missing': 'warning',
 'needs-authorization': 'warning',
 'other-administrator': 'info',
 'needs-admin-approval': 'neutral',
}
const profiles = computed(() => (a.status.value?.profiles ?? []).filter(p => !OPT_IN_PROFILES.includes(p.name)))
const allProfiles = computed(() => a.status.value?.profiles ?? [])
// The caller's own grants that no profile uses any more, still revocable.
const otherGrants = computed<AuthorityGrant[]>(() => (a.status.value?.grants ?? [])
 .filter(g => !g.revoked && !allProfiles.value.some(p => p.grantId === g.delegation_id)))

function stateText(p: AuthorityProfile) {
 return p.state === 'other-administrator' && p.configuredBy
  ? k.t('ui.authority.byOther', {user: p.configuredBy})
  : k.t(`ui.authority.state.${p.state}`)
}
function toggle(name: string) {
 expanded.value = expanded.value.includes(name) ? expanded.value.filter(n => n !== name) : [...expanded.value, name]
}
async function authorize(p: AuthorityProfile) {
 busy.value = p.name
 try {
  const failure = await a.grant([p.name])
  if(failure) toast?.danger(k.error(failure))
  else toast?.success(k.t('ui.authority.granted', {name: k.t(profileKey(p.name))}))
 } finally {busy.value = undefined}
}
async function revoke() {
 const target = confirm.value
 confirm.value = undefined
 if(!target) return
 busy.value = target.id
 try {
  await a.revoke(target.profile, target.id)
  toast?.success(k.t('ui.authority.revoked'))
 } catch(e) {toast?.danger(k.error(e))}
 finally {busy.value = undefined}
}
const grantProfile = (g: AuthorityGrant) => (g.scope ?? '') as AuthorityProfileName

defineExpose({refresh: a.refresh})
onMounted(() => void a.refresh())
</script>

<template>
 <SettingsSection :title="k.t('core.authority.title')" :description="k.t('core.authority.intro')" :collapsible="false" :loading="a.loading.value && !a.status.value" data-section="authority">
  <Callout v-if="a.error.value && !a.status.value" tone="danger" dismiss-scope="occurrence" :dismissible="false"><span role="alert">{{ k.error(a.error.value) }}</span></Callout>
  <Callout v-if="a.needsApproval.value" tone="info" variant="inline" dismiss-scope="occurrence" :dismissible="false" :title="k.t('ui.authority.approvalTitle')">{{ k.t('ui.authority.approvalBody') }}</Callout>
  <div v-if="profiles.length" class="msa-profiles" role="list">
   <div v-for="p in profiles" :key="p.name" class="msa-profile" role="listitem" :data-profile="p.name" :data-state="p.state">
    <div class="msa-profile-head">
     <span class="msa-profile-title">{{ k.t(profileKey(p.name)) }}</span>
     <Badge :tone="tones[p.state]">{{ stateText(p) }}</Badge>
    </div>
    <div class="msa-quiet">{{ k.t(WRITE_PROFILES.includes(p.name) ? 'ui.authority.changes' : 'ui.authority.readsOnly') }}</div>
    <ProfileApis v-if="expanded.includes(p.name)" :profile="p" />
    <div class="msa-row-actions">
     <Button v-if="p.state !== 'granted' && !a.needsApproval.value" variant="secondary" :disabled="!!busy" @click="authorize(p)">{{ k.t('core.authority.grant') }}</Button>
     <Button v-if="p.canRevoke && p.grantId" variant="secondary" :disabled="!!busy" @click="confirm = {profile: p.name, id: p.grantId}">{{ k.t('core.authority.revoke') }}</Button>
     <Button variant="ghost" :aria-expanded="expanded.includes(p.name)" @click="toggle(p.name)">{{ k.t(expanded.includes(p.name) ? 'ui.authority.hideApis' : 'ui.authority.showApis') }}</Button>
    </div>
   </div>
  </div>
  <div v-if="otherGrants.length" class="msa-profiles" role="list" :aria-label="k.t('ui.authority.otherGrants')">
   <div class="msa-profile-title" role="heading" aria-level="3">{{ k.t('ui.authority.otherGrants') }}</div>
   <div v-for="g in otherGrants" :key="g.delegation_id" class="msa-profile" role="listitem">
    <div class="msa-profile-head">
     <span>{{ k.t(profileKey(grantProfile(g))) }}</span>
     <Button variant="secondary" :disabled="!!busy" @click="confirm = {profile: grantProfile(g), id: g.delegation_id}">{{ k.t('core.authority.revoke') }}</Button>
    </div>
    <div v-if="formatTime(k.locale, g.expires_at)" class="msa-quiet">{{ k.t('ui.authority.expires', {time: formatTime(k.locale, g.expires_at)}) }}</div>
   </div>
  </div>
 </SettingsSection>

 <Dialog :open="!!confirm" :title="k.t('ui.authority.revokeTitle')" size="sm" @update:open="v => {if(!v) confirm = undefined}">
  <div>{{ k.t('ui.authority.revokeBody') }}</div>
  <template #footer>
   <Button variant="secondary" @click="confirm = undefined">{{ k.t('ui.common.cancel') }}</Button>
   <Button variant="danger" @click="revoke">{{ k.t('core.authority.revoke') }}</Button>
  </template>
 </Dialog>
</template>
