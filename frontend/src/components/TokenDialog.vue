<script setup lang="ts">
/**
 * Re-entering a Cloudflare token: the same guided entry as the
 * setup's sign-in (the steps, the create-token link with every permission
 * filled in, the permission list), in one dialog. For a kept setup
 * (mode "kept") it calls mail.inbound.token, which checks the token against
 * every permission the setup needs and replaces it everywhere at once (the
 * relay's SMTP login, the sync, the removal); for a setup flow waiting on
 * its decision (mode "flow") it calls mail.setup.cloudflare, which replaces
 * the flow's sealed sign-in in place. Missing permissions are named. The
 * field is emptied as soon as the reply comes; the token is never shown.
 */
import {computed, ref, watch} from 'vue'
import {Accordion, Button, Callout, Dialog, Form, FormItem, Input, Space, StepList} from '@synopackageland/ui'
import type {AccordionEntry, StepListItem} from '@synopackageland/ui'
import {errorCode, useAssistant} from '../api/assistant'
import {cloudflareTokenUrl, openCloudflare, tokenPermissionCodes} from '../api/cloudflare'
import {listText} from '../api/evidence'
import type {AssistantError} from '../api/types'

const props = defineProps<{open: boolean; id: string; domain: string; mode: 'kept' | 'flow'}>()
const emit = defineEmits<{'update:open': [open: boolean]; saved: []}>()
const k = useAssistant()
const token = ref('')
const busy = ref(false)
const error = ref<unknown>()
watch(() => props.open, o => {if(o) {token.value = ''; error.value = undefined}})

const tokenUrl = cloudflareTokenUrl()
const steps = computed<StepListItem[]>(() => [
 {title: k.t('mail.setup.cloudflare.step1')},
 {title: k.t('mail.setup.cloudflare.step2'), description: k.t('mail.setup.cloudflare.step2Hint')},
 {title: k.t('mail.setup.cloudflare.step3')},
])
const permissionLines = computed(() => tokenPermissionCodes.map(c => k.t(`mail.setup.cloudflare.permission.${c}`)))
const permissionFold = computed<AccordionEntry[]>(() => [{value: 'permissions', title: k.t('mail.setup.cloudflare.permissions', {count: tokenPermissionCodes.length})}])

/** The permissions a refused token lacks, in plain words (empty for any other error). */
const missing = computed(() => {
 const d = (error.value as Partial<AssistantError> | undefined)?.details
 if(errorCode(error.value) !== 'permission_refused' || !d?.permissions) return ''
 return listText(k.locale, d.permissions.split(',').filter(Boolean).map(c => k.t(`mail.setup.cloudflare.permission.${c}`)))
})

async function save() {
 const pasted = token.value.trim()
 token.value = ''
 if(!pasted) return
 busy.value = true
 error.value = undefined
 try {
  if(props.mode === 'kept') await k.call('mail.inbound.token', {id: props.id, token: pasted})
  else await k.call('mail.setup.cloudflare', {id: props.id, token: pasted})
  emit('saved')
  emit('update:open', false)
 } catch(e) {error.value = e}
 finally {busy.value = false}
}
</script>

<template>
 <Dialog :open="open" :title="k.t('ui.token.title', {domain})" size="md" @update:open="o => emit('update:open', o)">
  <Space direction="column" spacing="regular" data-token-dialog>
   <div>{{ k.t('ui.token.body') }}</div>
   <Callout v-if="missing" tone="warning" :dismissible="false" data-token-missing><span role="alert">{{ k.t('ui.token.missing', {permissions: missing}) }}</span></Callout>
   <Callout v-else-if="error" tone="danger" :dismissible="false" data-token-error><span role="alert">{{ k.error(error) }}</span></Callout>
   <StepList :items="steps" data-token-steps />
   <div><Button variant="secondary" data-create-token @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button></div>
   <Accordion :items="permissionFold" data-permissions>
    <template #item-permissions>
     <Space direction="column" spacing="dense" role="list">
      <div v-for="line in permissionLines" :key="line" role="listitem" data-permission>{{ line }}</div>
     </Space>
    </template>
   </Accordion>
   <Form direction="vertical">
    <FormItem :label="k.t('mail.setup.cloudflare.token')" :description="k.t('mail.setup.cloudflare.tokenHint')">
     <Input v-model="token" type="password" autocomplete="off" spellcheck="false" data-new-token />
    </FormItem>
   </Form>
  </Space>
  <template #footer>
   <Button variant="secondary" data-token-cancel @click="emit('update:open', false)">{{ k.t('ui.token.cancel') }}</Button>
   <Button variant="primary" :disabled="busy || !token.trim()" data-token-save @click="save">{{ k.t('ui.token.save') }}</Button>
  </template>
 </Dialog>
</template>
