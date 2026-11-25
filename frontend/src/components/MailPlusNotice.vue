<script setup lang="ts">
/**
 * What the MailPlus Server precondition says and what to do: not installed or
 * stopped → Open Package Center (SDK DSM App launcher) with the written path;
 * unknown → neutral text and Check again. Nothing is started or installed by
 * this App. Coming back is the parent's re-check (window-activated).
 */
import {computed, ref} from 'vue'
import {Button, Callout} from '@synopackageland/ui'
import type {DsmAppLaunchResult} from '@synopackageland/sdk'
import {useAssistant} from '../api/assistant'
import {mailPlusCopy, openPackageCenter} from '../api/mailplus'
import type {MailPlusStatus} from '../api/types'

// recheck: show Check again (default); a wizard step that re-checks with Next passes false.
const props = withDefaults(defineProps<{status?: MailPlusStatus; checking?: boolean; recheck?: boolean}>(), {recheck: true})
const emit = defineEmits<{recheck: []; launched: []}>()
const k = useAssistant()
const copy = computed(() => mailPlusCopy(props.status))
const tone = computed(() => props.status?.state === 'unknown' ? 'info' as const : 'warning' as const)
const cause = computed(() => props.status?.causeKey ? k.t(props.status.causeKey, props.status.causeParams) : k.t('mail.setup.cause.unavailable'))
const launch = ref<DsmAppLaunchResult['status']>()
async function open() {
 launch.value = await openPackageCenter()
 emit('launched')
}
const launchText = computed(() => !launch.value ? '' : k.t(launch.value === 'requested' ? 'ui.mailplus.launchRequested' : 'ui.mailplus.launchManual'))
</script>

<template>
 <Callout v-if="copy" :tone="tone" :dismissible="false" :title="k.t(copy.title)" :data-mailplus="status?.state">
  <span>{{ k.t(copy.body, {cause}) }}</span>
  <span v-if="launchText" class="msa-quiet" role="status"> {{ launchText }}</span>
  <template #actions>
   <Button v-if="status?.state !== 'unknown'" variant="primary" data-open-package-center @click="open">{{ k.t('ui.mailplus.openPackageCenter') }}</Button>
   <Button v-if="recheck" variant="secondary" :disabled="checking" data-mailplus-recheck @click="emit('recheck')">{{ k.t(checking ? 'ui.mailplus.checking' : 'ui.mailplus.recheck') }}</Button>
  </template>
 </Callout>
</template>
