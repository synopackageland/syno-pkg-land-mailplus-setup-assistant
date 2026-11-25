<script setup lang="ts">
import {ref} from 'vue'
import type {Context} from '@synopackageland/sdk'
import {ExecutorSettings} from '@synopackageland/sdk/vue'
defineProps<{ctx:Context;admin:boolean}>()
/** confirmed: an administrator approved the executor here (the access notice reads its state again). */
const emit=defineEmits<{confirmed:[]}>()
const executor=ref<{refresh():unknown}>()
defineExpose({refresh:()=>void executor.value?.refresh()})
</script>
<template><ExecutorSettings v-if="ctx.executor" ref="executor" :admin="admin" :locale="ctx.locale" @confirmed="emit('confirmed')" /></template>
