<script lang="ts">
// The App's pages, shown at once. The root-ops overlay replaces this file to
// hold them until an administrator approves the executor.
export const holdsPages = false
</script>
<script setup lang="ts">
import type {Context} from '@synopackageland/sdk'
defineProps<{ctx:Context;admin:boolean}>()
</script>
<template><slot /></template>
