<script setup lang="ts">
/**
 * One quiet line on what Cloudflare charges: receiving is free; on Workers
 * Free, sending reaches only the account's verified addresses, and sending to
 * anyone needs Workers Paid (3,000 mails a month included). Cloudflare's page
 * decides. Shown on the route step (before a choice and with Cloudflare).
 */
import {Link} from '@synopackageland/ui'
import {useAssistant} from '../api/assistant'
import {CLOUDFLARE_PRICING_URL} from '../api/links'

const k = useAssistant()
</script>

<template>
 <div class="msa-quiet msa-plan-note" data-plan-note>
  <span>{{ k.t('ui.pricing.note') }}</span>
  <Link :href="CLOUDFLARE_PRICING_URL" external target="_blank" rel="noopener noreferrer" data-pricing-link>{{ k.t('ui.pricing.link') }}</Link>
 </div>
</template>
