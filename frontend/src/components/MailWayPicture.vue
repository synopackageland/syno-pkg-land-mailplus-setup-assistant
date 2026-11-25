<script setup lang="ts">
/**
 * A concept picture of one of the two ways this App sets mail up, not an
 * architecture: `direct` is the NAS talking with the internet itself (it needs
 * a fixed IP and port 25); `cloudflare` puts Cloudflare in front, so the NAS
 * can be anywhere (drawn inside a house). Arrows go both ways (send and
 * receive). Inline SVG: colours are theme tokens (light and dark), every word
 * is a catalog key, and it scales with its container. No markers, so several
 * copies on one page need no unique IDs.
 */
import {Cloud, Globe, House, Server} from '@lucide/vue'
import {useAssistant} from '../api/assistant'

const props = defineProps<{way: 'direct' | 'cloudflare'}>()
const k = useAssistant()
const W = 240
const H = 62
const mid = 22
/** A two-headed arrow from x1 to x2 at the icons' middle. */
const arrow = (x1: number, x2: number) => ({
 line: {x1: x1 + 7, x2: x2 - 7},
 heads: [`${x1},${mid} ${x1 + 8},${mid - 4.5} ${x1 + 8},${mid + 4.5}`, `${x2},${mid} ${x2 - 8},${mid - 4.5} ${x2 - 8},${mid + 4.5}`],
})
const nodes = props.way === 'direct'
 ? [{key: 'nas', x: 44, icon: Server}, {key: 'internet', x: 196, icon: Globe}]
 : [{key: 'nas', x: 32, icon: House}, {key: 'cloudflare', x: 120, icon: Cloud}, {key: 'internet', x: 208, icon: Globe}]
const arrows = props.way === 'direct' ? [arrow(70, 170)] : [arrow(56, 96), arrow(144, 184)]
</script>

<template>
 <svg class="msa-way-picture" :viewBox="`0 0 ${W} ${H}`" role="img" :aria-label="k.t(`ui.ways.${props.way}.summary`)" :data-way-picture="props.way">
  <title>{{ k.t(`ui.ways.${props.way}.summary`) }}</title>
  <g v-for="n in nodes" :key="n.key" :data-node="n.key">
   <component :is="n.icon" :x="n.x - 18" :y="mid - 18" :width="36" :height="36" :stroke-width="1.6" class="msa-way-icon" aria-hidden="true" />
   <!-- The NAS on the Cloudflare way sits inside the house: anywhere will do. -->
   <component :is="Server" v-if="n.icon === House" :x="n.x - 7" :y="mid - 3" :width="14" :height="14" :stroke-width="2" class="msa-way-icon" aria-hidden="true" />
   <text :x="n.x" :y="H - 4" text-anchor="middle" class="msa-way-label">{{ k.t(`ui.ways.node.${n.key}`) }}</text>
  </g>
  <g v-for="(a, i) in arrows" :key="i" data-arrow>
   <line :x1="a.line.x1" :y1="mid" :x2="a.line.x2" :y2="mid" class="msa-way-path" />
   <polygon v-for="h in a.heads" :key="h" :points="h" class="msa-way-head" />
  </g>
 </svg>
</template>
