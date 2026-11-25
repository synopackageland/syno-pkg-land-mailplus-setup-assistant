<script setup lang="ts">
/**
 * Interactive Cloudflare send/receive flow diagram for the Overview page
 * (split-bridge hub layout with inbound/outbound station steppers).
 *
 * Collapsed by default; animation runs only while open and pauses cleanly on
 * collapse, unmount, or when prefers-reduced-motion is enabled. Colours,
 * spacing, typography and radii come from @synopackageland/ui theme tokens.
 */
import {computed, nextTick, onMounted, onUnmounted, ref, useId, watch} from 'vue'
import {Button, SettingsSection, Tooltip} from '@synopackageland/ui'
import {CircleHelp, Cloud, Globe, HardDrive, Link2, MailCheck, Pause, Play, RotateCcw, Sparkles} from '@lucide/vue'
import {useAssistant} from '../api/assistant'

type FlowDir = 'in' | 'out'
type FlowMode = 'both' | FlowDir
type Side = 'left' | 'right' | 'top' | 'bottom' | 'center'
type BadgeKind = 'raw' | 'routed' | 'size' | 'vpc' | 'port25' | 'inbox' | 'starttls' | 'tlstoken' | 'dkim' | 'sent'

interface StationSpec {
 id: string
 badge: BadgeKind
 chipKey: string
 tagKey: string
}

interface SegmentSpec {
 from: string
 fromSide: Side
 fromOffset?: number
 to: string
 toSide: Side
 toOffset?: number
 bow?: number
 gutter?: 'left' | 'right'
}

interface Point {x: number; y: number}

interface BuiltSegment {
 el: SVGPathElement
 len: number
 from: string
 to: string
 p1: Point
 p2: Point
}

interface PigeonActor {
 g: SVGGElement
 birdPos: SVGGElement
 orient: SVGGElement
 frontWing: SVGGElement
 backWing: SVGGElement
 collar: SVGPathElement | null
 envWrap: SVGGElement | null
 envShift: SVGGElement | null
 envRect: SVGRectElement | null
 envShade: SVGPathElement | null
 envFlap: SVGPathElement | null
 badge: SVGGElement | null
 isGhost: boolean
}

const SVG_NS = 'http://www.w3.org/2000/svg'
const COMPACT_STAGE_WIDTH = 580
const START_DWELL = 480
const FLY_MS = 1050
const STOP_DWELL = 760
const END_DWELL = 1150

const FLOWS: Record<FlowDir, StationSpec[]> = {
 in: [
  {id: 'internet', badge: 'raw', chipKey: 'ui.cfFlow.chip.internet', tagKey: 'ui.cfFlow.step.in.internet'},
  {id: 'routing', badge: 'routed', chipKey: 'ui.cfFlow.chip.routing', tagKey: 'ui.cfFlow.step.in.routing'},
  {id: 'worker', badge: 'size', chipKey: 'ui.cfFlow.chip.worker', tagKey: 'ui.cfFlow.step.in.worker'},
  {id: 'vpc', badge: 'vpc', chipKey: 'ui.cfFlow.chip.vpc', tagKey: 'ui.cfFlow.step.in.vpc'},
  {id: 'tunnel', badge: 'port25', chipKey: 'ui.cfFlow.chip.tunnel', tagKey: 'ui.cfFlow.step.in.tunnel'},
  {id: 'mailplus', badge: 'inbox', chipKey: 'ui.cfFlow.chip.mailplus', tagKey: 'ui.cfFlow.step.in.mailplus'},
 ],
 out: [
  {id: 'mailplus', badge: 'starttls', chipKey: 'ui.cfFlow.chip.mailplus', tagKey: 'ui.cfFlow.step.out.mailplus'},
  {id: 'relay', badge: 'tlstoken', chipKey: 'ui.cfFlow.chip.relay', tagKey: 'ui.cfFlow.step.out.relay'},
  {id: 'sending', badge: 'dkim', chipKey: 'ui.cfFlow.chip.sending', tagKey: 'ui.cfFlow.step.out.sending'},
  {id: 'internet', badge: 'sent', chipKey: 'ui.cfFlow.chip.internet', tagKey: 'ui.cfFlow.step.out.internet'},
 ],
}

const k = useAssistant()
const uid = useId()
const pigeonShadowId = `msa-pigeon-shadow-${uid}`
const envShadowId = `msa-env-shadow-${uid}`

const open = ref(false)
const mode = ref<FlowMode>('both')
const paused = ref(false)
const reducedMotion = ref(false)
const activeDir = ref<FlowDir>('in')
const activeNodeId = ref<string | null>(null)
const activeStepIdx = ref(0)

const stageRef = ref<HTMLElement | null>(null)
const svgUnderRef = ref<SVGSVGElement | null>(null)
const svgOverRef = ref<SVGSVGElement | null>(null)

const isPlaying = computed(() => open.value && !paused.value && !reducedMotion.value)
const showInboundStepper = computed(() => mode.value !== 'out')
const showOutboundStepper = computed(() => mode.value !== 'in')

let elapsed = 0
let lastTs = 0
let rafId = 0
let dashOffset = 0
let wingPhase = 0
let routes: Record<FlowDir, BuiltSegment[]> = {in: [], out: []}
let dots: Record<FlowDir, SVGCircleElement[]> = {in: [], out: []}
let resizeObserver: ResizeObserver | null = null
let rmQuery: MediaQueryList | null = null

let ghostActor: PigeonActor | null = null
let mainActor: PigeonActor | null = null
let rmOutActor: PigeonActor | null = null
let popGroup: SVGGElement | null = null
let popRect: SVGRectElement | null = null
let popText: SVGTextElement | null = null

function svgEl<K extends keyof SVGElementTagNameMap>(
 tag: K,
 attrs: Record<string, string | number> = {},
 parent: Element | null = null,
): SVGElementTagNameMap[K] {
 const n = document.createElementNS(SVG_NS, tag)
 for(const [key, val] of Object.entries(attrs)) n.setAttribute(key, String(val))
 if(parent) parent.appendChild(n)
 return n
}

function createPigeonGroup(isGhost: boolean): PigeonActor {
 const root = svgEl('g', {
  class: isGhost ? 'msa-cf-pigeon-ghost' : 'msa-cf-pigeon-actor',
  opacity: isGhost ? '0.24' : '1',
 })
 const birdPos = svgEl('g', {}, root)
 const orient = svgEl('g', {}, birdPos)
 if(!isGhost) orient.setAttribute('filter', `url(#${pigeonShadowId})`)

 const bodyStroke = isGhost ? 'var(--ui-blue-7)' : 'var(--ui-gray-10)'
 const bodyFill = isGhost ? 'var(--ui-blue-3)' : 'var(--ui-surface)'
 const shadeFill = isGhost ? 'var(--ui-blue-4)' : 'var(--ui-gray-4)'

 const backWingPivot = svgEl('g', {transform: 'translate(1, -3.2)'}, orient)
 const backWing = svgEl('g', {}, backWingPivot)
 svgEl('path', {
  d: 'M 0,0 C -1.5,-8.5 -7.5,-14.2 -14.8,-13.5 C -12.0,-9.2 -9.5,-5.5 -6.2,-2.2 Z',
  fill: shadeFill,
  stroke: isGhost ? 'var(--ui-blue-7)' : 'var(--ui-gray-8)',
  'stroke-width': isGhost ? '0.9' : '1.0',
  'stroke-linejoin': 'round',
 }, backWing)

 svgEl('path', {
  d: 'M -9.2,1.2 L -19.5,-3.6 C -18.6,-0.2 -17.8,2.6 -16.2,5.6 L -8.6,3.6 Z',
  fill: isGhost ? 'var(--ui-blue-3)' : 'var(--ui-surface-subtle)',
  stroke: bodyStroke,
  'stroke-width': isGhost ? '0.9' : '1.08',
  'stroke-linejoin': 'round',
 }, orient)
 if(!isGhost) {
  svgEl('path', {
   d: 'M -10.5,2.2 L -17.6,0.4 M -10.0,3.1 L -16.4,3.4',
   fill: 'none',
   stroke: 'var(--ui-gray-6)',
   'stroke-width': '0.8',
   'stroke-linecap': 'round',
  }, orient)
 }

 svgEl('path', {
  d: 'M -10.2,2.0 C -6.2,-2.2 -1.2,-4.6 4.4,-5.4 C 6.6,-9.0 11.4,-9.0 12.8,-5.4 C 13.5,-3.6 12.7,-1.2 10.8,0.5 C 8.0,4.6 1.2,6.4 -5.8,4.6 C -8.2,4.0 -9.6,3.0 -10.2,2.0 Z',
  fill: bodyFill,
  stroke: bodyStroke,
  'stroke-width': isGhost ? '1.0' : '1.2',
  'stroke-linejoin': 'round',
 }, orient)

 let collar: SVGPathElement | null = null
 if(!isGhost) {
  svgEl('path', {
   d: 'M -5.8,3.4 C -0.2,5.0 5.8,3.6 9.3,0.4 C 6.4,2.2 0.8,3.3 -5.6,2.2 Z',
   fill: 'var(--ui-gray-4)',
   opacity: '0.72',
  }, orient)

  collar = svgEl('path', {
   d: 'M 5.4,-3.8 Q 8.4,-2.2 10.7,-3.4',
   fill: 'none',
   stroke: 'var(--ui-blue-9)',
   'stroke-width': '1.55',
   'stroke-linecap': 'round',
  }, orient)

  svgEl('path', {
   d: 'M 12.2,-5.6 L 16.6,-4.0 L 12.3,-2.6 Z',
   fill: 'var(--ui-orange-9)',
   stroke: 'var(--ui-orange-11)',
   'stroke-width': '0.8',
   'stroke-linejoin': 'round',
  }, orient)

  svgEl('circle', {cx: '10.0', cy: '-5.7', r: '1.18', fill: 'var(--ui-text)'}, orient)
  svgEl('circle', {cx: '10.38', cy: '-6.05', r: '0.38', fill: 'var(--ui-surface)'}, orient)
 }

 const frontWingPivot = svgEl('g', {transform: 'translate(1.5, -1.5)'}, orient)
 const frontWing = svgEl('g', {}, frontWingPivot)
 svgEl('path', {
  d: 'M 0,0 C -1.0,-7.2 -6.0,-14.0 -15.0,-14.4 C -12.8,-10.2 -11.0,-7.4 -9.4,-5.4 C -11.0,-5.8 -12.4,-6.2 -13.2,-6.5 C -10.4,-2.8 -7.2,-0.6 -3.2,1.0 C -1.6,1.4 -0.4,0.8 0,0 Z',
  fill: bodyFill,
  stroke: bodyStroke,
  'stroke-width': isGhost ? '0.95' : '1.15',
  'stroke-linejoin': 'round',
 }, frontWing)
 if(!isGhost) {
  svgEl('path', {
   d: 'M -2.8,-2.6 Q -7.0,-6.8 -11.8,-10.0 M -3.4,-1.2 Q -7.0,-3.8 -10.4,-5.8',
   fill: 'none',
   stroke: 'var(--ui-gray-6)',
   'stroke-width': '0.85',
   'stroke-linecap': 'round',
  }, frontWing)
 }

 let envWrap: SVGGElement | null = null
 let envShift: SVGGElement | null = null
 let envRect: SVGRectElement | null = null
 let envShade: SVGPathElement | null = null
 let envFlap: SVGPathElement | null = null
 let badge: SVGGElement | null = null

 if(!isGhost) {
  envWrap = svgEl('g', {filter: `url(#${envShadowId})`}, root)
  envShift = svgEl('g', {}, envWrap)
  envRect = svgEl('rect', {
   x: '-9.5', y: '0.4', width: '19', height: '13.2', rx: '2.5',
   fill: 'var(--ui-surface)',
   stroke: 'var(--ui-blue-9)',
   'stroke-width': '1.35',
  }, envShift)
  envShade = svgEl('path', {
   d: 'M -8.6,12.8 L 0,6.4 L 8.6,12.8 Z',
   fill: 'var(--ui-blue-2)',
  }, envShift)
  envFlap = svgEl('path', {
   d: 'M -8.6,1.2 L 0,7.7 L 8.6,1.2',
   fill: 'none',
   stroke: 'var(--ui-blue-9)',
   'stroke-width': '1.3',
   'stroke-linecap': 'round',
   'stroke-linejoin': 'round',
  }, envShift)
  badge = svgEl('g', {transform: 'translate(9.5, 12.2)'}, envShift)
 }

 return {
  g: root,
  birdPos,
  orient,
  frontWing,
  backWing,
  collar,
  envWrap,
  envShift,
  envRect,
  envShade,
  envFlap,
  badge,
  isGhost,
 }
}

function renderEnvelopeBadge(badgeGroup: SVGGElement | null, badgeType: BadgeKind) {
 if(!badgeGroup || badgeGroup.dataset.badge === badgeType) return
 badgeGroup.dataset.badge = badgeType
 badgeGroup.textContent = ''
 if(badgeType === 'raw') return

 if(badgeType === 'routed') {
  svgEl('circle', {r: '5.4', fill: 'var(--ui-blue-9)', stroke: 'var(--ui-surface)', 'stroke-width': '1.2'}, badgeGroup)
  const t = svgEl('text', {x: '0', y: '2.5', 'text-anchor': 'middle', fill: 'var(--ui-surface)', 'font-size': '7.4', 'font-weight': '700'}, badgeGroup)
  t.textContent = '@'
 } else if(badgeType === 'size' || badgeType === 'inbox' || badgeType === 'sent') {
  svgEl('circle', {r: '5.5', fill: 'var(--ui-green-9)', stroke: 'var(--ui-surface)', 'stroke-width': '1.2'}, badgeGroup)
  svgEl('path', {d: 'M -2.3,0.2 L -0.6,2.0 L 2.6,-1.8', fill: 'none', stroke: 'var(--ui-surface)', 'stroke-width': '1.5', 'stroke-linecap': 'round', 'stroke-linejoin': 'round'}, badgeGroup)
 } else if(badgeType === 'vpc') {
  svgEl('circle', {r: '5.5', fill: 'var(--ui-accent-9)', stroke: 'var(--ui-surface)', 'stroke-width': '1.2'}, badgeGroup)
  svgEl('path', {d: 'M -2.1,-1.4 L 0.4,0 L -2.1,1.4 M 0.4,-1.4 L 2.7,0 L 0.4,1.4', fill: 'none', stroke: 'var(--ui-surface)', 'stroke-width': '1.25', 'stroke-linecap': 'round', 'stroke-linejoin': 'round'}, badgeGroup)
 } else if(badgeType === 'port25') {
  svgEl('rect', {x: '-7.6', y: '-4.9', width: '15.2', height: '9.8', rx: '4.9', fill: 'var(--ui-info)', stroke: 'var(--ui-surface)', 'stroke-width': '1.1'}, badgeGroup)
  const t = svgEl('text', {x: '0', y: '2.4', 'text-anchor': 'middle', fill: 'var(--ui-surface)', 'font-size': '6.7', 'font-weight': '700'}, badgeGroup)
  t.textContent = ':25'
 } else if(badgeType === 'starttls') {
  svgEl('circle', {r: '5.6', fill: 'var(--ui-warning)', stroke: 'var(--ui-surface)', 'stroke-width': '1.2'}, badgeGroup)
  svgEl('rect', {x: '-2.4', y: '-0.3', width: '4.8', height: '3.6', rx: '0.8', fill: 'var(--ui-surface)'}, badgeGroup)
  svgEl('path', {d: 'M -1.4,-0.4 v-1.4 a1.4,1.4 0 0 1 2.8,0 v1.4', fill: 'none', stroke: 'var(--ui-surface)', 'stroke-width': '1.15'}, badgeGroup)
 } else if(badgeType === 'tlstoken') {
  svgEl('rect', {x: '-8.2', y: '-5.0', width: '16.4', height: '10.0', rx: '5.0', fill: 'var(--ui-orange-9)', stroke: 'var(--ui-surface)', 'stroke-width': '1.1'}, badgeGroup)
  svgEl('circle', {cx: '-3.1', cy: '0', r: '1.65', fill: 'none', stroke: 'var(--ui-surface)', 'stroke-width': '1.15'}, badgeGroup)
  svgEl('path', {d: 'M -1.4,0 H 3.7 M 1.9,0 v1.5 M 3.5,0 v1.5', fill: 'none', stroke: 'var(--ui-surface)', 'stroke-width': '1.15', 'stroke-linecap': 'round'}, badgeGroup)
 } else if(badgeType === 'dkim') {
  svgEl('circle', {r: '5.9', fill: 'var(--ui-danger)', stroke: 'var(--ui-surface)', 'stroke-width': '1.2'}, badgeGroup)
  svgEl('path', {d: 'M 0,-3.1 L 0.9,-0.9 L 3.2,-0.9 L 1.3,0.6 L 2.0,2.8 L 0,1.4 L -2.0,2.8 L -1.3,0.6 L -3.2,-0.9 L -0.9,-0.9 Z', fill: 'var(--ui-orange-2)'}, badgeGroup)
 }
}

function initOverlay() {
 const svgOver = svgOverRef.value
 if(!svgOver || mainActor) return
 svgOver.textContent = ''
 const defs = svgEl('defs', {}, svgOver)
 const pShadow = svgEl('filter', {id: pigeonShadowId, x: '-55%', y: '-55%', width: '210%', height: '210%'}, defs)
 svgEl('feDropShadow', {dx: '0', dy: '2.2', stdDeviation: '2.2', 'flood-color': '#0f172a', 'flood-opacity': '0.18'}, pShadow)
 const eShadow = svgEl('filter', {id: envShadowId, x: '-50%', y: '-50%', width: '200%', height: '200%'}, defs)
 svgEl('feDropShadow', {dx: '0', dy: '1.5', stdDeviation: '1.5', 'flood-color': '#0f172a', 'flood-opacity': '0.14'}, eShadow)

 ghostActor = createPigeonGroup(true)
 mainActor = createPigeonGroup(false)
 rmOutActor = createPigeonGroup(false)
 rmOutActor.g.style.display = 'none'
 svgOver.appendChild(ghostActor.g)
 svgOver.appendChild(mainActor.g)
 svgOver.appendChild(rmOutActor.g)

 popGroup = svgEl('g', {class: 'msa-cf-pop-tag', opacity: '0'}, svgOver)
 popRect = svgEl('rect', {rx: '9', height: '19', y: '0'}, popGroup)
 popText = svgEl('text', {'font-size': '10.5', 'text-anchor': 'middle', fill: '#ffffff', y: '13.5'}, popGroup)
}

function clearOverlayRefs() {
 ghostActor = null
 mainActor = null
 rmOutActor = null
 popGroup = null
 popRect = null
 popText = null
}

function showPopTag(x: number, y: number, label: string, dir: FlowDir, opacity: number) {
 if(!popGroup || !popRect || !popText) return
 if(!label || opacity <= 0.02) {
  popGroup.setAttribute('opacity', '0')
  return
 }
 popText.textContent = label
 const wideChars = [...label].reduce((sum, ch) => sum + (ch.charCodeAt(0) > 255 ? 11 : 6.6), 0)
 const approxW = Math.max(46, Math.ceil(wideChars) + 16)
 const stageW = stageRef.value?.clientWidth || 720
 const cx = Math.max(approxW / 2 + 6, Math.min(stageW - approxW / 2 - 6, x))
 const cy = Math.max(4, y - 48)
 popRect.setAttribute('x', String(-approxW / 2))
 popRect.setAttribute('width', String(approxW))
 popRect.setAttribute('fill', dir === 'in' ? 'var(--ui-blue-10)' : 'var(--ui-orange-10)')
 popGroup.setAttribute('transform', `translate(${cx.toFixed(1)}, ${cy.toFixed(1)})`)
 popGroup.setAttribute('opacity', opacity.toFixed(3))
}

function posePigeon(
 actor: PigeonActor,
 x: number,
 y: number,
 angleRad: number,
 phase: number,
 dir: FlowDir,
 badgeType: BadgeKind,
 opts: {scale?: number; flying?: boolean; staticPose?: boolean; preferLeft?: boolean} = {},
) {
 const stageW = stageRef.value?.clientWidth || 720
 const isCompact = stageW < COMPACT_STAGE_WIDTH
 const baseScale = (opts.scale ?? 1.0) * (isCompact ? 0.84 : 1.0)
 const flying = Boolean(opts.flying)
 const isIn = dir === 'in'
 const accent = isIn ? 'var(--ui-blue-9)' : 'var(--ui-orange-9)'
 const tint = isIn ? 'var(--ui-blue-2)' : 'var(--ui-orange-2)'
 const ghostFill = isIn ? 'var(--ui-blue-3)' : 'var(--ui-orange-3)'
 const ghostStroke = isIn ? 'var(--ui-blue-7)' : 'var(--ui-orange-7)'

 const vx = Math.cos(angleRad)
 const facingLeft = opts.preferLeft !== undefined
  ? (Math.abs(vx) < 0.08 ? opts.preferLeft : vx < 0)
  : vx < -0.05

 const bob = flying ? Math.sin(phase - 0.6) * 2.1 : Math.sin(phase * 0.45) * 0.8
 const px = x
 const py = y + bob

 actor.birdPos.setAttribute('transform', `translate(${px.toFixed(1)}, ${py.toFixed(1)}) scale(${baseScale.toFixed(3)})`)
 const angleDeg = (angleRad * 180) / Math.PI
 actor.orient.setAttribute('transform', facingLeft ? `rotate(${angleDeg.toFixed(1)}) scale(1,-1)` : `rotate(${angleDeg.toFixed(1)})`)

 if(flying) {
  const fScaleY = 0.16 + 0.86 * Math.cos(phase)
  const fRot = -6 + 14 * Math.sin(phase)
  const bScaleY = 0.18 + 0.82 * Math.cos(phase + 0.42)
  const bRot = -10 + 12 * Math.sin(phase + 0.42)
  actor.frontWing.setAttribute('transform', `rotate(${fRot.toFixed(1)}) scale(1, ${fScaleY.toFixed(3)})`)
  actor.backWing.setAttribute('transform', `rotate(${bRot.toFixed(1)}) scale(1, ${bScaleY.toFixed(3)})`)
 } else {
  const hover = opts.staticPose ? 0 : Math.sin(phase * 0.5) * 0.12
  actor.frontWing.setAttribute('transform', `rotate(-10) scale(1, ${(0.78 + hover).toFixed(3)})`)
  actor.backWing.setAttribute('transform', `rotate(-14) scale(1, ${(0.68 - hover * 0.7).toFixed(3)})`)
 }

 if(actor.isGhost) {
  actor.orient.querySelectorAll('path').forEach(p => {
   p.setAttribute('fill', ghostFill)
   p.setAttribute('stroke', ghostStroke)
  })
  return
 }

 if(actor.collar) actor.collar.setAttribute('stroke', accent)

 const lx = 16.4
 const ly = facingLeft ? 4.0 : -4.0
 const cosA = Math.cos(angleRad)
 const sinA = Math.sin(angleRad)
 const beakX = px + baseScale * (lx * cosA - ly * sinA)
 const beakY = py + baseScale * (lx * sinA + ly * cosA)
 const swayDeg = flying
  ? (-vx * 7.5 + Math.sin(phase) * 2.8)
  : (opts.staticPose ? 0 : Math.sin(phase * 0.5) * 1.8)
 const envScale = baseScale * 0.92
 actor.envWrap?.setAttribute('transform', `translate(${beakX.toFixed(1)}, ${beakY.toFixed(1)}) rotate(${swayDeg.toFixed(1)}) scale(${envScale.toFixed(3)})`)

 const steepUp = sinA < -0.55
 const shiftX = facingLeft ? (steepUp ? -7.4 : -5.6) : (steepUp ? 7.4 : 5.6)
 const shiftY = steepUp ? -1.5 : 0
 actor.envShift?.setAttribute('transform', `translate(${shiftX.toFixed(1)}, ${shiftY.toFixed(1)})`)
 actor.envRect?.setAttribute('stroke', accent)
 actor.envShade?.setAttribute('fill', tint)
 actor.envFlap?.setAttribute('stroke', accent)
 if(actor.badge) {
  actor.badge.setAttribute('transform', `translate(${facingLeft ? -9.2 : 9.2}, 12.2)`)
  renderEnvelopeBadge(actor.badge, badgeType)
 }
}

function getAnchor(nodeId: string, side: Side = 'center', offset = 0): Point {
 const stage = stageRef.value
 if(!stage) return {x: 0, y: 0}
 const node = stage.querySelector<HTMLElement>(`[data-flow-node="${nodeId}"]`)
 if(!node) return {x: 0, y: 0}
 const sr = stage.getBoundingClientRect()
 const r = node.getBoundingClientRect()
 const x = r.left - sr.left
 const y = r.top - sr.top
 const w = r.width
 const h = r.height
 switch(side) {
  case 'left': return {x, y: y + h * 0.5 + offset}
  case 'right': return {x: x + w, y: y + h * 0.5 + offset}
  case 'top': return {x: x + w * 0.5 + offset, y}
  case 'bottom': return {x: x + w * 0.5 + offset, y: y + h}
  default: return {x: x + w * 0.5, y: y + h * 0.5}
 }
}

function bezierD(p1: Point, p2: Point, s1: Side, s2: Side, bow = 0): string {
 const dx = p2.x - p1.x
 const dy = p2.y - p1.y
 const dist = Math.hypot(dx, dy)
 const pull = Math.min(72, Math.max(20, dist * 0.42))
 const vec = (side: Side): [number, number] => {
  if(side === 'right') return [1, 0]
  if(side === 'left') return [-1, 0]
  if(side === 'top') return [0, -1]
  if(side === 'bottom') return [0, 1]
  return [0, 0]
 }
 const [vx1, vy1] = vec(s1)
 const [vx2, vy2] = vec(s2)
 let c1x = p1.x + vx1 * pull
 let c1y = p1.y + vy1 * pull
 let c2x = p2.x + vx2 * pull
 let c2y = p2.y + vy2 * pull
 if(bow !== 0) {
  const nx = -dy / (dist || 1)
  const ny = dx / (dist || 1)
  c1x += nx * bow
  c1y += ny * bow
  c2x += nx * bow
  c2y += ny * bow
 }
 return `M ${p1.x.toFixed(1)} ${p1.y.toFixed(1)} C ${c1x.toFixed(1)} ${c1y.toFixed(1)}, ${c2x.toFixed(1)} ${c2y.toFixed(1)}, ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`
}

function gutterD(p1: Point, p2: Point, side: 'left' | 'right'): string {
 const w = stageRef.value?.clientWidth || 340
 const gx = side === 'left' ? 16 : w - 16
 const r = 12
 const dirY = p2.y >= p1.y ? 1 : -1
 const dirX1 = gx >= p1.x ? 1 : -1
 const dirX2 = p2.x >= gx ? 1 : -1
 const r1 = Math.min(r, Math.abs(gx - p1.x) * 0.85, Math.abs(p2.y - p1.y) * 0.35)
 const r2 = Math.min(r, Math.abs(p2.x - gx) * 0.85, Math.abs(p2.y - p1.y) * 0.35)
 return [
  `M ${p1.x.toFixed(1)} ${p1.y.toFixed(1)}`,
  `L ${(gx - dirX1 * r1).toFixed(1)} ${p1.y.toFixed(1)}`,
  `Q ${gx.toFixed(1)} ${p1.y.toFixed(1)}, ${gx.toFixed(1)} ${(p1.y + dirY * r1).toFixed(1)}`,
  `L ${gx.toFixed(1)} ${(p2.y - dirY * r2).toFixed(1)}`,
  `Q ${gx.toFixed(1)} ${p2.y.toFixed(1)}, ${(gx + dirX2 * r2).toFixed(1)} ${p2.y.toFixed(1)}`,
  `L ${p2.x.toFixed(1)} ${p2.y.toFixed(1)}`,
 ].join(' ')
}

function getSegments(isCompact: boolean): Record<FlowDir, SegmentSpec[]> {
 if(isCompact) {
  return {
   in: [
    {from: 'internet', fromSide: 'bottom', to: 'routing', toSide: 'top', bow: 0},
    {from: 'routing', fromSide: 'bottom', to: 'worker', toSide: 'top', bow: 0},
    {from: 'worker', fromSide: 'bottom', to: 'vpc', toSide: 'top', bow: 0},
    {from: 'vpc', fromSide: 'left', to: 'tunnel', toSide: 'left', gutter: 'left'},
    {from: 'tunnel', fromSide: 'bottom', to: 'mailplus', toSide: 'top', bow: 0},
   ],
   out: [
    {from: 'mailplus', fromSide: 'bottom', to: 'relay', toSide: 'top', bow: 0},
    {from: 'relay', fromSide: 'right', to: 'sending', toSide: 'right', gutter: 'right'},
    {from: 'sending', fromSide: 'right', to: 'internet', toSide: 'right', gutter: 'right'},
   ],
  }
 }
 return {
  in: [
   {from: 'internet', fromSide: 'right', fromOffset: -14, to: 'routing', toSide: 'left', bow: -14},
   {from: 'routing', fromSide: 'bottom', to: 'worker', toSide: 'top', bow: 0},
   {from: 'worker', fromSide: 'bottom', to: 'vpc', toSide: 'top', bow: 0},
   {from: 'vpc', fromSide: 'right', to: 'tunnel', toSide: 'left', bow: 0},
   {from: 'tunnel', fromSide: 'top', to: 'mailplus', toSide: 'bottom', toOffset: -18, bow: -14},
  ],
  out: [
   {from: 'mailplus', fromSide: 'bottom', fromOffset: 22, to: 'relay', toSide: 'top', toOffset: 22, bow: 16},
   {from: 'relay', fromSide: 'left', to: 'sending', toSide: 'right', bow: 12},
   {from: 'sending', fromSide: 'left', to: 'internet', toSide: 'right', toOffset: 14, bow: 16},
  ],
 }
}

function pathLength(el: SVGPathElement, p1: Point, p2: Point): number {
 if(typeof el.getTotalLength === 'function') {
  try {return el.getTotalLength()} catch { /* jsdom fallback */ }
 }
 return Math.hypot(p2.x - p1.x, p2.y - p1.y)
}

function pointAt(seg: BuiltSegment, dist: number): Point {
 if(typeof seg.el.getPointAtLength === 'function') {
  try {
   const pt = seg.el.getPointAtLength(dist)
   return {x: pt.x, y: pt.y}
  } catch { /* jsdom fallback */ }
 }
 const t = seg.len > 0 ? Math.max(0, Math.min(1, dist / seg.len)) : 0
 return {x: seg.p1.x + (seg.p2.x - seg.p1.x) * t, y: seg.p1.y + (seg.p2.y - seg.p1.y) * t}
}

function sampleSegment(seg: BuiltSegment, t: number) {
 const clamped = Math.max(0, Math.min(1, t))
 const len = seg.len
 const dist = clamped * len
 const p = pointAt(seg, dist)
 const eps = Math.min(4, Math.max(0.5, len * 0.02))
 const pA = pointAt(seg, Math.max(0, dist - eps))
 const pB = pointAt(seg, Math.min(len, dist + eps))
 const angle = Math.atan2(pB.y - pA.y, pB.x - pA.x)

 const gDist = Math.max(0, dist - 22)
 const gp = pointAt(seg, gDist)
 const gpA = pointAt(seg, Math.max(0, gDist - eps))
 const gpB = pointAt(seg, Math.min(len, gDist + eps))
 const gAngle = Math.atan2(gpB.y - gpA.y, gpB.x - gpA.x)

 return {p, angle, gp, gAngle, showGhost: dist > 14, preferLeft: seg.p2.x < seg.p1.x}
}

function stylePaths(curDir: FlowDir, activeSegIdx = -1) {
 for(const dir of ['in', 'out'] as const) {
  const isCurrent = dir === curDir
  routes[dir].forEach((r, idx) => {
   r.el.classList.toggle('is-active', isCurrent && (activeSegIdx < 0 || idx <= activeSegIdx))
   r.el.classList.toggle('is-dim', !isCurrent)
  })
  dots[dir].forEach(dot => dot.classList.toggle('is-dim', !isCurrent))
 }
}

function flowDuration(dir: FlowDir): number {
 const segCount = routes[dir].length
 if(!segCount) return 1000
 return START_DWELL + segCount * FLY_MS + (segCount - 1) * STOP_DWELL + END_DWELL
}

function easeInOutSine(x: number): number {
 return -(Math.cos(Math.PI * x) - 1) / 2
}

function renderReducedStatic() {
 if(!mainActor || !rmOutActor || !ghostActor) return
 activeNodeId.value = null
 showPopTag(0, 0, '', 'in', 0)
 ghostActor.g.style.display = 'none'

 for(const dir of ['in', 'out'] as const) {
  const visible = mode.value === 'both' || mode.value === dir
  routes[dir].forEach(r => {
   r.el.classList.toggle('is-active', visible)
   r.el.classList.toggle('is-dim', !visible)
  })
  dots[dir].forEach(dot => dot.classList.toggle('is-dim', !visible))
 }

 const inSegs = routes.in
 if(inSegs.length && mode.value !== 'out') {
  let bestIdx = 0
  for(let i = 1; i < inSegs.length; i++) if(inSegs[i]!.len > inSegs[bestIdx]!.len) bestIdx = i
  if(bestIdx === 0) {
   let altIdx = -1
   for(let i = 1; i < inSegs.length; i++) {
    if(inSegs[i]!.len >= 80 && (altIdx < 0 || inSegs[i]!.len > inSegs[altIdx]!.len)) altIdx = i
   }
   if(altIdx >= 0) bestIdx = altIdx
  }
  const seg = inSegs[bestIdx]!
  const s = sampleSegment(seg, 0.5)
  mainActor.g.style.display = ''
  posePigeon(mainActor, s.p.x, s.p.y, s.angle, 0.25, 'in', FLOWS.in[bestIdx]!.badge, {
   scale: 0.94, flying: false, staticPose: true, preferLeft: s.preferLeft,
  })
 } else {
  mainActor.g.style.display = 'none'
 }

 const outSegs = routes.out
 if(outSegs.length && mode.value !== 'in') {
  let bestIdx = outSegs.length - 1
  if(outSegs[bestIdx]!.len < 80) {
   for(let i = 0; i < outSegs.length; i++) if(outSegs[i]!.len > outSegs[bestIdx]!.len) bestIdx = i
  }
  const seg = outSegs[bestIdx]!
  const s = sampleSegment(seg, 0.5)
  rmOutActor.g.style.display = ''
  posePigeon(rmOutActor, s.p.x, s.p.y, s.angle, 0.25, 'out', FLOWS.out[bestIdx]!.badge, {
   scale: 0.94, flying: false, staticPose: true, preferLeft: s.preferLeft,
  })
 } else {
  rmOutActor.g.style.display = 'none'
 }
}

function renderFrame(dt: number) {
 if(!mainActor || !ghostActor || !rmOutActor) return
 const dir = activeDir.value
 const segs = routes[dir]
 const stations = FLOWS[dir]
 if(!segs.length) return

 rmOutActor.g.style.display = 'none'
 mainActor.g.style.display = ''

 const total = flowDuration(dir)
 if(!paused.value && dt > 0) {
  elapsed += dt
  dashOffset -= dt * 0.022
  wingPhase += dt * 0.0175
 }
 if(elapsed >= total) {
  elapsed = 0
  if(mode.value === 'both') {
   activeDir.value = dir === 'in' ? 'out' : 'in'
   renderFrame(0)
   return
  }
 }

 segs.forEach(r => {r.el.style.strokeDashoffset = dashOffset.toFixed(1)})

 let t = elapsed
 if(t < START_DWELL) {
  const s0 = sampleSegment(segs[0]!, 0)
  const st = stations[0]!
  stylePaths(dir, 0)
  activeNodeId.value = st.id
  activeStepIdx.value = 0
  ghostActor.g.style.display = 'none'
  posePigeon(mainActor, s0.p.x, s0.p.y, s0.angle, wingPhase, dir, st.badge, {scale: 0.98, flying: false, preferLeft: s0.preferLeft})
  showPopTag(s0.p.x, s0.p.y, k.t(st.tagKey), dir, Math.min(1, t / 140))
  return
 }
 t -= START_DWELL

 for(let i = 0; i < segs.length; i++) {
  const seg = segs[i]!
  const isLast = i === segs.length - 1
  const dwell = isLast ? END_DWELL : STOP_DWELL

  if(t < FLY_MS) {
   const u = easeInOutSine(t / FLY_MS)
   const sample = sampleSegment(seg, u)
   const prev = stations[i]!
   stylePaths(dir, i)
   activeNodeId.value = u < 0.25 ? prev.id : null
   activeStepIdx.value = i
   posePigeon(mainActor, sample.p.x, sample.p.y, sample.angle, wingPhase, dir, prev.badge, {scale: 1.0, flying: true, preferLeft: sample.preferLeft})
   if(sample.showGhost) {
    ghostActor.g.style.display = ''
    posePigeon(ghostActor, sample.gp.x, sample.gp.y, sample.gAngle, wingPhase - 0.9, dir, 'raw', {scale: 0.88, flying: true, preferLeft: sample.preferLeft})
   } else {
    ghostActor.g.style.display = 'none'
   }
   const tagAlpha = u < 0.08 ? 1 - u / 0.08 : 0
   showPopTag(seg.p1.x, seg.p1.y, k.t(prev.tagKey), dir, tagAlpha)
   return
  }
  t -= FLY_MS

  if(t < dwell) {
   const sEnd = sampleSegment(seg, 1)
   const st = stations[i + 1]!
   stylePaths(dir, i)
   activeNodeId.value = st.id
   activeStepIdx.value = i + 1
   ghostActor.g.style.display = 'none'
   const popScale = t < 240 ? 1 + 0.08 * Math.sin((t / 240) * Math.PI) : 1.0
   posePigeon(mainActor, sEnd.p.x, sEnd.p.y, sEnd.angle, wingPhase, dir, st.badge, {scale: popScale, flying: false, preferLeft: sEnd.preferLeft})
   const fadeIn = Math.min(1, t / 140)
   const fadeOut = isLast && t > dwell - 220 ? Math.max(0, (dwell - t) / 220) : 1
   showPopTag(sEnd.p.x, sEnd.p.y, k.t(st.tagKey), dir, Math.min(fadeIn, fadeOut))
   return
  }
  t -= dwell
 }
}

function rebuildRoutes() {
 const stage = stageRef.value
 const svgUnder = svgUnderRef.value
 const svgOver = svgOverRef.value
 if(!open.value || !stage || !svgUnder || !svgOver) return
 initOverlay()

 const w = stage.clientWidth
 const h = stage.clientHeight
 if(!w || !h) return
 svgUnder.textContent = ''
 svgUnder.setAttribute('viewBox', `0 0 ${w} ${h}`)
 svgOver.setAttribute('viewBox', `0 0 ${w} ${h}`)

 const specs = getSegments(w < COMPACT_STAGE_WIDTH)
 routes = {in: [], out: []}
 dots = {in: [], out: []}

 for(const dir of ['in', 'out'] as const) {
  specs[dir].forEach((seg, idx) => {
   const p1 = getAnchor(seg.from, seg.fromSide, seg.fromOffset ?? 0)
   const p2 = getAnchor(seg.to, seg.toSide, seg.toOffset ?? 0)
   const d = seg.gutter ? gutterD(p1, p2, seg.gutter) : bezierD(p1, p2, seg.fromSide, seg.toSide, seg.bow ?? 0)
   const pathEl = svgEl('path', {
    d,
    class: `msa-cf-route ${dir}`,
    'data-dir': dir,
    'data-seg': idx,
   }, svgUnder)
   routes[dir].push({el: pathEl, len: pathLength(pathEl, p1, p2), from: seg.from, to: seg.to, p1, p2})
   const d1 = svgEl('circle', {cx: p1.x.toFixed(1), cy: p1.y.toFixed(1), r: '3.2', class: `msa-cf-dot ${dir}`}, svgUnder)
   const d2 = svgEl('circle', {cx: p2.x.toFixed(1), cy: p2.y.toFixed(1), r: '3.2', class: `msa-cf-dot ${dir}`}, svgUnder)
   dots[dir].push(d1, d2)
  })
 }

 if(reducedMotion.value) renderReducedStatic()
 else renderFrame(0)
}

function stopLoop() {
 if(rafId) {
  cancelAnimationFrame(rafId)
  rafId = 0
 }
 lastTs = 0
}

function tick(ts: number) {
 if(!open.value || paused.value || reducedMotion.value) {
  rafId = 0
  return
 }
 const dt = lastTs ? Math.min(50, ts - lastTs) : 16
 lastTs = ts
 renderFrame(dt)
 rafId = requestAnimationFrame(tick)
}

function startLoop() {
 if(!open.value) {
  stopLoop()
  return
 }
 if(reducedMotion.value) {
  stopLoop()
  renderReducedStatic()
  return
 }
 if(paused.value) {
  stopLoop()
  renderFrame(0)
  return
 }
 if(!rafId) {
  lastTs = 0
  rafId = requestAnimationFrame(tick)
 }
}

function setMode(next: FlowMode) {
 mode.value = next
 if(next !== 'both') activeDir.value = next
 else if(activeDir.value !== 'in' && activeDir.value !== 'out') activeDir.value = 'in'
 elapsed = 0
 activeStepIdx.value = 0
 if(reducedMotion.value) renderReducedStatic()
 else renderFrame(0)
}

function togglePause() {
 paused.value = !paused.value
 if(paused.value) stopLoop()
 else startLoop()
}

function replay() {
 paused.value = false
 elapsed = 0
 activeDir.value = mode.value === 'out' ? 'out' : 'in'
 activeStepIdx.value = 0
 if(reducedMotion.value) renderReducedStatic()
 else {
  renderFrame(0)
  startLoop()
 }
}

function jumpToStation(dir: FlowDir, idx: number) {
 activeDir.value = dir
 activeStepIdx.value = idx
 if(mode.value !== 'both' && mode.value !== dir) mode.value = dir
 if(reducedMotion.value) {
  activeNodeId.value = FLOWS[dir][idx]?.id ?? null
  stylePaths(dir, Math.max(0, idx - 1))
  return
 }
 elapsed = idx === 0 ? 120 : START_DWELL + idx * FLY_MS + (idx - 1) * STOP_DWELL + 180
 renderFrame(0)
}

function nodeClass(id: string) {
 if(activeNodeId.value !== id) return ''
 return activeDir.value === 'in' ? 'is-active-in' : 'is-active-out'
}

function attachObserver() {
 if(resizeObserver) {resizeObserver.disconnect(); resizeObserver = null}
 if(!stageRef.value || typeof ResizeObserver === 'undefined') return
 resizeObserver = new ResizeObserver(() => rebuildRoutes())
 resizeObserver.observe(stageRef.value)
}

function onReducedMotionChange(e: MediaQueryListEvent) {
 reducedMotion.value = e.matches
 if(open.value) {
  if(reducedMotion.value) {
   stopLoop()
   renderReducedStatic()
  } else {
   startLoop()
  }
 }
}

watch(open, async isOpen => {
 if(isOpen) {
  await nextTick()
  attachObserver()
  rebuildRoutes()
  startLoop()
 } else {
  stopLoop()
  if(resizeObserver) {resizeObserver.disconnect(); resizeObserver = null}
  clearOverlayRefs()
  activeNodeId.value = null
 }
})

onMounted(() => {
 if(typeof window.matchMedia === 'function') {
  rmQuery = window.matchMedia('(prefers-reduced-motion: reduce)')
  reducedMotion.value = rmQuery.matches
  rmQuery.addEventListener?.('change', onReducedMotionChange)
 }
})

onUnmounted(() => {
 stopLoop()
 if(resizeObserver) {resizeObserver.disconnect(); resizeObserver = null}
 rmQuery?.removeEventListener?.('change', onReducedMotionChange)
 clearOverlayRefs()
})
</script>

<template>
 <SettingsSection
  v-model:open="open"
  collapsible
  :title="k.t('ui.cfFlow.title')"
  data-section="cloudflare-flow"
 >
  <div
   class="msa-cf-flow"
   :data-playing="isPlaying ? 'true' : 'false'"
   :data-reduced="reducedMotion ? 'true' : 'false'"
   :data-mode="mode"
   :data-active-dir="activeDir"
  >
   <div class="msa-cf-toolbar">
    <div class="msa-cf-seg" role="tablist" :aria-label="k.t('ui.cfFlow.title')">
     <button
      type="button"
      role="tab"
      class="msa-cf-seg-btn"
      :class="{'is-active': mode === 'both'}"
      :aria-selected="mode === 'both'"
      data-flow-mode="both"
      @click="setMode('both')"
     >
      {{ k.t('ui.cfFlow.modeBoth') }}
     </button>
     <button
      type="button"
      role="tab"
      class="msa-cf-seg-btn"
      :class="{'is-active': mode === 'in'}"
      :aria-selected="mode === 'in'"
      data-flow-mode="in"
      @click="setMode('in')"
     >
      <span class="msa-cf-dot-in" aria-hidden="true" />
      {{ k.t('ui.cfFlow.modeIn') }}
     </button>
     <button
      type="button"
      role="tab"
      class="msa-cf-seg-btn"
      :class="{'is-active': mode === 'out'}"
      :aria-selected="mode === 'out'"
      data-flow-mode="out"
      @click="setMode('out')"
     >
      <span class="msa-cf-dot-out" aria-hidden="true" />
      {{ k.t('ui.cfFlow.modeOut') }}
     </button>
    </div>

    <div v-if="!reducedMotion" class="msa-cf-controls">
     <Button variant="secondary" size="sm" data-flow-pause @click="togglePause">
      <component :is="paused ? Play : Pause" class="msa-cf-btn-ico" aria-hidden="true" />
      {{ k.t(paused ? 'ui.cfFlow.play' : 'ui.cfFlow.pause') }}
     </Button>
     <Button variant="secondary" size="sm" data-flow-replay @click="replay">
      <RotateCcw class="msa-cf-btn-ico" aria-hidden="true" />
      {{ k.t('ui.cfFlow.replay') }}
     </Button>
    </div>
   </div>

   <div ref="stageRef" class="msa-cf-stage" role="img" :aria-label="k.t('ui.cfFlow.stageLabel')">
    <svg ref="svgUnderRef" class="msa-cf-svg msa-cf-svg-under" aria-hidden="true" />

    <div class="msa-cf-grid">
     <!-- Left zone: Internet -->
     <div class="msa-cf-col-internet">
      <div class="msa-cf-zone msa-cf-zone-internet">
       <div class="msa-cf-zone-title">
        <Globe class="msa-cf-zone-ico" aria-hidden="true" />
        <span>{{ k.t('ui.cfFlow.zoneInternet') }}</span>
       </div>
       <div class="msa-cf-node msa-cf-node-stack" :class="nodeClass('internet')" data-flow-node="internet">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <circle cx="18" cy="18" r="13" stroke="var(--ui-gray-7)" stroke-width="1.3" stroke-dasharray="3 3" opacity="0.55" />
         <circle cx="18" cy="18" r="9.5" fill="var(--ui-surface-subtle)" stroke="var(--ui-gray-11)" stroke-width="1.5" />
         <ellipse cx="18" cy="18" rx="4.4" ry="9.5" stroke="var(--ui-gray-10)" stroke-width="1.25" />
         <line x1="8.8" y1="15" x2="27.2" y2="15" stroke="var(--ui-gray-8)" stroke-width="1.15" />
         <line x1="8.8" y1="21" x2="27.2" y2="21" stroke="var(--ui-gray-8)" stroke-width="1.15" />
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.internet') }}</span>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.internetSub') }}</div>
         <span class="msa-cf-rm-badge">MX</span>
        </div>
       </div>
      </div>
     </div>

     <!-- Center zone: Cloudflare Hub -->
     <div class="msa-cf-zone msa-cf-zone-cf">
      <div class="msa-cf-zone-title">
       <Cloud class="msa-cf-zone-ico msa-cf-zone-ico-cf" aria-hidden="true" />
       <span>{{ k.t('ui.cfFlow.zoneCloudflare') }}</span>
      </div>

      <div class="msa-cf-branch msa-cf-branch-in">
       <div class="msa-cf-branch-label is-in">
        <span class="msa-cf-dot-in" aria-hidden="true" />
        <span>{{ k.t('ui.cfFlow.branchIn') }}</span>
       </div>

       <div class="msa-cf-node" :class="nodeClass('routing')" data-flow-node="routing">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <path d="M6 18h8" stroke="var(--ui-gray-10)" stroke-width="1.6" stroke-linecap="round" />
         <path d="M14 18c3 0 4.5-6 9-6h6" stroke="var(--ui-blue-9)" stroke-width="1.8" stroke-linecap="round" />
         <path d="M14 18c3 0 4.5 6 9 6h6" stroke="var(--ui-gray-6)" stroke-width="1.5" stroke-linecap="round" stroke-dasharray="2.5 2.5" />
         <path d="M26.5 9.5 29.5 12l-3 2.5" stroke="var(--ui-blue-9)" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" />
         <circle class="msa-g-split-dot" cx="14" cy="18" r="2.6" fill="var(--ui-blue-9)" />
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.routing') }}</span>
          <span class="msa-cf-tag is-native">
           <Cloud class="msa-cf-tag-ico" aria-hidden="true" />
           {{ k.t('ui.cfFlow.tag.native') }}
          </span>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.routingSub') }}</div>
         <span class="msa-cf-rm-badge">@</span>
        </div>
       </div>

       <div class="msa-cf-node" :class="nodeClass('worker')" data-flow-node="worker">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <rect x="7" y="7" width="22" height="22" rx="6" fill="var(--ui-accent-2)" stroke="var(--ui-accent-9)" stroke-width="1.45" />
         <path class="msa-g-scan" d="M11 13h14" stroke="var(--ui-accent-8)" stroke-width="1.5" stroke-linecap="round" />
         <path d="M12.5 19.5 16.5 23l7.5-8" stroke="var(--ui-green-9)" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.worker') }}</span>
          <span class="msa-cf-tag is-auto">
           <Sparkles class="msa-cf-tag-ico" aria-hidden="true" />
           {{ k.t('ui.cfFlow.tag.auto') }}
          </span>
          <Tooltip :content="k.t('ui.cfFlow.workerTip')" side="top">
           <button
            type="button"
            class="msa-cf-help-btn"
            :aria-label="k.t('ui.cfFlow.workerTipLabel')"
            data-worker-help
           >
            <CircleHelp class="msa-cf-help-ico" aria-hidden="true" />
           </button>
          </Tooltip>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.workerSub') }}</div>
         <span class="msa-cf-rm-badge">≤25M</span>
        </div>
       </div>

       <div class="msa-cf-node" :class="nodeClass('vpc')" data-flow-node="vpc">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <rect x="6" y="10" width="24" height="16" rx="8" fill="var(--ui-accent-2)" stroke="var(--ui-accent-9)" stroke-width="1.45" />
         <path class="msa-g-chev-1" d="M13 14.5 16.5 18 13 21.5" stroke="var(--ui-accent-9)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
         <path class="msa-g-chev-2" d="M19 14.5 22.5 18 19 21.5" stroke="var(--ui-accent-9)" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.vpc') }}</span>
          <span class="msa-cf-tag is-auto">
           <Sparkles class="msa-cf-tag-ico" aria-hidden="true" />
           {{ k.t('ui.cfFlow.tag.auto') }}
          </span>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.vpcSub') }}</div>
         <span class="msa-cf-rm-badge">TCP 25</span>
        </div>
       </div>
      </div>

      <div class="msa-cf-branch">
       <div class="msa-cf-branch-label is-out">
        <span class="msa-cf-dot-out" aria-hidden="true" />
        <span>{{ k.t('ui.cfFlow.branchOut') }}</span>
       </div>

       <div class="msa-cf-node" :class="nodeClass('sending')" data-flow-node="sending">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <path d="M7 22c3.5-1 6-2 8.5-3.2" stroke="var(--ui-orange-7)" stroke-width="1.6" stroke-linecap="round" stroke-dasharray="2.5 2.5" />
         <g class="msa-g-plane">
          <path d="M11 17.5 28 10 21.8 26.5 18 19.8 11 17.5Z" fill="var(--ui-orange-2)" stroke="var(--ui-orange-9)" stroke-width="1.5" stroke-linejoin="round" />
          <path d="M18 19.8 28 10" stroke="var(--ui-orange-9)" stroke-width="1.3" stroke-linecap="round" />
         </g>
         <circle cx="25.5" cy="24.5" r="3.6" fill="var(--ui-danger)" stroke="var(--ui-surface)" stroke-width="1.2" />
         <path d="M24.2 24.5l.9.9 1.7-1.8" stroke="var(--ui-surface)" stroke-width="1.15" stroke-linecap="round" stroke-linejoin="round" />
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.sending') }}</span>
          <span class="msa-cf-tag is-native">
           <Cloud class="msa-cf-tag-ico" aria-hidden="true" />
           {{ k.t('ui.cfFlow.tag.native') }}
          </span>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.sendingSub') }}</div>
         <span class="msa-cf-rm-badge">DKIM</span>
        </div>
       </div>
      </div>
     </div>

     <!-- Right zone: Your NAS (with Tunnel on the border) -->
     <div class="msa-cf-zone msa-cf-zone-nas">
      <div class="msa-cf-zone-title">
       <HardDrive class="msa-cf-zone-ico" aria-hidden="true" />
       <span>{{ k.t('ui.cfFlow.zoneNas') }}</span>
      </div>

      <div class="msa-cf-node msa-cf-tunnel-gate" :class="nodeClass('tunnel')" data-flow-node="tunnel">
       <svg class="msa-cf-glyph msa-cf-glyph-sm" viewBox="0 0 36 36" fill="none" aria-hidden="true">
        <ellipse cx="12" cy="18" rx="4" ry="8.5" stroke="var(--ui-info)" stroke-width="1.5" fill="var(--ui-info-soft)" fill-opacity="0.55" />
        <ellipse cx="18" cy="18" rx="4" ry="8.5" stroke="var(--ui-info)" stroke-width="1.5" fill="var(--ui-info-soft)" fill-opacity="0.4" />
        <ellipse cx="24" cy="18" rx="4" ry="8.5" stroke="var(--ui-info-text)" stroke-width="1.5" fill="var(--ui-info-soft)" fill-opacity="0.4" />
        <circle class="msa-g-pulse-dot" cx="10" cy="18" r="2.4" fill="var(--ui-info)" />
       </svg>
       <div class="msa-cf-node-meta">
        <div class="msa-cf-node-name-row">
         <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.tunnel') }}</span>
         <span class="msa-cf-tag is-connect">
          <Link2 class="msa-cf-tag-ico" aria-hidden="true" />
          {{ k.t('ui.cfFlow.tag.connect') }}
         </span>
        </div>
        <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.tunnelSub') }}</div>
        <span class="msa-cf-rm-badge">:25</span>
       </div>
      </div>

      <div class="msa-cf-nas-top">
       <div class="msa-cf-node" :class="nodeClass('mailplus')" data-flow-node="mailplus">
        <div class="msa-cf-mp-tile" aria-hidden="true">
         <span class="msa-cf-mp-halo" />
         <MailCheck class="msa-cf-mp-ico" />
        </div>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.mailplus') }}</span>
         </div>
         <div class="msa-cf-node-sub">{{ k.t('ui.cfFlow.node.mailplusSub') }}</div>
         <span class="msa-cf-rm-badge">250 OK</span>
        </div>
       </div>
      </div>

      <div class="msa-cf-nas-bottom">
       <div class="msa-cf-node" :class="nodeClass('relay')" data-flow-node="relay">
        <svg class="msa-cf-glyph" viewBox="0 0 36 36" fill="none" aria-hidden="true">
         <rect x="5.5" y="8" width="25" height="20" rx="5.5" fill="var(--ui-orange-2)" stroke="var(--ui-orange-9)" stroke-width="1.45" />
         <g class="msa-g-env-in">
          <rect x="8.5" y="13.5" width="9" height="6.5" rx="1.2" fill="var(--ui-surface)" stroke="var(--ui-orange-9)" stroke-width="1.2" />
          <path d="M9 14.2 13 17.2 17 14.2" stroke="var(--ui-orange-9)" stroke-width="1.1" stroke-linecap="round" />
         </g>
         <path d="M19 16.8h4.5m-1.8-2 2 2-2 2" stroke="var(--ui-orange-10)" stroke-width="1.4" stroke-linecap="round" stroke-linejoin="round" />
         <g class="msa-g-env-out">
          <rect x="19" y="19" width="8.5" height="6" rx="1.2" fill="var(--ui-surface)" stroke="var(--ui-orange-10)" stroke-width="1.2" />
          <path d="M19.5 19.6 23.2 22.2 27 19.6" stroke="var(--ui-orange-10)" stroke-width="1.05" stroke-linecap="round" />
         </g>
        </svg>
        <div class="msa-cf-node-meta">
         <div class="msa-cf-node-name-row">
          <span class="msa-cf-node-name">{{ k.t('ui.cfFlow.node.relay') }}</span>
         </div>
         <div class="msa-cf-node-sub msa-cf-mono">{{ k.t('ui.cfFlow.node.relaySub') }}</div>
         <span class="msa-cf-rm-badge">TLS :465</span>
        </div>
       </div>
      </div>
     </div>
    </div>

    <svg ref="svgOverRef" class="msa-cf-svg msa-cf-svg-over" aria-hidden="true" />
   </div>

   <!-- Split inbound / outbound clickable station chip groups -->
   <div class="msa-cf-steppers" :aria-label="k.t('ui.cfFlow.stepperLabel')">
    <div v-if="showInboundStepper" class="msa-cf-step-group" data-stepper-group="in">
     <span class="msa-cf-step-group-label is-in">
      <span class="msa-cf-dot-in" aria-hidden="true" />
      {{ k.t('ui.cfFlow.dirIn') }}
     </span>
     <div class="msa-cf-step-chips">
      <button
       v-for="(st, idx) in FLOWS.in"
       :key="`in-${st.id}`"
       type="button"
       class="msa-cf-step-chip is-in"
       :class="{'is-current': activeDir === 'in' && activeStepIdx === idx && !reducedMotion}"
       :data-step-dir="'in'"
       :data-step-node="st.id"
       @click="jumpToStation('in', idx)"
      >
       <span class="msa-cf-step-num">{{ idx + 1 }}</span>
       <span>{{ k.t(st.chipKey) }}</span>
       <span class="msa-cf-step-tag">{{ k.t(st.tagKey) }}</span>
      </button>
     </div>
    </div>

    <div v-if="showOutboundStepper" class="msa-cf-step-group" data-stepper-group="out">
     <span class="msa-cf-step-group-label is-out">
      <span class="msa-cf-dot-out" aria-hidden="true" />
      {{ k.t('ui.cfFlow.dirOut') }}
     </span>
     <div class="msa-cf-step-chips">
      <button
       v-for="(st, idx) in FLOWS.out"
       :key="`out-${st.id}`"
       type="button"
       class="msa-cf-step-chip is-out"
       :class="{'is-current': activeDir === 'out' && activeStepIdx === idx && !reducedMotion}"
       :data-step-dir="'out'"
       :data-step-node="st.id"
       @click="jumpToStation('out', idx)"
      >
       <span class="msa-cf-step-num">{{ idx + 1 }}</span>
       <span>{{ k.t(st.chipKey) }}</span>
       <span class="msa-cf-step-tag">{{ k.t(st.tagKey) }}</span>
      </button>
     </div>
    </div>
   </div>

   <div class="msa-cf-legend">
    <span class="msa-cf-legend-item">
     <span class="msa-cf-legend-line is-in" aria-hidden="true" />
     {{ k.t('ui.cfFlow.legendIn') }}
    </span>
    <span class="msa-cf-legend-item">
     <span class="msa-cf-legend-line is-out" aria-hidden="true" />
     {{ k.t('ui.cfFlow.legendOut') }}
    </span>
    <span class="msa-cf-legend-item">
     <span class="msa-cf-tag is-native">
      <Cloud class="msa-cf-tag-ico" aria-hidden="true" />
      {{ k.t('ui.cfFlow.tag.native') }}
     </span>
     {{ k.t('ui.cfFlow.legendNative') }}
    </span>
    <span class="msa-cf-legend-item">
     <span class="msa-cf-tag is-auto">
      <Sparkles class="msa-cf-tag-ico" aria-hidden="true" />
      {{ k.t('ui.cfFlow.tag.auto') }}
     </span>
     {{ k.t('ui.cfFlow.legendAuto') }}
    </span>
    <span class="msa-cf-legend-item">
     <span class="msa-cf-tag is-connect">
      <Link2 class="msa-cf-tag-ico" aria-hidden="true" />
      {{ k.t('ui.cfFlow.tag.connect') }}
     </span>
     {{ k.t('ui.cfFlow.legendConnect') }}
    </span>
   </div>
  </div>
 </SettingsSection>
</template>

<style scoped>
.msa-cf-flow {
 container-type: inline-size;
 display: flex;
 flex-direction: column;
 gap: var(--ui-space-3);
 color: var(--ui-text);
 font-family: var(--ui-font-sans);
}

.msa-cf-toolbar {
 display: flex;
 flex-wrap: wrap;
 align-items: center;
 justify-content: space-between;
 gap: var(--ui-space-2);
}

.msa-cf-seg {
 display: inline-flex;
 align-items: center;
 gap: 2px;
 padding: 3px;
 border-radius: var(--ui-radius-control);
 background: var(--ui-surface-inset);
 border: 1px solid var(--ui-border-subtle);
}

.msa-cf-seg-btn {
 display: inline-flex;
 align-items: center;
 gap: 5px;
 padding: 4px 10px;
 border: 0;
 border-radius: calc(var(--ui-radius-control) - 2px);
 background: transparent;
 color: var(--ui-text-secondary);
 font: inherit;
 font-size: var(--ui-font-size-sm);
 font-weight: var(--ui-font-weight-medium);
 cursor: pointer;
 transition: background var(--ui-motion-fast) var(--ui-ease-standard), color var(--ui-motion-fast) var(--ui-ease-standard);
}

.msa-cf-seg-btn:hover {
 color: var(--ui-text);
}

.msa-cf-seg-btn.is-active {
 background: var(--ui-surface);
 color: var(--ui-text);
 font-weight: var(--ui-font-weight-strong);
 box-shadow: var(--ui-shadow-control);
}

.msa-cf-controls {
 display: inline-flex;
 align-items: center;
 gap: var(--ui-space-2);
}

.msa-cf-btn-ico {
 width: 13px;
 height: 13px;
 flex: none;
}

.msa-cf-dot-in,
.msa-cf-dot-out {
 width: 7px;
 height: 7px;
 border-radius: var(--ui-radius-pill);
 flex: none;
 display: inline-block;
}

.msa-cf-dot-in { background: var(--ui-blue-9); }
.msa-cf-dot-out { background: var(--ui-orange-9); }

.msa-cf-stage {
 position: relative;
 padding: var(--ui-space-4) var(--ui-space-2) var(--ui-space-3);
 overflow: visible;
}

.msa-cf-svg {
 position: absolute;
 inset: 0;
 width: 100%;
 height: 100%;
 pointer-events: none;
 overflow: visible;
}

.msa-cf-svg-under { z-index: 2; }
.msa-cf-svg-over { z-index: 12; }

.msa-cf-stage :deep(.msa-cf-route) {
 fill: none;
 stroke-width: 2.15;
 stroke-dasharray: 6 5;
 stroke-linecap: round;
 transition: opacity 220ms ease, stroke-width 220ms ease;
}

.msa-cf-stage :deep(.msa-cf-route.in) { stroke: var(--ui-blue-9); opacity: 0.42; }
.msa-cf-stage :deep(.msa-cf-route.out) { stroke: var(--ui-orange-9); opacity: 0.42; }
.msa-cf-stage :deep(.msa-cf-route.is-active) { opacity: 0.94; stroke-width: 2.4; }
.msa-cf-stage :deep(.msa-cf-route.is-dim) { opacity: 0.18; }

.msa-cf-stage :deep(.msa-cf-dot) {
 transition: opacity 220ms ease;
}

.msa-cf-stage :deep(.msa-cf-dot.in) { fill: var(--ui-surface); stroke: var(--ui-blue-9); stroke-width: 2; }
.msa-cf-stage :deep(.msa-cf-dot.out) { fill: var(--ui-surface); stroke: var(--ui-orange-9); stroke-width: 2; }
.msa-cf-stage :deep(.msa-cf-dot.is-dim) { opacity: 0.25; }

.msa-cf-stage :deep(.msa-cf-pop-tag) {
 font-family: var(--ui-font-sans);
 font-weight: 600;
}

.msa-cf-grid {
 display: grid;
 grid-template-columns: minmax(98px, 114px) minmax(0, 1.48fr) minmax(0, 1.02fr);
 gap: 22px;
 align-items: center;
 position: relative;
}

.msa-cf-zone {
 position: relative;
 border-radius: var(--ui-radius-card);
 padding: 30px 10px 14px;
}

.msa-cf-zone-title {
 position: absolute;
 top: 9px;
 left: 12px;
 display: inline-flex;
 align-items: center;
 gap: 5px;
 font-size: var(--ui-font-size-xs);
 font-weight: var(--ui-font-weight-strong);
 line-height: 1.2;
}

.msa-cf-zone-ico {
 width: 14px;
 height: 14px;
 flex: none;
}

.msa-cf-zone-ico-cf {
 color: var(--ui-orange-9);
}

.msa-cf-zone-internet {
 background: var(--ui-surface-subtle);
 border: 1.5px dashed var(--ui-border-strong);
 padding: 28px 8px 12px;
}

.msa-cf-zone-internet .msa-cf-zone-title {
 color: var(--ui-text-secondary);
}

.msa-cf-zone-cf {
 background: var(--ui-orange-1);
 border: 1.5px solid var(--ui-orange-5);
 display: flex;
 flex-direction: column;
 gap: 16px;
}

.msa-cf-zone-cf .msa-cf-zone-title {
 color: var(--ui-orange-11);
}

.msa-cf-zone-nas {
 background: var(--ui-blue-1);
 border: 1.5px solid var(--ui-blue-5);
 padding: 34px 10px 14px 28px;
 display: flex;
 flex-direction: column;
 justify-content: space-between;
 gap: 84px;
 align-self: stretch;
}

.msa-cf-zone-nas .msa-cf-zone-title {
 color: var(--ui-blue-11);
}

.msa-cf-branch {
 background: color-mix(in srgb, var(--ui-surface) 78%, transparent);
 border: 1px solid var(--ui-orange-4);
 border-radius: var(--ui-radius-md);
 padding: 9px;
 display: flex;
 flex-direction: column;
 gap: 18px;
}

.msa-cf-branch-in {
 border-color: var(--ui-blue-4);
}

.msa-cf-branch-label {
 display: inline-flex;
 align-items: center;
 gap: 5px;
 font-size: 11px;
 font-weight: var(--ui-font-weight-strong);
}

.msa-cf-branch-label.is-in { color: var(--ui-blue-11); }
.msa-cf-branch-label.is-out { color: var(--ui-orange-11); }

.msa-cf-node {
 position: relative;
 z-index: 5;
 background: var(--ui-surface);
 border: 1.25px solid var(--ui-border);
 border-radius: var(--ui-radius-md);
 padding: 8px 9px;
 display: flex;
 align-items: center;
 gap: 8px;
 box-shadow: var(--ui-shadow-card);
 transition: border-color 200ms ease, box-shadow 200ms ease, transform 200ms ease;
 min-width: 0;
}

.msa-cf-node-stack {
 flex-direction: column;
 text-align: center;
 padding: 12px 8px;
 gap: 6px;
}

.msa-cf-node-stack .msa-cf-node-name-row {
 justify-content: center;
}

.msa-cf-node.is-active-in {
 border-color: var(--ui-blue-9);
 box-shadow: 0 0 0 3px var(--ui-blue-a3), var(--ui-shadow-card-hover);
 transform: translateY(-1px);
}

.msa-cf-node.is-active-out {
 border-color: var(--ui-orange-9);
 box-shadow: 0 0 0 3px var(--ui-orange-a3), var(--ui-shadow-card-hover);
 transform: translateY(-1px);
}

.msa-cf-tunnel-gate {
 position: absolute;
 left: -22px;
 top: 52%;
 transform: translateY(-50%);
 z-index: 8;
 width: 146px;
 padding: 7px 9px;
 border-color: var(--ui-info);
 background: var(--ui-surface);
 box-shadow: var(--ui-shadow-card-hover);
}

.msa-cf-tunnel-gate.is-active-in {
 transform: translateY(-50%) scale(1.01);
}

.msa-cf-glyph {
 width: 32px;
 height: 32px;
 flex: none;
}

.msa-cf-glyph-sm {
 width: 26px;
 height: 26px;
}

.msa-cf-mp-tile {
 position: relative;
 width: 34px;
 height: 34px;
 flex: none;
 border-radius: var(--ui-radius-sm);
 background: var(--ui-primary-soft);
 border: 1px solid var(--ui-blue-4);
 color: var(--ui-primary);
 display: grid;
 place-items: center;
}

.msa-cf-mp-ico {
 width: 20px;
 height: 20px;
 position: relative;
 z-index: 2;
}

.msa-cf-mp-halo {
 position: absolute;
 inset: -4px;
 border-radius: var(--ui-radius-md);
 opacity: 0;
 z-index: 1;
 pointer-events: none;
}

.msa-cf-node.is-active-in .msa-cf-mp-halo {
 opacity: 1;
 background: radial-gradient(circle, var(--ui-blue-a4) 0%, transparent 72%);
 animation: msaCfHalo 900ms ease-out infinite;
}

.msa-cf-node.is-active-out .msa-cf-mp-halo {
 opacity: 1;
 background: radial-gradient(circle, var(--ui-orange-a4) 0%, transparent 72%);
 animation: msaCfHalo 900ms ease-out infinite;
}

.msa-cf-node-meta {
 display: flex;
 flex-direction: column;
 gap: 2px;
 min-width: 0;
}

.msa-cf-node-name-row {
 display: flex;
 align-items: center;
 gap: 4px;
 flex-wrap: wrap;
}

.msa-cf-node-name {
 font-size: var(--ui-font-size-sm);
 font-weight: var(--ui-font-weight-strong);
 color: var(--ui-text);
 line-height: 1.25;
}

.msa-cf-node-sub {
 font-size: 11px;
 color: var(--ui-text-secondary);
 line-height: 1.3;
 overflow-wrap: anywhere;
}

.msa-cf-mono {
 font-family: var(--ui-font-mono);
 font-size: 10.5px;
}

.msa-cf-tag {
 display: inline-flex;
 align-items: center;
 gap: 3px;
 padding: 1px 6px;
 border-radius: var(--ui-radius-pill);
 font-size: 10px;
 font-weight: var(--ui-font-weight-strong);
 line-height: 1.35;
 white-space: nowrap;
}

.msa-cf-tag-ico {
 width: 10px;
 height: 10px;
 flex: none;
}

.msa-cf-tag.is-native {
 background: var(--ui-orange-2);
 color: var(--ui-orange-11);
 border: 1px solid var(--ui-orange-5);
}

.msa-cf-tag.is-auto {
 background: var(--ui-accent-2);
 color: var(--ui-accent-11);
 border: 1px solid var(--ui-accent-5);
}

.msa-cf-tag.is-connect {
 background: var(--ui-info-soft);
 color: var(--ui-info-text);
 border: 1px solid var(--ui-blue-5);
}

.msa-cf-help-btn {
 width: 18px;
 height: 18px;
 padding: 0;
 border: 0;
 border-radius: var(--ui-radius-pill);
 background: transparent;
 color: var(--ui-accent-10);
 cursor: pointer;
 display: inline-grid;
 place-items: center;
 flex: none;
}

.msa-cf-help-btn:hover,
.msa-cf-help-btn:focus-visible {
 background: var(--ui-accent-3);
 color: var(--ui-accent-11);
 outline: none;
}

.msa-cf-help-ico {
 width: 14px;
 height: 14px;
}

.msa-cf-rm-badge {
 display: none;
 font-size: 10px;
 font-weight: var(--ui-font-weight-strong);
 padding: 1px 6px;
 border-radius: var(--ui-radius-sm);
 background: var(--ui-surface-inset);
 color: var(--ui-text-secondary);
 border: 1px solid var(--ui-border);
 align-self: flex-start;
 white-space: nowrap;
}

.msa-cf-node-stack .msa-cf-rm-badge {
 align-self: center;
}

.msa-cf-flow[data-reduced="true"] .msa-cf-rm-badge {
 display: inline-flex;
}

.msa-cf-flow[data-reduced="true"] * {
 animation: none !important;
 transition: none !important;
}

/* Split inbound & outbound station chip groups */
.msa-cf-steppers {
 display: flex;
 flex-direction: column;
 gap: var(--ui-space-2);
 padding: var(--ui-space-2) var(--ui-space-3);
 background: var(--ui-surface-subtle);
 border: 1px solid var(--ui-border-subtle);
 border-radius: var(--ui-radius-md);
}

.msa-cf-step-group {
 display: flex;
 flex-wrap: wrap;
 align-items: center;
 gap: var(--ui-space-2);
}

.msa-cf-step-group + .msa-cf-step-group {
 padding-block-start: var(--ui-space-2);
 border-block-start: 1px solid var(--ui-border-subtle);
}

.msa-cf-step-group-label {
 display: inline-flex;
 align-items: center;
 gap: 5px;
 min-width: 56px;
 font-size: 11px;
 font-weight: var(--ui-font-weight-strong);
 white-space: nowrap;
}

.msa-cf-step-group-label.is-in { color: var(--ui-blue-11); }
.msa-cf-step-group-label.is-out { color: var(--ui-orange-11); }

.msa-cf-step-chips {
 display: flex;
 flex-wrap: wrap;
 align-items: center;
 gap: 6px;
 flex: 1;
 min-width: 0;
}

.msa-cf-step-chip {
 border: 1px solid var(--ui-border);
 background: var(--ui-surface);
 color: var(--ui-text-secondary);
 font: inherit;
 font-size: 11px;
 padding: 4px 8px;
 border-radius: var(--ui-radius-control);
 cursor: pointer;
 display: inline-flex;
 align-items: center;
 gap: 5px;
 transition: border-color 140ms ease, background 140ms ease, color 140ms ease;
}

.msa-cf-step-chip:hover {
 border-color: var(--ui-border-strong);
 color: var(--ui-text);
}

.msa-cf-step-num {
 width: 15px;
 height: 15px;
 border-radius: var(--ui-radius-pill);
 font-size: 10px;
 font-weight: var(--ui-font-weight-strong);
 display: inline-grid;
 place-items: center;
 background: var(--ui-surface-inset);
 color: var(--ui-text-secondary);
 flex: none;
}

.msa-cf-step-tag {
 font-size: 10.5px;
 color: var(--ui-text-muted);
}

.msa-cf-step-chip.is-in.is-current {
 border-color: var(--ui-blue-9);
 background: var(--ui-blue-2);
 color: var(--ui-blue-11);
 font-weight: var(--ui-font-weight-strong);
}

.msa-cf-step-chip.is-in.is-current .msa-cf-step-num {
 background: var(--ui-blue-9);
 color: var(--ui-surface);
}

.msa-cf-step-chip.is-in.is-current .msa-cf-step-tag {
 color: var(--ui-blue-10);
}

.msa-cf-step-chip.is-out.is-current {
 border-color: var(--ui-orange-9);
 background: var(--ui-orange-2);
 color: var(--ui-orange-11);
 font-weight: var(--ui-font-weight-strong);
}

.msa-cf-step-chip.is-out.is-current .msa-cf-step-num {
 background: var(--ui-orange-9);
 color: var(--ui-surface);
}

.msa-cf-step-chip.is-out.is-current .msa-cf-step-tag {
 color: var(--ui-orange-10);
}

.msa-cf-legend {
 display: flex;
 flex-wrap: wrap;
 align-items: center;
 gap: var(--ui-space-2) var(--ui-space-4);
 padding-block-start: var(--ui-space-2);
 border-block-start: 1px solid var(--ui-border-subtle);
 font-size: 11.5px;
 color: var(--ui-text-secondary);
}

.msa-cf-legend-item {
 display: inline-flex;
 align-items: center;
 gap: 5px;
}

.msa-cf-legend-line {
 width: 18px;
 height: 0;
 border-top: 2px dashed;
 display: inline-block;
}

.msa-cf-legend-line.is-in { border-color: var(--ui-blue-9); }
.msa-cf-legend-line.is-out { border-color: var(--ui-orange-9); }

/* Node internal micro-animations while actively playing */
@keyframes msaCfHalo {
 0% { transform: scale(0.92); opacity: 0.85; }
 70% { transform: scale(1.18); opacity: 0.2; }
 100% { transform: scale(1.22); opacity: 0; }
}
@keyframes msaCfPulse {
 0%, 100% { transform: scale(1); }
 50% { transform: scale(1.32); }
}
@keyframes msaCfScan {
 0%, 100% { transform: translateY(0); opacity: 0.45; }
 50% { transform: translateY(9px); opacity: 1; }
}
@keyframes msaCfChev {
 0%, 100% { transform: translateX(-1.5px); opacity: 0.45; }
 50% { transform: translateX(2.5px); opacity: 1; }
}
@keyframes msaCfTunnel {
 0% { transform: translateX(0); opacity: 0; }
 20%, 80% { opacity: 1; }
 100% { transform: translateX(16px); opacity: 0; }
}
@keyframes msaCfRelayIn {
 0%, 100% { transform: translateX(0); opacity: 1; }
 50% { transform: translateX(3px); opacity: 0.65; }
}
@keyframes msaCfRelayOut {
 0%, 100% { transform: translateX(0); opacity: 0.7; }
 50% { transform: translateX(3px); opacity: 1; }
}
@keyframes msaCfPlane {
 0%, 100% { transform: translate(0, 0); }
 50% { transform: translate(2.5px, -2px); }
}

.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-in .msa-g-split-dot {
 transform-box: fill-box;
 transform-origin: center;
 animation: msaCfPulse 600ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-in .msa-g-scan {
 animation: msaCfScan 750ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-in .msa-g-chev-1 {
 animation: msaCfChev 650ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-in .msa-g-chev-2 {
 animation: msaCfChev 650ms 160ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-in .msa-g-pulse-dot {
 animation: msaCfTunnel 850ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-out .msa-g-env-in {
 animation: msaCfRelayIn 750ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-out .msa-g-env-out {
 animation: msaCfRelayOut 750ms ease-in-out infinite;
}
.msa-cf-flow[data-playing="true"] .msa-cf-node.is-active-out .msa-g-plane {
 animation: msaCfPlane 700ms ease-in-out infinite;
}

/* Compact / mobile container layout (390px viewport and narrow windows) */
@container (max-width: 579px) {
 .msa-cf-stage {
  padding: var(--ui-space-3) 30px var(--ui-space-2);
 }
 .msa-cf-grid {
  grid-template-columns: 1fr;
  gap: 24px;
 }
 .msa-cf-node-stack {
  flex-direction: row;
  text-align: left;
  padding: 9px 10px;
  gap: 9px;
 }
 .msa-cf-node-stack .msa-cf-node-name-row {
  justify-content: flex-start;
 }
 .msa-cf-node-stack .msa-cf-rm-badge {
  align-self: flex-start;
 }
 .msa-cf-zone-cf {
  padding: 32px 10px 12px;
 }
 .msa-cf-branch {
  padding: 9px 8px 10px;
 }
 .msa-cf-zone-nas {
  padding: 46px 10px 12px;
  gap: 18px;
 }
 .msa-cf-zone-nas > .msa-cf-zone-title {
  position: static;
 }
 .msa-cf-tunnel-gate {
  left: 50%;
  top: -22px;
  transform: translateX(-50%);
  width: auto;
  min-width: 186px;
 }
 .msa-cf-tunnel-gate.is-active-in {
  transform: translateX(-50%) scale(1.01);
 }
 .msa-cf-step-group {
  flex-direction: column;
  align-items: flex-start;
 }
}

@media (prefers-reduced-motion: reduce) {
 .msa-cf-flow * {
  animation: none !important;
  transition: none !important;
 }
}
</style>
