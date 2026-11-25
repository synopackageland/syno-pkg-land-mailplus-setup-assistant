<script setup lang="ts">
/**
 * The Overview's Cloudflare section: each kept setup on Cloudflare,
 * how it receives (the whole domain, or the listed mailboxes), for the listed
 * mailboxes the "Sync mailboxes" button, and for every setup "Remove
 * Cloudflare setup". Only the administrator's press starts a
 * sync or a removal: opening the Overview reads the package's own records
 * (no MailPlus or Cloudflare call), nothing polls, nothing is scheduled
 * (the page only hides a fresh sync result after a few seconds).
 * While a pressed sync or removal still runs in the worker, its reply is
 * asked for again. A missing or refused Cloudflare token asks for a token
 * here, with the same create-token link as the setup; the token is sent once
 * and never shown. There is no "Forget
 * token" here: removal and rollback forget the token, and forgetting it alone
 * would only stop sending and sync. One row per domain, the
 * actions on its right (Sync mailboxes; a quiet "Remove…", whose dialog
 * carries the danger); a line under the row only when something needs
 * attention. The uninstall note is in the section description and the
 * remove dialog. A token Cloudflare refused (deleted or rolled in its
 * dashboard) is one line with "Enter a new token", which opens the
 * guided entry (TokenDialog); the new token replaces the old one everywhere.
 * A removal that had to leave receiving records Cloudflare locks (a
 * subdomain's MX) says so in its result, lists them and links to
 * Cloudflare's Email Routing page, with a warning that turning routing off
 * there may stop receiving for the whole domain. Every finished removal tells
 * the Overview, which reads the relay's state again (removal may turn it off).
 * A removal stopped because MailPlus Server access was not allowed offers
 * "Allow access" beside Try again.
 */
import {computed, onUnmounted, ref} from 'vue'
import {Button, Callout, Checkbox, Dialog, Form, FormItem, Input, Progress, SettingsSection, Space, Tooltip} from '@synopackageland/ui'
import {errorCode, pause, useAssistant} from '../api/assistant'
import {cloudflareTokenUrl, emailRoutingUrl, openCloudflare} from '../api/cloudflare'
import {isProfile, profileName} from '../api/authority'
import type {AssistantError, AuthorityProfileName, KeptView, LockedRecord, RemoveRun} from '../api/types'
import TokenDialog from './TokenDialog.vue'

const k = useAssistant()
const emit = defineEmits<{removed: []}>()
const setups = ref<KeptView[]>()
const error = ref<unknown>()
/** Per setup: a call in flight, its error, and what a token is asked for (sync or remove). */
const busy = ref<Record<string, boolean>>({})
const errors = ref<Record<string, unknown>>({})
const asking = ref<Record<string, 'sync' | 'remove' | undefined>>({})
const tokens = ref<Record<string, string>>({})
/** Setups removed while the page is open (their records are gone): the kept setup's id and domain, and what Cloudflare locked. */
interface Removed {id: string; domain: string; locked?: LockedRecord[]; accountId?: string; zone?: string; keptDomain?: string}
const removed = ref<Removed[]>([])
/** The confirm dialog: the setup it is for, and the routing option (unticked). */
const confirming = ref<KeptView>()
const routingOff = ref(false)
/** The routing choice of the last removal of each setup (Try again keeps it). */
const routingChoice = ref<Record<string, boolean>>({})
const tokenUrl = cloudflareTokenUrl()
/** The setup whose refused token is being replaced, and the domains replaced while the page is open. */
const replacing = ref<KeptView>()
const replaced = ref<string[]>([])
let alive = true
onUnmounted(() => {alive = false})

const shown = computed(() => setups.value ?? [])

async function read() {
 error.value = undefined
 try {
  const list = (await k.call('mail.inbound.status')).setups
  setups.value = list
  // A domain set up again (a new kept setup, another id) is no longer "removed".
  const again = (r: {id: string; domain: string}) => list.some(s => s.id !== r.id && s.domain.toLowerCase() === r.domain.toLowerCase())
  if(removed.value.some(again)) removed.value = removed.value.filter(r => !again(r))
 }
 catch(e) {error.value = e}
}
/** The Overview reads it with its own reads (on opening, and after a wizard). */
defineExpose({read})

function update(v: KeptView) {
 setups.value = (setups.value ?? []).map(s => s.id === v.id ? v : s)
}
const tokenCause = 'mail.inbound.cause.token'
function wantsToken(e: unknown) {
 const reason = (e as Partial<AssistantError> | undefined)?.details?.reason
 return errorCode(e) === 'permission_refused' || reason === 'mail.inbound.tokenRequired'
}
function set<T>(r: {value: Record<string, T>}, id: string, v: T) {r.value = {...r.value, [id]: v}}

/** One sync run: started by the press; while it runs, its reply is asked for again (no new run). */
async function sync(s: KeptView) {
 set(busy, s.id, true)
 set(errors, s.id, undefined)
 try {
  let v = await k.call('mail.inbound.sync', {id: s.id})
  update(v)
  while(alive && v.last?.state === 'running') {
   await pause(2000)
   v = await k.call('mail.inbound.sync', {id: s.id, poll: true})
   update(v)
  }
  if(v.last?.causeKey === tokenCause) set(asking, s.id, 'sync')
  if(v.last?.state === 'done') {
   set(justSynced, s.id, true)
   setTimeout(() => {if(alive) set(justSynced, s.id, false)}, SHOW_RESULT_MS)
  }
 } catch(e) {
  if(wantsToken(e)) set(asking, s.id, 'sync')
  else set(errors, s.id, e)
 } finally {set(busy, s.id, false)}
}

function askRemove(s: KeptView) {
 routingOff.value = false
 confirming.value = s
}
async function confirmRemove() {
 const s = confirming.value
 if(!s) return
 confirming.value = undefined
 await remove(s, !!s.routingOwned && routingOff.value)
}
/** One removal: started by the confirmed press; its reply is asked for again while it runs. */
async function remove(s: KeptView, routing: boolean) {
 set(routingChoice, s.id, routing)
 set(busy, s.id, true)
 set(errors, s.id, undefined)
 try {
  let v = await k.call('mail.cloudflare.remove', routing ? {id: s.id, routing: true} : {id: s.id})
  update(v)
  while(alive && v.removal?.state === 'running') {
   await pause(2000)
   v = await k.call('mail.cloudflare.remove', {id: s.id, poll: true})
   update(v)
  }
  if(v.removal?.state === 'done') {
   const r = v.removal
   removed.value = [...removed.value, {id: s.id, domain: s.domain, locked: r.locked?.length ? r.locked : undefined, accountId: r.accountId, zone: r.zone, keptDomain: r.keptDomain}]
   setups.value = (setups.value ?? []).filter(x => x.id !== s.id)
   void read()
  } else if(v.removal?.causeKey === tokenCause) set(asking, s.id, 'remove')
  if(v.removal?.state !== 'running') emit('removed')
 } catch(e) {
  if(wantsToken(e)) set(asking, s.id, 'remove')
  else set(errors, s.id, e)
 } finally {set(busy, s.id, false)}
}
/**
 * A removal step the executor refused for want of a grant (a MailPlus Server
 * restore needs MailPlus change access, which may never have been allowed or
 * which DSM no longer honours): the line names the access and offers
 * "Allow access", as the setup does; Try again then goes on where it stopped.
 */
const accessCause = 'mail.remove.cause.authority'
function accessFor(r: RemoveRun): AuthorityProfileName[] | undefined {
 return r.causeKey === accessCause && isProfile(r.profile) ? [r.profile] : undefined
}
function removeFailed(r: RemoveRun): string {
 const access = accessFor(r)
 if(access) return k.t('ui.remove.access', {profile: k.t(profileName(access[0]!))})
 return k.t('ui.remove.failed', {cause: k.t(r.causeKey ?? 'mail.inbound.cause.cloudflare')})
}
const lockedLine = (l: LockedRecord) => `${l.type} ${l.name} ${l.content}`

/** Seals a pasted token (checked by the worker first); for a sync it then syncs once. The field is emptied at once. */
async function saveToken(s: KeptView) {
 const pasted = (tokens.value[s.id] ?? '').trim()
 const forWhat = asking.value[s.id]
 set(tokens, s.id, '')
 if(!pasted) return
 set(busy, s.id, true)
 set(errors, s.id, undefined)
 try {
  update(await k.call('mail.inbound.token', {id: s.id, token: pasted}))
  set(asking, s.id, undefined)
 } catch(e) {
  set(errors, s.id, e)
  return
 } finally {set(busy, s.id, false)}
 if(forWhat !== 'remove' && s.receive === 'addresses') await sync(s)
}

/** A new token replaced the refused one: read the setups again (the state is cleared). */
async function tokenReplaced(s: KeptView) {
 replaced.value = [...replaced.value.filter(d => d !== s.domain), s.domain]
 set(asking, s.id, undefined)
 await read()
}

function mode(s: KeptView): string {
 if(s.receive === 'domain') return k.t('ui.inbound.mode.domain')
 if(s.receive === 'addresses') return k.t('ui.inbound.mode.addresses')
 return k.t('ui.inbound.mode.send')
}
/** The last sync's result, shown in the row for a while after a press (then its time only). */
const justSynced = ref<Record<string, boolean>>({})
const SHOW_RESULT_MS = 10_000
function resultText(s: KeptView): string {
 const r = s.last
 if(!r || r.state !== 'done') return ''
 if(!r.added && !r.removed) return k.t('ui.inbound.inLine')
 return k.t('ui.inbound.result', {added: r.added, removed: r.removed})
}
function syncTime(at: number | undefined): string {
 if(!at) return ''
 const d = new Date(at * 1000)
 const today = new Date().toDateString() === d.toDateString()
 try {return new Intl.DateTimeFormat(k.locale, today ? {hour: '2-digit', minute: '2-digit', hourCycle: 'h23'} : {month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'}).format(d)}
 catch {return d.toLocaleString()}
}
/** Shown in the row's muted text for listed mailboxes: the fresh result just after a press, otherwise the last sync's time. A refused token hides both (sync is paused). */
function freshResult(s: KeptView): string {
 return s.receive === 'addresses' && !s.tokenInvalid && justSynced.value[s.id] ? resultText(s) : ''
}
/** Listed mailboxes: how many the last completed sync (or the setup) left receiving, and what that sync added or removed. From the record only. */
function syncedCount(s: KeptView): string {
 if(s.receive !== 'addresses' || !s.synced) return ''
 const count = k.t('ui.inbound.autoSynced', {count: s.synced.mailboxes})
 // Just after a press the fresh result already says what changed.
 if(freshResult(s)) return count
 const parts = [
  ...(s.synced.added ? [k.t('ui.inbound.change.added', {count: s.synced.added})] : []),
  ...(s.synced.removed ? [k.t('ui.inbound.change.removed', {count: s.synced.removed})] : []),
 ]
 return parts.length ? k.t('ui.inbound.autoSyncedChanges', {count: s.synced.mailboxes, list: parts.join(k.t('ui.inbound.change.sep'))}) : count
}
function lastSync(s: KeptView): string {
 if(s.receive !== 'addresses' || s.tokenInvalid) return ''
 // The latest of: a manual sync, the stored sync, an automatic check that found it in line.
 const at = Math.max(s.last?.state === 'done' ? s.last.at ?? 0 : 0, s.synced?.at ?? 0, s.auto?.state === 'ok' ? s.auto.checkedAt ?? 0 : 0)
 const time = syncTime(at)
 return time ? k.t('ui.inbound.lastSync', {time}) : ''
}
/** The automatic sync's notice (warning tone), or '' when it needs nothing. A refused token has its own notice. */
function autoNotice(s: KeptView): string {
 const a = s.auto
 if(s.receive !== 'addresses' || !a || busy.value[s.id] || s.last?.state === 'running') return ''
 const cause = a.causeKey ? k.t(a.causeKey) : ''
 if(a.state === 'stopped') return k.t('ui.inbound.autoStopped', {cause})
 if(a.held) return a.causeKey === 'mail.inbound.auto.cause.empty' ? k.t('ui.inbound.heldEmpty', {cause, count: a.held}) : k.t('ui.inbound.held', {count: a.held})
 if(a.state === 'failing' && a.unsynced && !s.tokenInvalid) return k.t('ui.inbound.unsynced', {count: a.unsynced, cause})
 return ''
}
const removing = (s: KeptView) => s.removal?.state === 'running'
function tokenAsked(s: KeptView) {return !s.tokenInvalid && (!!asking.value[s.id] || !s.token)}
</script>

<template>
 <SettingsSection v-if="shown.length || removed.length || error" :title="k.t('ui.inbound.title')" :description="k.t('ui.inbound.body')" :collapsible="false" data-section="inbound">
  <Callout v-if="error" tone="danger" :dismissible="false"><span role="alert">{{ k.error(error) }}</span></Callout>
  <template v-for="r in removed" :key="r.id">
   <Callout tone="success" :dismissible="false" data-remove-result>
    <span role="status">{{ k.t('ui.remove.done', {domain: r.domain}) }}</span>
   </Callout>
   <Callout v-if="r.keptDomain" tone="info" :dismissible="false" data-remove-kept-domain>
    {{ k.t('ui.remove.keptDomain', {domain: r.keptDomain}) }}
   </Callout>
   <Callout v-if="r.locked" tone="warning" :dismissible="false" :title="k.t('ui.remove.locked.title')" data-remove-locked>
    <div class="msa-locked">
     <div>{{ k.t('ui.remove.locked.body', {domain: r.domain}) }}</div>
     <div class="msa-locked-records" role="list" data-locked-records>
      <div v-for="l in r.locked" :key="lockedLine(l)" role="listitem">{{ lockedLine(l) }}</div>
     </div>
     <div>{{ r.zone ? k.t('ui.remove.locked.where', {zone: r.zone}) : k.t('ui.remove.locked.whereAny') }}</div>
     <div class="msa-quiet" data-locked-warning>{{ k.t('ui.remove.locked.warning') }}</div>
    </div>
    <template #actions>
     <Button variant="secondary" data-open-routing @click="openCloudflare(emailRoutingUrl(r.accountId))">{{ k.t('ui.remove.locked.open') }}</Button>
    </template>
   </Callout>
  </template>
  <div v-for="s in shown" :key="s.id" class="msa-kept" :data-inbound="s.id">
   <!-- One row: the domain, how it receives, how many mailboxes it syncs and when (muted), the actions on the right. -->
   <div class="msa-kept-row">
    <div class="msa-kept-main">
     <span class="msa-kept-domain">{{ s.domain }}</span>
     <span class="msa-quiet msa-small">
      <span data-mode>{{ mode(s) }}</span>
      <template v-if="syncedCount(s)"> · <span data-synced>{{ syncedCount(s) }}</span></template>
      <template v-if="freshResult(s)"> · <span role="status" data-sync-result>{{ freshResult(s) }}</span></template>
      <template v-else-if="lastSync(s)"> · <span data-last-sync>{{ lastSync(s) }}</span></template>
     </span>
    </div>
    <div class="msa-kept-actions">
     <Tooltip v-if="s.receive === 'addresses'" :content="k.t('ui.inbound.hint')">
      <Button variant="secondary" :disabled="busy[s.id] || s.tokenInvalid || s.last?.state === 'running' || removing(s)" :aria-description="k.t('ui.inbound.hint')"
       data-sync @click="sync(s)">{{ k.t('ui.inbound.sync') }}</Button>
     </Tooltip>
     <Button variant="ghost" kind="tool" :disabled="busy[s.id] || removing(s) || s.last?.state === 'running'" :aria-label="k.t('ui.remove.action')"
      data-remove @click="askRemove(s)">{{ k.t('ui.remove.short') }}</Button>
    </div>
   </div>
   <!-- Under the row only what needs attention, or what runs now. -->
   <Progress v-if="s.receive === 'addresses' && ((busy[s.id] && !s.removal) || s.last?.state === 'running')" indeterminate :label="k.t('ui.inbound.syncing')" />
   <Progress v-if="removing(s)" :value="s.removal!.done" :max="s.removal!.total" :label="k.t('ui.remove.running', {done: s.removal!.done, total: s.removal!.total})" data-remove-progress />
   <Callout v-if="s.tokenInvalid" tone="danger" :dismissible="false" data-token-invalid>
    <span role="alert">{{ k.t(s.relay ? 'ui.token.invalid' : 'ui.token.invalidNoRelay') }}</span>
    <div v-if="s.relay" class="msa-quiet" data-token-queued>{{ k.t('ui.token.queued') }}</div>
    <template #actions><Button variant="primary" data-reenter-token @click="replacing = s">{{ k.t('ui.token.reenter') }}</Button></template>
   </Callout>
   <Callout v-else-if="replaced.includes(s.domain)" tone="success" :dismissible="false" data-token-saved>
    <span role="status">{{ k.t('ui.token.saved', {domain: s.domain}) }}</span>
   </Callout>
   <Callout v-if="!busy[s.id] && !s.tokenInvalid && s.last?.state === 'failed' && s.last.causeKey !== tokenCause" tone="warning" :dismissible="false" data-sync-failed>
    <span role="alert">{{ k.t('ui.inbound.failed', {cause: k.t(s.last.causeKey ?? 'mail.inbound.cause.cloudflare')}) }}</span>
    <template #actions><Button variant="secondary" data-retry @click="sync(s)">{{ k.t('ui.inbound.retry') }}</Button></template>
   </Callout>
   <Callout v-if="autoNotice(s)" tone="warning" :dismissible="false" data-auto-notice>
    <span role="alert">{{ autoNotice(s) }}</span>
   </Callout>
   <div v-if="s.tokenInvalid && s.auto?.unsynced" class="msa-quiet msa-small" data-auto-unsynced>
    {{ k.t('ui.inbound.unsynced', {count: s.auto.unsynced, cause: k.t('mail.inbound.cause.token')}) }}
   </div>
   <div v-if="!s.tokenInvalid && s.last?.state === 'done' && s.last.pending" class="msa-quiet msa-small" data-sync-pending>
    {{ k.t('ui.inbound.pending', {count: s.last.pending, list: (s.last.addresses ?? []).join(', ')}) }}
   </div>
   <Callout v-if="!busy[s.id] && s.removal?.state === 'failed' && s.removal.causeKey !== tokenCause" tone="warning" :dismissible="false" data-remove-failed>
    <span role="alert">{{ removeFailed(s.removal) }}</span>
    <template #actions>
     <Button v-if="accessFor(s.removal)" variant="secondary" data-remove-access @click="k.askAccess(accessFor(s.removal))">{{ k.t('ui.access.needed') }}</Button>
     <Button variant="secondary" data-remove-retry @click="remove(s, !!routingChoice[s.id])">{{ k.t('ui.inbound.retry') }}</Button>
    </template>
   </Callout>
   <Callout v-if="errors[s.id]" tone="danger" :dismissible="false" data-sync-error>
    <span role="alert">{{ k.error(errors[s.id]) }}</span>
    <template #actions><Button variant="secondary" data-retry @click="s.removal ? remove(s, !!routingChoice[s.id]) : sync(s)">{{ k.t('ui.inbound.retry') }}</Button></template>
   </Callout>
   <template v-if="tokenAsked(s)">
    <Callout tone="info" :dismissible="false" :title="k.t('ui.inbound.tokenTitle')" data-token-ask>
     {{ k.t('ui.inbound.tokenBody') }}
     <template #actions><Button variant="secondary" data-create-token @click="openCloudflare(tokenUrl)">{{ k.t('mail.setup.cloudflare.create') }}</Button></template>
    </Callout>
    <Form direction="vertical">
     <FormItem :label="k.t('mail.setup.cloudflare.token')" :description="k.t('ui.inbound.tokenHint')">
      <Input v-model="tokens[s.id]" type="password" autocomplete="off" spellcheck="false" data-inbound-token />
     </FormItem>
     <div><Button variant="primary" :disabled="busy[s.id] || !tokens[s.id]?.trim()" data-save-token @click="saveToken(s)">
      {{ k.t(asking[s.id] === 'remove' || s.receive !== 'addresses' ? 'ui.remove.saveToken' : 'ui.inbound.saveToken') }}
     </Button></div>
    </Form>
   </template>
  </div>
  <TokenDialog :open="!!replacing" :id="replacing?.id ?? ''" :domain="replacing?.domain ?? ''" mode="kept"
   @update:open="o => {if(!o) replacing = undefined}" @saved="replacing && tokenReplaced(replacing)" />
  <Dialog :open="!!confirming" :title="confirming ? k.t('ui.remove.title', {domain: confirming.domain}) : ''" size="md" @update:open="o => {if(!o) confirming = undefined}">
   <Space v-if="confirming" direction="column" spacing="dense" data-remove-confirm>
    <div>{{ k.t('ui.remove.body') }}</div>
    <ul class="msa-remove-list" data-remove-items>
     <li v-for="item in confirming.removes ?? []" :key="item" :data-item="item">{{ k.t(item) }}</li>
    </ul>
    <div class="msa-quiet" data-remove-kept>{{ k.t('ui.remove.kept') }}</div>
    <div class="msa-quiet" data-uninstall-note>{{ k.t('ui.remove.uninstall') }}</div>
    <Checkbox v-if="confirming.routingOwned" v-model="routingOff" :label="k.t('ui.remove.routing')" :description="k.t('ui.remove.routingBody')" data-remove-routing />
   </Space>
   <template #footer>
    <Button variant="secondary" data-remove-cancel @click="confirming = undefined">{{ k.t('ui.remove.cancel') }}</Button>
    <Button variant="danger" data-confirm-remove @click="confirmRemove()">{{ k.t('ui.remove.confirm') }}</Button>
   </template>
  </Dialog>
 </SettingsSection>
</template>
