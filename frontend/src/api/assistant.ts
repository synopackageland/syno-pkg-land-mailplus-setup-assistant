import {inject, provide, type InjectionKey} from 'vue'
import type {Context} from '@synopackageland/sdk'
import {bridgeErrorCopy} from '@synopackageland/sdk'
import {uiLocale} from '@synopackageland/sdk/vue'
import {appCopy} from '../i18n'
import type {AssistantError, AuthorityProfileName, Finding, Operations, OpName, Severity} from './types'
import {createAuthority, isProfile, profileName, type Authority} from './authority'

/** Typed access to the worker operations and the package message catalog. */
export interface Assistant {
 call<K extends OpName>(op: K, params?: Operations[K][0]): Promise<Operations[K][1]>
 /** Translates a catalog key; a missing key shows the generic sentence of its kind (fallbackKey), never the key. */
 t(key: string | undefined, params?: Record<string, unknown>): string
 /** True when the catalog has the key (so an optional hint can be left out). */
 has(key: string | undefined): boolean
 locale: string
 /** A failed call in the DSM language: known refusals in their own words, a mail rule's reason, else the code. */
 error(e: unknown): string
 /** A permission refusal (not an administrator, or a missing DSM profile); undefined for any other failure. */
 refusal(e: unknown): Refusal | undefined
 /** Leads to the decision that removes a refusal: the consent for these profiles, or Settings while the executor waits. */
 askAccess(profiles?: AuthorityProfileName[]): void
 /** Opens a wizard; set by the App. A finding's Fix passes the finding. */
 openWizard(id: 'mail.setup' | 'mail.diagnose', from?: Finding): void
 authority: Authority
 openConsent(profiles?: AuthorityProfileName[]): void
 openSettings(): void
 /** The host adapter (window events such as `window-activated`). */
 host: Context['host']
}

export interface AssistantHooks {
 openWizard: Assistant['openWizard']
 openConsent: Assistant['openConsent']
 openSettings: Assistant['openSettings']
}

export type Refusal = {code: 'admin_required'} | {code: 'authority_required'; profile?: AuthorityProfileName}

export const errorCode = (e: unknown) => (e as Partial<AssistantError> | undefined)?.code || 'request_failed'

export function refusalOf(e: unknown): Refusal | undefined {
 const code = errorCode(e)
 if(code === 'admin_required') return {code}
 if(code !== 'authority_required') return undefined
 const profile = (e as AssistantError).details?.profile
 return {code, profile: isProfile(profile) ? profile : undefined}
}

/**
 * The generic sentence shown for a key the catalog lacks: a reason
 * (mail.setup.unreadable.*) or a cause (mail.setup.cause.*) gets the generic
 * one of its kind; anything else the generic error.
 */
export function fallbackKey(key: string): string {
 if(key.startsWith('mail.setup.unreadable.')) return 'mail.setup.unreadable.unavailable'
 if(key.startsWith('mail.setup.cause.')) return 'mail.setup.cause.unavailable'
 return 'ui.common.error'
}

const AssistantKey: InjectionKey<Assistant> = Symbol('assistant')

export function createAssistant(ctx: Context, hooks: AssistantHooks): Assistant {
 /** The catalog text, or the key itself when the catalog lacks it. */
 const raw = (key: string, params?: Record<string, unknown>) => ctx.t ? ctx.t(key, params) : key
 const t = (key: string | undefined, params?: Record<string, unknown>) => {
  if(!key) return ''
  const text = raw(key, params)
  if(text !== key) return text
  // A raw key never reaches the page: a missing reason or cause shows the
  // generic sentence of its kind, anything else the generic error. Only a
  // context with no catalog at all (tests) keeps the key.
  const generic = fallbackKey(key)
  const fallback = raw(generic, params)
  return fallback !== generic ? fallback : key
 }
 const call: Assistant['call'] = (op, params) => ctx.call(op, (params ?? {}) as Record<string, unknown>)
 const authority = createAuthority(call)
 return {
  host: ctx.host,
  call,
  t,
  has: key => !!key && raw(key) !== key,
  locale: uiLocale(ctx.locale),
  error(e) {
   const code = errorCode(e)
   const bridge = bridgeErrorCopy(e, ctx.locale)
   if(bridge) return bridge
   const known = appCopy(ctx.locale).errors as Record<string, string>
   if(code !== 'request_failed' && known[code]) return known[code]!
   const refusal = refusalOf(e)
   if(refusal?.code === 'authority_required' && refusal.profile) return t('ui.authority.profileBody', {profile: t(profileName(refusal.profile))})
   // A mail rule refused with its fixed reason key (mail.setup.stalePlan, ...).
   const reason = (e as Partial<AssistantError>)?.details?.reason
   if(reason && /^mail\.[\w.]+$/.test(reason) && raw(reason) !== reason) return t(reason)
   const key = `error.${code}`
   const text = raw(key, {...(e as Partial<AssistantError>)?.details})
   return text && text !== key && !/\{\w+\}/.test(text) ? text : t('ui.common.error', {code})
  },
  refusal: refusalOf,
  askAccess(profiles) {
   if(authority.needsApproval.value) hooks.openSettings()
   else hooks.openConsent(profiles)
  },
  authority,
  ...hooks,
 }
}

export function provideAssistant(a: Assistant) {provide(AssistantKey, a)}
export function useAssistant(): Assistant {
 const a = inject(AssistantKey)
 if(!a) throw new Error('MailPlus Setup Assistant context is missing')
 return a
}

export type Tone = 'neutral' | 'info' | 'success' | 'warning' | 'danger'
export function severityTone(severity: Severity | undefined): Tone {
 switch(severity) {
  case 'ok': return 'success'
  case 'info': return 'info'
  case 'warning': return 'warning'
  case 'critical': return 'danger'
  default: return 'neutral'
 }
}

/** Locale-aware date and time, never a hardcoded format. Go's zero time counts as unset. */
export function formatTime(locale: string, iso: string | undefined): string {
 if(!iso) return ''
 const date = new Date(iso)
 if(Number.isNaN(date.getTime()) || date.getUTCFullYear() <= 1) return ''
 try {return new Intl.DateTimeFormat(locale, {dateStyle: 'medium', timeStyle: 'short'}).format(date)}
 catch {return date.toLocaleString()}
}

/** Resolves after ms, or at once when the signal is aborted. */
export function pause(ms: number, signal?: AbortSignal): Promise<void> {
 return new Promise(resolve => {
  if(signal?.aborted) return resolve()
  const timer = setTimeout(resolve, ms)
  signal?.addEventListener('abort', () => {clearTimeout(timer); resolve()}, {once: true})
 })
}
