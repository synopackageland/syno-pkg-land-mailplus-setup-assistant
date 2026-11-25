import {ref} from 'vue'
import {openApp, packageCenterUrl, type DsmAppLaunchResult} from '@synopackageland/sdk'
import {pause, type Assistant} from './assistant'
import type {MailPlusStatus} from './types'

/**
 * The MailPlus Server precondition (mail.mailplus.status): installed and
 * running, decided by the worker from DSM's package list only. Every flow that
 * needs MailPlus Server asks it first; nothing that needs MailPlus Server is
 * asked before it says running.
 */

/** DSM's Package Center. DSM documents no launch to a single package's page. */
export const PACKAGE_CENTER_APP = {appId: 'SYNO.SDS.PkgManApp.Instance'} as const
/** The desktop link for the written fallback (relative: this DSM). */
export const PACKAGE_CENTER_URL = packageCenterUrl()

/** Opens Package Center through the SDK DSM App launcher; `requested` only says DSM was asked. */
export async function openPackageCenter(): Promise<DsmAppLaunchResult['status']> {
 return (await openApp(PACKAGE_CENTER_APP)).status
}

/** The catalog keys that say what the state means and what to do. */
export function mailPlusCopy(s: MailPlusStatus | undefined): {title: string; body: string} | undefined {
 switch(s?.state) {
  case 'notInstalled': return {title: 'ui.mailplus.notInstalled.title', body: 'ui.mailplus.notInstalled.body'}
  case 'stopped': return {title: 'ui.mailplus.stopped.title', body: s.broken ? 'ui.mailplus.broken.body' : 'ui.mailplus.stopped.body'}
  case 'unknown': return {title: 'ui.mailplus.unknown.title', body: 'ui.mailplus.unknown.body'}
  default: return undefined
 }
}

/** A cause key whose words name the precondition (the zone step's domain read). */
export const MAILPLUS_CAUSES = new Set(['mail.setup.cause.mailplusNotInstalled', 'mail.setup.cause.mailplusStopped'])

/** The least time between two come-back re-checks (each reads DSM). */
export const MAILPLUS_RECHECK_INTERVAL = 15_000

/**
 * Reads the precondition and follows the worker while it answers `checking`
 * (one request at a time; the worker waits up to 8 s per call). A refusal
 * (no read access, not an administrator) is kept in `error`, not as unknown.
 */
export function useMailPlus(k: Assistant) {
 const status = ref<MailPlusStatus>()
 const error = ref<unknown>()
 const checking = ref(false)
 let round = 0
 let last = 0
 async function check(signal?: AbortSignal): Promise<MailPlusStatus | undefined> {
  const mine = ++round
  checking.value = true
  last = Date.now()
  try {
   let s = await k.call('mail.mailplus.status')
   while(s.state === 'checking' && !signal?.aborted && mine === round) {
    status.value = s
    await pause(1000, signal)
    if(signal?.aborted || mine !== round) return
    s = await k.call('mail.mailplus.status')
   }
   if(signal?.aborted || mine !== round) return
   status.value = s
   error.value = undefined
   return s
  } catch(e) {
   if(signal?.aborted || mine !== round) return
   error.value = e
   status.value = undefined
  } finally {if(mine === round) checking.value = false}
 }
 /** A come-back re-check, at most once per interval and one at a time. */
 function recheckSoon(signal?: AbortSignal) {
  if(checking.value || Date.now() - last < MAILPLUS_RECHECK_INTERVAL) return
  void check(signal)
 }
 function cancel() {round++; checking.value = false}
 return {status, error, checking, check, recheckSoon, cancel}
}
