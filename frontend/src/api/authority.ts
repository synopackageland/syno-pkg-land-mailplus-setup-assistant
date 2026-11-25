import {computed, ref} from 'vue'
import type {AuthorityProfile, AuthorityProfileName, AuthorityStatus, Operations, OpName} from './types'

type Call = <K extends OpName>(op: K, params?: Operations[K][0]) => Promise<Operations[K][1]>

/** Checks and diagnosis only read; writes are asked for separately. */
export const READ_PROFILES: AuthorityProfileName[] = ['mail-read']
export const WRITE_PROFILES: AuthorityProfileName[] = ['mail-write']
/** No profile here is asked for only by its own opt-in box. */
export const OPT_IN_PROFILES: AuthorityProfileName[] = []

/**
 * Shared DSM authority state (dsm.authority.*). One instance per App window,
 * loaded in the background. A status read never grants anything: every grant
 * is one explicit, confirmed call per profile the administrator selected.
 */
export function createAuthority(call: Call) {
 const status = ref<AuthorityStatus>()
 const loading = ref(false)
 const error = ref<unknown>()
 let generation = 0

 async function refresh() {
  const mine = ++generation
  loading.value = true
  try {
   const s = await call('dsm.authority.status')
   if(mine === generation) {status.value = s; error.value = undefined}
  } catch(e) {if(mine === generation) error.value = e}
  finally {if(mine === generation) loading.value = false}
 }

 const profile = (name: AuthorityProfileName): AuthorityProfile | undefined => status.value?.profiles.find(p => p.name === name)
 const granted = (name: AuthorityProfileName) => profile(name)?.state === 'granted'
 /** The package executor itself still needs an administrator's approval. */
 const needsApproval = computed(() => !!status.value && status.value.capability.state !== 'ready')
 /** Some read-only checks cannot run yet. Unknown until the first status arrives. */
 const readsMissing = computed(() => !!status.value && READ_PROFILES.some(n => !granted(n)))

 /** One confirmed grant per selected profile, in order; refreshes afterwards. Returns the first failure. */
 async function grant(names: AuthorityProfileName[]): Promise<unknown> {
  let failure: unknown
  for(const name of names) {
   try {await call('dsm.authority.grant', {profile: name, confirmed: true})}
   catch(e) {failure = e; break}
  }
  await refresh()
  return failure
 }

 /** Revokes the caller's own grant by its original ID; repeating after a lost reply is safe. */
 async function revoke(name: AuthorityProfileName, id: string) {
  try {await call('dsm.authority.revoke', {profile: name, id})}
  finally {await refresh()}
 }

 return {status, loading, error, refresh, profile, granted, needsApproval, readsMissing, grant, revoke}
}

export type Authority = ReturnType<typeof createAuthority>

export const isProfile = (name: unknown): name is AuthorityProfileName => typeof name === 'string' && [...READ_PROFILES, ...WRITE_PROFILES].includes(name as AuthorityProfileName)

/** Catalog key for a profile's short name inside a sentence (ui.authority.name.mail-read). */
export const profileName = (name: AuthorityProfileName) => `ui.authority.name.${name}`

/** Catalog key for a profile's own text, owned by core (core.authority.mail_read). */
export const profileKey = (name: AuthorityProfileName) => `core.authority.${name.replace('-', '_')}`
