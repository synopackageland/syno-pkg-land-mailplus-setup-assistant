import {vi} from 'vitest'
import {createStandaloneContext, createStandaloneHost, type Context} from '@synopackageland/sdk'
/** The ctx the CLI gives a DSM desktop window; activateWindow is a spy. */
export function dsmWindow(fields: Pick<Context, 'call'> & Partial<Omit<Context, 'call'>>): Context {
 const host = createStandaloneHost({host: 'dsm', dsmStandalone: false})
 vi.spyOn(host, 'activateWindow')
 return createStandaloneContext({fullPage: false, host, ...fields})
}
