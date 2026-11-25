// @vitest-environment jsdom
// Every reason the backend can emit has copy in every locale, and the UI never
// shows a raw catalog key: a missing one shows the generic sentence of its kind.
import {expect,test} from 'vitest'
import {readFileSync,readdirSync} from 'node:fs'
import {join} from 'node:path'
import {format,type Context} from '@synopackageland/sdk'
import {createAssistant,fallbackKey} from '../src/api/assistant'

const locales=['en','zh-TW','zh-CN','ja','ko','de','fr','es','it']
const catalogs=Object.fromEntries(locales.map(l=>[l,JSON.parse(readFileSync(join(__dirname,`../../i18n/messages/${l}.json`),'utf8')) as Record<string,string>]))
const RAW_KEY=/\b(mail|ui|error)\.[\w-]+\.[\w.-]+/

/** Every cause key the worker sends: the mail.setup.cause.* literals in the Go source. */
function backendCauseKeys(){
 const keys=new Set<string>()
 const walk=(dir:string)=>{for(const e of readdirSync(dir,{withFileTypes:true})){
  const p=join(dir,e.name)
  if(e.isDirectory())walk(p)
  else if(p.endsWith('.go')&&!p.endsWith('_test.go'))for(const m of readFileSync(p,'utf8').matchAll(/"(mail\.setup\.cause\.\w+)"/g))keys.add(m[1]!)
 }}
 walk(join(__dirname,'../../backend/internal'))
 return [...keys]
}

test('every cause and reason the backend can emit has copy in every locale',()=>{
 const keys=backendCauseKeys()
 expect(keys.length).toBeGreaterThan(20)
 for(const loc of locales)for(const key of keys){
  const reason=key.replace('mail.setup.cause.','mail.setup.unreadable.')
  for(const k of [key,reason]){
   const text=catalogs[loc]![k]
   expect(text,`${loc}: ${k}`).toBeTruthy()
   expect(text,`${loc}: ${k}`).not.toMatch(RAW_KEY)
   expect(text,`${loc}: ${k}`).not.toMatch(/\{code\}/)
  }
 }
 // The nine that lacked a reason before.
 for(const r of ['incomplete','badResponse','notChecked','noDomain','notInMailPlus','dnsUnknown','ipUnknown','ptrNone','notStarted'])
  for(const loc of locales)expect(catalogs[loc]![`mail.setup.unreadable.${r}`],`${loc} ${r}`).toBeTruthy()
})

function assistantFor(loc:string){
 const catalog=catalogs[loc]!
 const t=(key:string,params:Record<string,unknown>={})=>catalog[key]===undefined?key:format(catalog[key]!,params as never)
 return createAssistant({locale:loc,t,call:async()=>({})} as unknown as Context,{openWizard(){},openConsent(){},openSettings(){}})
}

test.each(locales)('a missing key shows the generic sentence, never the key (%s)',loc=>{
 const a=assistantFor(loc),c=catalogs[loc]!
 expect(a.t('mail.setup.unreadable.someFutureReason')).toBe(c['mail.setup.unreadable.unavailable'])
 expect(a.t('mail.setup.cause.someFutureCause')).toBe(c['mail.setup.cause.unavailable'])
 expect(a.t('mail.diag.someFuture.title')).toBe(c['ui.common.error'])
 for(const k of ['mail.setup.unreadable.x','mail.setup.cause.x','mail.x.y','ui.x.y'])expect(a.t(k)).not.toMatch(RAW_KEY)
 // A present key is untouched, and has() still tells a missing key apart.
 expect(a.t('mail.setup.unreadable.ptrNone')).toBe(c['mail.setup.unreadable.ptrNone'])
 expect(a.has('mail.setup.cause.someFutureCause')).toBe(false)
 expect(a.has('mail.setup.cause.ptrNone')).toBe(true)
})

test('fallback keys exist in every locale',()=>{
 for(const k of ['mail.setup.unreadable.x','mail.setup.cause.x','ui.x'].map(fallbackKey))
  for(const loc of locales)expect(catalogs[loc]![k],`${loc} ${k}`).toBeTruthy()
})

test.each(locales)('a finding with an unknown reason renders words, never a key (%s)',async loc=>{
 const {createApp,h,nextTick}=await import('vue')
 const {provideAssistant}=await import('../src/api/assistant')
 const FindingCard=(await import('../src/components/FindingCard.vue')).default
 const a=assistantFor(loc),c=catalogs[loc]!
 const finding={id:'mail.diag.mailplus.unavailable',module:'mail',check:'mail.diag.mailplus',severity:'info',
  titleKey:'mail.diag.unavailable.mailplus.title',whyKey:'mail.setup.unreadable.someFutureReason',params:{cause:'unavailable',subject:''},
  evidence:{cause:'mail.setup.cause.someFutureCause'}}
 const root=document.createElement('div');document.body.append(root)
 const app=createApp({setup(){provideAssistant(a);return()=>h(FindingCard,{finding} as never)}})
 app.mount(root);await nextTick()
 ;(root.querySelector('button[aria-expanded]') as HTMLButtonElement|null)?.click();await nextTick()
 const text=root.textContent??''
 expect(text).toContain(c['mail.setup.unreadable.unavailable'])
 expect(root.querySelector('.msa-evidence')?.textContent).toContain(c['mail.setup.cause.unavailable'])
 expect(text).not.toMatch(RAW_KEY)
 app.unmount();root.remove()
})
