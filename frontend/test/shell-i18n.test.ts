// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://nas.test"}
import {expect,test,vi} from 'vitest'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'
import {appCopy} from '../src/i18n'
import {identityCopy} from '@synopackageland/sdk/vue'
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
const buttons=(root:HTMLElement)=>[...root.querySelectorAll('button')].map(b=>b.textContent?.trim())
function start(locale:string,call:(method:string)=>Promise<unknown>){
 const ctx=dsmWindow({locale,call:vi.fn(call) as never})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 return {root,close(){app.unmount();root.remove()}}
}
test('the shell and its pages follow the DSM language through ctx.t',async()=>{
 const copy=appCopy('ger')
 const de:Record<string,string>={'ui.nav.overview':'Übersicht','ui.nav.settings':'Einstellungen'}
 const ctx=dsmWindow({locale:'de',t:(key:string)=>de[key]??key,call:vi.fn(async(method:string)=>{
  if(method==='app.status')return {package:'Pkg',version:'1',user:'admin',admin:true}
  throw {code:'admin_required'}
 }) as never})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 try{
  await settle()
  expect(root.textContent).toContain('Übersicht')
  expect(root.textContent).toContain('Einstellungen')
  expect(root.querySelector('[role="alert"]')?.textContent).toContain(copy.errors.admin_required)
 }finally{app.unmount();root.remove()}
})
test('failures never show a code or ask for a Refresh that no longer exists',()=>{
 for(const locale of ['en','zh-TW','zh-CN','ja','ko','de','fr','es','it']){
  const copy=appCopy(locale)
  for(const text of [copy.statusError,...Object.values(copy.errors)]){
   expect(text).not.toMatch(/\{code\}/)
   expect(text).not.toMatch(/Refresh|重新整理|刷新|Aktualisieren|Actualis|Actualice|Aggiorna|새로 고|更新して|最新の情報/)
  }
 }
})
