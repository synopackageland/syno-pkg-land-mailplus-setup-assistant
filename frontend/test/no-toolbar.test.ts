// @vitest-environment jsdom
// @vitest-environment-options {"url":"https://nas.test"}
import {expect,test,vi} from 'vitest'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'
import en from '../src/i18n/en.json'
import zhTW from '../src/i18n/zh-TW.json'
import messages from '../../i18n/messages/zh-TW.json'
import {format} from '@synopackageland/sdk'
const catalog=messages as Record<string,string>
const t=(key:string,params?:Record<string,unknown>)=>catalog[key]===undefined?key:params?format(catalog[key]!,params as never):catalog[key]!
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
const refreshWords=['Refresh','重新整理','刷新','Aktualisieren','Actualiser','Actualizar','Aggiorna','새로 고침','最新の情報に更新']
function reply(method:string):unknown{
 if(method==='app.status')return {package:'Pkg',version:'1',user:'admin',admin:true}
 if(method==='mail.relay.status')return {enabled:false,status:{running:false}}
 if(method==='mail.setup.start')return {id:'f1',resume:false}
 throw {code:'unknown_method'}
}
function start(){
 let reopen:(()=>void)|undefined
 const call=vi.fn(async(method:string)=>reply(method))
 const ctx=dsmWindow({locale:'zh-TW',t:t as never,call:call as never,reopen:(fn:()=>void)=>{reopen=fn;return ()=>{reopen=undefined}}})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 return {root,call,reopen:()=>reopen?.(),close(){app.unmount();root.remove()}}
}
/** No header row: the page bar is absent or hidden and no layout bar takes height. */
function expectNoHeaderRow(root:HTMLElement){
 const bar=root.querySelector<HTMLElement>('[data-app-page-bar]')
 expect(bar===null||bar.hidden).toBe(true)
 expect(root.querySelector('[data-ui-layout-bar-short]')).toBeNull()
 for(const toolbar of root.querySelectorAll('[data-ui-app-toolbar]'))expect(toolbar.closest('[hidden]')).not.toBeNull()
 const labels=[...root.querySelectorAll('button')].map(b=>b.textContent?.trim()??'')
 for(const word of refreshWords)expect(labels).not.toContain(word)
}
test('the app copy has no Refresh string any more',()=>{
 expect('refresh' in en).toBe(false)
 expect('refresh' in zhTW).toBe(false)
})
/** The sidebar's page items, in order (the shell's SidebarNav buttons). */
function navItems(root:HTMLElement){
 return [...root.querySelectorAll<HTMLElement>('nav button, nav a')].filter(el=>el.textContent?.trim())
}
/** What the page area shows: the page content, without the visually hidden title. */
function pageText(root:HTMLElement){
 const content=root.querySelector<HTMLElement>('.app-page-content')
 return content?.textContent?.replace(/\s+/g,' ').trim()??''
}
test('the sidebar has no Background tab: the App submits no background jobs',async()=>{
 const s=start()
 try{
  await settle()
  const labels=navItems(s.root).map(el=>el.textContent!.trim())
  expect(labels).toEqual(['總覽','設定'])
  for(const label of labels)expect(label).not.toMatch(/背景|Background/i)
 }finally{s.close()}
})
test('every page in the sidebar shows content and no header row or Refresh button',async()=>{
 const s=start()
 try{
  await settle()
  const items=navItems(s.root)
  expect(items.length).toBeGreaterThan(0)
  for(const item of items){
   item.click();await settle()
   const shown=s.root.querySelector<HTMLElement>('[data-page]')
   expect(shown,`page for ${item.textContent}`).not.toBeNull()
   // Never blank: the page has its own words, not only its title.
   expect(pageText(s.root).length,`text on ${item.textContent}`).toBeGreaterThan(20)
   expectNoHeaderRow(s.root)
  }
  expect(s.root.querySelector('[data-page="settings"]')).not.toBeNull()
 }finally{s.close()}
})
test('the relay section re-reads with its own Check again',async()=>{
 const s=start()
 try{
  await settle()
  const before=s.call.mock.calls.filter(([m])=>m==='mail.relay.status').length
  const button=s.root.querySelector<HTMLButtonElement>('[data-relay-recheck]')
  expect(button).not.toBeNull()
  button!.click();await settle()
  expect(s.call.mock.calls.filter(([m])=>m==='mail.relay.status').length).toBe(before+1)
 }finally{s.close()}
})
test('reopening the window still re-reads status and the overview',async()=>{
 const s=start()
 try{
  await settle()
  const count=(m:string)=>s.call.mock.calls.filter(([x])=>x===m).length
  const status=count('app.status'),relay=count('mail.relay.status')
  s.reopen();await settle()
  expect(count('app.status')).toBeGreaterThan(status)
  expect(count('mail.relay.status')).toBeGreaterThan(relay)
 }finally{s.close()}
})
test('the generic error names no code and says what the user can do now',async()=>{
 const all=import.meta.glob('../../i18n/messages/*.json',{eager:true,import:'default'}) as Record<string,Record<string,string>>
 expect(Object.keys(all)).toHaveLength(9)
 for(const [file,catalog] of Object.entries(all)){
  for(const key of ['ui.common.error','mail.setup.unreadable.dsmSession']){
   const text=catalog[key]
   expect(text,`${file} ${key}`).toBeTruthy()
   expect(text).not.toMatch(/\{code\}/)
   expect(text).not.toMatch(/Refresh|重新整理|刷新|Aktualisieren|Neu laden|neu\b|Actualis|Actualice|Aggiorna|새로 고|更新して|再読み込み/)
  }
 }
})
test('an unknown failure shows the plain error without its code',async()=>{
 let reopen:(()=>void)|undefined
 const call=vi.fn(async(method:string)=>{if(method==='mail.relay.status')throw {code:'WEIRD_9000'};return reply(method)})
 const ctx=dsmWindow({locale:'zh-TW',t:t as never,call:call as never,reopen:(fn:()=>void)=>{reopen=fn;return ()=>{reopen=undefined}}})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 try{
  await settle()
  const alert=root.querySelector('[role="alert"]')?.textContent??''
  expect(alert).toBe(catalog['ui.common.error'])
  expect(alert).not.toContain('WEIRD_9000')
  expect(root.querySelector('[data-relay-recheck]')).not.toBeNull()
 }finally{app.unmount();root.remove();void reopen}
})
