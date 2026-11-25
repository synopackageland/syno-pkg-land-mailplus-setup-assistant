// @vitest-environment jsdom
// The App sets mail up two ways: with a fixed IP the NAS sends and receives
// directly; without one Cloudflare does it in front of the NAS, wherever it is.
// The setup wizard's route step says so in one line above the two cards, each
// with its own mini picture (moved there from the Overview); every word exists in
// the nine locales.
import {afterEach,expect,test,vi} from 'vitest'
import {existsSync,readFileSync} from 'node:fs'
import {join} from 'node:path'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'
import {createAssistant} from '../src/api/assistant'
import type {Context} from '@synopackageland/sdk'

const locales=['en','zh-TW','zh-CN','ja','ko','de','fr','es','it']
const catalogs=Object.fromEntries(locales.map(l=>[l,JSON.parse(readFileSync(join(__dirname,`../../i18n/messages/${l}.json`),'utf8')) as Record<string,string>]))
const KEYS=['mail.setup.route.headline',
 ...['direct','cloudflare'].map(w=>`ui.ways.${w}.summary`),
 ...['nas','cloudflare','internet'].map(k=>`ui.ways.node.${k}`),
 'mail.setup.route.cloudflareHint','mail.setup.route.directHint','ui.relay.body','ui.pricing.note','ui.pricing.link','mail.setup.sendingPlan']
/** Keys build 38's overview and diagram used; nothing reads them any more. */
const GONE=['ui.overview.headline',...['direct','cloudflare'].flatMap(w=>['title','caption'].map(k=>`ui.ways.${w}.${k}`)),'ui.overview.keyPoint','ui.overview.intro','ui.overview.howShow','ui.overview.howHide','ui.overview.howNeeds',
 ...['summary','nas','nasCaption','router','cloudflare','internet','internetCaption','noFixedIp','noPorts','send','receive','sendNote','receiveNote'].map(k=>`ui.diagram.${k}`)]
const PRICING='https://developers.cloudflare.com/email-service/platform/pricing/'
// User-facing copy stays plain: none of the Cloudflare product internals
// ("Workers Paid", the plan's own name, is the one exception).
const JARGON=/Email Routing|Worker(?!s)|VPC|PTR|FCrDNS|cloudflared|tunnel|relay/i

async function settle(){for(let i=0;i<30;i++){await Promise.resolve();await nextTick()}}
afterEach(()=>{document.body.innerHTML=''})

function open(locale='zh-TW'){
 const catalog=catalogs[locale]!
 const call=vi.fn(async(method:string)=>{
  if(method==='app.status')return {package:'SynoMailPlusSetupAssistant',version:'0.1.0',user:'admin',admin:true}
  if(method==='dsm.authority.status')return {capability:{state:'ready'},profiles:[
   {name:'mail-read',profile:{purpose:'',apis:{}},state:'granted',canRevoke:true},
   {name:'mail-write',profile:{purpose:'',apis:{}},state:'granted',canRevoke:true}],grants:[]}
  if(method==='mail.relay.status')return {id:'mail.relay',enabled:false,status:{running:false}}
  if(method==='mail.mailplus.status')return {state:'running',version:'3.3.0-21430'}
  if(method==='mail.setup.start')return {id:'0'.repeat(32),phase:'',done:0,total:0,changes:[],findings:[],verified:false,resume:false}
  if(method==='mail.setup.detect')return {done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:true,fields:[],warnings:[]}}
  throw {code:'unknown_method'}
 })
 const ctx=dsmWindow({locale,call:call as never,t:(key:string)=>catalog[key]??key})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 return {root,close(){app.unmount();root.remove()}}
}

test.each(locales)('every key has plain, short copy in %s',loc=>{
 const c=catalogs[loc]!
 for(const key of KEYS){
  expect(c[key],`${loc}: ${key}`).toBeTruthy()
  if(!key.startsWith('ui.pricing')&&key!=='mail.setup.sendingPlan'&&key!=='ui.relay.body')expect(c[key],`${loc}: ${key}`).not.toMatch(JARGON)
 }
 for(const key of GONE)expect(c[key],`${loc}: ${key} is unused`).toBeUndefined()
 // Fewer words: one headline, short titles and captions, one-word picture labels.
 expect(c['mail.setup.route.headline']!.length).toBeLessThan(70)
 for(const n of ['nas','cloudflare','internet'])expect(c[`ui.ways.node.${n}`]!.split(/\s+/).length).toBeLessThanOrEqual(3)
 for(const h of ['cloudflareHint','directHint'])expect(c[`mail.setup.route.${h}`]!.length).toBeLessThan(80)
})

test('MailPathDiagram is gone',()=>{
 expect(existsSync(join(__dirname,'../src/components/MailPathDiagram.vue'))).toBe(false)
 for(const f of ['pages/OverviewPage.vue','wizards/SetupWizard.vue','style.css'])
  expect(readFileSync(join(__dirname,'../src',f),'utf8')).not.toMatch(/MailPathDiagram|msa-diagram|ui\.diagram\./)
})

function expectPicture(svg:Element|null,way:'direct'|'cloudflare',c:Record<string,string>){
 expect(svg,way).toBeTruthy()
 expect(svg!.getAttribute('role')).toBe('img')
 expect(svg!.getAttribute('aria-label')).toBe(c[`ui.ways.${way}.summary`])
 expect(svg!.querySelector('title')?.textContent).toBe(c[`ui.ways.${way}.summary`])
 // A concept, not an architecture: the NAS, (Cloudflare,) the internet, arrows both ways.
 const nodes=[...svg!.querySelectorAll('[data-node]')].map(n=>n.getAttribute('data-node'))
 expect(nodes).toEqual(way==='direct'?['nas','internet']:['nas','cloudflare','internet'])
 const arrows=svg!.querySelectorAll('[data-arrow]')
 expect(arrows.length).toBe(way==='direct'?1:2)
 for(const a of arrows)expect(a.querySelectorAll('polygon').length).toBe(2)
 for(const n of nodes)expect(svg!.textContent).toContain(c[`ui.ways.node.${n}`])
 expect(svg!.querySelector('[data-lane]')).toBeNull()
 // Scales with its container.
 expect(svg!.getAttribute('viewBox')).toMatch(/^0 0 \d+ \d+$/)
 expect(svg!.hasAttribute('width')).toBe(false)
}

// The Overview starts with MailPlus Server; the promise
// and both ways live in the setup wizard's route step (its cards carry the pictures).
test.each(['zh-TW','en'])('the overview has no intro: it starts with MailPlus Server (%s)',async loc=>{
 const c=catalogs[loc]!
 const h=open(loc)
 try{
  await settle()
  expect(h.root.querySelector('[data-intro]')).toBeNull()
  expect(h.root.querySelector('[data-ways]')).toBeNull()
  expect(h.root.querySelector('[data-key-point]')).toBeNull()
  expect(h.root.querySelectorAll('svg[data-way-picture]').length).toBe(0)
  expect(h.root.textContent).not.toContain(c['mail.setup.route.headline'])
  const page=h.root.querySelector('[data-page="overview"]')!
  const first=[...page.children].find(e=>!e.matches('[data-ui-callout], [role="alert"]'))
  expect(first?.getAttribute('data-section')).toBe('mailplus')
 }finally{h.close()}
})

test('MailWays is gone',()=>{
 expect(existsSync(join(__dirname,'../src/components/MailWays.vue'))).toBe(false)
 expect(readFileSync(join(__dirname,'../src/style.css'),'utf8')).not.toMatch(/\.msa-(intro|ways|way-title|way-caption)\b/)
})

test('the zh-TW copy says both ways, not only Cloudflare',()=>{
 const z=catalogs['zh-TW']!
 expect(z['mail.setup.route.headline']).toBe('不論有沒有固定 IP，都能幫您把收發信架好')
 expect(z['mail.setup.route.directHint']).toBe('直接收發，需要固定 IP 和 25 埠')
 expect(z['mail.setup.route.cloudflareHint']).toBe('NAS 在哪裡都可以，不用設定路由器')
})

test('the relay section is short and does not repeat the intro',async()=>{
 const h=open('zh-TW')
 const z=catalogs['zh-TW']!
 try{
  await settle()
  const relay=h.root.querySelector('[data-section="relay"]')!.textContent!
  expect(relay).toContain(z['ui.relay.body'])
  expect(relay).not.toContain(z['mail.setup.route.headline'])
  for(const loc of locales)expect(catalogs[loc]!['ui.relay.body']!.length,loc).toBeLessThan(130)
 }finally{h.close()}
})

test('the route step: each card has its mini picture and parallel copy; the plan note stays on Cloudflare',async()=>{
 vi.useFakeTimers({toFake:['setTimeout','clearTimeout','Date']})
 const h=open('zh-TW')
 const z=catalogs['zh-TW']!
 const dialog=()=>document.querySelector<HTMLElement>('[role="dialog"]')!
 const shown='section:not([aria-hidden="true"])'
 const press=async(label:string,scope:ParentNode=document)=>{
  const b=[...scope.querySelectorAll('button')].find(x=>x.textContent?.trim()===label)
  if(!b)throw new Error(`no button ${label}`)
  b.click();await settle()
 }
 try{
  await settle()
  await press(z['ui.overview.start']!,h.root.querySelector('[data-section="setup"]')!)
  await press('下一步',dialog())
  dialog().querySelector<HTMLElement>(`${shown} [data-sources] [role=radio]`)!.click();await settle()
  await press('下一步',dialog())
  const input=dialog().querySelector<HTMLInputElement>(`${shown} input`)!
  input.value='example.com';input.dispatchEvent(new Event('input',{bubbles:true}));await settle()
  await press('下一步',dialog())
  for(let i=0;i<4;i++){await vi.advanceTimersByTimeAsync(1100);await settle()}
  const step=()=>dialog().querySelector<HTMLElement>(`${shown}[data-wizard-step="route"]`)!
  expect(step()).toBeTruthy()
  // The promise that used to open the Overview, once, above the two cards.
  const key=step().querySelectorAll('[data-key-point]')
  expect(key.length).toBe(1)
  expect(key[0]!.textContent?.trim()).toBe('不論有沒有固定 IP，都能幫您把收發信架好')
  expect(key[0]!.compareDocumentPosition(step().querySelector('[data-routes]')!)&Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy()
  const cards=[...step().querySelectorAll<HTMLElement>('[data-routes] [data-ui-choice-card]')]
  expect(cards.length).toBe(2)
  const card=(way:'direct'|'cloudflare')=>cards.find(c=>c.querySelector(`[data-way-picture="${way}"]`))!
  expect(card('cloudflare').textContent).toContain(z['mail.setup.route.cloudflare'])
  expect(card('cloudflare').textContent).toContain('NAS 在哪裡都可以，不用設定路由器')
  expect(card('direct').textContent).toContain(z['mail.setup.route.direct'])
  expect(card('direct').textContent).toContain('直接收發，需要固定 IP 和 25 埠')
  expectPicture(card('cloudflare').querySelector('svg[data-way-picture]'),'cloudflare',z)
  expectPicture(card('direct').querySelector('svg[data-way-picture]'),'direct',z)
  // No big diagram any more, whatever is chosen.
  expect(step().querySelectorAll('svg[data-way-picture]').length).toBe(2)
  expect(step().querySelector('[data-plan-note] [data-pricing-link]')?.getAttribute('href')).toBe(PRICING)
  card('cloudflare').querySelector<HTMLElement>('[role=radio]')!.click();await settle()
  expect(step().querySelector('[data-plan-note]')).toBeTruthy()
  expect(step().querySelectorAll('svg[data-way-picture]').length).toBe(2)
  card('direct').querySelector<HTMLElement>('[role=radio]')!.click();await settle()
  expect(step().querySelector('[data-plan-note]')).toBeNull()
  expect(step().querySelectorAll('svg[data-way-picture]').length).toBe(2)
 }finally{h.close();vi.useRealTimers()}
})

test('the plan note: receiving free, sending on Workers Paid, Cloudflare decides, one link',()=>{
 for(const loc of locales){
  expect(catalogs[loc]!['ui.pricing.note']).toMatch(/Workers/)
  expect(catalogs[loc]!['ui.pricing.note']).toMatch(/3[,. ]?000/)
 }
 expect(catalogs['zh-TW']!['ui.pricing.note']).toBe('收信免費；寄信需要 Cloudflare Workers 付費方案（每月含 3,000 封）。以 Cloudflare 公告為準')
})

test.each(locales)('a Workers Free refusal of sending reads as plain words (%s)',loc=>{
 const catalog=catalogs[loc]!
 const a=createAssistant({locale:loc,t:(key:string)=>catalog[key]??key,call:async()=>({})} as unknown as Context,{openWizard(){},openConsent(){},openSettings(){}})
 const text=a.error({code:'unavailable',details:{reason:'mail.setup.sendingPlan'}})
 expect(text).toBe(catalog['mail.setup.sendingPlan'])
 expect(text).not.toMatch(/unavailable|plan_limit|402|\{/)
})
