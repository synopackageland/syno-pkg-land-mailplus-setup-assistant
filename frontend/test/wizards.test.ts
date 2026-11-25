// @vitest-environment jsdom
// The two wizards on the UI SDK Wizard, against a mocked worker: each test
// presses the real buttons and asserts what the worker receives.
import {afterEach,beforeEach,expect,test,vi} from 'vitest'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

async function settle(){
 for(let i=0;i<30;i++){await Promise.resolve();await nextTick()}
 // A flow armed by toDomain() picks its route as soon as the route step shows.
 if(autoRoute&&document.querySelector('[role="dialog"] section:not([aria-hidden="true"])[data-wizard-step="route"]')){const r=autoRoute;autoRoute=undefined;await chooseRoute(r)}
}
/** The route a flow takes when its route step shows (toDomain arms it; undefined: the test picks itself). */
let autoRoute:'direct'|'cloudflare'|undefined
async function tick(ms=1100){await vi.advanceTimersByTimeAsync(ms);await settle()}
// A loaded CI host can take seconds per DOM-driven flow; the flows use fake timers, so time is not what is tested.
vi.setConfig({testTimeout:20_000})
beforeEach(()=>{autoRoute=undefined;vi.useFakeTimers({toFake:['setTimeout','clearTimeout','Date']})})
afterEach(()=>{vi.useRealTimers();document.body.innerHTML=''})

const ID='0123456789abcdef0123456789abcdef'
type Reply=unknown|((params:Record<string,unknown>)=>unknown)
const refusal=(code:string,details?:Record<string,string>)=>({__throw:{code,details}})

/**
 * activation: what ctx.host.subscribe('window-activated') answers. 'unsupported'
 * (an older generated host) is the default, so the focus fallback is exercised;
 * 'subscribed' records the listener so a test can activate the window.
 */
function harness(replies:Record<string,Reply>,activation:'subscribed'|'unsupported'='unsupported'){
 const call=vi.fn(async(method:string,params:Record<string,unknown>={})=>{
  if(method==='app.status')return {package:'SynoMailPlusSetupAssistant',version:'0.1.0',user:'admin',admin:true}
  if(method==='dsm.authority.status')return {capability:{state:'ready'},profiles:[
   {name:'mail-read',profile:{purpose:'',apis:{}},state:'granted',canRevoke:true},
   {name:'mail-write',profile:{purpose:'',apis:{}},state:'granted',canRevoke:true}],grants:[]}
  if(method==='mail.relay.status')return {id:'mail.relay',enabled:false,status:{running:false}}
  // MailPlus Server runs unless a test says otherwise.
  if(method==='mail.mailplus.status'&&!(method in replies))return {state:'running',version:'3.3.0-21430'}
  if(!(method in replies))throw {code:'unknown_method'}
  const r=replies[method]
  const value=typeof r==='function'?(r as (p:Record<string,unknown>)=>unknown)(params):r
  if(value&&typeof value==='object'&&'__throw' in (value as object))throw (value as {__throw:unknown}).__throw
  return value
 })
 // Keys render as themselves, so assertions read stable catalog keys; a wait also shows its seconds.
 const ctx=dsmWindow({call:call as never,t:(key:string,params?:Record<string,unknown>)=>params&&'seconds' in params?`${key} ${params.seconds}`
  // The missing-access message shows which step and which access it names.
  :key.startsWith('ui.setup.authority.')&&params?`${key} step=${params.step} access=${params.access}`:key})
 const listeners=new Set<()=>void>()
 const subscriptions={made:0,disposed:0}
 const hostSubscribe=ctx.host.subscribe.bind(ctx.host)
 const subscribe=vi.spyOn(ctx.host,'subscribe').mockImplementation((event,listener)=>{
  if(event!=='window-activated')return hostSubscribe(event,listener)
  if(activation!=='subscribed')return {status:'unsupported'}
  subscriptions.made++;listeners.add(listener)
  return {status:'subscribed',dispose(){if(listeners.delete(listener))subscriptions.disposed++}}
 })
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 return {root,call,close(){app.unmount();root.remove()},subscribe,subscriptions,
  async activate(){for(const l of [...listeners])l();await settle()},
  methods:()=>call.mock.calls.map(([m])=>m),
  params:(method:string)=>call.mock.calls.filter(([m])=>m===method).map(([,p])=>p as Record<string,unknown>)}
}
const dialog=()=>document.querySelector<HTMLElement>('[role="dialog"]')!
const title=()=>[...dialog().querySelectorAll('h1,h2,h3,[role=heading]')].map(e=>e.textContent?.trim()).join(' | ')
function button(label:string,scope:ParentNode=document){
 const b=[...scope.querySelectorAll('button')].find(x=>x.textContent?.trim()===label)
 if(!b)throw new Error(`no button "${label}": ${[...scope.querySelectorAll('button')].map(x=>x.textContent?.trim()).join(' | ')}`)
 return b
}
async function press(label:string,scope?:ParentNode){button(label,scope).click();await settle()}
async function fill(index:number,value:string){
 const el=[...dialog().querySelectorAll<HTMLInputElement|HTMLTextAreaElement>('input:not([type=radio]),textarea')].filter(e=>e.offsetParent!==null||true)[index]!
 el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));await settle()
}
async function choose(label:string){
 const radio=[...dialog().querySelectorAll<HTMLElement>('[role=radio],input[type=radio]')].find(r=>(r.closest('label')??r).textContent?.includes(label))
 if(!radio)throw new Error(`no radio ${label}`)
 radio.click();await settle()
}
/** The shown step's choice card with this label (the SDK renders a button[role=radio]). */
function radio(label:string){
 const r=[...dialog().querySelectorAll<HTMLButtonElement>('section:not([aria-hidden="true"]) [role=radio]')].find(x=>(x.closest('label')??x).textContent?.includes(label))
 if(!r)throw new Error(`no radio ${label}`)
 return {checked:r.getAttribute('aria-checked')==='true'||r.dataset.state==='checked',disabled:r.disabled||r.hasAttribute('data-disabled')}
}
/** A Cloudflare sign-in view: one account holding example.com (active). */
const signedIn=(extra:Record<string,unknown>={})=>({accounts:[{id:'a'.repeat(32),name:'Home'}],accountId:'a'.repeat(32),
 zones:[{id:'b'.repeat(32),name:'example.com',status:'active'}],match:'b'.repeat(32),missing:[],...extra})
const flow=(phase='',extra:Record<string,unknown>={})=>({id:ID,phase,done:0,total:0,changes:[],findings:[],verified:false,resume:false,...extra})
const change={id:'dns.spf',target:'cloudflare.dns',actionKey:'mail.setup.change.dns.spf',params:{domain:'example.com'},before:'missing',after:'TXT v=spf1 ~all'}
async function openSetup(h:ReturnType<typeof harness>){
 await settle()
 await press('ui.overview.start',h.root.querySelector('[data-section="setup"]')!)
}
/** The route step: pick a route card; the own-IP route is confirmed too. Then Next. */
async function chooseRoute(route:'direct'|'cloudflare',next=true){
 const card=[...dialog().querySelectorAll<HTMLElement>('section:not([aria-hidden="true"]) [data-routes] [role=radio]')].find(x=>(x.closest('label')??x).textContent?.includes(`mail.setup.route.${route}`))
 if(!card)throw new Error(`no route ${route}`)
 card.click();await settle()
 if(route==='direct'){
  const box=dialog().querySelector<HTMLElement>('section:not([aria-hidden="true"]) [data-confirm] [role=checkbox], section:not([aria-hidden="true"]) [data-confirm] button, section:not([aria-hidden="true"]) [data-confirm]')
  if(!box)throw new Error('no confirmation');box.click();await settle()
 }
 if(next)await press('Next')
}
/** The start step: pick the own-domain (A) or Cloudflare (B) card, then Next. */
async function startWith(source:'own'|'cloudflare'='own'){
 const card=[...dialog().querySelectorAll<HTMLElement>('section:not([aria-hidden="true"]) [data-sources] [role=radio]')].find(x=>(x.closest('label')??x).textContent?.includes(`mail.setup.start.${source}`))
 if(!card)throw new Error(`no source ${source}`)
 card.click();await settle()
 await press('Next')
}
/** To the domain step (choosing the own-domain source when the start step shows), and arms the route the
 * flow takes once the detection is done: 'yes' the confirmed own IP, otherwise Cloudflare. */
async function answerNetwork(answer:'yes'|'no'|'unsure'='yes'){
 autoRoute=answer==='yes'?'direct':'cloudflare'
 if(dialog().querySelector('section:not([aria-hidden="true"]) [data-sources]'))await startWith('own')
}
// Only fields of the shown step are filled: the wizard keeps inactive steps mounted.
const visibleInputs=()=>[...dialog().querySelectorAll<HTMLElement>('section:not([aria-hidden="true"]) input:not([type=radio]), section:not([aria-hidden="true"]) textarea')]
async function fillVisible(index:number,value:string){
 const el=visibleInputs()[index] as HTMLInputElement
 if(!el)throw new Error(`no visible input ${index}`)
 el.value=value;el.dispatchEvent(new Event('input',{bubbles:true}));await settle()
}

test('setup: Cloudflare send path previews, applies in the background, verifies and keeps',async()=>{
 let polls=0
 let statusPolls=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':()=>++polls<3?{done:false}:{done:true,facts:[{labelKey:'mail.setup.fact.package',value:'running',status:'ok'}],
   branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:true,fields:[],warnings:[]}},
  'mail.setup.cloudflare':signedIn(),
  'mail.setup.zones':signedIn({zoneId:'b'.repeat(32)}),
  'mail.setup.permissions':{permissions:[{scope:'zone',resource:'b'.repeat(32),name:'DNS Write'}]},
  'mail.setup.preview':{changes:[change],permissions:[],warnings:[]},
  'mail.setup.apply':flow('applying',{total:1}),
  'mail.setup.status':()=>++statusPolls<2?flow('applying',{done:0,total:1}):flow('decision',{done:1,total:1,changes:[change],verified:true}),
  'mail.setup.decide':flow('kept',{done:1,total:1,changes:[change],verified:true,outcome:'ok'}),
 })
 try{
  await openSetup(h)
  expect(title()).toContain('mail.setup.intent')
  await press('Next')
  expect(title()).toContain('mail.setup.start')
  // Nothing is pre-selected: Next waits for a card.
  expect(button('Next',dialog()).disabled).toBe(true)
  await startWith('own')
  // The domain comes right after the start step; the route is asked after the detection.
  expect(title()).toContain('mail.setup.domain')
  await fillVisible(0,'example.com')
  await press('Next')
  expect(h.params('mail.setup.detect')[0]).toEqual({id:ID,intent:'send',domain:'example.com',answers:{source:'own'},refresh:false})
  expect(title()).toContain('mail.setup.detect')
  await tick();await tick()
  expect(title()).toContain('mail.setup.route')
  await chooseRoute('direct')
  expect(h.params('mail.setup.detect').at(-1)).toEqual({id:ID,intent:'send',domain:'example.com',answers:{source:'own',route:'direct'},refresh:false})
  expect(title()).toContain('mail.setup.facts')
  expect(dialog().textContent).toContain('mail.setup.fact.package')
  await press('Next')
  // The branch needs Cloudflare: the own-domain route signs in with the token, no typed IDs.
  expect(title()).toContain('mail.setup.cloudflare')
  await fillVisible(0,'cf-token-value')
  await press('Next')
  expect(h.params('mail.setup.cloudflare')).toEqual([{id:ID,token:'cf-token-value'}])
  expect(visibleInputs().some(e=>(e as HTMLInputElement).value==='cf-token-value')).toBe(false)
  expect(title()).toContain('mail.setup.accountFor')
  // The domain is in the headline only; the line says the account holds it, with no "zone".
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-matched]')?.textContent).toBe('mail.setup.account.found')
  await press('Next')
  // Entering the account step lists the zones again (the match for the domain detected now), then binds the matched zone.
  expect(h.params('mail.setup.zones')).toEqual([{id:ID,accountId:'a'.repeat(32)},{id:ID,accountId:'a'.repeat(32),zoneId:'b'.repeat(32)}])
  expect(h.params('mail.setup.permissions')[0]).toEqual({id:ID,accountId:'a'.repeat(32),zoneId:'b'.repeat(32)})
  expect(title()).toContain('mail.setup.configuration')
  // The permissions are not listed raw on the configuration step: the preview folds them as purposes.
  expect(active().textContent).not.toContain('DNS Write')
  await press('Next')
  expect(h.params('mail.setup.preview')[0]).toEqual({id:ID})
  expect(title()).toContain('mail.setup.preview')
  // One plain line per change; the exact values only inside the details fold.
  expect(active().querySelector('[data-summary]')?.textContent).toContain('mail.setup.summary.dnsCloudflare')
  expect(active().textContent).not.toContain('TXT v=spf1 ~all')
  await openDetails()
  expect(active().querySelector('[data-technical]')?.textContent).toContain('TXT v=spf1 ~all')
  expect(h.methods()).not.toContain('mail.setup.apply')
  await press('ui.wizard.apply')
  expect(h.methods()).toContain('mail.setup.apply')
  await tick();await tick()
  expect(title()).toContain('mail.setup.verified')
  // One choice and one confirm action: Keep is pre-selected after verification.
  expect(radio('mail.setup.keep').checked).toBe(true)
  expect(()=>button('mail.setup.rollback',dialog())).toThrow()
  await press('ui.setup.confirmDecision')
  expect(h.params('mail.setup.decide')[0]).toEqual({id:ID,choice:'keep'})
  expect(title()).toContain('mail.setup.kept')
 }finally{h.close()}
})

test('setup: a slow preview shows reading progress, polls without the token, then a timed-out apply says the state is unconfirmed',async()=>{
 let previews=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[{name:'addresses',kind:'text',labelKey:'mail.setup.addresses',required:true}],warnings:[]}},
  'mail.setup.preview':()=>++previews<3?{changes:[],permissions:[],warnings:[],pending:true}:{changes:[change],permissions:[],warnings:[]},
  'mail.setup.apply':flow('applying',{total:1}),
  'mail.setup.status':flow('failed',{done:1,total:1,changes:[change],error:'mail.setup.unconfirmed'}),
 })
 try{
  await openSetup(h)
  await press('Next')
  await answerNetwork()
  await fillVisible(0,'example.com')
  await press('Next')
  await tick()
  expect(title()).toContain('mail.setup.facts')
  await press('Next')
  expect(title()).toContain('mail.setup.configuration')
  await fillVisible(0,'alice@example.com')
  await press('Next')
  // Still preparing: the configuration step shows that it is reading.
  expect(dialog().textContent).toContain('ui.setup.previewProgress')
  expect(dialog().textContent).toContain('ui.wait.elapsed')
  await tick();await tick()
  expect(title()).toContain('mail.setup.preview')
  // The token went out once; polls carry only the flow id.
  expect(h.params('mail.setup.preview')).toEqual([expect.objectContaining({id:ID,addresses:'alice@example.com'}),{id:ID,poll:true},{id:ID,poll:true}])
  await press('ui.wizard.apply')
  await tick()
  expect(dialog().querySelector('[data-unconfirmed]')?.textContent).toContain('mail.setup.unconfirmedBody')
  // Only an explicit rollback is offered; nothing is applied again.
  expect(radio('mail.setup.keep').disabled).toBe(true)
  expect(h.params('mail.setup.apply')).toHaveLength(1)
 }finally{h.close()}
})

test('setup: a timed-out apply that rolled back says why, neutrally; a step that never started says so',async()=>{
 for(const [status,expectText] of [
  [flow('rolledBack',{done:1,total:1,changes:[change],error:'mail.setup.unconfirmed',outcome:'rolledBack'}),'mail.setup.rolledBackAfterTimeout'],
  [flow('rolledBack',{done:1,total:1,changes:[change],error:'mail.setup.integrationUnavailable',outcome:'rolledBack'}),'mail.setup.rolledBackAfterProblem'],
  [flow('failed',{done:0,total:1,changes:[change],error:'mail.setup.notStarted'}),'mail.setup.notStarted'],
 ] as const){
  const h=harness({
   'mail.setup.start':flow(),
   'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[{name:'addresses',kind:'text',labelKey:'mail.setup.addresses',required:true}],warnings:[]}},
   'mail.setup.preview':{changes:[change],permissions:[],warnings:[]},
   'mail.setup.apply':flow('applying',{total:1}),
   'mail.setup.status':status,
  })
  try{
   await openSetup(h)
   await press('Next')
   await answerNetwork()
   await fillVisible(0,'example.com')
   await press('Next')
   await tick()
   await press('Next')
   await fillVisible(0,'alice@example.com')
   await press('Next')
   await press('ui.wizard.apply')
   await tick()
   expect(dialog().textContent).toContain(expectText)
   expect(dialog().textContent).not.toContain('ui.wizard.autoRolledBack')
  }finally{h.close()}
 }
})

test('setup: a MailPlus write refused for a missing grant names the step and the access, with Allow access',async()=>{
 const write={id:'mailplus.relay',target:'mailplus',actionKey:'mail.setup.change.mailplus.relay',params:{}}
 for(const [status,key] of [
  [flow('rolledBack',{done:1,total:2,changes:[change,write],error:'authority_required:mail-write',failedStep:'mailplus.relay',outcome:'rolledBack'}),'ui.setup.authority.rolledBack'],
  [flow('failed',{done:1,total:2,changes:[change,write],error:'authority_required:mail-write',failedStep:'mailplus.relay'}),'ui.setup.authority.failed'],
 ] as const){
  const h=harness({
   'mail.setup.start':flow(),
   'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[{name:'addresses',kind:'text',labelKey:'mail.setup.addresses',required:true}],warnings:[]}},
   'mail.setup.preview':{changes:[change,write],permissions:[],warnings:[]},
   'mail.setup.apply':flow('applying',{total:2}),
   'mail.setup.status':status,
  })
  try{
   await openSetup(h)
   await press('Next')
   await answerNetwork()
   await fillVisible(0,'example.com')
   await press('Next')
   await tick()
   await press('Next')
   await fillVisible(0,'alice@example.com')
   await press('Next')
   await press('ui.wizard.apply')
   await tick()
   const text=dialog().textContent!
   expect(text).toContain(`${key} step=mail.setup.change.mailplus.relay access=ui.authority.name.mail-write`)
   // No DSM code, no raw error code, no generic sentence.
   expect(text).not.toMatch(/authority_required|\b10[0-9]\b|mail\.setup\.integrationUnavailable|mail\.setup\.rolledBackAfterProblem/)
   expect(dialog().querySelector('[data-flow-access]')?.textContent).toContain('ui.access.needed')
  }finally{h.close()}
 }
})

test('setup: a blocked unknown branch lists each missing fact and why',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[{labelKey:'mail.setup.fact.package',value:'mail.setup.value.package.running',params:{version:'4.1.1-31785'}}],
   branch:{kind:'blocked',reason:'unknown',titleKey:'mail.setup.unknown',bodyKey:'mail.setup.unknownFactsBody',needsAccount:false,
    warnings:[{labelKey:'mail.setup.fact.addressing',value:'mail.setup.cause.notChecked',status:'warning'},{labelKey:'mail.setup.fact.domainDNS',value:'mail.setup.cause.noDomain',status:'warning'}]}},
 })
 try{
  await openSetup(h)
  await press('Next')
  await answerNetwork()
  await fillVisible(0,'sample-nas.test')
  await press('Next')
  await tick()
  expect(title()).toContain('mail.setup.facts')
  await press('Next')
  const missing=dialog().querySelector('[data-missing]')
  expect(missing?.textContent).toContain('mail.setup.fact.addressing')
  expect(missing?.textContent).toContain('mail.setup.fact.domainDNS')
  expect(dialog().textContent).toContain('mail.setup.unknownFactsBody')
 }finally{h.close()}
})

test('setup: a stop branch explains, checks again with a fresh detection and hands off to diagnosis',async()=>{
 let n=0
 const h=harness({
  'mail.setup.start':flow(),
  // Blocked until Check again's fresh detection, which finds MailPlus Server lacking the domain.
  'mail.setup.detect':(p:Record<string,unknown>)=>({done:true,facts:[{labelKey:'mail.setup.fact.package',value:'stopped',status:'warning'}],
   branch:!(p.refresh||n)?{kind:'blocked',reason:'stopped',titleKey:'mail.setup.stopped',bodyKey:'mail.setup.stoppedBody',needsAccount:false}
    :(n=1,configureMailPlus.branch)}),
  'mail.diagnose.start':{id:'r',symptom:'cannot-send',done:0,total:1,checks:['mail.diag.mailplus'],findings:[],complete:false},
 })
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick()
  expect(title()).toContain('mail.setup.facts')
  await press('Next')
  expect(title()).toContain('mail.setup.stopped')
  expect(dialog().textContent).toContain('mail.setup.stoppedBody')
  await press('ui.setup.checkAgain')
  expect(h.params('mail.setup.detect').at(-1)).toMatchObject({refresh:true})
  await tick()
  // MailPlus Server's own gap shows on the prerequisite step, never as a stop.
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(dialog().textContent).toContain('mail.setup.prereq.noDomain')
  expect(dialog().textContent).toContain('ui.setup.openMailPlus')
  await press('ui.setup.handoffDiagnose')
  expect(title()).toContain('mail.diag.wizard.symptom')
 }finally{h.close()}
})

test('setup: an unfinished transaction resumes at the decision and can be rolled back',async()=>{
 let rolled=false
 const h=harness({
  'mail.setup.start':flow('interrupted',{resume:true,intent:'send',domain:'example.com',changes:[change],done:1,total:1}),
  'mail.setup.decide':(p:Record<string,unknown>)=>{rolled=p.choice==='rollback';return flow('rollingBack',{total:1})},
  'mail.setup.status':()=>flow('rolledBack',{outcome:'rolledBack'}),
 })
 try{
  await settle()
  expect(h.root.querySelector('[data-resume]')).not.toBeNull()
  await press('ui.overview.resume')
  expect(title()).toContain('ui.wizard.failedTitle')
  expect(dialog().textContent).toContain('ui.setup.interruptedBody')
  // Keep is not offered for an interrupted transaction: the card is disabled, nothing is pre-selected.
  expect(radio('mail.setup.keep').disabled).toBe(true)
  expect(radio('mail.setup.rollback').checked).toBe(false)
  expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(true)
  await choose('mail.setup.rollback')
  expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(false)
  await press('ui.setup.confirmDecision')
  expect(rolled).toBe(true)
  await tick()
  expect(title()).toContain('mail.setup.rolledback')
 }finally{h.close()}
})

test('setup: the decision is one choice plus Confirm; choosing Roll back rolls back a verified change',async()=>{
 const h=harness({
  'mail.setup.start':flow('decision',{resume:true,intent:'send',domain:'example.com',changes:[change],done:1,total:1,verified:true}),
  'mail.setup.decide':flow('rollingBack',{total:1}),
  'mail.setup.status':()=>flow('rolledBack',{outcome:'rolledBack'}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  expect(title()).toContain('mail.setup.verified')
  expect(radio('mail.setup.keep').checked).toBe(true)
  expect(h.methods()).not.toContain('mail.setup.decide')
  await choose('mail.setup.rollback')
  expect(radio('mail.setup.rollback').checked).toBe(true)
  // Choosing alone writes nothing; Confirm sends the one decision.
  expect(h.methods()).not.toContain('mail.setup.decide')
  await press('ui.setup.confirmDecision')
  expect(h.params('mail.setup.decide')).toEqual([{id:ID,choice:'rollback'}])
  await tick()
  expect(title()).toContain('mail.setup.rolledback')
 }finally{h.close()}
})

for(const pick of ['keep','rollback'] as const){
 test(`setup: an unverified decision selects nothing and keeps Confirm disabled until ${pick} is picked`,async()=>{
  const h=harness({
   'mail.setup.start':flow('decision',{resume:true,intent:'send',domain:'example.com',changes:[change],done:1,total:1,verified:false}),
   'mail.setup.decide':(p:Record<string,unknown>)=>p.choice==='keep'?flow('kept',{changes:[change],verified:false}):flow('rollingBack',{total:1}),
   'mail.setup.status':()=>flow('rolledBack',{outcome:'rolledBack'}),
  })
  try{
   await settle()
   await press('ui.overview.resume')
   expect(title()).toContain('mail.setup.verificationFailed')
   expect(radio('mail.setup.keep').checked).toBe(false)
   expect(radio('mail.setup.rollback').checked).toBe(false)
   expect(radio('mail.setup.keep').disabled).toBe(false)
   expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(true)
   await press('ui.setup.confirmDecision')
   expect(h.methods()).not.toContain('mail.setup.decide')
   await choose(`mail.setup.${pick}`)
   expect(radio(`mail.setup.${pick}`).checked).toBe(true)
   expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(false)
   expect(h.methods()).not.toContain('mail.setup.decide')
   await press('ui.setup.confirmDecision')
   expect(h.params('mail.setup.decide')).toEqual([{id:ID,choice:pick}])
   if(pick==='rollback')await tick()
   expect(title()).toContain(pick==='keep'?'mail.setup.kept':'mail.setup.rolledback')
  }finally{h.close()}
 })
}

test('setup: a refusal for a missing grant offers the access consent',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,
   fields:[{name:'members',kind:'text',labelKey:'mail.setup.members',required:true},{name:'addresses',kind:'text',labelKey:'mail.setup.addresses',required:true}]}},
  'mail.setup.preview':refusal('authority_required',{profile:'mail-write'}),
 })
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await press('Next')
  expect(title()).toContain('mail.setup.configuration')
  await fillVisible(0,'alice');await fillVisible(1,'alice@example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.configuration')
  expect(dialog().textContent).toContain('ui.authority.profileBody')
  await press('ui.access.needed')
  expect(document.body.textContent).toContain('ui.authority.consentTitle')
 }finally{h.close()}
})

test('diagnose: runs one check per call with progress and ranks the result; Fix opens setup with the intent',async()=>{
 let done=0
 const finding={id:'mail.diag.dns.spf',module:'mail',check:'mail.diag.dns',severity:'warning',titleKey:'mail.diag.cause.spf',fixWizard:'mail.setup',params:{intent:'send'}}
 const h=harness({
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:2,checks:['a','b'],findings:[],complete:false},
  'mail.diagnose.next':()=>{done++;return {id:'run',symptom:'cannot-send',done,total:2,checks:['a','b'],findings:done===2?[finding]:[],complete:done===2,
   summary:done===2?{verdict:'problems',problems:[{key:'spf',severity:'warning',action:'setup',intent:'send',targets:['example.com'],findings:[finding.id]}],others:[]}:undefined}},
  'mail.setup.start':flow(),
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  expect(title()).toContain('mail.diag.wizard.symptom')
  await choose('mail.diag.symptom.cannot-receive')
  await press('Next')
  expect(h.params('mail.diagnose.start')[0]).toEqual({symptom:'cannot-receive'})
  await settle()
  expect(h.params('mail.diagnose.next')).toHaveLength(2)
  expect(title()).toContain('mail.diag.wizard.result')
  expect(active().dataset.tone).toBe('warning')
  expect(dialog().textContent).toContain('ui.diag.verdict.one')
  expect(dialog().textContent).toContain('mail.diag.problem.spf.title')
  await press('ui.diag.action.setup')
  expect(title()).toContain('mail.setup.intent')
  // The finding's intent is pre-selected.
  await press('Next')
  await answerNetwork()
  await fillVisible(0,'example.com')
 }finally{h.close()}
})

test('diagnose: a slow read shows what runs and the time waited, then completes',async()=>{
 let calls=0
 const pending={id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false,pending:true,phase:'reading'}
 const h=harness({
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false},
  'mail.diagnose.next':()=>++calls<4?pending:{id:'run',symptom:'cannot-send',done:1,total:1,checks:['a'],findings:[],complete:true},
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await press('Next')
  expect(title()).toContain('mail.diag.wizard.running')
  expect(dialog().textContent).toContain('ui.diag.reading')
  expect(dialog().textContent).toContain('ui.wait.elapsed')
  // Pending replies are paced, not repeated in a tight loop.
  expect(h.params('mail.diagnose.next')).toHaveLength(1)
  await tick();await tick();await tick()
  expect(h.params('mail.diagnose.next')).toHaveLength(4)
  expect(title()).toContain('mail.diag.wizard.result')
 }finally{h.close()}
})

test('diagnose: a missing read grant pauses the run and offers access',async()=>{
 const h=harness({
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false},
  'mail.diagnose.next':refusal('authority_required',{profile:'mail-read'}),
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await press('Next')
  expect(title()).toContain('mail.diag.wizard.running')
  expect(dialog().textContent).toContain('ui.authority.profileBody')
  await press('ui.access.needed')
  expect(document.body.textContent).toContain('ui.authority.consentTitle')
 }finally{h.close()}
})

// ---- UI 0.25 wizard features: progress and result steps, guard redirects, the DSM App launcher.
const active=()=>dialog().querySelector<HTMLElement>('section[data-active]')!
/** Opens the shown step's details fold (mail.setup.details). */
async function openDetails(){await press('mail.setup.details',active())}
async function closeWizard(){
 const close=[...dialog().querySelectorAll<HTMLButtonElement>('button[aria-label]')].find(b=>/close/i.test(b.getAttribute('aria-label')??''))
 if(!close)throw new Error('no close button')
 close.click();await settle()
 // A wizard with input asks first; Discard closes it.
 const discard=[...document.querySelectorAll<HTMLButtonElement>('[role=dialog] button,[role=alertdialog] button')].find(b=>b.textContent?.trim()==='Discard')
 if(discard){discard.click();await settle()}
}
type Desktop={AppLaunch?:ReturnType<typeof vi.fn>;StatusNotifier?:{isAppEnabled?:(id:string)=>boolean}}
function desktop(d:Desktop|undefined){(globalThis as {SYNO?:unknown}).SYNO=d?{SDS:d}:undefined}
afterEach(()=>desktop(undefined))

test('setup: clicking the disabled Keep card leaves the selection empty; a failed transaction offers only roll back',async()=>{
 let reads=0
 const h=harness({
  'mail.setup.start':flow('failed',{resume:true,intent:'send',domain:'example.com',changes:[change],done:1,total:1,outcome:'failed'}),
  'mail.setup.decide':flow('rollingBack',{total:1}),
  'mail.setup.status':()=>++reads<2?flow('rollingBack',{total:1}):flow('rolledBack',{outcome:'rolledBack'}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  // A failed transaction resumes at the decision, not at a result.
  expect(active().dataset.wizardStep).toBe('decision')
  expect(title()).toContain('ui.wizard.failedTitle')
  expect(dialog().textContent).toContain('ui.wizard.failedKeptBody')
  expect(radio('mail.setup.keep').disabled).toBe(true)
  await choose('mail.setup.keep')
  expect(radio('mail.setup.keep').checked).toBe(false)
  expect(radio('mail.setup.rollback').checked).toBe(false)
  expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(true)
  expect(h.methods()).not.toContain('mail.setup.decide')
  await choose('mail.setup.rollback')
  await press('ui.setup.confirmDecision')
  expect(h.params('mail.setup.decide')).toEqual([{id:ID,choice:'rollback'}])
  // The guard's {goTo:'applying'} shows the rollback on the progress step.
  expect(active().dataset.wizardStep).toBe('applying')
  expect(active().dataset.type).toBe('progress')
  await tick()
  expect(active().dataset.wizardStep).toBe('result')
  expect(active().dataset.tone).toBe('neutral')
 }finally{h.close()}
})

test('setup: reopening on another transaction resets the pick',async()=>{
 const OTHER='fedcba9876543210fedcba9876543210'
 let opened=0
 const h=harness({
  'mail.setup.start':()=>++opened<=2
   ?flow('decision',{resume:true,intent:'send',domain:'example.com',changes:[change],done:1,total:1,verified:false})
   :{...flow('decision',{resume:true,intent:'send',domain:'example.org',changes:[change],done:1,total:1,verified:false}),id:OTHER},
 })
 try{
  await settle()
  await press('ui.overview.resume')
  await choose('mail.setup.rollback')
  expect(radio('mail.setup.rollback').checked).toBe(true)
  await closeWizard()
  expect(document.querySelector('[role=dialog]')).toBeNull()
  await press('ui.overview.resume')
  expect(h.params('mail.setup.start').length).toBeGreaterThanOrEqual(3)
  expect(title()).toContain('mail.setup.verificationFailed')
  expect(radio('mail.setup.rollback').checked).toBe(false)
  expect(radio('mail.setup.keep').checked).toBe(false)
  expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(true)
 }finally{h.close()}
})

for(const [name,decided,tone] of [
 ['kept and verified','kept',{outcome:'ok',verified:true},'success'],
 ['kept unverified','kept',{outcome:'failed',verified:false},'warning'],
 ['rolled back after a failed check','rolledBack',{outcome:'rolledBack',error:'verify'},'warning'],
].map(([n,p,x,t])=>[n as string,flow(p as string,x as Record<string,unknown>),t as string] as const)){
 test(`setup: the result step's tone follows the outcome (${name} → ${tone})`,async()=>{
  const h=harness({'mail.setup.start':{...decided,resume:true,intent:'send',domain:'example.com'}})
  try{
   await settle()
   await press('ui.overview.resume')
   expect(active().dataset.wizardStep).toBe('result')
   expect(active().dataset.type).toBe('result')
   expect(active().dataset.tone).toBe(tone)
   expect(dialog().querySelector('[data-wizard-celebrate]:not([data-wizard-result])')).toBeNull()
  }finally{h.close()}
 })
}

test('setup: a failed status read keeps the progress and checks again without re-applying',async()=>{
 let reads=0
 const h=harness({
  'mail.setup.start':flow('applying',{resume:true,intent:'send',domain:'example.com',done:0,total:2}),
  'mail.setup.status':()=>++reads===1?{__throw:{code:'unavailable'}}:flow('decision',{done:2,total:2,changes:[change],verified:true}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  expect(active().dataset.wizardStep).toBe('applying')
  expect(dialog().textContent).toContain('ui.setup.statusStale')
  await tick(5000)
  expect(reads).toBe(1)
  await press('ui.setup.checkAgain')
  expect(title()).toContain('mail.setup.verified')
  expect(h.methods()).not.toContain('mail.setup.apply')
 }finally{h.close()}
})

const configureMailPlus={done:true,facts:[],branch:{kind:'configureMailPlus',reason:'configureMailPlus',titleKey:'mail.setup.prereq.noDomain',bodyKey:'mail.setup.prereq.noDomainBody',params:{domain:'example.com'},needsAccount:false}}
/** The user returns after the re-check interval (15 s since the last detection). */
async function comeBack(){await tick(15_000);window.dispatchEvent(new Event('focus'));await settle()}
/** To the prerequisite step: right after the domain, the detection says what MailPlus Server lacks. */
async function toHandoff(h:ReturnType<typeof harness>,titleKey='mail.setup.prereq.noDomain'){
 await openSetup(h)
 await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
 await tick()
 expect(active().dataset.wizardStep).toBe('prereq')
 expect(title()).toContain('mail.setup.prereq')
 expect(dialog().textContent).toContain(titleKey)
}

test('setup: Open MailPlus Server asks DSM to launch it; requested is not success and the step stays',async()=>{
 const AppLaunch=vi.fn()
 desktop({AppLaunch})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus})
 try{
  await toHandoff(h)
  // The manual path shows before and after the launch.
  expect(dialog().textContent).toContain('ui.setup.openMailPlus')
  const detects=h.params('mail.setup.detect').length
  await press('ui.setup.openMailPlusButton')
  expect(AppLaunch).toHaveBeenCalledTimes(1)
  expect(AppLaunch.mock.calls[0]![0]).toBe('SYNO.SDS.MailPlusServer.Instance')
  // DSM's AppLaunch calls config.hasOwnProperty(); SDK <= 0.53.19 passed a
  // prototype-free object, so the launch threw inside DSM (seen on a test NAS).
  const config=AppLaunch.mock.calls[0]![1] as {hasOwnProperty?:unknown}
  expect(typeof config.hasOwnProperty).toBe('function')
  expect(Object.getPrototypeOf(config)).toBe(Object.prototype)
  expect(dialog().querySelector('[data-launch]')?.textContent).toBe('ui.setup.launchRequested')
  expect(dialog().textContent).toContain('ui.setup.openMailPlus')
  await tick(5000)
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(h.params('mail.setup.detect')).toHaveLength(detects)
 }finally{h.close()}
})

for(const [status,d] of [['unsupported',undefined],['unavailable',{AppLaunch:vi.fn(),StatusNotifier:{isAppEnabled:()=>false}}],['failed',{AppLaunch:vi.fn(()=>{throw new Error('x')})}]] as const){
 test(`setup: a launcher answer of ${status} shows the manual path`,async()=>{
  desktop(d as Desktop|undefined)
  const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus})
  try{
   await toHandoff(h)
   await press('ui.setup.openMailPlusButton')
   expect(dialog().querySelector('[data-launch]')?.textContent).toBe('ui.setup.launchManual')
   expect(active().dataset.wizardStep).toBe('prereq')
  }finally{h.close()}
 })
}

test('setup: coming back re-checks in place and never moves the wizard; Check again moves on',async()=>{
 desktop({AppLaunch:vi.fn()})
 let configured=false
 const h=harness({'mail.setup.start':flow(),
  'mail.setup.detect':()=>configured?{done:true,facts:[],branch:{kind:'already',reason:'configured',titleKey:'mail.setup.configured',outcome:'ok',needsAccount:false}}:configureMailPlus})
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  await comeBack()
  expect(h.params('mail.setup.detect').at(-1)).toMatchObject({refresh:true})
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.still')
  configured=true
  await comeBack()
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.changed')
  // Still on the hand-off, never moved: the step now says MailPlus Server is ready and Next goes on.
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(dialog().textContent).toContain('mail.setup.prereq.ready')
  expect(()=>button('ui.setup.checkAgain',dialog())).toThrow()
  await press('Next')
  expect(active().dataset.wizardStep).toBe('facts')
  await press('Next')
  expect(active().dataset.wizardStep).toBe('already')
  expect(active().dataset.tone).toBe('success')
 }finally{h.close()}
})

test('setup: a re-check that cannot read the state says unknown',async()=>{
 desktop({AppLaunch:vi.fn()})
 let fail=false
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>fail?{__throw:{code:'unavailable'}}:configureMailPlus})
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  fail=true
  await comeBack()
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.unknown')
  expect(active().dataset.wizardStep).toBe('prereq')
 }finally{h.close()}
})

test('diagnose: running is a progress step and the result tone says what was found',async()=>{
 const clean={id:'run',symptom:'cannot-send',done:1,total:1,checks:['a'],findings:[],complete:true,summary:{verdict:'clear',problems:[],others:[{key:'ok',state:'ok',check:'mailplus'}]}}
 const h=harness({
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false},
  'mail.diagnose.next':clean,
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await press('Next')
  await settle()
  expect(active().dataset.wizardStep).toBe('result')
  expect(active().dataset.tone).toBe('success')
  expect(dialog().textContent).toContain('ui.diag.verdict.clear')
  expect(dialog().textContent).toContain('ui.diag.next.cannot-send')
 }finally{h.close()}
})

test('diagnose: Back on the progress step stops the run',async()=>{
 let release:(v:unknown)=>void=()=>{}
 const h=harness({
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:2,checks:['a','b'],findings:[],complete:false},
  'mail.diagnose.next':()=>new Promise(r=>{release=r}),
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await press('Next')
  expect(active().dataset.type).toBe('progress')
  await press('Back')
  expect(active().dataset.wizardStep).toBe('symptom')
  release({id:'run',symptom:'cannot-send',done:2,total:2,checks:['a','b'],findings:[],complete:true})
  await settle()
  expect(active().dataset.wizardStep).toBe('symptom')
  expect(h.params('mail.diagnose.next')).toHaveLength(1)
 }finally{h.close()}
})

// ---- Watching stops when closed, unclear is never success, the re-check is paced.
test('setup: closing on the detect step stops every detect call while closed',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:false}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick();await tick()
  expect(active().dataset.wizardStep).toBe('detect')
  await closeWizard()
  const calls=h.params('mail.setup.detect').length
  await tick(30_000)
  expect(h.params('mail.setup.detect')).toHaveLength(calls)
 }finally{h.close()}
})

test('setup: closing on the applying step stops every status call while closed',async()=>{
 const h=harness({
  'mail.setup.start':flow('applying',{resume:true,intent:'send',domain:'example.com',done:0,total:2}),
  'mail.setup.status':flow('applying',{done:1,total:2}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  await tick()
  expect(active().dataset.wizardStep).toBe('applying')
  await closeWizard()
  const calls=h.params('mail.setup.status').length
  await tick(30_000)
  expect(h.params('mail.setup.status')).toHaveLength(calls)
 }finally{h.close()}
})

for(const [name,state,tone] of [
 ['a failed transaction','',{outcome:'failed'},'danger'],
 ['an outcome the worker did not state','',{outcome:'unexpected'},'warning'],
].map(([n,p,x,t])=>[n as string,flow(p as string,x as Record<string,unknown>),t as string] as const)){
 test(`setup: the result tone for ${name} is ${tone}`,async()=>{
  const h=harness({'mail.setup.start':{...state,resume:true,intent:'send',domain:'example.com'}})
  try{
   await settle()
   await press('ui.overview.resume')
   expect(active().dataset.wizardStep).toBe('result')
   expect(active().dataset.tone).toBe(tone)
   expect(title()).toContain('ui.wizard.failedTitle')
  }finally{h.close()}
 })
}

for(const [name,branch,expected] of [
 ['blocked for an unknown reason',{kind:'blocked',reason:'unknown',titleKey:'mail.setup.unknown',needsAccount:false},'unknown'],
 ['an unavailable integration',{kind:'unavailable',titleKey:'mail.setup.integrationUnavailable',needsAccount:false},'unknown'],
 ['blocked because MailPlus Server stopped',{kind:'blocked',reason:'stopped',titleKey:'mail.setup.stopped',needsAccount:false},'changed'],
] as const){
 test(`setup: a re-check that finds ${name} says ${expected}`,async()=>{
  desktop({AppLaunch:vi.fn()})
  let after=false
  const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>after?{done:true,facts:[],branch}:configureMailPlus})
  try{
   await toHandoff(h)
   await press('ui.setup.openMailPlusButton')
   after=true
   await comeBack()
   expect(dialog().querySelector('[data-recheck]')?.textContent).toBe(`ui.setup.recheck.${expected}`)
   expect(active().dataset.wizardStep).toBe('prereq')
  }finally{h.close()}
 })
}

// A licence shortfall hands off to MailPlus Server like a missing domain; the
// re-check says "still" only while the reason is the same.
const licenseShort={done:true,facts:[],branch:{kind:'configureMailPlus',reason:'licenseShort',titleKey:'mail.setup.licenseShort',bodyKey:'mail.setup.licenseShortBody',params:{active:'6',licensed:'5'},needsAccount:false}}
for(const [name,after,expected] of [
 ['the same shortfall',licenseShort,'still'],
 ['a missing domain instead',configureMailPlus,'changed'],
] as const){
 test(`setup: a licence shortfall hands off to MailPlus Server; a re-check finding ${name} says ${expected}`,async()=>{
  desktop({AppLaunch:vi.fn()})
  let launched=false
  const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>launched?after:licenseShort})
  try{
   await toHandoff(h,'mail.setup.licenseShort')
   expect(dialog().textContent).toContain('mail.setup.licenseShortBody')
   await press('ui.setup.openMailPlusButton')
   launched=true
   await comeBack()
   expect(dialog().querySelector('[data-recheck]')?.textContent).toBe(`ui.setup.recheck.${expected}`)
   expect(active().dataset.wizardStep).toBe('prereq')
  }finally{h.close()}
 })
}

test('setup: focus coming back into the wizard re-checks on the prerequisite step, with or without a launch',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus})
 const refreshes=()=>h.params('mail.setup.detect').filter(p=>p.refresh).length
 const leaveAndReturn=async()=>{
  const inside=button('ui.setup.openMailPlusButton',dialog()),outside=h.root
  inside.dispatchEvent(new FocusEvent('focusout',{bubbles:true,relatedTarget:outside}))
  inside.dispatchEvent(new FocusEvent('focusin',{bubbles:true,relatedTarget:outside}))
  await settle()
 }
 try{
  await toHandoff(h)
  await tick(15_000)
  const before=refreshes()
  // The administrator may open MailPlus Server from the DSM menu: no launch is needed.
  await leaveAndReturn()
  expect(refreshes()).toBe(before+1)
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.still')
  // The page becoming visible again counts as coming back too.
  await tick(15_000)
  Object.defineProperty(document,'visibilityState',{configurable:true,get:()=>'visible'})
  document.dispatchEvent(new Event('visibilitychange'));await settle()
  expect(refreshes()).toBe(before+2)
  await press('ui.setup.openMailPlusButton')
  await tick(15_000)
  await leaveAndReturn()
  expect(refreshes()).toBe(before+3)
 }finally{h.close()}
})

test('setup: the re-check waits 15 s after the last detection and runs one at a time',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus})
 const refreshes=()=>h.params('mail.setup.detect').filter(p=>p.refresh).length
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  const before=refreshes()
  window.dispatchEvent(new Event('focus'));await settle()
  expect(refreshes()).toBe(before)
  await tick(12_000)
  window.dispatchEvent(new Event('focus'));await settle()
  expect(refreshes()).toBe(before)
  await comeBack()
  expect(refreshes()).toBe(before+1)
  // Right after a re-check, another focus does nothing.
  window.dispatchEvent(new Event('focus'));await settle()
  expect(refreshes()).toBe(before+1)
 }finally{h.close()}
})

test('setup: Check again during a re-check follows its job instead of starting another',async()=>{
 desktop({AppLaunch:vi.fn()})
 let polls=0,recheckStarted=false
 const h=harness({'mail.setup.start':flow(),
  'mail.setup.detect':(p:Record<string,unknown>)=>{
   if(!recheckStarted)return configureMailPlus
   if(p.refresh)return {done:false}
   return ++polls<2?{done:false}:configureMailPlus
  }})
 const refreshes=()=>h.params('mail.setup.detect').filter(p=>p.refresh).length
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  recheckStarted=true
  await comeBack()
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.checking')
  const before=refreshes()
  await press('ui.setup.checkAgain')
  expect(refreshes()).toBe(before)
  expect(h.params('mail.setup.detect').at(-1)).toMatchObject({refresh:false})
  // The answer is still being read: followed on the detect step, then back on the prerequisite step (still lacking).
  expect(active().dataset.wizardStep).toBe('detect')
  await tick();await tick()
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(refreshes()).toBe(before)
 }finally{h.close()}
})

test('setup: a detect failure that arrives after the wizard closed is dropped',async()=>{
 let fail:(e:unknown)=>void=()=>{}
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>new Promise((_,r)=>{fail=r})})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com')
  button('Next',dialog()).click();await settle()
  await closeWizard()
  await openSetup(h)
  expect(active().dataset.wizardStep).toBe('intent')
  fail({code:'unavailable'});await settle()
  // The abandoned guard's failure does not show on the reopened wizard.
  expect(dialog().querySelector('[role=alert]')).toBeNull()
 }finally{h.close()}
})

for(const [name,summary,tone] of [
 ['MailPlus Server it could not read',{verdict:'unreadable',problems:[],others:[]},'warning'],
 ['checks that could not read everything',{verdict:'unclear',problems:[],others:[{key:'unread',state:'unknown',check:'domain'}]},'neutral'],
 ['a problem',{verdict:'problems',problems:[{key:'smtp_off',severity:'critical',action:'mailplus',findings:['x']}],others:[]},'warning'],
 ['nothing found',{verdict:'clear',problems:[],others:[]},'success'],
] as const){
 test(`diagnose: a result with ${name} has the ${tone} tone`,async()=>{
  const h=harness({
   'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false},
   'mail.diagnose.next':{id:'run',symptom:'cannot-send',done:1,total:1,checks:['a'],findings:[],complete:true,summary},
  })
  try{
   await settle()
   await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
   await press('Next');await settle()
   expect(active().dataset.wizardStep).toBe('result')
   expect(active().dataset.tone).toBe(tone)
  }finally{h.close()}
 })
}

// ---- SDK 0.53.16 / CLI 0.52.11: the host's window-activated event.
const activations=(h:ReturnType<typeof harness>)=>h.subscribe.mock.calls.filter(([e])=>e==='window-activated').length
const refreshCount=(h:ReturnType<typeof harness>)=>h.params('mail.setup.detect').filter(p=>p.refresh).length

test('setup: with window-activated the host event re-checks on the prerequisite step; window focus is not used',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus},'subscribed')
 try{
  await toHandoff(h)
  // Watched from the moment the step shows; a launch adds nothing.
  expect(activations(h)).toBe(1)
  await press('ui.setup.openMailPlusButton')
  expect(activations(h)).toBe(1)
  await tick(15_000)
  const before=refreshCount(h)
  window.dispatchEvent(new Event('focus'));await settle()
  expect(refreshCount(h)).toBe(before)
  await h.activate()
  expect(refreshCount(h)).toBe(before+1)
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.still')
  // A refresh hint, never success: the wizard stays on the hand-off.
  expect(active().dataset.wizardStep).toBe('prereq')
  // A second launch does not subscribe twice.
  await press('ui.setup.openMailPlusButton')
  expect(activations(h)).toBe(1)
 }finally{h.close()}
})

test('setup: the window-activated subscription is disposed when the wizard closes',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus},'subscribed')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  expect(h.subscriptions).toEqual({made:1,disposed:0})
  await closeWizard()
  expect(h.subscriptions).toEqual({made:1,disposed:1})
  const calls=h.params('mail.setup.detect').length
  await tick(30_000);await h.activate()
  expect(h.params('mail.setup.detect')).toHaveLength(calls)
 }finally{h.close()}
})

test('setup: the window-activated subscription is disposed when the wizard leaves the hand-off and on unmount',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus,
  'mail.diagnose.start':{id:'r',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false}},'subscribed')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  await press('Back')
  expect(active().dataset.wizardStep).toBe('domain')
  expect(h.subscriptions).toEqual({made:1,disposed:1})
  await press('Next');await tick()
  expect(active().dataset.wizardStep).toBe('prereq')
  await press('ui.setup.openMailPlusButton')
  expect(h.subscriptions).toEqual({made:2,disposed:1})
 }finally{h.close()}
 expect(h.subscriptions).toEqual({made:2,disposed:2})
})

test('setup: an unsupported window-activated falls back to window focus',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus},'unsupported')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  expect(activations(h)).toBe(1)
  expect(h.subscriptions.made).toBe(0)
  const before=refreshCount(h)
  await comeBack()
  expect(refreshCount(h)).toBe(before+1)
 }finally{h.close()}
})

test('setup: a come-back inside the 15 s interval re-checks once when the interval ends',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus},'subscribed')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  const before=refreshCount(h)
  await h.activate();await h.activate()
  expect(refreshCount(h)).toBe(before)
  await tick(15_000)
  expect(refreshCount(h)).toBe(before+1)
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.still')
  await tick(30_000)
  expect(refreshCount(h)).toBe(before+1)
 }finally{h.close()}
})

test('setup: a deferred re-check is cancelled when the wizard closes',async()=>{
 desktop({AppLaunch:vi.fn()})
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus},'subscribed')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  await h.activate()
  await closeWizard()
  const calls=h.params('mail.setup.detect').length
  await tick(30_000)
  expect(h.params('mail.setup.detect')).toHaveLength(calls)
 }finally{h.close()}
})

test('setup: Check again starts a fresh detection when the re-check could not start one',async()=>{
 desktop({AppLaunch:vi.fn()})
 let reject:(e:unknown)=>void=()=>{},armed=false
 const h=harness({'mail.setup.start':flow(),
  'mail.setup.detect':(p:Record<string,unknown>)=>armed&&p.refresh?new Promise((_,r)=>{reject=r;armed=false}):configureMailPlus},'subscribed')
 try{
  await toHandoff(h)
  await press('ui.setup.openMailPlusButton')
  armed=true
  await tick(15_000);await h.activate()
  expect(dialog().querySelector('[data-recheck]')?.textContent).toBe('ui.setup.recheck.checking')
  const before=refreshCount(h)
  button('ui.setup.checkAgain',dialog()).click();await settle()
  reject({code:'unavailable'});await settle()
  expect(refreshCount(h)).toBe(before+1)
  expect(h.params('mail.setup.detect').at(-1)).toMatchObject({refresh:true})
  await tick()
  expect(active().dataset.wizardStep).toBe('prereq')
 }finally{h.close()}
})

// ---- The route step: asked right after the detection; replaces the Yes/No/Not sure questions.
const routeFacts=[
 {labelKey:'mail.setup.fact.package',value:'mail.setup.value.package.running',group:'mailplus',state:'ok',status:'ok'},
 {labelKey:'mail.setup.fact.ip',value:'mail.setup.value.text',params:{text:'203.0.113.24'},group:'network',state:'ok',status:'ok'},
 {labelKey:'mail.setup.fact.outbound',value:'mail.setup.value.reachable',group:'network',state:'ok',status:'ok'},
 {labelKey:'mail.setup.fact.ptr',value:'mail.setup.value.ptr.none',group:'network',state:'problem',status:'warning'},
]
const routeDetect=(facts:unknown[]=routeFacts)=>({done:true,facts,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}})
const routeStep=()=>dialog().querySelector<HTMLElement>('section[data-wizard-step="route"]')!
async function toRoute(h:ReturnType<typeof harness>,intent='mail.setup.intent.both'){
 await openSetup(h)
 await choose(intent)
 await press('Next')
 await startWith('own')
 await fillVisible(0,'example.com')
 await press('Next')
 await tick()
 expect(active().dataset.wizardStep).toBe('route')
}

test('setup: the route step offers Cloudflare or the own IP; the own IP shows its requirements and waits for the confirmation',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':routeDetect()})
 try{
  await toRoute(h)
  expect(title()).toContain('mail.setup.route')
  // Nothing is pre-selected: Next waits for a card.
  expect(button('Next',dialog()).disabled).toBe(true)
  expect(radio('mail.setup.route.cloudflare').checked).toBe(false)
  await chooseRoute('cloudflare',false)
  expect(routeStep().querySelector('[data-requirements]')).toBeNull()
  expect(button('Next',dialog()).disabled).toBe(false)
  // The own IP: requirements, the outside test for the detected IP, what the NAS detected; Next waits for the confirmation.
  const card=[...routeStep().querySelectorAll<HTMLElement>('[data-routes] [role=radio]')].find(x=>(x.closest('label')??x).textContent?.includes('mail.setup.route.direct'))!
  card.click();await settle()
  const req=routeStep().querySelector('[data-requirements]')!
  expect(req.textContent).toContain('mail.setup.route.fixedIp')
  expect(req.textContent).toContain('mail.setup.route.inbound')
  const link=req.querySelector<HTMLAnchorElement>('[data-smtp-test]')!
  expect(link.getAttribute('href')).toBe('https://mxtoolbox.com/SuperTool.aspx?action=smtp%3a203.0.113.24&run=toolpage')
  expect(link.textContent).toContain('mail.setup.route.test')
  expect(req.textContent).toContain('mail.setup.route.testNote')
  const detected=req.querySelector('[data-route-facts]')!
  for(const f of ['mail.setup.fact.ip','mail.setup.fact.outbound','mail.setup.fact.ptr'])expect(detected.textContent).toContain(f)
  // PTR is a problem: the page says the detected results do not meet the requirements.
  expect(req.querySelector('[data-checks-disagree]')).not.toBeNull()
  expect(button('Next',dialog()).disabled).toBe(true)
  // Not eligible: one press switches to Cloudflare.
  await press('mail.setup.route.useCloudflare')
  expect(radio('mail.setup.route.cloudflare').checked).toBe(true)
  expect(routeStep().querySelector('[data-requirements]')).toBeNull()
  // Back to the own IP: the confirmation is asked again.
  card.click();await settle()
  expect(button('Next',dialog()).disabled).toBe(true)
  await chooseRoute('direct',false)
  expect(button('Next',dialog()).disabled).toBe(false)
  await press('Next')
  expect(h.params('mail.setup.detect').at(-1)).toEqual({id:ID,intent:'both',domain:'example.com',answers:{source:'own',route:'direct'},refresh:false})
  expect(active().dataset.wizardStep).toBe('facts')
 }finally{h.close()}
})

test('setup: sending alone asks no inbound port and links no outside test; without a detected IP the link opens the tool page',async()=>{
 const noIp=routeFacts.map(f=>f.labelKey==='mail.setup.fact.ip'?{...f,value:'mail.setup.cause.ipUnknown',params:undefined,state:'unknown',status:'info'}:f)
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':routeDetect(noIp)})
 try{
  await toRoute(h,'mail.setup.intent.send')
  await chooseRoute('direct',false)
  const req=routeStep().querySelector('[data-requirements]')!
  expect(req.textContent).toContain('mail.setup.route.fixedIp')
  expect(req.textContent).not.toContain('mail.setup.route.inbound')
  expect(req.querySelector('[data-smtp-test]')).toBeNull()
  expect(req.querySelector('[data-route-facts]')?.textContent).toContain('mail.setup.fact.outbound')
 }finally{h.close()}
 const r=harness({'mail.setup.start':flow(),'mail.setup.detect':routeDetect(noIp)})
 try{
  await toRoute(r,'mail.setup.intent.receive')
  await chooseRoute('direct',false)
  const link=routeStep().querySelector<HTMLAnchorElement>('[data-smtp-test]')!
  expect(link.getAttribute('href')).toBe('https://mxtoolbox.com/SuperTool.aspx')
  expect(link.textContent).toContain('mail.setup.route.testNoIp')
  // Receiving alone: outbound 25 and PTR are not shown as requirements.
  expect(routeStep().querySelector('[data-route-facts]')?.textContent).not.toContain('mail.setup.fact.ptr')
 }finally{r.close()}
})

test('setup: the first detection runs without a route; the chosen route goes with every later call and re-decides without a new read',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':routeDetect()})
 try{
  await toRoute(h,'mail.setup.intent.receive')
  const sent=h.params('mail.setup.detect')
  expect(sent[0]!.answers).toEqual({source:'own'})
  const before=sent.length
  await chooseRoute('cloudflare')
  const after=h.params('mail.setup.detect').slice(before)
  expect(after.length).toBeGreaterThan(0)
  for(const p of after)expect(p).toMatchObject({intent:'receive',answers:{source:'own',route:'cloudflare'},refresh:false})
  expect(active().dataset.wizardStep).toBe('facts')
  // Back from the facts returns to the route, with the choice kept.
  await press('Back')
  expect(active().dataset.wizardStep).toBe('route')
  expect(radio('mail.setup.route.cloudflare').checked).toBe(true)
 }finally{h.close()}
})

test('setup: the facts, stop and configuration steps say which path was chosen and why',async()=>{
 const paths=[
  {direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:['mail.setup.why.fcrdnsFail']},
  {direction:'receive',branch:'cloudflare-routing',titleKey:'mail.setup.path.cloudflare-routing',why:['mail.setup.why.routeCloudflare','mail.setup.why.ipUnknown']},
 ]
 for(const branch of [
  {kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[],paths,mailboxes:['alice@example.com']},
  {kind:'blocked',reason:'moveDNS',titleKey:'mail.setup.moveDNS',bodyKey:'mail.setup.moveDNSBody',needsAccount:false,paths},
 ]){
  const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch}})
  try{
   await openSetup(h)
   await choose('mail.setup.intent.both')
   await press('Next')
   await answerNetwork()
   await fillVisible(0,'example.com')
   await press('Next')
   await tick()
   expect(title()).toContain('mail.setup.facts')
   const shown=()=>dialog().querySelector('section:not([aria-hidden="true"]) [data-paths]')
   // The own-IP route was chosen: the facts say which directions moved to Cloudflare and why, never "because you chose".
   const moved=active().querySelector('[data-moved-paths]')
   for(const text of ['mail.setup.pathChanged.send','mail.setup.why.fcrdnsFail','mail.setup.pathChanged.receive','mail.setup.why.ipUnknown'])
    expect(moved?.textContent).toContain(text)
   expect(active().textContent).not.toContain('mail.setup.why.routeCloudflare')
   expect(shown()).toBeNull()
   await press('Next')
   if(branch.kind==='configure'){
    // The configuration step does not echo the path the administrator just saw: it says the consequences.
    expect(title()).toContain('mail.setup.configurationFor')
    expect(shown()).toBeNull()
    continue
   }
   expect(title()).toContain('mail.setup.moveDNS')
   expect(shown()?.textContent).toContain('mail.setup.why.fcrdnsFail')
   expect(shown()?.querySelectorAll('[data-path]')).toHaveLength(2)
   // The stop step drops the echo of the chosen route too.
   expect(shown()?.textContent).not.toContain('mail.setup.why.routeCloudflare')
  }finally{h.close()}
 }
})

test('setup: a facts step without decided paths shows no path section',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:{kind:'already',reason:'alreadyCorrect',titleKey:'mail.setup.alreadyCorrect',outcome:'ok',needsAccount:false}}})
 try{
  await openSetup(h)
  await press('Next')
  await answerNetwork()
  await fillVisible(0,'example.com')
  await press('Next')
  await tick()
  expect(title()).toContain('mail.setup.facts')
  expect(dialog().querySelector('[data-paths]')).toBeNull()
 }finally{h.close()}
})

test('setup: the facts step asks for more evidence only when a shown fact is really unknown (not just not checked)',async()=>{
 const known={labelKey:'mail.setup.fact.package',value:'mail.setup.value.package.running',params:{version:'4.1.1-31785'}}
 const unknown={labelKey:'mail.setup.fact.dns',value:'mail.setup.cause.dnsUnknown'}
 // "Not checked by this version" is unknown by design, not missing evidence.
 const notChecked={labelKey:'mail.setup.fact.addressing',value:'mail.setup.cause.notChecked'}
 // Certain negatives are not missing evidence either.
 const noDomain={labelKey:'mail.setup.fact.domainDNS',value:'mail.setup.cause.noDomain'}
 const ptrNone={labelKey:'mail.setup.fact.ptr',value:'mail.setup.cause.ptrNone'}
 const notInMailPlus={labelKey:'mail.setup.fact.accounts',value:'mail.setup.cause.notInMailPlus'}
 // More accounts than the app reads: really unknown.
 const tooManyAccounts={labelKey:'mail.setup.fact.accounts',value:'mail.setup.cause.accountsTooLarge'}
 for(const [facts,shown] of [[[known],false],[[known,notChecked,tooManyAccounts],true],[[known,notChecked],false],[[known,noDomain,ptrNone,notInMailPlus,notChecked],false],[[known,notChecked,unknown],true],[[known,noDomain,unknown],true]] as const){
  const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts,branch:{kind:'already',reason:'alreadyCorrect',titleKey:'mail.setup.alreadyCorrect',outcome:'ok',needsAccount:false}}})
  try{
   await openSetup(h)
   await press('Next')
   await answerNetwork()
   await fillVisible(0,'example.com')
   await press('Next')
   await tick()
   expect(title()).toContain('mail.setup.facts')
   const step=dialog().querySelector('section:not([aria-hidden="true"])')
   expect(step?.textContent).toContain('mail.setup.fact.package')
   expect(step?.textContent?.includes('mail.setup.factsBody')).toBe(shown)
  }finally{h.close()}
 }
})

const configureBranch={kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[{name:'addresses',kind:'text',labelKey:'mail.setup.addresses',required:true}],warnings:[]}
async function toConfiguration(h:ReturnType<typeof harness>){
 await openSetup(h)
 await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
 await tick()
 await press('Next')
 expect(title()).toContain('mail.setup.configuration')
}

test('setup: leaving the configuration step stops the preview polling, and its late error shows nowhere',async()=>{
 let polls=0
 let reject:((e:unknown)=>void)|undefined
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:configureBranch},
  // The first poll hangs until the test lets it fail.
  'mail.setup.preview':(p:Record<string,unknown>)=>p.poll&&++polls===1?new Promise((_,r)=>{reject=r}):{changes:[],permissions:[],warnings:[],pending:true},
 })
 try{
  await toConfiguration(h)
  await fillVisible(0,'alice@example.com')
  await press('Next')
  await tick()
  expect(dialog().textContent).toContain('ui.setup.previewProgress')
  expect(reject).toBeDefined()
  // The wizard holds the step while its guard runs; closing is the way out.
  await closeWizard()
  await openSetup(h)
  expect(title()).toContain('mail.setup.intent')
  // The abandoned poll fails late: its error must not reach the new wizard.
  reject!({code:'conflict',details:{reason:'mail.setup.planChanged'}})
  for(let i=0;i<5;i++)await tick()
  expect(title()).toContain('mail.setup.intent')
  expect(dialog().querySelector('[role=alert]')).toBeNull()
  expect(h.params('mail.setup.preview').filter(p=>p.poll)).toHaveLength(1)
 }finally{h.close()}
})

test('setup: a plan changed before apply offers to generate the preview again',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:configureBranch},
  'mail.setup.preview':{changes:[change],permissions:[],warnings:[]},
  'mail.setup.apply':refusal('conflict',{reason:'mail.setup.planChanged'}),
 })
 try{
  await toConfiguration(h)
  await fillVisible(0,'alice@example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.preview')
  await press('ui.wizard.apply')
  // The worker refused the old plan: its own reason, not stalePlan, and a way on.
  expect(title()).toContain('mail.setup.preview')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-regenerate]')).not.toBeNull()
  await press('ui.setup.regeneratePreview',dialog().querySelector('section:not([aria-hidden="true"])')!)
  expect(title()).toContain('mail.setup.configuration')
  expect(dialog().querySelector('[role=alert]')).toBeNull()
  // The sealed token was dropped from the page: type it again, then preview anew.
  await fillVisible(0,'alice@example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.preview')
  expect(h.params('mail.setup.preview')).toHaveLength(2)
  expect(h.params('mail.setup.apply')).toHaveLength(1)
 }finally{h.close()}
})

test('setup: a plan changed while the preview was prepared can be generated again on the spot',async()=>{
 let calls=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:configureBranch},
  'mail.setup.preview':()=>++calls===1?refusal('conflict',{reason:'mail.setup.planChanged'}):{changes:[change],permissions:[],warnings:[]},
 })
 try{
  await toConfiguration(h)
  await fillVisible(0,'alice@example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.configuration')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-regenerate]')).not.toBeNull()
  // A failed preview keeps the typed fields, so the button works at once.
  await press('ui.setup.regeneratePreview',dialog().querySelector('section:not([aria-hidden="true"])')!)
  await tick()
  expect(title()).toContain('mail.setup.preview')
  expect(h.params('mail.setup.preview')).toEqual([expect.objectContaining({addresses:'alice@example.com'}),expect.objectContaining({addresses:'alice@example.com'})])
  await openDetails()
  expect(active().textContent).toContain('TXT v=spf1 ~all')
 }finally{h.close()}
})

// ---- a round that ends late leaves the newer round alone.
test('setup: an abandoned detect round that ends after a new round started does not freeze its elapsed counter',async()=>{
 vi.useFakeTimers({toFake:['setTimeout','clearTimeout','setInterval','clearInterval','Date']})
 let n=0
 let finish:((v:unknown)=>void)|undefined
 // Call 1 starts round A; its first poll (call 2) hangs until the test ends it. Later calls are pending detections.
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>++n===2?new Promise(r=>{finish=r}):{done:false}})
 const elapsed=()=>[...active().querySelectorAll('.msa-quiet')].map(e=>e.textContent?.trim()).find(t=>t?.startsWith('ui.wait.elapsed'))
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick()
  expect(finish).toBeDefined()
  await press('Back')
  expect(active().dataset.wizardStep).toBe('domain')
  await press('Next')
  expect(active().dataset.wizardStep).toBe('detect')
  // Round A's poll answers now: it is dropped, and its end must not stop round B's counter.
  finish!({done:false});await settle()
  await tick(3000)
  expect(elapsed()).toBe('ui.wait.elapsed 3')
 }finally{h.close()}
})

// ---- each stop-polling layer alone. The parent setting open=false
// (here: opening the diagnose wizard) closes setup without its close button and
// without a step change; Back changes the step while the dialog stays open.
async function closeByParent(h:ReturnType<typeof harness>){
 h.root.querySelector<HTMLButtonElement>('[data-open="mail.diagnose"]')!.click();await settle()
}
test('setup: the parent closing the wizard (open=false only) stops the detect polling',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:false},
  'mail.diagnose.start':{id:'r',symptom:'cannot-send',done:0,total:1,checks:[],findings:[],complete:false}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick();await tick()
  expect(active().dataset.wizardStep).toBe('detect')
  const before=h.params('mail.setup.detect').length
  await closeByParent(h)
  expect(document.body.textContent).toContain('mail.diag.wizard.symptom')
  await tick(30_000)
  expect(h.params('mail.setup.detect')).toHaveLength(before)
 }finally{h.close()}
})

test('setup: the parent closing the wizard (open=false only) stops the status polling',async()=>{
 const h=harness({
  'mail.setup.start':flow('applying',{resume:true,intent:'send',domain:'example.com',done:0,total:2}),
  'mail.setup.status':flow('applying',{done:1,total:2}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  await tick()
  expect(active().dataset.wizardStep).toBe('applying')
  const before=h.params('mail.setup.status').length
  await closeByParent(h)
  await tick(30_000)
  expect(h.params('mail.setup.status')).toHaveLength(before)
 }finally{h.close()}
})

test('setup: Back on the detect step (step change only, still open) stops the detect polling',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:false}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick();await tick()
  await press('Back')
  expect(active().dataset.wizardStep).toBe('domain')
  const before=h.params('mail.setup.detect').length
  await tick(30_000)
  expect(h.params('mail.setup.detect')).toHaveLength(before)
 }finally{h.close()}
})

test('setup: Check again keeps the stop step whole while it runs and after it fails',async()=>{
 let n=0
 let fail:((e:unknown)=>void)|undefined
 const stopped={done:true,facts:[],branch:{kind:'blocked',reason:'stopped',titleKey:'mail.setup.stopped',bodyKey:'mail.setup.stoppedBody',needsAccount:false,
  records:[change]}}
 // Detections before Check again (the domain's, the route's) answer at once; Check again's fresh one hangs, then fails.
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':(p:Record<string,unknown>)=>(p.refresh&&++n)?new Promise((_,r)=>{fail=r}):stopped})
 const stopWhole=()=>{
  expect(active().dataset.wizardStep).toBe('stop')
  expect(title()).toContain('mail.setup.stopped')
  expect(active().textContent).toContain('mail.setup.stoppedBody')
  expect(active().textContent).toContain('ui.setup.records')
 }
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
  await tick()
  await press('Next')
  stopWhole()
  button('ui.setup.checkAgain',dialog()).click();await settle()
  expect(fail).toBeDefined()
  stopWhole()
  fail!({code:'unavailable'});await settle()
  stopWhole()
  expect(active().querySelector('[role=alert]')).not.toBeNull()
 }finally{h.close()}
})

test('setup: a mail.setup.start reply that arrives after a fast close and reopen is dropped',async()=>{
 // The overview also calls mail.setup.start; only the wizard's openings are held.
 let hold=false
 const held:{resolve:(v:unknown)=>void;reject:(e:unknown)=>void}[]=[]
 const h=harness({'mail.setup.start':()=>hold?new Promise((resolve,reject)=>{held.push({resolve,reject})}):flow()})
 async function openHeld(){hold=true;await openSetup(h);hold=false;expect(held).not.toHaveLength(0);return held.at(-1)!}
 try{
  const first=await openHeld()
  await closeWizard()
  const second=await openHeld()
  expect(second).not.toBe(first)
  // The reopened wizard's own start answers first: a new flow.
  second.resolve(flow());await settle()
  // The first opening's reply comes late: a flow to resume at the decision. It must not move the wizard.
  first.resolve(flow('decision',{resume:true,intent:'send',domain:'old.example',changes:[change],verified:true}));await settle()
  expect(active().dataset.wizardStep).toBe('intent')
  await press('Next');await answerNetwork()
  expect((visibleInputs()[0] as HTMLInputElement).value).toBe('')
  // A late failure of an abandoned opening shows nowhere either.
  await closeWizard()
  const third=await openHeld()
  await closeWizard()
  const fourth=await openHeld()
  third.reject({code:'unavailable'});await settle()
  fourth.resolve(flow());await settle()
  expect(dialog().querySelector('[role=alert]')).toBeNull()
 }finally{h.close()}
})

// ---- Discard asks only about what the user typed in this opening.
/** Presses the close button and reports whether the wizard asked to discard (then discards). */
async function closeAsks(){
 const close=[...dialog().querySelectorAll<HTMLButtonElement>('button[aria-label]')].find(b=>/close/i.test(b.getAttribute('aria-label')??''))!
 close.click();await settle()
 const discard=[...document.querySelectorAll<HTMLButtonElement>('[role=dialog] button,[role=alertdialog] button')].find(b=>b.textContent?.trim()==='Discard')
 if(discard){discard.click();await settle()}
 return discard!==undefined
}
test('setup: closing a resumed flow without edits does not ask to discard',async()=>{
 const h=harness({'mail.setup.start':flow('decision',{resume:true,intent:'send',domain:'example.com',changes:[change],verified:true})})
 try{
  await settle()
  await press('ui.overview.resume')
  expect(active().dataset.wizardStep).toBe('decision')
  expect(await closeAsks()).toBe(false)
  expect(document.querySelector('[role=dialog]')).toBeNull()
 }finally{h.close()}
})
test('setup: a domain typed in this opening asks before closing; reopening without typing does not',async()=>{
 const h=harness({'mail.setup.start':flow()})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'example.com')
  expect(await closeAsks()).toBe(true)
  await openSetup(h)
  expect(await closeAsks()).toBe(false)
 }finally{h.close()}
})

// ---- Every value typed in this opening asks before closing.
/** To the configuration (or account) step with the domain the opening already holds, so only what is typed there counts. */
async function toStepKeepingDomain(h:ReturnType<typeof harness>,at:string){
 await openSetup(h)
 await press('Next');await answerNetwork();await fillVisible(0,'example.com');await press('Next')
 await tick()
 await press('Next')
 expect(active().dataset.wizardStep).toBe(at)
}
test('setup: a token typed on the configuration step asks before closing',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:configureBranch}})
 try{
  // The first opening types the domain; the next openings keep it, so it no longer counts.
  await toStepKeepingDomain(h,'configuration')
  expect(await closeAsks()).toBe(true)
  await toStepKeepingDomain(h,'configuration')
  expect(await closeAsks()).toBe(false)
  await toStepKeepingDomain(h,'configuration')
  await fillVisible(0,'alice@example.com')
  expect(await closeAsks()).toBe(true)
 }finally{h.close()}
})
test('setup: a pasted token, or a sign-in already made, asks before closing',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:{...configureBranch,needsAccount:true}},
  'mail.setup.cloudflare':signedIn()})
 try{
  await toStepKeepingDomain(h,'cloudflare')
  expect(await closeAsks()).toBe(true)
  await toStepKeepingDomain(h,'cloudflare')
  expect(await closeAsks()).toBe(false)
  await toStepKeepingDomain(h,'cloudflare')
  await fillVisible(0,'cf-token-value')
  expect(await closeAsks()).toBe(true)
  await toStepKeepingDomain(h,'cloudflare')
  await fillVisible(0,'cf-token-value');await press('Next')
  expect(active().dataset.wizardStep).toBe('account')
  expect(await closeAsks()).toBe(true)
 }finally{h.close()}
})

// ---- Path B: Cloudflare from the start.
/** Opens the shown step's Select inside [data-<name>] and returns its options. */
async function openSelect(name:string){
 const t=dialog().querySelector<HTMLElement>(`section:not([aria-hidden="true"]) [data-${name}] [role=combobox]`)
 if(!t)throw new Error(`no select ${name}`)
 t.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));await settle()
 return [...document.querySelectorAll<HTMLElement>('[role=option]')]
}
async function selectOption(name:string,label:string){
 const o=(await openSelect(name)).find(x=>x.textContent?.trim()===label)
 if(!o)throw new Error(`no option ${label}`)
 o.dispatchEvent(new KeyboardEvent('keydown',{key:'Enter',bubbles:true}));await settle()
}
const cfBranch={kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[],
 paths:[{direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:['mail.setup.why.routeCloudflare']}]}
const A='a'.repeat(32),B='b'.repeat(32),C='c'.repeat(32),P='d'.repeat(32)
/** intent → start (Cloudflare) → token step, signed in on Next. */
async function toZone(h:ReturnType<typeof harness>){
 await openSetup(h)
 await press('Next')
 await startWith('cloudflare')
 expect(title()).toContain('mail.setup.cloudflare')
 await fillVisible(0,'cf-token-value')
 await press('Next')
}

test('setup B: start → token → zone → detect → route → facts → configuration → preview, with no typed IDs',async()=>{
 const opened:string[]=[]
 vi.spyOn(window,'open').mockImplementation((url?:string|URL)=>{opened.push(String(url));return null})
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':signedIn({match:undefined}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,mailDomains:p.zoneId?['example.com']:[],mailDomainsState:p.zoneId?'read':''}),
  'mail.setup.detect':{done:true,facts:[],branch:cfBranch},
  'mail.setup.preview':{changes:[change],permissions:[],warnings:[]},
 })
 try{
  await openSetup(h)
  await press('Next')
  await startWith('cloudflare')
  expect(title()).toContain('mail.setup.cloudflare')
  // The create-token button pre-fills the documented permission keys.
  await press('mail.setup.cloudflare.create',dialog())
  // The account token form, every permission filled in by its canonical group ID.
  expect(opened[0]!.startsWith('https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=')).toBe(true)
  expect(opened[0]!.endsWith('&name=MailPlus%20Setup%20Assistant')).toBe(true)
  const url=new URL(opened[0]!)
  expect(JSON.parse(url.searchParams.get('permissionGroupKeys')!).map((p:{key:string})=>p.key)).toEqual([
   'c8fed203ed3043cba015a93ad1616f1f','4755a26eedb94da69e1066d98aa820be','5df633d6b41c42bcaf5b4a62b9d14b64',
   // Inbound: one token carries every permission.
   '3030687196b94b638145a3953da2b699','79b3ec0d10ce4148a8f8bdc0cc5f97f2','e086da7e2179491d91ee5f35b3ca210a',
   '77efc2c0724d4c4eb94bfd9656247130','efea2ab8357b47888938f101ae5e053f'])
  expect(url.searchParams.has('accountId')).toBe(false)
  expect(url.searchParams.has('zoneId')).toBe(false)
  // One line, three numbered steps (the second says all zones by default, narrowable), the button, the field.
  const tokenStep=dialog().querySelector('section[data-wizard-step="cloudflare"]')!
  const steps=tokenStep.querySelector('[data-token-steps]')!
  for(const key of ['mail.setup.cloudflare.step1','mail.setup.cloudflare.step2','mail.setup.cloudflare.step2Hint','mail.setup.cloudflare.step3'])expect(steps.textContent).toContain(key)
  // The permissions are folded under their count, one per line, never a run-on sentence.
  const fold=tokenStep.querySelector('[data-permissions]')!
  expect(fold.textContent).toContain('mail.setup.cloudflare.permissions')
  expect(tokenStep.querySelectorAll('[data-permission]')).toHaveLength(0)
  ;[...fold.querySelectorAll<HTMLElement>('button')].find(b=>b.textContent?.includes('mail.setup.cloudflare.permissions'))!.click();await settle()
  expect([...tokenStep.querySelectorAll('[data-permission]')].map(e=>e.textContent?.trim())).toEqual(
   ['zoneRead','dnsEdit','sendingEdit','zoneSettingsEdit','routingRulesEdit','workersEdit','vpcAdmin','tunnelRead'].map(c=>`mail.setup.cloudflare.permission.${c}`))
  // Short notes: the token is the relay's password, sign-in reads cannot prove a write.
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-relay-note]')?.textContent).toContain('mail.setup.cloudflare.relayNote')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-read-only-check]')?.textContent).toContain('mail.setup.cloudflare.readOnlyCheck')
  // The token lasts one setup run (start forgets it; an upgrade reopens the wizard).
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-one-run]')?.textContent).toContain('mail.setup.cloudflare.oneRun')
  expect(button('Next',dialog()).disabled).toBe(true)
  await fillVisible(0,'cf-token-value')
  await press('Next')
  expect(h.params('mail.setup.cloudflare')).toEqual([{id:ID,token:'cf-token-value'}])
  // Sealed: the token is gone from the page.
  expect(dialog().querySelectorAll<HTMLInputElement>('input[type=password]')).toSatisfy((l:NodeListOf<HTMLInputElement>)=>[...l].every(e=>e.value===''))
  expect(title()).toContain('mail.setup.zone')
  // One account: chosen silently, no account dropdown.
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-account]')).toBeNull()
  expect(button('Next',dialog()).disabled).toBe(true)
  await selectOption('zones','example.com')
  // Choosing the zone reads it at once; its one MailPlus domain is preselected.
  expect(h.params('mail.setup.zones')).toEqual([{id:ID,accountId:A,zoneId:B}])
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-mail-domains]')).not.toBeNull()
  expect(h.methods()).not.toContain('mail.setup.detect')
  // Leaving the zone starts the detection at once; the route is asked after it, as on the own-domain path.
  await press('Next')
  expect(h.params('mail.setup.zones')).toEqual([{id:ID,accountId:A,zoneId:B}])
  expect(h.params('mail.setup.detect')[0]).toEqual({id:ID,intent:'send',domain:'example.com',answers:{source:'cloudflare'},refresh:false})
  await tick()
  expect(title()).toContain('mail.setup.route')
  await chooseRoute('cloudflare')
  expect(title()).toContain('mail.setup.facts')
  // The Cloudflare route was chosen: the facts do not echo it.
  expect(active().textContent).not.toContain('mail.setup.why.routeCloudflare')
  expect(active().querySelector('[data-moved-paths]')).toBeNull()
  await press('Next')
  expect(title()).toContain('mail.setup.configuration')
  await press('Next')
  // The relay path reads the zone again (Email Sending) before the plan.
  expect(h.params('mail.setup.zones')).toEqual([{id:ID,accountId:A,zoneId:B},{id:ID,accountId:A,zoneId:B}])
  expect(h.params('mail.setup.preview')[0]).toEqual({id:ID})
  expect(title()).toContain('mail.setup.preview')
  expect(h.methods()).not.toContain('mail.setup.permissions')
  for(const p of h.params('mail.setup.detect').slice(1))expect(p.answers).toEqual({source:'cloudflare',route:'cloudflare'})
 }finally{h.close();vi.restoreAllMocks()}
})

test('setup B: several accounts are a dropdown; a pending zone is listed but cannot be chosen; the mail domain is picked from MailPlus',async()=>{
 const zones:Record<string,unknown[]>={[A]:[{id:B,name:'example.com',status:'active'},{id:P,name:'waiting.com',status:'pending'}],[C]:[]}
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':{accounts:[{id:A,name:'Home'},{id:C,name:'Work'}],zones:[],missing:[],mailDomains:[]},
  'mail.setup.zones':(p)=>({accounts:[{id:A,name:'Home'},{id:C,name:'Work'}],accountId:p.accountId,zones:zones[p.accountId as string],zoneId:p.zoneId,missing:[],
   mailDomains:p.zoneId?['a.b.example.com','mail.example.com']:[],mailDomainsState:p.zoneId?'read':''}),
  'mail.setup.detect':{done:false},
 })
 try{
  await toZone(h)
  expect(title()).toContain('mail.setup.zone')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-zones]')).toBeNull()
  await selectOption('account','Home')
  expect(h.params('mail.setup.zones')[0]).toEqual({id:ID,accountId:A})
  const options=await openSelect('zones')
  expect(options.map(o=>o.textContent?.trim())).toEqual(['example.com','mail.setup.zone.pending'])
  expect(options[1]!.hasAttribute('data-disabled')).toBe(true)
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));await settle()
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-pending-note]')?.textContent).toContain('mail.setup.zone.pendingNote')
  await selectOption('zones','example.com')
  expect(h.params('mail.setup.zones')[1]).toEqual({id:ID,accountId:A,zoneId:B})
  // Two MailPlus domains in the zone: none is preselected, and never the apex.
  const domains=await openSelect('mail-domains')
  expect(domains.map(o=>o.textContent?.trim())).toEqual(['a.b.example.com','mail.example.com'])
  document.dispatchEvent(new KeyboardEvent('keydown',{key:'Escape',bubbles:true}));await settle()
  expect(button('Next',dialog()).disabled).toBe(true)
  await selectOption('mail-domains','a.b.example.com')
  await press('Next')
  expect(h.params('mail.setup.detect')[0]).toMatchObject({domain:'a.b.example.com',answers:{source:'cloudflare'}})
 }finally{h.close()}
})

test('setup B: a zone with no MailPlus domain shows what to add and offers no apex; the one Check again reads the zone again',async()=>{
 let reads=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,
   ...(++reads===1?{mailDomains:[],mailDomainsState:'read'}:reads===2?{mailDomains:[],mailDomainsState:'unknown',mailDomainsCause:'unavailable'}:{mailDomains:['in.example.com'],mailDomainsState:'read'})}),
 })
 try{
  await toZone(h)
  await selectOption('zones','example.com')
  const none=dialog().querySelector('section:not([aria-hidden="true"]) [data-no-mail-domain]')
  // MailPlus Server is set up (or its state is unknown here): the guidance names the zone to add.
  expect(none?.textContent).toContain('mail.setup.zone.help.either.title')
  expect(none?.querySelector('[data-copy="domain"] code')?.textContent).toBe('example.com')
  expect(none?.querySelector('[data-copy="host"] code')?.textContent).toBe('mail.example.com')
  expect(none?.querySelector('[data-open-mailplus]')).not.toBeNull()
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-mail-domains]')).toBeNull()
  expect(button('Next',dialog()).disabled).toBe(true)
  // One Check again, in the footer: none inside the guidance.
  const rechecks=()=>[...dialog().querySelectorAll('button')].filter(b=>['ui.setup.checkAgain','mail.setup.zone.recheck'].includes(b.textContent?.trim()??''))
  expect(rechecks()).toHaveLength(1)
  await press('mail.setup.zone.recheck',dialog())
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-mail-domains-unknown]')?.textContent).toContain('mail.setup.zone.mailDomainsUnknown')
  expect(rechecks()).toHaveLength(1)
  expect(button('Next',dialog()).disabled).toBe(true)
  await press('mail.setup.zone.recheck',dialog())
  // One domain in the zone: preselected.
  expect(button('Next',dialog()).disabled).toBe(false)
  expect(h.params('mail.setup.zones').filter(p=>p.zoneId)).toHaveLength(3)
 }finally{h.close()}
})

// MailPlus Server never set up has no domain, and its own first-run
// wizard asks for the domain name and host name: the zone step gives exactly
// those, opens MailPlus Server, and reads the zone again on coming back.
test('setup B: a MailPlus Server never set up gets the first-run values; coming back reads the zone again',async()=>{
 desktop({AppLaunch:vi.fn()})
 let created=false
 const h=harness({
  'mail.setup.start':flow(),
  'mail.mailplus.status':()=>({state:'running',version:'3.3.0-21430',setUp:created}),
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,mailDomains:created?['example.com']:[],mailDomainsState:'read'}),
 },'subscribed')
 try{
  await toZone(h)
  await selectOption('zones','example.com')
  const help=()=>dialog().querySelector<HTMLElement>('section:not([aria-hidden="true"]) [data-no-mail-domain]')
  expect(help()?.dataset.help).toBe('firstRun')
  expect(help()?.textContent).toContain('mail.setup.zone.help.firstRun.title')
  expect(help()?.querySelector('[data-copy="domain"] code')?.textContent).toBe('example.com')
  expect(help()?.querySelector('[data-copy="host"] code')?.textContent).toBe('mail.example.com')
  expect(help()?.querySelectorAll('[data-copy] button')).toHaveLength(2)
  expect(activations(h)).toBe(1)
  await press('ui.setup.openMailPlusButton',help()!)
  const zoneReads=()=>h.params('mail.setup.zones').filter(p=>p.zoneId).length
  // Coming back too soon waits for the interval; then one read says still none.
  await tick(15_000)
  let before=zoneReads()
  await h.activate();await tick()
  expect(zoneReads()).toBe(before+1)
  expect(help()?.querySelector('[data-recheck]')?.textContent).toBe('mail.setup.zone.help.still')
  expect(button('Next',dialog()).disabled).toBe(true)
  // The administrator finished MailPlus Server's wizard: the domain is there and preselected.
  created=true
  await tick(15_000)
  before=zoneReads()
  await h.activate();await tick()
  expect(zoneReads()).toBe(before+1)
  expect(help()).toBeNull()
  expect(button('Next',dialog()).disabled).toBe(false)
  // Leaving the guidance stops watching.
  expect(h.subscriptions.disposed).toBe(1)
 }finally{h.close()}
})

// Receiving alone needs mailboxes a new domain does not have: guidance stays.
test('setup B: receiving only, a set-up MailPlus Server without the zone gets Domain → Create, with only the domain name',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.mailplus.status':{state:'running',version:'3.3.0-21430',setUp:true},
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,mailDomains:[],mailDomainsState:'read'}),
 })
 try{
  await openSetup(h)
  await choose('mail.setup.intent.receive')
  await press('Next')
  await startWith('cloudflare')
  await fillVisible(0,'cf-token-value')
  await press('Next')
  await selectOption('zones','example.com')
  const help=dialog().querySelector<HTMLElement>('section:not([aria-hidden="true"]) [data-no-mail-domain]')
  expect(help?.dataset.help).toBe('addDomain')
  expect(help?.textContent).toContain('mail.setup.zone.help.addDomain.body')
  expect(help?.querySelector('[data-copy="host"]')).toBeNull()
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-new-domain]')).toBeNull()
 }finally{h.close()}
})

// MailPlus Server is set up but has no mail domain in the zone, and the
// setup sends: the App offers to create it (the zone's name by default, or a
// name under it); the preview then shows the step, confirmed like the others.
test('setup B: a set-up MailPlus Server without the zone offers a new mail domain, checked before Next',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.mailplus.status':{state:'running',version:'3.3.0-21430',setUp:true},
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,mailDomains:p.zoneId?['other.example.com']:[],mailDomainsState:p.zoneId?'read':''}),
  'mail.setup.detect':()=>({done:false}),
 })
 try{
  await toZone(h)
  await selectOption('zones','example.com')
  // One domain exists: it is preselected; creating is the other choice.
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-no-mail-domain]')).toBeNull()
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-new-domain]')).toBeNull()
  await selectOption('mail-domains','mail.setup.zone.newDomain')
  const field=()=>dialog().querySelector<HTMLInputElement>('section:not([aria-hidden="true"]) [data-new-domain] input')!
  expect(field().value).toBe('example.com')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-new-domain-note]')?.textContent).toContain('mail.setup.zone.newDomainNote')
  expect(button('Next',dialog()).disabled).toBe(false)
  for(const bad of ['example.org','other.example.com','not a domain']){
   field().value=bad;field().dispatchEvent(new Event('input',{bubbles:true}));await settle()
   expect(button('Next',dialog()).disabled).toBe(true)
  }
  field().value='Mail.Example.com';field().dispatchEvent(new Event('input',{bubbles:true}));await settle()
  expect(button('Next',dialog()).disabled).toBe(false)
  await press('Next')
  expect(h.params('mail.setup.detect')[0]?.domain).toBe('mail.example.com')
 }finally{h.close()}
})

test('setup B: no zones explains, links to Cloudflare registration and checks again',async()=>{
 const opened:string[]=[]
 vi.spyOn(window,'open').mockImplementation((url?:string|URL)=>{opened.push(String(url));return null})
 let registered=false
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':signedIn({zones:[],match:undefined}),
  'mail.setup.zones':()=>signedIn({zones:registered?[{id:B,name:'new.com',status:'active'}]:[],match:undefined}),
 })
 try{
  await toZone(h)
  const none=dialog().querySelector('section:not([aria-hidden="true"]) [data-no-zones]')
  expect(none?.textContent).toContain('mail.setup.zone.none')
  expect(none?.textContent).toContain('mail.setup.zone.noneBody')
  expect(button('Next',dialog()).disabled).toBe(true)
  await press('mail.setup.zone.register',dialog())
  expect(opened).toEqual(['https://dash.cloudflare.com/?to=/:account/registrar/register'])
  registered=true
  await press('mail.setup.zone.recheck',dialog())
  expect(h.params('mail.setup.zones')).toEqual([{id:ID,accountId:A}])
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-no-zones]')).toBeNull()
  expect((await openSelect('zones')).map(o=>o.textContent?.trim())).toEqual(['new.com'])
 }finally{h.close();vi.restoreAllMocks()}
})

test('setup B: a missing permission is named, with the link again and Replace the token; an invalid token is refused in words',async()=>{
 let tokens=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':()=>++tokens===1?refusal('bad_request',{reason:'mail.setup.tokenInvalid'}):signedIn({match:undefined}),
  'mail.setup.zones':(p)=>signedIn({match:undefined,zoneId:p.zoneId,missing:['sendingEdit']}),
  'mail.setup.detect':{done:false},
 })
 try{
  await openSetup(h)
  await press('Next')
  await startWith('cloudflare')
  await fillVisible(0,'bad-token')
  await press('Next')
  expect(title()).toContain('mail.setup.cloudflare')
  // A refusal shows as an alert on the step (the localized reason; keys render as themselves here).
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [role=alert]')).not.toBeNull()
  // Even a refused token leaves the page: the worker sealed it before asking Cloudflare.
  expect(visibleInputs().some(e=>(e as HTMLInputElement).value==='bad-token')).toBe(false)
  await fillVisible(0,'cf-token-value')
  await press('Next')
  expect(title()).toContain('mail.setup.zone')
  await selectOption('zones','example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.zone')
  expect(h.methods()).not.toContain('mail.setup.detect')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-missing-permissions]')).not.toBeNull()
  const missing=dialog().querySelector('section:not([aria-hidden="true"]) [data-missing-permissions]')
  expect(missing?.textContent).toContain('mail.setup.cloudflare.missing')
  expect(button('mail.setup.cloudflare.create',missing!)).toBeTruthy()
  await press('mail.setup.cloudflare.replace',missing!)
  expect(title()).toContain('mail.setup.cloudflare')
 }finally{h.close()}
})

test('setup: resuming a Cloudflare-source transaction goes to the decision',async()=>{
 const h=harness({'mail.setup.start':flow('decision',{intent:'send',source:'cloudflare',domain:'example.com',resume:true,total:1,done:1,changes:[change],verified:true})})
 try{
  await openSetup(h)
  expect(active().dataset.wizardStep).toBe('decision')
 }finally{h.close()}
})

// A refusal on path B must not follow the administrator to path A.
test('setup: an error clears on Back and on a source change; a detection failure shows on the step it returns to',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':refusal('bad_request',{reason:'mail.setup.tokenInvalid'}),
  'mail.setup.detect':refusal('unavailable',{reason:'mail.setup.integrationUnavailable'}),
 })
 const alert=()=>dialog().querySelector('section:not([aria-hidden="true"]) [role=alert]')
 try{
  await openSetup(h)
  await press('Next')
  await startWith('cloudflare')
  await fillVisible(0,'bad-token')
  await press('Next')
  expect(title()).toContain('mail.setup.cloudflare')
  expect(alert()).not.toBeNull()
  await press('Back')
  expect(title()).toContain('mail.setup.start')
  expect(alert()).toBeNull()
  await startWith('own')
  expect(title()).toContain('mail.setup.domain')
  expect(alert()).toBeNull()
  // The domain step's detection start fails: the error shows on the domain step.
  await fillVisible(0,'example.com')
  await press('Next')
  expect(title()).toContain('mail.setup.domain')
  expect(alert()).not.toBeNull()
  await press('Back')
  expect(alert()).toBeNull()
 }finally{h.close()}
})

/** The wizard's "Step n of total" line. */
const counter=()=>/Step (\d+) of (\d+)/.exec(dialog().textContent??'')?.slice(1).map(Number)

test('setup: the step counter counts only the chosen path',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.cloudflare':signedIn({match:undefined}),'mail.setup.detect':{done:false}})
 try{
  await openSetup(h)
  await press('Next')
  // Own domain: intent, start, network, domain, detect, facts, configuration, preview, applying, decision, result.
  await startWith('own')
  expect(counter()).toEqual([3,11])
  await press('Back')
  // Cloudflare: intent, start, cloudflare, zone, network, detect, facts, configuration, preview, applying, decision, result.
  await startWith('cloudflare')
  expect(counter()).toEqual([3,12])
 }finally{h.close()}
})

test('setup: inbound with no certain tunnel asks to pick one, preselects Syno Connect, and previews again with it',async()=>{
 let previews=0
 const connect={id:'11111111-2222-4333-8444-555555555555',name:'synopkgconnect-nas-1',connect:true,match:true}
 const office={id:'66666666-7777-4888-8999-aaaaaaaaaaaa',name:'office',connect:false,match:true}
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:configureBranch},
  'mail.setup.preview':()=>++previews===1?{changes:[],permissions:[],warnings:[],tunnels:[connect,office]}:{changes:[change],permissions:[],warnings:[]},
 })
 try{
  await toConfiguration(h)
  await fillVisible(0,'alice@example.com')
  await press('Next')
  // Nothing was planned: the step stays and asks for the tunnel.
  expect(title()).toContain('mail.setup.configuration')
  expect(dialog().querySelector('[data-tunnel-choice]')).not.toBeNull()
  expect(dialog().textContent).toContain('mail.setup.tunnelChoice')
  expect(radio('synopkgconnect-nas-1').checked).toBe(true)
  expect(radio('office').checked).toBe(false)
  await press('Next')
  const sent=h.params('mail.setup.preview')
  expect(sent[0].tunnel).toBeUndefined()
  expect(sent[1]).toMatchObject({id:ID,addresses:'alice@example.com',tunnel:connect.id})
  expect(title()).toContain('mail.setup.preview')
 }finally{h.close()}
})

test('setup: an unconfirmed inbound delivery offers Check again, which re-verifies without a decision',async()=>{
 const check={id:'mail.setup.inbound',module:'mail',check:'mail.setup',severity:'warning',titleKey:'mail.setup.inbound.checkMail',whyKey:'mail.setup.inbound.checkMailBody',params:{address:'admin@example.com',code:'MPSA-1A2B3C4D'}}
 const ok={...check,severity:'ok',titleKey:'mail.setup.inbound.delivered',whyKey:'mail.setup.inbound.deliveredBody'}
 let statuses=0
 const h=harness({
  'mail.setup.start':flow('decision',{resume:true,intent:'receive',domain:'example.com',changes:[change],done:1,total:1,verified:false,findings:[check]}),
  'mail.setup.decide':flow('verifying',{changes:[change],done:1,total:1,findings:[check]}),
  'mail.setup.status':()=>++statuses<2?flow('verifying',{changes:[change],findings:[check]}):flow('decision',{changes:[change],done:1,total:1,verified:true,findings:[ok]}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  // Only waiting for the check mail: a neutral wait with what to send, not a warning.
  expect(title()).toContain('mail.setup.waitMail.headline')
  expect(dialog().textContent).toContain('mail.setup.waitMail.body')
  // three blocks; Check again is the verification block's header action, apart from the findings and the choice.
  const step=dialog().querySelector('section[data-wizard-step="decision"]')!
  expect([...step.querySelectorAll('.msa-block')]).toEqual(
   ['applied','verify','decide'].map(name=>step.querySelector(`[data-${name}]`)),
  )
  expect(step.querySelector('[data-verify] .msa-block-head [data-check-again]')).not.toBeNull()
  expect(step.querySelector('[data-decide] [data-check-again]')).toBeNull()
  expect(step.querySelector('[data-verify] [role=radiogroup]')).toBeNull()
  await press('ui.setup.checkAgain',dialog().querySelector('section:not([aria-hidden="true"])')!)
  expect(h.params('mail.setup.decide')).toEqual([{id:ID,choice:'verify'}])
  await tick(2100);await tick(2100)
  expect(title()).toContain('mail.setup.verified')
  expect(radio('mail.setup.keep').checked).toBe(true)
  expect(dialog().querySelector('[data-check-again]')).toBeNull()
 }finally{h.close()}
})

const checkMail={id:'mail.setup.inbound',module:'mail',check:'mail.setup',severity:'warning',titleKey:'mail.setup.inbound.checkMail',whyKey:'mail.setup.inbound.checkMailBody',params:{address:'admin@example.com',code:'MPSA-1A2B3C4D'}}
const unverified={id:'mail.setup.verification',module:'mail',check:'mail.setup',severity:'warning',titleKey:'mail.setup.verificationFailed',whyKey:'mail.setup.verificationFailedBody',fixWizard:'mail.diagnose'}
const waiting=(extra:Record<string,unknown>={})=>flow('decision',{resume:true,intent:'both',domain:'example.com',changes:[change],done:1,total:1,verified:false,findings:[checkMail,unverified],...extra})

test('setup: waiting for the check mail is a neutral wait with plain next steps, not a warning or a failure',async()=>{
 const h=harness({
  'mail.setup.start':waiting(),
  'mail.setup.decide':(p:Record<string,unknown>)=>p.choice==='keep'?flow('kept',{changes:[change],verified:false}):flow('rollingBack',{total:1}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  const step=active()
  expect(step.dataset.wizardStep).toBe('decision')
  expect(title()).toContain('mail.setup.waitMail.headline')
  expect(title()).not.toContain('mail.setup.verificationFailed')
  // No warning card and no generic "incomplete or failed" line while it only waits.
  expect(step.querySelectorAll('[data-severity]')).toHaveLength(0)
  expect(step.textContent).not.toContain('mail.setup.verificationFailedBody')
  expect(step.textContent).not.toContain('ui.severity.warning')
  // What to send, where, and what next; the address and the code can be copied.
  const wait=step.querySelector('[data-verify] [data-wait-mail]')!
  expect(wait).not.toBeNull()
  for(const text of ['mail.setup.waitMail.body','mail.setup.waitMail.after','mail.setup.waitMail.decide','admin@example.com','MPSA-1A2B3C4D'])expect(wait.textContent).toContain(text)
  expect(wait.querySelector('[data-copy="address"] code')?.textContent).toBe('admin@example.com')
  expect(wait.querySelector('[data-copy="code"] code')?.textContent).toBe('MPSA-1A2B3C4D')
  expect(wait.querySelector('[data-not-yet]')).toBeNull()
  expect(step.querySelector('[data-verify] [data-check-again]')).not.toBeNull()
  // The keep/roll back choice still works: nothing picked, Confirm waits, Keep is sent.
  expect(radio('mail.setup.keep').checked).toBe(false)
  expect(button('ui.setup.confirmDecision',dialog()).disabled).toBe(true)
  await choose('mail.setup.keep')
  await press('ui.setup.confirmDecision')
  expect(h.params('mail.setup.decide')).toEqual([{id:ID,choice:'keep'}])
 }finally{h.close()}
})

test('setup: a Check again that finds no check mail yet says "not arrived yet" and still does not warn',async()=>{
 const h=harness({
  'mail.setup.start':waiting(),
  'mail.setup.decide':flow('verifying',{changes:[change],done:1,total:1,findings:[checkMail,unverified]}),
  'mail.setup.status':()=>waiting({resume:false}),
 })
 try{
  await settle()
  await press('ui.overview.resume')
  await press('ui.setup.checkAgain',active())
  await tick(2100)
  const step=active()
  expect(title()).toContain('mail.setup.waitMail.headline')
  expect(step.querySelector('[data-wait-mail] [data-not-yet]')?.textContent).toContain('mail.setup.waitMail.notYet')
  expect(step.querySelectorAll('[data-severity]')).toHaveLength(0)
 }finally{h.close()}
})

for(const [name,extra] of [
 ['a check that really failed (the readback)',{findings:[{...checkMail,titleKey:'mail.setup.inbound.readbackFailed',whyKey:'mail.setup.inbound.readbackFailedBody',params:undefined},unverified]}],
 ['a timed-out verification',{error:'mail.setup.unconfirmed'}],
] as const){
 test(`setup: ${name} still shows the failure wording and its findings`,async()=>{
  const h=harness({'mail.setup.start':waiting(extra as Record<string,unknown>)})
  try{
   await settle()
   await press('ui.overview.resume')
   const step=active()
   expect(title()).toContain('mail.setup.verificationFailed')
   expect(step.querySelector('[data-wait-mail]')).toBeNull()
   expect(step.querySelectorAll('[data-severity="warning"]').length).toBeGreaterThan(0)
   expect(step.textContent).toContain('mail.setup.verificationFailedBody')
  }finally{h.close()}
 })
}

test('setup: the configuration step stacks its blocks, and the receive cards span the step under their label',async()=>{
 const paths=[
  {direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:[]},
  {direction:'receive',branch:'cloudflare-routing',titleKey:'mail.setup.path.cloudflare-routing',why:[]},
 ]
 const h=harness({'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[],paths,mailboxes:['alice@example.com']}},
  'mail.setup.receivemodes':{domain:false,domainReason:'mail.setup.receive.subdomain'}})
 try{
  await openSetup(h)
  await choose('mail.setup.intent.both')
  await press('Next')
  await answerNetwork()
  await fillVisible(0,'example.com')
  await press('Next')
  await tick()
  await press('Next')
  expect(title()).toContain('mail.setup.configurationFor')
  const step=active()
  // WizardStep does not space its content: one Space stacks the lines, the details fold and the choice.
  const stack=step.querySelector('[data-configuration]')
  expect(stack).not.toBeNull()
  for(const part of ['[data-consequences]','[data-details]','[data-receive-mode]'])expect(stack!.contains(step.querySelector(part))).toBe(true)
  // The receive cards: a heading above, the full width of the step, side by side; not a FormItem beside a label column.
  const item=step.querySelector<HTMLElement>('[data-receive-mode]')!
  expect(item.closest('[data-ui-form]')).toBeNull()
  expect(item.querySelector('[data-form-label]')).toBeNull()
  expect(item.querySelector('[role=heading]')?.textContent).toBe('mail.setup.receive.title')
  expect(item.querySelector('[role=radiogroup]')?.getAttribute('data-orientation')).toBe('horizontal')
 }finally{h.close()}
})

test('setup B: the zone\'s MailPlus domain read is polled while the worker reads it',async()=>{
 let polls=0
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':(p)=>p.poll
   ?signedIn({match:undefined,zoneId:'b'.repeat(32),...(++polls<2?{mailDomains:[],mailDomainsState:'reading'}:{mailDomains:['in.example.com'],mailDomainsState:'read'})})
   :signedIn({match:undefined,zoneId:p.zoneId,mailDomains:[],mailDomainsState:'reading'}),
 })
 try{
  await toZone(h)
  await selectOption('zones','example.com')
  expect(button('Next',dialog()).disabled).toBe(true)
  await tick();await tick()
  expect(h.params('mail.setup.zones').filter(p=>p.poll)).toEqual([{id:ID,poll:true},{id:ID,poll:true}])
  expect(button('Next',dialog()).disabled).toBe(false)
 }finally{h.close()}
})

test('setup B: a missing read grant at the zone step offers access instead of "check again"',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.cloudflare':signedIn({match:undefined,mailDomains:[]}),
  'mail.setup.zones':refusal('authority_required',{profile:'mail-read'}),
 })
 try{
  await toZone(h)
  await selectOption('zones','example.com')
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-zone-access]')).not.toBeNull()
  expect(dialog().querySelector('section:not([aria-hidden="true"]) [data-mail-domains-unknown]')).toBeNull()
 }finally{h.close()}
})

test('setup: an error on a step is scrolled into view',async()=>{
 const seen:string[]=[]
 const spy=vi.fn(function(this:HTMLElement){seen.push(this.textContent??'')})
 ;(Element.prototype as unknown as {scrollIntoView:unknown}).scrollIntoView=spy
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:configureBranch},
  'mail.setup.preview':refusal('unavailable',{reason:'mail.setup.routingConflict'}),
 })
 try{
  await toConfiguration(h)
  await fillVisible(0,'alice@example.com')
  await press('Next')
  expect(spy).toHaveBeenCalled()
  expect(seen.some(t=>t.length>0)).toBe(true)
 }finally{h.close();delete (Element.prototype as unknown as {scrollIntoView?:unknown}).scrollIntoView}
})

// ---- The detection results: what needs attention first, by group; the rest folded, nothing dropped.
const fact=(label:string,value:string,group:string,state:string,unrelated=false)=>({labelKey:`mail.setup.fact.${label}`,value,group,state,status:state==='ok'?'ok':state==='problem'?'warning':'info',unrelated})
const groupedFacts=[
 fact('package','mail.setup.value.package.running','mailplus','ok'),
 fact('accounts','mail.setup.value.accounts','mailplus','problem'),
 fact('fcrdns','mail.setup.cause.dnsUnknown','network','unknown'),
 fact('inbound','mail.setup.cause.notChecked','network','notChecked'),
 fact('mx','mail.setup.value.record.missing','dns','ok'),
 fact('dns','mail.setup.value.cloudflare.yes','cloudflare','ok'),
 fact('ptr','mail.setup.value.ptr.none','network','problem',true),
 fact('tunnel','mail.setup.cause.notChecked','cloudflare','notChecked',true),
]
test('setup: the facts show what needs attention first with a badge, by group; fine, not-checked and unrelated rows fold away but stay',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:groupedFacts,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork('no');await fillVisible(0,'example.com');await press('Next')
  await tick()
  expect(active().dataset.wizardStep).toBe('facts')
  const step=active()
  const attention=step.querySelector('[data-attention]')!
  // Attention rows only, under their group, each with its badge.
  expect([...attention.querySelectorAll('[data-fact-group]')].map(g=>(g as HTMLElement).dataset.factGroup)).toEqual(['mailplus','network'])
  expect([...attention.querySelectorAll('[role=listitem]')].map(r=>(r as HTMLElement).dataset.state)).toEqual(['problem','unknown'])
  expect([...attention.querySelectorAll('[data-fact-badge]')].map(b=>b.textContent?.trim())).toEqual(['mail.setup.facts.state.problem','mail.setup.facts.state.unknown'])
  expect(attention.textContent).toContain('mail.setup.facts.group.mailplus')
  // An unrelated problem (PTR on the Cloudflare route) is not among them.
  expect(attention.textContent).not.toContain('mail.setup.fact.ptr')
  // The rest is folded under its count; nothing is dropped.
  const folds=step.querySelector('[data-fact-folds]')!
  expect(folds.textContent).toContain('mail.setup.facts.others')
  expect(folds.textContent).toContain('mail.setup.facts.unrelated')
  expect(step.textContent).not.toContain('mail.setup.fact.package')
  // One fold at a time; together they hold every other fact.
  const open=async(key:string)=>{[...folds.querySelectorAll<HTMLElement>('button')].find(b=>b.textContent?.includes(key))!.click();await settle()}
  await open('mail.setup.facts.others')
  for(const f of groupedFacts.filter(f=>!f.unrelated&&(f.state==='ok'||f.state==='notChecked')))expect(step.textContent).toContain(f.labelKey)
  await open('mail.setup.facts.unrelated')
  for(const f of groupedFacts.filter(f=>f.unrelated))expect(step.textContent).toContain(f.labelKey)
 }finally{h.close()}
})

test('setup: facts without groups (an older worker) still show as one list; nothing to look at says so',async()=>{
 const plain=[{labelKey:'mail.setup.fact.package',value:'running',status:'ok'}]
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:plain,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork('no');await fillVisible(0,'example.com');await press('Next')
  await tick()
  expect(active().textContent).toContain('mail.setup.fact.package')
  expect(active().querySelector('[data-fact-folds]')).toBeNull()
 }finally{h.close()}
 const fine=[fact('package','mail.setup.value.package.running','mailplus','ok')]
 const g=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:fine,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}}})
 try{
  await openSetup(g)
  await press('Next');await answerNetwork('no');await fillVisible(0,'example.com');await press('Next')
  await tick()
  expect(active().querySelector('[data-all-fine]')?.textContent).toBe('mail.setup.facts.allFine')
 }finally{g.close()}
})

// what the decided plan creates (planned) or only recommends (optional)
// is never a problem: it shows in its own list, with its badge and why.
test('setup: facts the setup will create show as planned with the reason, never as a problem',async()=>{
 const planned=(label:string,note:string,state='planned')=>({...fact(label,'mail.setup.cause.noDomain','dns',state),status:'info',noteKey:note})
 const facts=[
  fact('package','mail.setup.value.package.running','mailplus','ok'),
  planned('domainDNS','mail.setup.planned.routing'),
  planned('mx','mail.setup.planned.routing'),
  planned('spf','mail.setup.planned.routing'),
  planned('dmarc','mail.setup.optional.dmarc','optional'),
 ]
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}}})
 try{
  await openSetup(h)
  await press('Next');await answerNetwork('no');await fillVisible(0,'example.com');await press('Next')
  await tick()
  const step=active()
  expect(step.querySelector('[data-attention]')).toBeNull()
  expect(step.querySelector('[data-all-fine]')?.textContent).toBe('mail.setup.facts.nothingToFix')
  const list=step.querySelector('[data-planned]')!
  expect(list.textContent).toContain('mail.setup.facts.planned')
  expect([...list.querySelectorAll('[data-fact-badge]')].map(b=>b.textContent?.trim())).toEqual(['mail.setup.facts.state.planned','mail.setup.facts.state.planned','mail.setup.facts.state.planned','mail.setup.facts.state.optional'])
  // Each reason once, under the facts it covers.
  expect([...list.querySelectorAll('[data-fact-note]')].map(b=>b.textContent?.trim())).toEqual(['mail.setup.planned.routing','mail.setup.optional.dmarc'])
  expect(step.textContent).not.toContain('mail.setup.facts.state.problem')
 }finally{h.close()}
})

// ---- The MailPlus Server prerequisite: checked right after the domain, before the route.
const noMailbox={done:true,facts:[fact('accounts','mail.setup.value.accounts','mailplus','problem')],
 branch:{kind:'configureMailPlus',reason:'configureMailPlus',titleKey:'mail.setup.prereq.noMailbox',bodyKey:'mail.setup.prereq.noMailboxBody',params:{domain:'testmail.example.com'},needsAccount:false}}
test('setup: receiving with no enabled mailbox is said right after the domain, before any route, and Check again stays until it is fixed',async()=>{
 desktop({AppLaunch:vi.fn()})
 let fixed=false
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':()=>fixed?routeDetect():noMailbox})
 try{
  await openSetup(h)
  await choose('mail.setup.intent.receive')
  await press('Next')
  await startWith('own')
  await fillVisible(0,'testmail.example.com')
  await press('Next')
  await tick()
  // No route was asked: the prerequisite comes first and names exactly what is missing.
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(h.params('mail.setup.detect').every(p=>!(p.answers as Record<string,unknown>).route)).toBe(true)
  expect(active().textContent).toContain('mail.setup.prereq.noMailbox')
  expect(active().querySelector('[data-prereq-body]')?.textContent).toContain('mail.setup.prereq.noMailboxBody')
  expect(active().querySelector('[data-prereq-facts]')?.textContent).toContain('mail.setup.fact.accounts')
  expect(button('ui.setup.openMailPlusButton',dialog())).toBeTruthy()
  // Check again while still missing: the step stays.
  await press('ui.setup.checkAgain')
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(h.params('mail.setup.detect').at(-1)).toMatchObject({refresh:true})
  // Fixed in MailPlus Server: Check again goes on to the route.
  fixed=true
  await press('ui.setup.checkAgain')
  await tick()
  expect(active().dataset.wizardStep).toBe('route')
  expect(h.methods().filter(m=>m.startsWith('mail.setup.')&&!['mail.setup.start','mail.setup.detect'].includes(m))).toEqual([])
 }finally{h.close()}
})

test('setup: send and receive with no enabled mailbox goes on with sending; receiving shows as pending',async()=>{
 const pending={done:true,facts:noMailbox.facts,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[],receivePending:true,
  paths:[{direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:['mail.setup.why.routeCloudflare']}]}}
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':pending})
 try{
  await openSetup(h)
  await choose('mail.setup.intent.both')
  await press('Next')
  await startWith('own')
  await fillVisible(0,'testmail.example.com')
  await press('Next')
  await tick()
  expect(active().dataset.wizardStep).toBe('prereq')
  expect(active().textContent).toContain('mail.setup.prereq.receivePending')
  expect(active().querySelector('[data-prereq-body]')?.textContent).toContain('mail.setup.prereq.receivePendingBody')
  // Not blocking: the main action continues with sending.
  expect(button('mail.setup.prereq.continueSend',dialog()).disabled).toBe(false)
  await press('mail.setup.prereq.continueSend')
  expect(active().dataset.wizardStep).toBe('route')
  await chooseRoute('cloudflare')
  expect(active().dataset.wizardStep).toBe('facts')
  expect(active().querySelector('[data-receive-pending]')?.textContent).toContain('mail.setup.prereq.receivePending')
  // The Cloudflare route was chosen: its paths are not echoed.
  expect(active().querySelector('[data-moved-paths]')).toBeNull()
  await press('Next')
  expect(active().dataset.wizardStep).toBe('configuration')
 }finally{h.close()}
})

// a mail domain the setup creates. The MailPlus Server check and the
// detection result do not warn about what only the new domain lacks, offer no
// hand-off to MailPlus Server and never ask for more evidence for it.
test('setup: a new mail domain the setup creates shows as planned, with no warnings and no Open MailPlus Server',async()=>{
 const facts=[
  fact('domains','mail.setup.value.domains','mailplus','planned'),
  {...fact('accounts','mail.setup.cause.notInMailPlus','mailplus','planned',true),noteKey:'mail.setup.planned.mailplusDomain'},
  {...fact('dkim','mail.setup.cause.notInMailPlus','mailplus','planned',true),noteKey:'mail.setup.planned.mailplusDomain'},
  fact('mx','mail.setup.cause.noDomain','dns','problem',true),
  // An unknown fact the chosen route does not use does not ask for more evidence.
  fact('ptr','mail.setup.cause.dnsUnknown','network','unknown',true),
  {...fact('domainDNS','mail.setup.cause.noDomain','dns','planned'),noteKey:'mail.setup.planned.sending'},
 ]
 facts[0]={...facts[0],noteKey:'mail.setup.planned.mailplusDomain'}
 const created={done:true,facts,branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[],receivePending:true,createsDomain:true,
  paths:[{direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:['mail.setup.why.routeCloudflare']}]}}
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':created})
 try{
  await openSetup(h)
  await choose('mail.setup.intent.both')
  await press('Next')
  await startWith('own')
  await fillVisible(0,'new.example.com')
  await press('Next')
  await tick()
  const prereq=active()
  expect(prereq.dataset.wizardStep).toBe('prereq')
  expect(prereq.textContent).toContain('mail.setup.prereq.receivePendingNew')
  // Nothing to fix in MailPlus Server: no problem rows, no hand-off.
  expect(prereq.querySelector('[data-prereq-facts]')).toBeNull()
  expect(prereq.textContent).not.toContain('mail.setup.facts.state.problem')
  expect(prereq.textContent).not.toContain('ui.setup.openMailPlus')
  expect(prereq.querySelector('[data-open-mailplus]')).toBeNull()
  // The domain the setup creates, said as planned.
  const planned=prereq.querySelector('[data-prereq-planned]')!
  expect(planned.textContent).toContain('mail.setup.fact.domains')
  expect(planned.textContent).toContain('mail.setup.facts.state.planned')
  expect(planned.textContent).not.toContain('mail.setup.fact.accounts')
  await press('mail.setup.prereq.continueSend')
  await chooseRoute('cloudflare')
  const step=active()
  expect(step.dataset.wizardStep).toBe('facts')
  // No "unknown results need more evidence" title, no attention list.
  expect(step.textContent).not.toContain('mail.setup.factsBody')
  expect(step.querySelector('[data-attention]')).toBeNull()
  expect(step.querySelector('[data-all-fine]')?.textContent).toBe('mail.setup.facts.nothingToFix')
  const list=step.querySelector('[data-planned]')!
  expect(list.textContent).toContain('mail.setup.fact.domains')
  expect([...list.querySelectorAll('[data-fact-note]')].map(n=>n.textContent?.trim())).toContain('mail.setup.planned.mailplusDomain')
  expect(step.textContent).not.toContain('mail.setup.facts.state.problem')
 }finally{h.close()}
})

// The MailPlus Server precondition (mail.mailplus.status): shown first on the
// Overview, stopping the setup wizard at its start, the diagnosis's only cause.
const mpSection=(h:ReturnType<typeof harness>)=>h.root.querySelector<HTMLElement>('[data-section="mailplus"]')!

for(const [state,title,badge] of [['notInstalled','ui.mailplus.notInstalled.title','ui.mailplus.notInstalled.badge'],['stopped','ui.mailplus.stopped.title','ui.mailplus.stopped.badge']] as const){
 test(`overview: MailPlus Server ${state} is shown first with Open Package Center`,async()=>{
  const AppLaunch=vi.fn()
  desktop({AppLaunch})
  const h=harness({'mail.setup.start':flow(),'mail.mailplus.status':{state,version:state==='stopped'?'3.3.0-21430':undefined}})
  try{
   await settle()
   const s=mpSection(h)
   expect(h.root.querySelector('[data-section]')).toBe(s)
   expect(s.querySelector(`[data-mailplus="${state}"]`)?.textContent).toContain(title)
   expect(s.querySelector('[data-mailplus-state]')?.textContent).toBe(badge)
   expect(s.querySelector('[data-mailplus-recheck]')?.textContent?.trim()).toBe('ui.mailplus.recheck')
   await press('ui.mailplus.openPackageCenter',s)
   expect(AppLaunch).toHaveBeenCalledTimes(1)
   expect(AppLaunch.mock.calls[0]![0]).toBe('SYNO.SDS.PkgManApp.Instance')
   // Nothing starts MailPlus Server: only the package list is read (and the
   // package's own records: the relay, the flow, the kept Cloudflare setups).
   expect(h.methods().filter(m=>m.startsWith('mail.')&&m!=='mail.mailplus.status'&&m!=='mail.relay.status'&&m!=='mail.setup.start'&&m!=='mail.inbound.status')).toEqual([])
  }finally{h.close()}
 })
}

test('overview: an unknown precondition is neutral, names the cause and offers only Check again',async()=>{
 let state='unknown'
 const h=harness({'mail.setup.start':flow(),'mail.mailplus.status':()=>state==='unknown'?{state,cause:'timeout',causeKey:'mail.setup.cause.timeout'}:{state,version:'3.3.0-21430'}})
 try{
  await settle()
  const s=mpSection(h)
  expect(s.querySelector('[data-mailplus="unknown"]')?.textContent).toContain('ui.mailplus.unknown.title')
  expect(s.querySelector('[data-open-package-center]')).toBeNull()
  state='running'
  await press('ui.mailplus.recheck',s)
  expect(s.querySelector('[data-mailplus-state]')?.textContent).toBe('ui.mailplus.running')
  expect(s.querySelector('[data-mailplus]')).toBeNull()
 }finally{h.close()}
})

test('overview: a checking answer is followed until the package read answers',async()=>{
 let n=0
 const h=harness({'mail.setup.start':flow(),'mail.mailplus.status':()=>++n<3?{state:'checking'}:{state:'notInstalled'}})
 try{
  await settle()
  await tick(5000)
  expect(mpSection(h).querySelector('[data-mailplus="notInstalled"]')).not.toBeNull()
  const polls=n;await tick(60_000)
  expect(n).toBe(polls) // nothing is polled once answered
 }finally{h.close()}
})

test('setup: MailPlus Server not installed stops the wizard at its start with Open Package Center; Check again moves on',async()=>{
 const AppLaunch=vi.fn()
 desktop({AppLaunch})
 let state='notInstalled'
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':configureMailPlus,'mail.mailplus.status':()=>({state})})
 try{
  await openSetup(h)
  expect(active().dataset.wizardStep).toBe('mailplus')
  expect(active().querySelector('[data-mailplus="notInstalled"]')?.textContent).toContain('ui.mailplus.notInstalled.title')
  expect(active().textContent).toContain('ui.mailplus.notInstalled.body')
  // Nothing that needs MailPlus Server was asked.
  expect(h.methods()).not.toContain('mail.setup.detect')
  expect(h.methods()).not.toContain('mail.setup.zones')
  await press('ui.mailplus.openPackageCenter',active())
  expect(AppLaunch.mock.calls[0]![0]).toBe('SYNO.SDS.PkgManApp.Instance')
  // Still not installed: Check again stays.
  // Next is Check again until MailPlus Server runs; still not installed, it stays.
  await press('ui.mailplus.recheck',dialog())
  expect(active().dataset.wizardStep).toBe('mailplus')
  state='running'
  // Running now: Check again moves on to the intent at once.
  await press('ui.mailplus.recheck',dialog())
  expect(active().dataset.wizardStep).toBe('intent')
  expect(h.methods()).not.toContain('mail.setup.detect')
 }finally{h.close()}
})

test('setup: MailPlus Server stopped stops the wizard at its start; it is never started by the App',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.mailplus.status':{state:'stopped',version:'3.3.0-21430'}})
 try{
  await openSetup(h)
  expect(active().dataset.wizardStep).toBe('mailplus')
  expect(active().querySelector('[data-mailplus="stopped"]')?.textContent).toContain('ui.mailplus.stopped.title')
  expect(button('ui.mailplus.openPackageCenter',active())).toBeTruthy()
  expect(h.methods().filter(m=>/start|set|apply|decide/.test(m)&&m!=='mail.setup.start')).toEqual([])
 }finally{h.close()}
})

test('diagnose: MailPlus Server not installed is the first and only cause, with Open Package Center',async()=>{
 const AppLaunch=vi.fn()
 desktop({AppLaunch})
 const missing={id:'mail.diag.mailplus.missing',module:'mail',check:'mail.diag.mailplus',severity:'critical',titleKey:'mail.diag.mailplus.missing.title',whyKey:'mail.diag.mailplus.missing.why',fixKey:'mail.diag.mailplus.missing.fix'}
 const h=harness({
  'mail.setup.start':flow(),
  'mail.mailplus.status':{state:'notInstalled'},
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:6,checks:['a','b','c','d','e','f'],findings:[],complete:false},
  'mail.diagnose.next':{id:'run',symptom:'cannot-send',done:6,total:6,checks:['a','b','c','d','e','f'],findings:[missing],complete:true,
   summary:{verdict:'problems',problems:[{key:'mailplus_missing',severity:'critical',action:'packages',findings:[missing.id]}],others:[]}},
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await choose('mail.diag.symptom.cannot-send')
  await press('Next');await settle()
  expect(title()).toContain('mail.diag.wizard.result')
  expect(h.params('mail.diagnose.next')).toHaveLength(1)
  const notice=active().querySelector('[data-diagnose-mailplus]')
  expect(notice?.querySelector('[data-mailplus="notInstalled"]')?.textContent ?? notice?.textContent).toContain('ui.mailplus.notInstalled.title')
  // The notice is the only cause shown: no finding card repeats it.
  expect(active().querySelector('.msa-findings')).toBeNull()
  await press('ui.mailplus.openPackageCenter',active())
  expect(AppLaunch.mock.calls[0]![0]).toBe('SYNO.SDS.PkgManApp.Instance')
 }finally{h.close()}
})

test('diagnose: the folded evidence names causes in words and never shows a DSM code',async()=>{
 const unread={id:'mail.diag.mailplus.unavailable',module:'mail',check:'mail.diag.mailplus',severity:'info',titleKey:'mail.diag.unavailable.mailplus.title',whyKey:'mail.setup.unreadable.dsmPermission',
  params:{cause:'unavailable',subject:''},evidence:{cause:'mail.setup.cause.dsmPermission',reads:[{api:'SYNO.MailPlusServer.Domain',cause:'dsm_117'}],note:'failed: dsm_119'}}
 const h=harness({
  'mail.setup.start':flow(),
  'mail.diagnose.start':{id:'run',symptom:'cannot-send',done:0,total:1,checks:['a'],findings:[],complete:false},
  'mail.diagnose.next':{id:'run',symptom:'cannot-send',done:1,total:1,checks:['a'],findings:[unread],complete:true,summary:{verdict:'unreadable',problems:[],others:[]}},
 })
 try{
  await settle()
  await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
  await choose('mail.diag.symptom.cannot-send')
  await press('Next');await settle()
  await press('ui.finding.showDetails',active())
  const text=active().querySelector('.msa-evidence')?.textContent ?? ''
  // The harness renders keys as themselves: a cause key is passed through t().
  expect(text).toContain('"mail.setup.cause.dsmPermission"')
  expect(text).toContain('SYNO.MailPlusServer.Domain')
  expect(text).not.toMatch(/dsm_\d+/)
  expect(text).toContain('mail.setup.cause.dsm')
 }finally{h.close()}
})

// ---- The result step: a verdict, at most three problems with one
// action each, the rest behind Show more, every other check folded as one line.
const info=(id:string,cause:string,titleKey=`mail.diag.${cause}.title`)=>({id,module:'mail',check:'mail.diag.transport',severity:'info',titleKey,whyKey:'mail.diag.transport_path.why',fixKey:'mail.diag.transport_path.fix',params:{cause}})
async function diagnoseResult(symptom:string,run:Record<string,unknown>){
 const h=harness({
  'mail.setup.start':flow(),
  'mail.diagnose.start':{id:'run',symptom,done:0,total:9,checks:[],findings:[],complete:false},
  'mail.diagnose.next':{id:'run',symptom,done:9,total:9,checks:[],complete:true,...run},
 })
 await settle()
 await press('ui.overview.start',h.root.querySelector('[data-section="diagnose"]')!)
 await choose(`mail.diag.symptom.${symptom}`)
 await press('Next');await settle()
 expect(active().dataset.wizardStep).toBe('result')
 return h
}
const problem=(key:string,extra:Record<string,unknown>={})=>({key,severity:'warning',action:'mailplus',findings:[`mail.diag.x.${key}`],...extra})
/** Text a person can see: a folded section's content is not rendered or hidden. */
function visibleText(el:Element):string{
 if(el instanceof HTMLElement&&(el.hidden||el.getAttribute('aria-hidden')==='true'||el.style.display==='none'))return ''
 if(el.children.length===0)return el.textContent??''
 return [...el.childNodes].map(n=>n.nodeType===Node.TEXT_NODE?n.textContent:n instanceof Element?visibleText(n):'').join('')
}

test('diagnose: not sure with many information findings shows the verdict, no card per finding and folded other checks',async()=>{
 const findings=[
  info('p1','path_unknown'),info('p2','path_send_unknown','mail.diag.path_send_unknown.title'),info('p3','path_receive_unknown','mail.diag.path_receive_unknown.title'),
  ...['sample-nas.test','testmail.example.test','mail.example.test'].map(d=>({...info(`dmarc.${d}`,'dmarc'),check:'mail.diag.domain',params:{cause:'dmarc',subject:d,target:d,status:'missing'}})),
  info('a','access_unknown'),info('b','block_unknown'),info('i','inbound_unknown'),info('c','client_unknown'),
 ]
 const summary={verdict:'unclear',problems:[],others:[
  {key:'dmarc_missing',state:'note',check:'domain',targets:['mail.example.test','sample-nas.test','testmail.example.test']},
  {key:'not_checked',state:'unknown',targets:['access','autoblock','client','inbound']},
  {key:'ok',state:'ok',check:'mailplus'},{key:'ok',state:'ok',check:'relay'},{key:'ok',state:'ok',check:'network'},
 ]}
 const h=await diagnoseResult('not-sure',{findings,summary})
 try{
  const step=active()
  expect(step.dataset.tone).toBe('neutral')
  expect(step.textContent).toContain('ui.diag.verdict.unclear')
  // No card per finding: the transport path, DMARC and unknown findings are not cards.
  expect(step.querySelectorAll('.msa-finding')).toHaveLength(0)
  expect(step.textContent).not.toContain('mail.diag.path_unknown.title')
  expect(step.textContent).not.toContain('mail.diag.transport_path.why')
  expect(step.textContent).not.toContain('ui.finding.why')
  // What to try next, and a simpler question: choose a specific problem.
  expect(step.querySelector('[data-next]')?.textContent).toContain('ui.diag.next.not-sure')
  // Other checks: one folded section, its lines not shown until opened.
  const others=step.querySelector<HTMLElement>('[data-others]')!
  expect(others.textContent).toContain('ui.diag.others')
  expect(visibleText(others)).not.toContain('mail.diag.other.dmarc_missing')
  others.querySelector<HTMLButtonElement>('button[aria-expanded]')!.click();await settle()
  const lines=[...step.querySelectorAll<HTMLElement>('[data-other]')]
  expect(lines.map(l=>l.dataset.other)).toEqual(['dmarc_missing','not_checked','ok','ok','ok'])
  // One line each, no why/what-to-do blocks.
  expect(others.textContent).not.toContain('ui.finding.fix')
  await press('ui.diag.chooseAgain',step)
  expect(title()).toContain('mail.diag.wizard.symptom')
 }finally{h.close()}
})

test('diagnose: at most three problems show, the rest behind Show more, each with one action',async()=>{
 const summary={verdict:'problems',
  problems:[problem('smtp_off',{severity:'critical'}),problem('queue_stuck'),problem('dmarc',{action:'setup',intent:'send',targets:['a.test','b.test','c.test']})],
  more:[problem('ptr',{action:'setup',intent:'send'}),problem('cert_soon',{action:undefined})],
  others:[{key:'ok',state:'ok',check:'relay'}]}
 const h=await diagnoseResult('cannot-send',{findings:[],summary})
 try{
  const step=active()
  expect(step.dataset.tone).toBe('warning')
  expect(step.textContent).toContain('ui.diag.verdict.many')
  const cards=()=>[...step.querySelectorAll<HTMLElement>('[data-problem]')].map(c=>c.dataset.problem)
  expect(cards()).toEqual(['smtp_off','queue_stuck','dmarc'])
  // One action per card: its sentence and at most one button.
  for(const card of step.querySelectorAll<HTMLElement>('[data-problem]')){
   expect(card.textContent).toContain(`mail.diag.problem.${card.dataset.problem}.action`)
   expect(card.querySelectorAll('[data-action]').length).toBeLessThanOrEqual(1)
  }
  expect(step.querySelector('[data-next]')).toBeNull()
  await press('ui.diag.more',step)
  expect(cards()).toEqual(['smtp_off','queue_stuck','dmarc','ptr','cert_soon'])
  // A problem without a button names the place in its action text.
  expect(step.querySelector('[data-problem="cert_soon"] [data-action]')).toBeNull()
 }finally{h.close()}
})

test('diagnose: one cause from several paths is one card; per-domain findings are one card listing the domains',async()=>{
 const summary={verdict:'problems',problems:[
  problem('deliver_auth',{findings:['mail.diag.mailplus.deferred_auth','mail.diag.transport.relay_failure.auth']}),
  problem('dmarc',{action:'setup',intent:'send',targets:['sample-nas.test','testmail.example.test','mail.example.test'],
   findings:['d1','d2','d3'],details:[{target:'sample-nas.test',evidence:{status:'fail'}},{target:'testmail.example.test',evidence:{status:'fail'}}]}),
 ],others:[]}
 const h=await diagnoseResult('bounce-or-spam',{findings:[],summary})
 try{
  const step=active()
  expect(step.querySelectorAll('[data-problem="deliver_auth"]')).toHaveLength(1)
  const dmarc=step.querySelectorAll<HTMLElement>('[data-problem="dmarc"]')
  expect(dmarc).toHaveLength(1)
  const targets=dmarc[0]!.querySelector('[data-targets]')!.textContent!
  expect(targets).toContain('ui.diag.targets')
  // The domains are listed once, on the card, not as a card each.
  expect(step.textContent!.split('mail.diag.problem.dmarc.title')).toHaveLength(2)
  // The setup wizard opens with the problem's intent.
  await press('ui.diag.action.setup',dmarc[0]!)
  expect(title()).toContain('mail.setup.intent')
 }finally{h.close()}
})

test('diagnose: no DSM code in any visible text of the result, details included',async()=>{
 const summary={verdict:'problems',problems:[problem('ptr',{action:'setup',intent:'send',targets:['203.0.113.8'],
  details:[{target:'203.0.113.8',evidence:{cause:'dsm_105',reads:[{api:'SYNO.MailPlusServer.Domain',cause:'dsm_117'}],note:'failed: dsm_119'}}]})],
  others:[{key:'not_checked',state:'unknown',targets:['certificate']}]}
 const h=await diagnoseResult('cannot-send',{findings:[{id:'x',module:'mail',check:'mail.diag.network',severity:'warning',titleKey:'mail.diag.ptr.title',params:{cause:'ptr',code:'dsm_105'},evidence:{cause:'dsm_105'}}],summary})
 try{
  const step=active()
  await press('ui.finding.showDetails',step)
  step.querySelector<HTMLElement>('[data-others] button[aria-expanded]')!.click();await settle()
  const text=dialog().textContent!
  expect(text).toContain('SYNO.MailPlusServer.Domain')
  expect(text).toContain('mail.setup.cause.dsm')
  expect(text).not.toMatch(/dsm_\d+/)
 }finally{h.close()}
})

// ---- The configuration ("required settings") step, receiving through Cloudflare.
// Nothing is typed or picked: the domain's mailboxes come from MailPlus Server.
const routingPaths=[
 {direction:'send',branch:'cloudflare-relay',titleKey:'mail.setup.path.cloudflare-relay',why:['mail.setup.why.routeCloudflare']},
 {direction:'receive',branch:'cloudflare-routing',titleKey:'mail.setup.path.cloudflare-routing',why:['mail.setup.why.routeCloudflare']}]
const routingWarnings=['mail.setup.globalDelivery','mail.setup.inbound.direct','mail.setup.inbound.rollback','mail.setup.inbound.spf','mail.setup.inbound.plan']
 .map(labelKey=>({labelKey,value:'example.com',status:'warning'}))
const routingBranch=(mailboxes:string[])=>({kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:routingWarnings,paths:routingPaths,mailboxes})
const shownStep=()=>dialog().querySelector<HTMLElement>('section:not([aria-hidden="true"])[data-wizard-step="configuration"]')!

test('setup: a missing receive tunnel offers the Connect catalog and keeps manual setup folded',async()=>{
 const h=harness({'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:routingBranch(['alice@example.com'])},
  'mail.setup.preview':refusal('unavailable',{reason:'mail.setup.tunnelRequired'})})
 const open=vi.spyOn(window,'open').mockReturnValue(null)
 try{
  await toConfiguration(h)
  await press('Next')
  const step=shownStep()
  const callout=step.querySelector('[data-tunnel-help]')!
  expect(callout.textContent).toContain('mail.setup.tunnelRequiredBody')
  expect([...callout.querySelectorAll('[data-tunnel-steps] li')].map(item=>item.textContent)).toEqual([
   'mail.setup.tunnelStepInstall','mail.setup.tunnelStepConnect','mail.setup.tunnelStepPreview',
  ])
  expect(callout.textContent).toContain('mail.setup.tunnelPublicDSM')
  expect(callout.textContent).toContain('mail.setup.tunnelSendOnly')
  const advanced=step.querySelector('[data-tunnel-advanced]')!
  expect(advanced.textContent).not.toContain('mail.setup.tunnelAdvancedBody')
  await press('mail.setup.tunnelOpenConnect',callout)
  expect(open).toHaveBeenCalledWith('https://synopkgland.com/apps/SynoPkgConnect/','_blank','noopener,noreferrer')
  await press('mail.setup.tunnelAdvanced',advanced)
  expect(advanced.textContent).toContain('mail.setup.tunnelAdvancedBody')
  expect(h.methods()).not.toContain('mail.setup.apply')
 }finally{open.mockRestore();h.close()}
})

test('setup: the configuration step asks for no address; it says the consequences and folds the rest',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:routingBranch(['alice@example.com','bob@example.com'])},
  'mail.setup.preview':{changes:[change],permissions:[],warnings:[]}})
 try{
  await toConfiguration(h)
  const step=shownStep()
  // The domain once, in the heading; no address field of any kind, no path echo, no per-line domain column.
  expect(title()).toContain('mail.setup.configurationFor')
  expect(step.querySelectorAll('input:not([type=radio]),textarea,[role=checkbox]')).toHaveLength(0)
  expect(step.textContent).not.toContain('mail.setup.addresses')
  expect(step.querySelector('[data-paths]')).toBeNull()
  expect(step.textContent).not.toContain('example.com')
  // At most three plain lines.
  expect([...step.querySelectorAll('[data-consequences] [role=listitem]')].map(e=>e.textContent)).toEqual(
   ['mail.setup.consequence.send','mail.setup.consequence.receive','mail.setup.consequence.offline'])
  // The rest is folded under Details, closed until opened.
  const fold=step.querySelector('[data-details]')!
  expect(fold.textContent).toContain('mail.setup.details')
  expect(step.querySelectorAll('[data-detail]')).toHaveLength(0)
  ;[...fold.querySelectorAll<HTMLElement>('button')].find(b=>b.textContent?.includes('mail.setup.details'))!.click();await settle()
  expect([...step.querySelectorAll('[data-detail]')].map(e=>e.textContent)).toEqual(['mail.setup.mailboxesNow','mail.setup.mailboxesLater',
   'mail.setup.inbound.direct','mail.setup.inbound.rollback','mail.setup.inbound.spf','mail.setup.inbound.plan'])
  // Next goes on with nothing typed; the worker reads the mailboxes itself.
  expect(button('Next',dialog()).disabled).toBe(false)
  await press('Next')
  // No answer about the whole domain: the listed mailboxes, said so.
  expect(h.params('mail.setup.preview')[0]).toMatchObject({id:ID,receive:'addresses'})
  expect(title()).toContain('mail.setup.preview')
 }finally{h.close()}
})

// ---- How mail is received through Cloudflare: the whole domain or the listed mailboxes.
const modeCards=()=>[...shownStep().querySelectorAll<HTMLButtonElement>('[data-receive-mode] [role=radio]')]
const modeCard=(mode:'domain'|'addresses')=>modeCards().find(x=>(x.closest('label')??x).textContent?.includes(`mail.setup.receive.${mode}`))!

test('setup: the whole domain is offered first when Cloudflare allows it, and the choice goes to the preview',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:routingBranch(['alice@example.com','bob@example.com'])},
  'mail.setup.receivemodes':{domain:true},'mail.setup.preview':{changes:[change],permissions:[],warnings:[],receiveMode:'domain'}})
 try{
  await toConfiguration(h)
  expect(h.params('mail.setup.receivemodes')).toEqual([{id:ID}])
  const step=shownStep()
  expect(step.querySelector('[data-receive-mode]')?.textContent).toContain('mail.setup.receive.title')
  expect(modeCards()).toHaveLength(2)
  expect(modeCard('domain').getAttribute('aria-checked')).toBe('true')
  expect(modeCard('domain').hasAttribute('disabled')||modeCard('domain').getAttribute('aria-disabled')==='true').toBe(false)
  expect(step.textContent).toContain('mail.setup.receive.domainBody')
  expect(step.textContent).toContain('mail.setup.receive.addressesBody')
  // The whole domain needs no mailbox list: one plain line says so.
  expect([...step.querySelectorAll('[data-consequences] [role=listitem]')].map(e=>e.textContent)).toEqual(
   ['mail.setup.consequence.send','mail.setup.consequence.receiveDomain','mail.setup.consequence.offline'])
  await press('Next')
  expect(h.params('mail.setup.preview')[0]).toMatchObject({id:ID,receive:'domain'})
 }finally{h.close()}
})

test('setup: the whole domain is shown disabled with its one-line reason; the mailboxes are chosen',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:routingBranch(['alice@example.com'])},
  'mail.setup.receivemodes':{domain:false,domainReason:'mail.setup.receive.subdomain'},'mail.setup.preview':{changes:[change],permissions:[],warnings:[]}})
 try{
  await toConfiguration(h)
  const step=shownStep()
  const whole=modeCard('domain')
  expect(whole.hasAttribute('disabled')||whole.getAttribute('aria-disabled')==='true').toBe(true)
  expect(step.textContent).toContain('mail.setup.receive.subdomain')
  expect(step.textContent).not.toContain('mail.setup.receive.domainBody')
  expect(modeCard('addresses').getAttribute('aria-checked')).toBe('true')
  whole.click();await settle()
  expect(modeCard('addresses').getAttribute('aria-checked')).toBe('true')
  expect([...step.querySelectorAll('[data-consequences] [role=listitem]')].map(e=>e.textContent)).toContain('mail.setup.consequence.receive')
  await press('Next')
  expect(h.params('mail.setup.preview')[0]).toMatchObject({id:ID,receive:'addresses'})
 }finally{h.close()}
})

test('setup: Next waits for the answer about the whole domain',async()=>{
 let answer:((v:unknown)=>void)|undefined
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:routingBranch(['alice@example.com'])},
  'mail.setup.receivemodes':()=>new Promise(r=>{answer=r})})
 try{
  await toConfiguration(h)
  expect(button('Next',dialog()).disabled).toBe(true)
  answer!({domain:true});await settle()
  expect(button('Next',dialog()).disabled).toBe(false)
 }finally{h.close()}
})

test('setup: receiving through Cloudflare with no enabled mailbox says so and points to MailPlus Server',async()=>{
 const h=harness({'mail.setup.start':flow(),'mail.setup.detect':{done:true,facts:[],branch:routingBranch([])}})
 try{
  await toConfiguration(h)
  const step=shownStep()
  expect(step.querySelector('[data-no-mailboxes]')?.textContent).toContain('mail.setup.noMailboxes')
  expect(step.querySelector('[data-no-mailboxes] [data-open-mailplus]')).not.toBeNull()
  // Only the sending line remains; receiving waits for a mailbox.
  expect([...step.querySelectorAll('[data-consequences] [role=listitem]')].map(e=>e.textContent)).toEqual(['mail.setup.consequence.send'])
  expect(button('Next',dialog()).disabled).toBe(true)
 }finally{h.close()}
})

// the preview says what changes in plain words, does not repeat the
// configuration step's warnings, shows at most two new ones, and folds the
// exact values, every warning and the token's permissions (as purposes).
test('setup: the preview is a plain list; repeated warnings are dropped; exact values and permissions are folded',async()=>{
 const w=(labelKey:string,extra:Record<string,unknown>={})=>({labelKey,value:'example.com',status:'warning',...extra})
 const said=[w('mail.setup.globalDelivery'),w('mail.setup.inbound.rollback')]
 const c=(id:string,target:string,after:string)=>({id,target,actionKey:`mail.setup.change.${id}`,params:{domain:'example.com'},before:'missing',after})
 const changes=[c('cloudflare.sending','cloudflare.sending','enabled: example.com'),c('relay.configure','homekeeper.relay','127.0.0.1:2525 STARTTLS AUTH enabled'),
  c('mailplus.delivery','mailplus.delivery','{"relay":true}'),c('inbound.vpc','cloudflare.vpc','hk-smtp → 192.168.1.20:25 via tunnel'),
  c('inbound.worker','cloudflare.worker','hk-inbound'),c('inbound.rules','cloudflare.routing','a@example.com → hk-inbound'),c('dns.mx','external.dns','MX mail.example.com')]
 const permissions=['Zone Read','Workers Scripts Write','Connectivity Directory Admin'].map(n=>({labelKey:'mail.setup.permissions',value:`account / ${'a'.repeat(32)} / ${n}`}))
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:said,mailboxes:['a@example.com','b@example.com']}},
  'mail.setup.preview':{changes,permissions,warnings:[...said,w('mail.setup.inbound.relayNetworks',{value:'mail.setup.inbound.relayNetworksCount',params:{count:'2'}}),
   w('mail.setup.inbound.relayNetworksUnknown'),w('mail.setup.inbound.spf'),w('mail.setup.inbound.plan')]},
 })
 try{
  await toConfiguration(h)
  await press('Next')
  expect(title()).toContain('mail.setup.previewFor')
  const step=active()
  const lines=[...step.querySelectorAll('[data-summary] [role=listitem]')].map(e=>e.textContent)
  expect(lines).toEqual(['mail.setup.summary.sendOn','mail.setup.summary.sendVia','mail.setup.summary.receiveProgram','mail.setup.summary.receiveRules','mail.setup.summary.dnsExternal'])
  // At most two new warnings show; the configuration step's are not repeated anywhere.
  // The relay client networks need no action (the Worker hands MailPlus only this domain's recipients): folded only.
  const notices=step.querySelector('[data-notices]')!
  expect(notices.children).toHaveLength(2)
  expect(notices.textContent).toContain('mail.setup.inbound.spf')
  expect(notices.textContent).not.toContain('relayNetworks')
  // Visible text: no raw permission names, no exact values, no echo of the domain per row.
  for(const raw of ['Workers Scripts Write','STARTTLS','192.168.1.20','mail.setup.globalDelivery','mail.setup.inbound.rollback','example.com'])expect(step.textContent).not.toContain(raw)
  await openDetails()
  const fold=step.querySelector('[data-preview-warnings]')!
  expect(fold.children).toHaveLength(4)
  expect(fold.textContent).not.toMatch(/globalDelivery|inbound\.rollback/)
  expect(step.querySelectorAll('[data-purposes] [role=listitem]')).toHaveLength(3)
  expect(step.querySelector('[data-technical]')?.textContent).toContain('192.168.1.20')
 }finally{h.close()}
})

test('setup: the relay client networks alone show no warning on the preview, only in its details',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:false,fields:[],warnings:[]}},
  'mail.setup.preview':{changes:[change],permissions:[],warnings:[{labelKey:'mail.setup.inbound.relayNetworks',value:'mail.setup.inbound.relayNetworksCount',params:{count:'2'},status:'warning'}]},
 })
 try{
  await toConfiguration(h)
  await press('Next')
  expect(active().querySelector('[data-notices]')).toBeNull()
  expect(active().textContent).not.toContain('relayNetworks')
  await openDetails()
  // Its text carries the count; the count is not appended again.
  expect(active().querySelector('[data-preview-warnings]')?.textContent).toBe('mail.setup.inbound.relayNetworks')
 }finally{h.close()}
})

test('setup: the account step names a parent domain only when the domain is under it',async()=>{
 const h=harness({
  'mail.setup.start':flow(),
  'mail.setup.detect':{done:true,facts:[],branch:{kind:'configure',titleKey:'mail.setup.configuration',needsAccount:true,fields:[],warnings:[]}},
  'mail.setup.cloudflare':signedIn(),
  'mail.setup.zones':signedIn(),
 })
 try{
  await openSetup(h)
  await press('Next');await answerNetwork();await fillVisible(0,'mail.example.com');await press('Next')
  await tick()
  await press('Next')
  await fillVisible(0,'cf-token-value')
  await press('Next')
  expect(active().dataset.wizardStep).toBe('account')
  expect(active().querySelector('[data-matched]')?.textContent).toBe('mail.setup.account.foundParent')
 }finally{h.close()}
})
