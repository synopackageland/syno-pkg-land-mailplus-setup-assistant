// @vitest-environment jsdom
// approving the App in the shell's approval dialog ends the
// Overview's "needs your approval" notice without a reload.
import {afterEach,expect,test,vi} from 'vitest'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'

async function settle(){for(let i=0;i<30;i++){await Promise.resolve();await nextTick()}}
afterEach(()=>{document.body.innerHTML=''})

test('overview: the approval notice disappears once the shell approval makes the executor ready',async()=>{
 let ready=false
 const call=vi.fn(async(method:string)=>{
  if(method==='app.status')return {package:'SynoMailPlusSetupAssistant',version:'0.1.0',user:'admin',admin:true}
  if(method==='dsm.authority.status')return {capability:{state:ready?'ready':'needs-admin-approval'},profiles:[
   {name:'mail-read',profile:{purpose:'',apis:{}},state:ready?'granted':'missing',canRevoke:true},
   {name:'mail-write',profile:{purpose:'',apis:{}},state:'missing',canRevoke:true}],grants:[]}
  if(method==='mail.relay.status')return {id:'mail.relay',enabled:false,status:{running:false}}
  if(method==='mail.mailplus.status')return {state:'running',version:'3.3.0-21430'}
  if(method==='mail.setup.start')return {id:'0123456789abcdef0123456789abcdef',phase:'',done:0,total:0,changes:[],findings:[],verified:false,resume:false}
  if(method==='mail.inbound.status'||method==='mail.cloudflare.kept')return {setups:[]}
  throw {code:'unknown_method'}
 })
 const authorize=vi.fn(async()=>{ready=true;return {state:'ready' as const}})
 const executor={status:async()=>({state:(ready?'ready':'needs-admin-approval') as 'ready'}),authorize,control:async()=>({state:'ready' as const})}
 const ctx=dsmWindow({call:call as never,t:(k:string)=>k,executor,user:{name:'admin',isAdmin:true}})
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,ctx)
 try{
  await settle()
  expect(root.textContent).toContain('ui.authority.noticeTitle')
  const reads=()=>call.mock.calls.filter(([m])=>m==='dsm.authority.status').length
  const before=reads()
  // The shell's approval dialog authorizes through ctx.executor as the App hands it over.
  // The shell's notice opens its approval dialog; the dialog authorizes
  // through ctx.executor as the App hands it to the shell.
  const approveIn=(scope:ParentNode)=>[...scope.querySelectorAll<HTMLButtonElement>('button')].find(b=>b.textContent?.trim()==='Approve')
  approveIn(document)!.click()
  await settle()
  const dlg=document.querySelector<HTMLElement>('[role="dialog"]')
  expect(dlg).toBeTruthy()
  const password=dlg!.querySelector<HTMLInputElement>('input[type="password"]')
  expect(password).toBeTruthy()
  password!.value='fixture-password';password!.dispatchEvent(new Event('input',{bubbles:true}))
  await settle()
  approveIn(dlg!)!.click()
  await settle()
  expect(authorize).toHaveBeenCalled()
  expect(reads()).toBeGreaterThan(before)
  expect(root.textContent).not.toContain('ui.authority.noticeTitle')
 }finally{app.unmount();root.remove()}
})
