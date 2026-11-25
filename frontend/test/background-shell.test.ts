// @vitest-environment jsdom
import {expect,test,vi} from 'vitest'
import {nextTick} from 'vue'
import {mount} from '../src/main'
import {dsmWindow} from './context'
async function settle(){for(let i=0;i<20;i++){await Promise.resolve();await nextTick()}}
test('a jobs project opens its shell without starting a job',async()=>{
 const call=vi.fn(async(method:string)=>{
  if(method==='app.status')return {package:'Jobs',version:'1',user:'alice',admin:false}
  throw {code:'unknown_method'}
 })
 const root=document.createElement('div');document.body.append(root)
 const app=mount(root,dsmWindow({call}))
 try{
  await settle()
  expect(root.querySelector('[data-page="overview"]')).not.toBeNull()
  expect(call.mock.calls.some(([method])=>method.startsWith('bg.'))).toBe(false)
 }finally{app.unmount();root.remove()}
})
