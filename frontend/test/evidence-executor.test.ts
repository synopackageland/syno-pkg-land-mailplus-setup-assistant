import {expect,test} from 'vitest'
import {evidenceText} from '../src/api/evidence'
import {format} from '@synopackageland/sdk'
const locales=['en','zh-TW','zh-CN','ja','ko','de','fr','es','it']
const CODE=/[A-Z][A-Z0-9]*_[A-Z0-9_]+|executor_|\{[a-zA-Z]/

for(const loc of locales){
 test(`executor refusal codes never show in details (${loc})`,async()=>{
  const catalog=(await import(`../../i18n/messages/${loc}.json`)).default as Record<string,string>
  const t=(key:string)=>catalog[key]===undefined?key:format(catalog[key]!,{} as never)
  for(const v of ['executor_POLICY_DENIED','executor_SOME_FUTURE_CODE',{cause:'executor_SCOPE_DENIED',detail:'read failed: executor_ROOT_BUSY'}]){
   const text=evidenceText(t,v)
   expect(text).toContain(catalog['mail.setup.cause.executor'])
   expect(text.replace(/"(cause|detail)"/g,'')).not.toMatch(CODE)
  }
  expect(evidenceText(t,'mail.setup.cause.executorApproval')).toBe(catalog['mail.setup.cause.executorApproval'])
 })
}
