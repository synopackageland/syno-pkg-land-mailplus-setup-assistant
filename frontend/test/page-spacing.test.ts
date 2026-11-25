import {readFileSync} from 'node:fs'
import {join} from 'node:path'
import {expect,test} from 'vitest'
// UI 0.10 spaces page sections with --ui-section-gap; the App adds no margins of its own.
const css=readFileSync(join(__dirname,'../src/style.css'),'utf8')
const rules=[...css.matchAll(/([^{}]+)\{([^}]*)\}/g)].map(([,selector,body])=>({selector:selector!.trim(),body:body!}))
test('the App stacks its pages and their sections at the UI section gap',()=>{
 const stack=rules.find(rule=>rule.selector.split(',').map(s=>s.trim()).includes('[data-ui-app] .integration-app > [data-page]'))
 expect(stack?.body).toMatch(/display:\s*flex/)
 expect(stack?.body).toMatch(/flex-direction:\s*column/)
 expect(stack?.body).toMatch(/gap:\s*var\(--ui-section-gap\)/)
})
test('no rule spaces sections or action rows with hand-written margins',()=>{
 expect(rules.filter(rule=>/margin/.test(rule.body)).map(rule=>rule.selector)).toEqual([])
})
