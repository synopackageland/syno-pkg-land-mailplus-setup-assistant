import {readdirSync,readFileSync} from 'node:fs'
import {join} from 'node:path'
import {expect,test} from 'vitest'
const root=join(__dirname,'../src')
const sources=(dir:string):string[]=>readdirSync(dir,{withFileTypes:true}).flatMap(e=>e.isDirectory()?sources(join(dir,e.name)):e.name.endsWith('.vue')?[join(dir,e.name)]:[])
const template=(file:string)=>readFileSync(file,'utf8').replace(/<script[\s\S]*?<\/script>/g,'').replace(/<style[\s\S]*?<\/style>/g,'')
const uses=(file:string,tag:string)=>new RegExp(`<${tag}[\\s>/]`).test(template(file))
// The template ships @synopackageland/ui controls only; a native form control
// means a missing UI component, which is a UI gap to report, not to paper over.
test.each(['select','option','textarea','label','input','a'])('no vue template renders a native <%s>',tag=>{
 expect(sources(root).filter(file=>uses(file,tag))).toEqual([])
})
// UI layout rules: labels sit above their controls, so a page Form is vertical; a control
// inside a FormItem binds its id/ARIA by itself.
test('FormItem labels sit above their controls and the UI binds the control id',()=>{
 const items=sources(root).filter(file=>uses(file,'FormItem'))
 // The base status page has no sample form; capability forms still obey these rules.
 const app=template(join(root,'App.vue'))
 expect(app).toContain('<KeyValueRow')
 expect(app).not.toMatch(/<(?:Form|FormItem|Textarea)[\s>]/)
 // The wizard runs in a Dialog, where the UI's layout rules keep the automatic direction.
 const pageForms=items.filter(file=>!file.includes('/wizards/'))
 expect(pageForms.filter(file=>/<Form(?![^>]*direction="vertical")[\s>]/.test(template(file)))).toEqual([])
 expect(items.filter(file=>/field\.controlId|#default="\{field\}"|<Form[^>]*direction="vertical"/.test(template(file))&&file.includes('/wizards/'))).toEqual([])
})
// UI built-in text follows the Provider locale (nine locales), so every app root sets it once and no
// component repeats a per-control locale or download label. AppShell's app-root sets it from its locale.
test('app roots set the UI locale once and components do not translate UI text themselves',()=>{
 expect(sources(root).filter(file=>/<AppShell[^>]*\sapp-root[\s>]/.test(template(file))).length).toBeGreaterThan(0)
 expect(sources(root).filter(file=>uses(file,'AppRoot')&&!uses(file,'ConfigProvider'))).toEqual([])
 expect(sources(root).filter(file=>/download-label|external-label|<FilePicker[^>]*:locale=/.test(template(file)))).toEqual([])
})
