import {createApp} from 'vue'
import App from './App.vue'
import type {Context} from '@synopackageland/sdk'
import {ExecutorSetupKey} from '@synopackageland/sdk/vue'
import '@synopackageland/ui/themes/dsm7-embedded.css'
import '@synopackageland/sdk/vue/style.css'
import './style.css'

let mountSequence = 0
export function mount(root: HTMLElement, ctx: Context) {
 const app = createApp(App, {ctx})
 app.provide(ExecutorSetupKey, ctx.executor ?? {
  async status() {return {state: 'unsupported'}},
  async authorize() {return {state: 'unsupported'}},
  async control() {return {state: 'unsupported'}},
 })
 // Include the generated package ID, an instance counter and randomness even
 // across separately loaded bundles. getRandomValues also works on DSM HTTP.
 app.config.idPrefix = `SynoMailPlusSetupAssistant-${++mountSequence}-${crypto.getRandomValues(new Uint32Array(4)).join('-')}`
 const hadRootClass = root.classList.contains('dsmapp-vue-root')
 root.classList.add('dsmapp-vue-root')
 app.mount(root)
 return {unmount() {app.unmount(); if(!hadRootClass) root.classList.remove('dsmapp-vue-root')}}
}
// The DSM window imports this module and calls mount for each window.
