import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
// @ts-expect-error The shared notice tool is a plain Node module.
import { writeThirdPartyNotices } from './third-party-notices.mjs'
export default defineConfig(({command}) => ({
  plugins: [vue(), {name: 'dependency-notices', closeBundle() {writeThirdPartyNotices('.', 'dist/LICENSES', {ui: true})}}],
  // Library mode must replace Vue dependency env guards for the DSM browser.
  define: command === 'build' ? {'process.env.NODE_ENV': JSON.stringify('production')} : {},
  resolve: {dedupe: ['vue']},
  base: './',
  build: {lib: {entry: 'src/main.ts', formats: ['es'], fileName: () => 'app.module.js'}, cssCodeSplit: false, rollupOptions: {output: {chunkFileNames: 'chunks/[name]-[hash].js', assetFileNames: asset => asset.names?.some(name => name.endsWith('.css')) ? 'app.css' : 'assets/[name]-[hash][extname]'}}},
}))
