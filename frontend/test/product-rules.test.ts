// Product rule: no answer ends in "contact Synology Support", in any locale.
import {readdirSync, readFileSync} from 'node:fs'
import {join} from 'node:path'
import {expect, test} from 'vitest'

const dir = join(__dirname, '../../i18n/messages')
const SUPPORT = /synology[ -]?(support|サポート)|(support|soporte|supporto|assistance)\s+(de\s+|von\s+)?synology|contact\w*\s+(the\s+)?support|联系\s*synology|聯絡\s*synology|synology\s*(支援|支持|技術支援|技术支持)|synology\s*지원/i

test('no catalog text sends the user to Synology Support', () => {
 const files = readdirSync(dir).filter(f => f.endsWith('.json'))
 expect(files).toHaveLength(9)
 const hits = files.flatMap(f => Object.entries(JSON.parse(readFileSync(join(dir, f), 'utf8')) as Record<string, string>)
  .filter(([, v]) => SUPPORT.test(v)).map(([k]) => `${f}:${k}`))
 expect(hits).toEqual([])
})

// Product rule: no raw DSM error code in user-facing text ("DSM 錯誤 102");
// a known code maps to a plain cause, the code goes to the worker log.
const DSM_CODE = /DSM\s*(錯誤|错误|エラー|오류|error|-?Fehler)|(erreur|error|errore)\s+(de\s+)?DSM|DSM[^"]{0,24}\{code\}|\{code\}[^"]{0,24}DSM/i

test('no catalog text shows a raw DSM error code', () => {
 const files = readdirSync(dir).filter(f => f.endsWith('.json'))
 expect(files).toHaveLength(9)
 const hits = files.flatMap(f => Object.entries(JSON.parse(readFileSync(join(dir, f), 'utf8')) as Record<string, string>)
  .filter(([, v]) => DSM_CODE.test(v)).map(([k]) => `${f}:${k}`))
 expect(hits).toEqual([])
 // The guard itself catches the old wording.
 expect(DSM_CODE.test('無法讀取（DSM 錯誤 {code}）')).toBe(true)
 expect(DSM_CODE.test('Not read (DSM error {code})')).toBe(true)
})
