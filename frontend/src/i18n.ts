import en from './i18n/en.json'
import zhTW from './i18n/zh-TW.json'
import zhCN from './i18n/zh-CN.json'
import ja from './i18n/ja.json'
import ko from './i18n/ko.json'
import de from './i18n/de.json'
import fr from './i18n/fr.json'
import es from './i18n/es.json'
import it from './i18n/it.json'
import {uiLocale} from '@synopackageland/sdk/vue'
export type AppCopy=typeof en
export const appCatalogs:Record<string,AppCopy>={en,'zh-TW':zhTW,'zh-CN':zhCN,ja,ko,de,fr,es,it}
export function appCopy(locale:string):AppCopy{return appCatalogs[uiLocale(locale)]!}
