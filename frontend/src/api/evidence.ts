/**
 * The folded technical details of a finding or problem. A cause key
 * (mail.setup.cause.*) shows in words; a raw DSM cause (dsm_<code>) or
 * executor refusal (executor_<CODE>) never shows: the worker already sends
 * the plain cause key instead, this is the last guard.
 */
const DSM_CAUSE = /\bdsm_\d+\b/g
const EXECUTOR_CAUSE = /\bexecutor_[A-Z0-9_]+\b/g

export function evidenceText(t: (key: string) => string, value: unknown): string {
 const plain = (text: string) => text.startsWith('mail.setup.cause.') ? t(text) : text.replace(DSM_CAUSE, () => t('mail.setup.cause.dsm')).replace(EXECUTOR_CAUSE, () => t('mail.setup.cause.executor'))
 if(value === undefined || value === null) return ''
 if(typeof value === 'string') return plain(value)
 return JSON.stringify(value, (_, v: unknown) => typeof v === 'string' ? plain(v) : v, 2)
}

/** A locale's list ("a, b and c" / 「a、b 和 c」); a plain join where Intl.ListFormat is missing. */
export function listText(locale: string, items: string[]): string {
 try {return new Intl.ListFormat(locale, {style: 'long', type: 'conjunction'}).format(items)}
 catch {return items.join(', ')}
}
