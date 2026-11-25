/**
 * An outside SMTP test the route step links to. The wizard never tests from
 * outside and never reads the result: the link only helps the administrator
 * check before confirming the own-IP route.
 *
 * MXToolbox's SMTP test connects to TCP 25 of the given host and shows the
 * banner and the SMTP dialogue. The URL form was checked on 2026-11-11: it
 * runs the test for the address it names (verified against a public mail
 * server's IPv4).
 */
const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/

/** The SMTP test for this public IPv4; without a valid IPv4, the tool page (the administrator types the address). */
export function smtpTestUrl(ip?: string): string {
 if(ip && IPV4.test(ip)) return `https://mxtoolbox.com/SuperTool.aspx?action=smtp%3a${ip}&run=toolpage`
 return 'https://mxtoolbox.com/SuperTool.aspx'
}

/**
 * Cloudflare's Email Service pricing page (receiving free on every plan;
 * sending needs Workers Paid, 3,000 mails a month included). Checked by the
 * owner on 2026-11-12; the copy says Cloudflare's own page decides.
 */
export const CLOUDFLARE_PRICING_URL = 'https://developers.cloudflare.com/email-service/platform/pricing/'

export const SYNO_CONNECT_CATALOG_URL = 'https://synopkgland.com/apps/SynoPkgConnect/'
