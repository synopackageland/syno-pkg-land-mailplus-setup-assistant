/**
 * Cloudflare dashboard links for the setup wizard's sign-in.
 *
 * The create-token link opens the dashboard's ACCOUNT token form, which takes
 * permission group IDs as `permissionGroupKeys` keys (the `type` field is
 * ignored for an ID), so every permission the mail path needs is filled in,
 * Email Sending included (developers.cloudflare.com/fundamentals/api/how-to/
 * account-owned-token-template/, "Account token URL format" and "Use
 * permission group IDs"). The dashboard asks for the account when the user
 * has several; the user chooses the zones. The IDs are Cloudflare's canonical
 * permission group IDs:
 *   Zone Read            c8fed203ed3043cba015a93ad1616f1f  (zone)    list the account's zones
 *   DNS Write            4755a26eedb94da69e1066d98aa820be  (zone)    the mail DNS records
 *   Email Sending Write  5df633d6b41c42bcaf5b4a62b9d14b64  (account) the Cloudflare relay, and its SMTP login
 * and for inbound mail through Cloudflare (setup.InboundPermissions):
 *   Zone Settings Write          3030687196b94b638145a3953da2b699  (zone)    Email Routing enable and status
 *   Email Routing Rules Write    79b3ec0d10ce4148a8f8bdc0cc5f97f2  (zone)    the exact-address rules
 *   Workers Scripts Write        e086da7e2179491d91ee5f35b3ca210a  (account) the inbound Email Worker
 *   Connectivity Directory Admin 77efc2c0724d4c4eb94bfd9656247130  (account) the Workers VPC Service
 *   Cloudflare Tunnel Read       efea2ab8357b47888938f101ae5e053f  (account) find the tunnel to the NAS
 * One token carries them all, whichever path the answers choose later.
 * Email Sending Read is not asked for: the client names Read or Write as the
 * alternatives for every Email Sending read the plan and its rollback make
 * (cloudflare/sending.go), and Write covers them.
 * The token this creates is account-owned; the worker verifies it through
 * the account's verify endpoint (mail/module.go, Accounts).
 */
export const tokenPermissions = [
 {key: 'c8fed203ed3043cba015a93ad1616f1f', type: 'read'},
 {key: '4755a26eedb94da69e1066d98aa820be', type: 'edit'},
 {key: '5df633d6b41c42bcaf5b4a62b9d14b64', type: 'edit'},
 {key: '3030687196b94b638145a3953da2b699', type: 'edit'},
 {key: '79b3ec0d10ce4148a8f8bdc0cc5f97f2', type: 'edit'},
 {key: 'e086da7e2179491d91ee5f35b3ca210a', type: 'edit'},
 {key: '77efc2c0724d4c4eb94bfd9656247130', type: 'edit'},
 {key: 'efea2ab8357b47888938f101ae5e053f', type: 'read'},
] as const

/** The permissions the link fills in, as catalog codes (mail.setup.cloudflare.permission.<code>). */
export const tokenPermissionCodes = ['zoneRead', 'dnsEdit', 'sendingEdit', 'zoneSettingsEdit', 'routingRulesEdit', 'workersEdit', 'vpcAdmin', 'tunnelRead'] as const

/** Cloudflare's account create-token page with every mail permission filled in. */
export function cloudflareTokenUrl(name = 'MailPlus Setup Assistant'): string {
 // encodeURIComponent, not URLSearchParams: the documented form encodes a space as %20.
 return `https://dash.cloudflare.com/?to=/:account/api-tokens&permissionGroupKeys=${encodeURIComponent(JSON.stringify(tokenPermissions))}&name=${encodeURIComponent(name)}`
}

/** Cloudflare's Register domains page. The dashboard has no documented
 * account-specific link, so the generic one asks for the account if needed
 * (developers.cloudflare.com/registrar/get-started/register-domain/). */
export const registerDomainUrl = 'https://dash.cloudflare.com/?to=/:account/registrar/register'

/** Cloudflare's Email Routing page (Compute > Email Service > Email Routing),
 * where the administrator selects the zone and opens Settings: the only place
 * Cloudflare offers for its locked receiving records. The docs link it as
 * https://dash.cloudflare.com/?to=/:account/email-service/routing
 * (developers.cloudflare.com/email-service/configuration/domains/, "Locked DNS
 * records" and "Disable Email Routing"; subdomains/ "Add a subdomain to Email
 * Routing": select the apex domain, then open Settings; read 2026-11-13). The
 * setup's account ID takes the place of `:account`; the page has no zone in
 * its path, so the zone's name is said next to the link. Without a valid ID
 * the documented link asks for the account. */
export function emailRoutingUrl(accountId?: string): string {
 const account = accountId && /^[0-9a-f]{32}$/.test(accountId) ? accountId : ':account'
 return `https://dash.cloudflare.com/?to=/${account}/email-service/routing`
}

/** Opens a Cloudflare page in a new browser tab, without a reference back to this window. */
export function openCloudflare(url: string): void {
 window.open(url, '_blank', 'noopener,noreferrer')
}
