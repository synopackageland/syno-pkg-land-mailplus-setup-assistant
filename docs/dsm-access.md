# DSM access

The assistant calls DSM only through the SDK WebAPI path, with an
administrator's executor grant per profile. It never uses the browser's
session cookie for DSM calls and never runs as root.

| Profile | Purpose | Tuples |
| --- | --- | --- |
| `mail-read` | Read MailPlus configuration and diagnostic evidence | `SYNO.API.Info query v1`, `SYNO.Core.Package list v2`, `SYNO.Core.Certificate.CRT list v1`, `SYNO.Core.Network get v2`, `SYNO.MailPlusServer.Service.SMTP get v1`, `SYNO.MailPlusServer.Domain list v1 / get_security v2`, `SYNO.MailPlusServer.Domain.User list v1`, `SYNO.MailPlusServer.License get_user_limit v1 / get_active_user_num v1`, `SYNO.MailPlusServer.SMTP.Delivery get_type v3 / get_multiple v3`, `SYNO.MailPlusServer.SMTP.RelayControl get v1`, `SYNO.MailPlusServer.Queue list v1`, `SYNO.MailPlusServer.Audit.TransactionLog list v1`, `SYNO.MailPlusServer.Util initial_check v2` |
| `mail-write` | Apply and restore previewed MailPlus SMTP, DKIM, default relay and mail domain changes | `SYNO.MailPlusServer.Service.SMTP set v1`, `SYNO.MailPlusServer.Domain set_security v2 / create v1 / delete v1`, `SYNO.MailPlusServer.SMTP.Delivery set_type v3 / set_multiple v3` |

The `SYNO.MailPlusServer.License` reads were added in build 6 and
verified read-only on a test NAS (MailPlus Server 4.1.1-31785):
`get_user_limit` v1 replies `{"limit":5}`, `get_active_user_num` v1
`{"total":4}`; versions 2 and 3 of both answer 103. No licence write, no
licence list. Adding them changed only the policy digest (the executor
digest is unchanged), so an administrator approves the App again after the
upgrade.

`SYNO.Core.Network get v2` was added in build 23 for the inbound
path's SMTP target: the default-gateway interface (`gateway_info`: `ip`,
`status`). Verified read-only on a test NAS: v2 answers
`gateway_info {ifname: eth0, ip: 172.23.42.201, status: connected}`
(Postfix answers on that address). The inbound verification reads
`SYNO.MailPlusServer.Audit.TransactionLog list v1`, already in `mail-read`.
This changes only the policy digest, so an administrator approves the App
again after the upgrade.

`SYNO.MailPlusServer.SMTP.RelayControl get v1` (`list_type: "network"`) was
added in build 24: MailPlus's SMTP relay client networks, read for an
inbound preview warning. Verified read-only on a test NAS: API Info lists it at
v1, and it answers `{client_list: [], total: 0}` (none configured). The entry
fields were not observed, so only the count is judged.

`SYNO.MailPlusServer.Util initial_check v2` was added in build 49 so
`mail.mailplus.status` can say whether MailPlus Server finished its own
first-run setup (`plusserver_initialized`); the zone step then shows the exact
values that wizard asks for. It is the call MailPlus Server's own page makes
on opening. Verified read-only on a test NAS: v2 answers
`{plusserver_initialized: true, mailserver_initialized: true, is_migrating: false, …}`;
v1 answers DSM error 5604. A failed read leaves the answer unknown. This
changes only the policy digest, so an administrator approves the App again
after the upgrade.

`SYNO.MailPlusServer.Domain create v1 / delete v1` were added to `mail-write`
in build 50: when MailPlus Server is already set up but has no mail
domain for the zone, the setup creates it as a previewed, confirmed step
(`mailplus.domain`), recorded in the ledger. Verified on a test NAS (a probe
domain created and deleted again): `create v1 {name, desc,
default_alias_pattern: "<a>", is_automatically_adding_users: false}` answers
`{domain_id}`; `delete v1 {domain_ids: [id]}`. A new domain has no users and
DKIM off. The App writes the description `Created by MailPlus Setup
Assistant`, keeps the domain ID in its operation record, and 移除 deletes the
domain only when that ID (or, after a lost create reply, that description)
matches and the domain has no users; otherwise it leaves it and says why. The
first-run case (MailPlus Server's own setup not done) stays guidance. This
changes the policy and executor digests, so an administrator approves the
App again after the upgrade.

The other tuples are copied unchanged from Syno Home Keeper. Keep
`backend/internal/core/dsmauthority/contract.go` and `capabilities.webapi` in
`dsm-package.yaml` equal; `TestAuthorityOperationEnumsNameEveryProfile`
checks the operation enums against the inventory.

Rules (from Home Keeper):

- Each grant is one explicit, confirmed `dsm.authority.grant`; a status read
  never grants anything. The consent preselects read access only.
- `mail-write` is used only with the interactive caller's own grant
  (`Authority.DSM(owner)`), never from the background.
- A refused grant (`DELEGATION_DENIED`, `APP_DENIED`, …) marks the binding
  unavailable and surfaces `authority_required` with the profile; writes are
  never retried; a lost write reply stays uncertain and is reconciled by the
  adapter, never resent blindly.
- Delivery credentials go to DSM only through the confidential transport
  (`setup.ConfidentialDSM.CallConfidential`).
