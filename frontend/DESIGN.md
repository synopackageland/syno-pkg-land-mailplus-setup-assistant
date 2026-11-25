---
name: Native DSM Vue template
description: Existing package settings UI using the installed @synopackageland/ui.
typography:
  body:
    fontFamily: "var(--ui-font-sans)"
    fontSize: "13px"
    lineHeight: 1.5
  title:
    fontSize: "20px"
    fontWeight: 600
  state:
    fontSize: "15px"
    fontWeight: 600
spacing:
  actions: "8px"
  heading-gap: "16px"
  section-gap: "24px"
---

# Design System: Native DSM Vue template

Read `AGENTS.md` at the project root and `synopkgland skill show ui-vue` before UI edits.

For UI discovery, run `npx --no syno-pkg-land-ui catalog --json` and
`npx --no syno-pkg-land-ui describe Button --json` from the installed frontend.
Read its prompt and exported Vue docs/types before choosing component APIs.
Use `syno-pkg-land-ui` directly in npm scripts; keep AI guidance version-independent.

## Overview

The template runs inside a DSM package window. `AppShell` provides status and
optional background navigation. The base page shows package status and a greeting
editor; the root overlay adds its existing fixed-operation authorization gate.

Use the installed `@synopackageland/ui` controls and `themes/dsm7-embedded.css`.
The theme owns colors, typography, spacing and dialogs. Keep per-app modal scope,
a unique Vue ID prefix and vertical scrolling at the DSM minimum window size.
In a DSM window, Dialogs may leave the window (`dialog-bounds="viewport"`) and a
press on one brings the window to the front; below 600px they are bottom sheets.

Refresh and save expose busy state and localized errors. Reopen refreshes status.
Each mount owns its state; unmount unsubscribes from host events and ignores late
responses. Backend route policies decide access.

### Background jobs

None. The worker (`jobs: true`) hosts the relay, setup transactions and diagnose
runs; their state shows on the Overview and in the wizards. There is no
Background tab and no `bg.*` API.

## Do's and Don'ts

- Do use existing public UI components, embedded theme tokens and state/recovery copy.
- Keep DSM windows light. Only an App-owned full page (`ctx.fullPage`) may follow `prefers-color-scheme`; never bind a DSM window's `color-scheme` or `colorScheme` to the system preference.
- Use `--with login` (`identity: standalone`) only for a product reason for independent sign-in outside a DSM window; it requires HTTPS for password sign-in and Continue with DSM. DSM-window Apps use the existing DSM session.
- Do retain permission gating, readable loading/empty/error states and per-instance cleanup.
- Do open the App at once: render `AppShell` immediately and run session, permission and status checks in the background, never a full-window "Checking…" placeholder. Only a confirmed refusal (signed out, expired session, not an administrator) shows the sign-in page or a library `Dialog`; loading text inside a section is fine.
- Do use the library's `Select`, `Checkbox`, `Input`, `Textarea`, `Form`, `FormItem`, `FilePicker` (`variant="compact"`, in the app locale) and `Link` for controls; there is no native `<input>` or `<a>`. Leave `Form` on its automatic direction (labels stack below 520px of container width) and let a `FormItem` bind its control, with no `direction="vertical"`, `role="group"` or `field.controlId`.
- Do not infer authority from frontend observations or scheduler history.
- Don't introduce a separate palette, component system or modal workaround around the library contract.
