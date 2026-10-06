# ServiceAPI — Rehydration

**Module**: ServiceAPI
**Version at time of writing**: 2.10.4 (verified statically and by import on PowerShell 7 and Windows PowerShell 5.1; not yet run against a real Aria tenant from this repository)
**Last updated**: 07-OCT-26
**Author**: Matthew Sillett

> Current-state and design-decision record for this repository. `readme.md` is the identity
> record. This file holds what a fresh session needs to continue the work: current state,
> design decisions, open items and planned scope. Durable reference documents also live in
> this folder. No real hostnames, tenant names, tokens or client identifiers belong here —
> use placeholders (`<aria-host>`, `<tenant>`).

---

## 1. Current State

- v2.9.0 (commit `6acd179`) added the `AriaOidc` SSO provider. v2.8.0 added automatic vault sync for `Set-`/`Clear-ServiceCredential`.
- v2.10.0 consolidates the highside v2.9.1 to v2.9.3 work (certificate-aware transport, SSO 403 guards, `-ProbeEndpoint`, the Phase 5 fix) and extends it. The `AriaOidc` provider is built from private functions: `Invoke-AriaOidcLogin` (orchestrator), `Invoke-AriaOidcRefresh` (call-shape ladder), `Get-AriaCourierScript` (userscript template), `Wait-AriaCourierToken` (loopback listener), `ConvertFrom-JwtPayload` and `Invoke-AriaOidcProbe` (diagnostic). Shared helpers are `Invoke-ServiceApiHttpRequest` (transport), `Invoke-ServiceSsoRetry` (403 guards), `Test-ServiceBearer` and `Get-ServiceProbeEndpoint`.
- v2.10.1 changes no behaviour. It replaces every em dash in the PowerShell source with ASCII punctuation (D16), brings the help of every function to the CMF three-example minimum (the help audit reports 32 of 32 compliant), and adds a complete help block to `Write-ServiceApiHandledError`.
- v2.10.2 fixes one defect: `Write-ServiceApiHandledError` dropped its `-Message` when SYSCommon `Debug-Error` was available. The message is now logged as its own entry through `Write-Log` first (D17).
- v2.10.3 passes the context to `Debug-Error -Message` when the installed SYSCommon provides it (2.8.0 and later) and keeps the `Write-Log` path for older SYSCommon (D17).
- v2.10.4 changes no code. It renames the two private files `InitializeServiceConfig.ps1` and `InitializeVaultIndex.ps1` to `InitialiseServiceConfig.ps1` and `InitialiseVaultIndex.ps1` so they match their functions, and corrects the manifest text to Data Centre and licence (D18).
- Verification so far, on the AWS WorkSpace only (Windows Server 2025, build 26100): every file parses and the module imports as 2.10.4 on both PowerShell 7 and Windows PowerShell 5.1. The certificate validator compiles under both compilers and its host-name matching passes (exact, case-insensitive, wildcard, IP address, untrusted root rejected). Earlier loopback smoke tests passed for the listener and the refresh ladder. The transport and the 403 guards were reimplemented from the highside v2.9.1 to v2.9.3 specification, which its author tested. This repository's copy has not been run against a tenant.
- Auth types: `Basic`, `Token`, `SSO`, `None`, `QueryParam`.
- SSO providers: `GCloud`, `AzureCLI`, `Aria` (username/password, pre-v9 only), `AriaOidc`.
- Loader: six-phase dot-source loader in `ServiceAPI.psm1` (dependency detection, paths,
  Private then Public functions, global state, vault index, registry load from
  `services.json`, exit cleanup).
- User data lives outside the module: `services.json` in `$env:APPDATA\ServiceAPI\` and
  `credential-index.json` in `$env:LOCALAPPDATA\ServiceAPI\`.
- Optional dependencies degrade gracefully: `SysCommon` (`Debug-Error`) and
  `Microsoft.PowerShell.SecretManagement`.

## 2. Design Decisions

| # | Decision | Rationale |
|---|----------|-----------|
| D1 | Keep the `Aria` provider unchanged | Still correct for pre-v9 instances. Against Aria v9 its CSP step is rejected (HTTP 403 `access_denied`, "Could not create session from IDP grant") because login now goes through the OIDC/identity-provider path. |
| D2 | `AriaOidc` harvests the portal's own OIDC browser-session tokens | No new platform capability may be requested. The SPA keeps tokens in memory only, so a Violentmonkey userscript (the courier) forwards the SPA's `/oidc/oauth2/token` response to a loopback listener. |
| D3 | `Set-ServiceCredential` owns the `AriaOidc` refresh cycle; `Get-ServiceCredential` delegates to it when stale | Avoids duplicating the Aria resolution blocks in both functions. |
| D4 | The silent refresh opens the browser only on OAuth `invalid_grant` | Any other error (for example `invalid_client`) would repeat on every refresh, so it is surfaced instead. |
| D5 | The refresh token is held in memory in `$global:ServiceSSOTokens`, never vaulted | Preserves the existing "SSO tokens are never stored in the vault" contract. |
| D6 | Listener hardening: `127.0.0.1` only, `X-Courier-Key` header, origin match, 64 KB cap, single accept | The custom header forces a CORS preflight for ordinary websites, which the listener refuses. |
| D7 | `BaseUrl` is the host root only; the tenant name lives in `SSOTenant` | The tenant appears only in the portal URL and discovery redirect, not in API paths. |
| D8 | Module load now forwards `SSODomain` and `SSOTenant` from `services.json` | Phase 5 previously forwarded only `SSOProvider`, silently dropping a persisted `SSODomain`. |
| D9 | The courier userscript is a template inside the module (`Get-AriaCourierScript`) and the listener serves it for a one-time install | No external file to obtain or commit. The portal origin is rendered from the service registry, so no hostname is stored in source control. |
| D10 | The refresh call is a ladder of shapes (bare with `tm_ui`, bare, `client_id` in the body, Basic `client_id:`) and the winning shape is cached | Discovery does not advertise unauthenticated clients and `tm_ui` is not an advertised scope, so the working shape is found at run time rather than assumed. The client id is read from the access token's `aud` claim. |
| D11 | The bearer is chosen by test: the OIDC access token if the IaaS API accepts it, otherwise the `iaas/api/login` token for the OIDC refresh token | Whether `iaas/` accepts the OIDC token directly was unknown. The pre-v9 step 2 is kept as the fallback. |
| D12 | Every HTTP call goes through `Invoke-ServiceApiHttpRequest`, not `Invoke-RestMethod` | `Invoke-RestMethod` cannot take a per-request certificate callback, so it cannot reach hosts whose chain trips the .NET name-constraints false positive. The callback is compiled C#, because a script block cannot run on the TLS handshake thread. |
| D13 | The validator accepts at once when the platform reports no errors. Otherwise it still requires a trusted root, uses server-sent intermediates as chain material, matches DNS names (including one-label wildcards) and IP addresses itself, and skips revocation | The relaxation is limited to the name-constraints check. Revocation endpoints are normally unreachable from a restricted network. |
| D14 | An SSO 403 is refreshed and retried once only when that can help, decided in `Invoke-ServiceSsoRetry` (Guard 1: bearer probe; Guard 2: bearer changed) | A 403 is an authorisation denial, which a refresh cannot fix. The function returns an outcome and `Invoke-APIRequest` reports the error in one place. |
| D15 | The probe endpoint comes from `Get-ServiceProbeEndpoint` (registry `ProbeEndpoint`, else the `AriaOidc` default, else none) and the bearer test is `Test-ServiceBearer` | The `AriaOidc` login and the 403 guard must agree on what proves a bearer is valid. |
| D16 | PowerShell source files are plain ASCII, with no em dashes or other typographic characters | Windows PowerShell 5.1 reads a file without a byte-order mark as ANSI, and the last byte of an em dash then reads as a closing quote, which breaks parsing. 27 of 34 files were affected. v2.10.0 added a BOM as a stopgap. v2.10.1 replaced all 196 em dashes (and one copyright sign and one arrow), so no BOM is needed. |
| D17 | Handled-error context goes to `Debug-Error -Message` when the installed SYSCommon provides it (2.8.0 and later); otherwise it is logged separately through SYSCommon `Write-Log` before `Debug-Error` reports the error | `Debug-Error` originally had no parameter for caller context (it took `-ErrorRecord`, `-Severity` and `-Bug`) and logs an HTTP response body in place of the exception message, so wrapping the context into the exception would not reliably surface it. SYSCommon 2.8.0 added `-Message`, which puts the context and the error in one log entry. The module detects the parameter with `Get-Command`, so it works with either SYSCommon generation. On older SYSCommon, `Write-Log` does not throw, so `Debug-Error` still controls the rethrow for Critical; the separate context line is skipped for an HTTP 404 under the same noise rule as `Debug-Error`, and falls back to the standard streams when `Write-Log` is absent. |
| D18 | Australian/British English throughout, including file names, function names, help, messages and documentation | The convention was first applied in 2.4.3, but two private file names kept the American spelling (`InitializeServiceConfig.ps1`, `InitializeVaultIndex.ps1`) while their functions were already `Initialise-...`; 2.10.4 renamed the files to match. Names that belong to something external are kept as they are: the HTTP `Authorization` header, .NET types such as `JavaScriptSerializer`, and manifest keys such as `LicenseUri` and `RequireLicenseAcceptance`. Product names follow the house spelling (Data Centre). Historical changelog entries keep the old names they record. |

## 3. Environment Facts (Aria v9, classic tenant)

- OIDC discovery lists token endpoint auth methods `client_secret_basic`, `client_secret_post`
  and `private_key_jwt` (no `none`) and scopes `openid`, `profile`, `email`, `phone`,
  `groups`, `vcd_idp`. The SPA itself requests `tm_ui`, which is not advertised.
- Access token lifetime is about 60 minutes. The browser session lasts about 8 hours. The
  refresh token is opaque, non-rotating and bound to the session (per the findings notes).
- The SPA authenticates its own refresh with its session cookie, not with client credentials.
- Both Confluence endpoints are TLS 1.3 only. Windows 10 SChannel cannot negotiate TLS 1.3,
  so native PowerShell on a Windows 10 host cannot reach them. The AWS WorkSpace used for this
  work runs Windows Server 2025, whose SChannel supports TLS 1.3, so that limit is not expected
  to apply there (not yet tested against the Confluence endpoints from this repository). The
  Aria host is TLS 1.2 and reachable from native PowerShell.
- The internal Aria CA issues leaf certificates that carry IP-address names, beneath a CA whose
  permitted subtrees are DNS-only. OpenSSL and CryptoAPI accept that chain. The .NET chain
  engine rejects it (the name-constraints false positive).

## 4. Open Items

1. Which refresh call shape the tenant accepts is unverified. `Invoke-AriaOidcRefresh` tries
   the ladder and caches the winner; `Invoke-AriaOidcProbe` reports the result of every shape.
2. Which bearer the `iaas/`, `deployment/` and `blueprint/` APIs accept (the OIDC access token
   or the `iaas/api/login` token) is unverified. Selection is by test at run time and the probe
   shows the outcome.
3. Violentmonkey is unverified in two respects: whether it offers to install the courier script
   served from `http://127.0.0.1:<port>/aria-oidc-courier.user.js` (fallback: open the URL, copy
   the text into a new script), and whether the `unsafeWindow` hooks capture the SPA's token
   call in the target browser.
4. The transport (`Invoke-ServiceApiHttpRequest`), the 403 guards and the `AriaOidc` provider
   are verified on PowerShell 7 and Windows PowerShell 5.1 only as far as parsing, import,
   validator compilation and host-name matching. Their runtime behaviour against a tenant is
   unverified in this repository, although the highside implementation they were taken from was
   tested by its author.
5. The Linux behaviour of `SecretManagement.KeePass`, and the availability of a PowerShell 7 package for RHEL 10, are unverified.

## 5. Planned Scope

- An unattended Aria v9 provider using a self-service API token, as the complement to the
  interactive `AriaOidc` path (the documented API-token exchange needs no browser).
- Verify the harvested access token's signature against the issuer's published signing keys
  (JWKS). Parked until testing is complete.
- Opt-in per-service transport using Git for Windows' OpenSSL/curl for TLS 1.3-only endpoints
  such as Confluence. Only needed on hosts whose SChannel lacks TLS 1.3 (Windows 10); not
  expected to be needed on Windows Server 2025 or Windows 11.
- Cross-platform (RHEL) support using OS branching at import time — previously planned,
  deferred pending the Phase 1 source.
- Multiple vaults with a vault selector, and KeePass support. The design record is in section 7.
- Remove the Windows PowerShell 5.1 limit on JSON responses of about 2 MB (`ConvertFrom-Json`),
  for example with a `JavaScriptSerializer` fallback in `Invoke-ServiceApiHttpRequest`.
- SYSCommon is installed under PowerShell 7 only. Thirteen of its PowerShell files contain non-ASCII characters and no BOM, so it does not load on Windows PowerShell 5.1 and ServiceAPI falls back to its local handler there. To be fixed in the SYSCommon repository.

## 6. Conventions and Gotchas

- Every function carries a `.NOTES` block with Author, Version, Date and a CHANGE LOG.
- Australian/British English throughout. Line endings are CRLF via `.gitattributes`.
- Deploy pattern copies `ServiceAPI.psm1`, `ServiceAPI.psd1` and the `functions\Private` and
  `functions\Public` `.ps1` files to the installed module path. Anything the module needs at
  run time must therefore be a function in those folders (the courier template is one).
- `IPAddress.IsLoopback` is a static method: use `[Net.IPAddress]::IsLoopback($address)`. The
  instance form `$address.IsLoopback` returns `$null`, which silently rejects every caller.
- `HttpListener.GetContextAsync()` hands the next request to the oldest pending task. Never
  abandon a pending task and call it again, or requests are lost.
- Loopback tests should use `Start-ThreadJob`, not `Start-Job`: a child process loads the whole
  PowerShell profile and delays the client by seconds.
- PowerShell source must be plain ASCII. Do not use em dashes, smart quotes, arrows or the copyright sign in code, comments, strings or help; use a colon, semicolon, comma or hyphen instead. If a non-ASCII character is unavoidable, save that file as UTF-8 with a BOM, because Windows PowerShell 5.1 otherwise misreads it and the module fails to import.
- Every function must carry at least three `.EXAMPLE` blocks (CMF).
- The C# validator in `Invoke-ServiceApiHttpRequest` must stay within C# 5 syntax, because
  Windows PowerShell 5.1 compiles it with the .NET Framework compiler.

## 7. Vault Selection Design (planned, not implemented)

No code for this section exists at v2.9.0. It records the design so that a fresh session does not re-derive it.

**Decided**

- Detect the vault. If none exists, prompt to create one through the default flow.
- A saved default vault, so the user is not asked every time, and a `-Vault` parameter to override it at run time.
- Reads use the vault recorded in the index for the label. `-Vault` also stores a credential in a different vault.
- `SecretManagement.KeePass` is wired in as a vault type because it suits both Windows and Linux.
- Several vaults separate capabilities. Documentation suggests generic names: `automation`, `local-systems`, `online-accounts`.
- Credential export and import for sharing between users is a separate follow-up (documentation suggestion only).
- A loader OS check sets script-scoped variables so the module runs a Windows or a Linux (RHEL) branch.

**Facts established**

- SecretStore is one store per Windows user. Registering several SecretStore vaults under different names duplicates the same store, so separation needs another extension.
- KeePass on Windows (PowerShell 7, `SecretManagement.KeePass` 0.9.3): a vault created with only a key file needs no prompt, a PSCredential round-trips, and a token string returns as a SecureString.
- An unscoped `Get-Secret` with the same name in two vaults returns silently from one of them, so scoping every call with `-Vault` is a correctness requirement.
- At v2.9.0 the module hardcodes `-Vault LocalStore` at five write and remove call sites (two in `Resolve-VaultCredential`, two in `Set-ServiceCredential`, one in `Clear-ServiceCredential`) and has two unscoped `Get-Secret` calls in `Resolve-VaultCredential`.
- Vault registrations are per user and per machine, so the index must record vault names, never file paths.

**Proposed (not confirmed as final)**

- Index schema `service-key -> label -> vault`. The old array form is read as legacy and rewritten on the next write.
- Resolver order: reads use `-Vault`, then the index-recorded vault, then the saved default. Writes use `-Vault`, the saved default, the single registered vault, then a prompt.
- New public functions `Set-ServiceVault` and `Get-ServiceVault`, with the saved default held in `vault-config.json` in the machine-local data folder.
- No vault: interactive runs offer to create a personal SecretStore vault named `LocalStore`. Non-interactive runs fall back to `-SessionOnly` with a warning.
- A loader phase sets `$script:ServiceApiIsWindows` and `$script:ServiceApiIsLinux` (`$IsWindows` is absent in PowerShell 5.1, which is Windows-only), and one path helper builds the config and index paths.
- Replace `PtrToStringAuto` on a BSTR (likely wrong on Linux) with `ConvertFrom-SecureString -AsPlainText` on PowerShell 7.

Implementation order: loader OS check and path helper, vault functions, `-Vault` and defaults, documentation, skill update.

---

## Change Log

| Version | Date | Change |
|---------|------|--------|
| 1.7.0 | 07-OCT-26 | Added D18 (Australian/British English including file names). Corrected the machine description: the AWS WorkSpace is Windows Server 2025, not Windows 10, so the TLS 1.3 limitation applies to Windows 10 hosts only. Brought current to module v2.10.4. |
| 1.6.0 | 07-OCT-26 | D17 revised: handled-error context uses Debug-Error -Message when SYSCommon 2.8.0 or later provides it. SYSCommon encoding gap recorded under planned scope. Brought current to module v2.10.3. |
| 1.5.0 | 07-OCT-26 | Added D17 (handled-error context logged through Write-Log). Brought current to module v2.10.2. |
| 1.4.0 | 06-OCT-26 | Help brought to the CMF standard on every function (audit: 32 of 32 compliant). Em dashes removed from all PowerShell source and D16 revised to a plain-ASCII rule. Brought current to module v2.10.1. |
| 1.3.0 | 06-OCT-26 | Brought current to v2.10.0: certificate-aware transport, SSO 403 guards and `-ProbeEndpoint` (D12 to D15); UTF-8 BOM requirement for Windows PowerShell 5.1 (D16); open item 4 rewritten; planned scope and gotchas extended. |
| 1.2.0 | 04-OCT-26 | Brought current to the committed v2.9.0 (6acd179); added the planned vault selection design record (section 7); skill refresh item completed. |
| 1.1.0 | 01-OCT-26 | Courier userscript and listener built into the module as private functions; refresh call-shape ladder and verified bearer selection added (D9–D11); gotchas from smoke testing recorded. |
| 1.0.0 | 01-OCT-26 | Initial rehydration record, written alongside v2.9.0 (`AriaOidc`). |
