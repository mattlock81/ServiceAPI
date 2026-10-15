# ServiceAPI tests

Scripted checks that run against a real SecretManagement vault and a real HTTP/HTTPS server on
`127.0.0.1`. They need **Linux and PowerShell 7**, and set `HOME` to a throwaway folder so the
module's data files and vault registrations never touch your profile. They refuse to run on
Windows for that reason. Nothing here needs a real service or credentials.

| Folder | What it checks | Needs |
|---|---|---|
| `LocalServer/` | `Invoke-APIRequest` end to end: None, Basic, Token and QueryParam auth, POST/PUT/DELETE, error handling, the `Accept` fix, HTTPS with trusted, self-signed, wrong-name and name-constrained certificates (including the rejection reasons), and the AriaOidc courier listener | Python 3, OpenSSL, `SecretManagement` and `SecretManagement.KeePass` |
| `LocalServer/` (AriaApiToken) | The `AriaApiToken` provider against the server's emulation of three Aria deployments (ports 18080 to 18082): exchange shapes, bearer choice, caching, stale refresh, a fresh process, bad and missing tokens, `-Vault`, the probe | as above |
| `LocalServer/` (PingFederate) | The `PingFederate` provider against `pingfed_mock.py` (ports 18090 to 18093): scope catalogue, discovery and its fallback, registration persistence, browser login, silent refresh, client authentication fallback, no refresh token, nonce and secret failures, the redirect listener. The browser and the vault are replaced inside the module, so no `SecretManagement` is needed | Python 3 |
| `LocalServer/` (AriaOidc login) | The AriaOidc browser path of `Invoke-AriaOidcLogin`: the portal URL reaches the browser opener, the courier's token pair comes back, and the no-browser message prints the URL. The browser is replaced inside the module and a job stands in for the courier, so no server, vault or `SecretManagement` is needed | none |
| `Vault/` | Vault selection: saved default, `-Vault`, the recorded-vault rule, scoped reads of a duplicate secret name, the legacy index migration, and unattended behaviour with no vault, one vault, two vaults and a vault that is no longer registered | `SecretManagement` and `SecretManagement.KeePass` |

`PingFederate-Live-Test-Plan.md` is a runbook for an AI tool (or a person) to test the PingFederate provider against a real server, with human steps marked and a report template. It needs a reachable PingFederate and a confidential client; it prints no tokens, secrets or claim values.

## Run

```bash
# Vault selection (interactive-capable session)
pwsh -NoProfile -File tests/Vault/Invoke-VaultTests.ps1 -ModulePath ./ServiceAPI.psd1

# Unattended vault scenarios: must be non-interactive so a prompt fails instead of hanging
pwsh -NoProfile -NonInteractive -File tests/Vault/Invoke-UnattendedVaultTests.ps1 -ModulePath ./ServiceAPI.psd1

# End to end against the local server
tests/LocalServer/make-certs.sh /tmp/svc-certs
python3 tests/LocalServer/server.py /tmp/svc-certs &        # prints "ready"; ports 18080 and 18443-18446
SSL_CERT_FILE=/tmp/svc-certs/roots.pem \
  pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-LocalTests.ps1 -ModulePath ./ServiceAPI.psd1
# AriaApiToken provider (same server; ports 18081 and 18082 emulate the other Aria deployments)
pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-AriaApiTokenTests.ps1 -ModulePath ./ServiceAPI.psd1
# PingFederate provider (its own mock; needs no vault)
python3 tests/LocalServer/pingfed_mock.py &
pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-PingFederateTests.ps1 -ModulePath ./ServiceAPI.psd1
# AriaOidc browser login (no server or vault needed)
pwsh -NoProfile -NonInteractive -File tests/LocalServer/Invoke-AriaOidcLoginTests.ps1 -ModulePath ./ServiceAPI.psd1
kill %1 %2
```

`SSL_CERT_FILE` makes .NET trust only the two test CAs, so the self-signed and wrong-name
certificates are rejected for the right reason. The certificates and keys are generated into the
folder you pass to `make-certs.sh`; keep that folder outside the repository.

Each runner prints `PASS` / `FAIL` per check and a final `RESULT` line. `OBSERVE` lines are
findings, not assertions: today they report whether a name-constrained CA with an IP address
SAN is accepted on this platform.

## Not covered

Windows, RHEL-family hosts, SecretStore (including the create-a-vault flow), interactive vault
prompts, a locked vault in an unattended session, and the SSO providers and their 403 retry
against a real service.
