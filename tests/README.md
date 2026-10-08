# ServiceAPI tests

Scripted checks that run against a real SecretManagement vault and a real HTTP/HTTPS server on
`127.0.0.1`. They need **Linux and PowerShell 7**, and set `HOME` to a throwaway folder so the
module's data files and vault registrations never touch your profile. They refuse to run on
Windows for that reason. Nothing here needs a real service or credentials.

| Folder | What it checks | Needs |
|---|---|---|
| `LocalServer/` | `Invoke-APIRequest` end to end: None, Basic, Token and QueryParam auth, POST/PUT/DELETE, error handling, the `Accept` fix, HTTPS with trusted, self-signed, wrong-name and name-constrained certificates (including the rejection reasons), and the AriaOidc courier listener | Python 3, OpenSSL, `SecretManagement` and `SecretManagement.KeePass` |
| `LocalServer/` (AriaApiToken) | The `AriaApiToken` provider against the server's emulation of three Aria deployments (ports 18080 to 18082): exchange shapes, bearer choice, caching, stale refresh, a fresh process, bad and missing tokens, `-Vault`, the probe | as above |
| `Vault/` | Vault selection: saved default, `-Vault`, the recorded-vault rule, scoped reads of a duplicate secret name, the legacy index migration, and unattended behaviour with no vault, one vault, two vaults and a vault that is no longer registered | `SecretManagement` and `SecretManagement.KeePass` |

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
kill %1
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
