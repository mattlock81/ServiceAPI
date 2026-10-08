<#
.SYNOPSIS
    Unattended vault scenarios: no vault, one vault, two vaults with no default, a recorded vault
    that is no longer registered. Must run non-interactively so a prompt fails instead of hanging.

        pwsh -NoProfile -NonInteractive -File Invoke-UnattendedVaultTests.ps1 -ModulePath <repo>/ServiceAPI.psd1
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'
# These tests point HOME at a throwaway folder. That isolates the module's data files and the
# SecretManagement registrations on Linux only; on Windows they would use the real profile.
if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('svu-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
function Reg($n) { Register-KeePassSecretVault -Name $n -Path (Join-Path $work "$n.kdbx") -KeyPath (Join-Path $work "$n.key") -UseMasterPassword:$false -Create 2>&1 | Out-Null }
$cred = [pscredential]::new('u', (ConvertTo-SecureString 'p' -AsPlainText -Force))
"interactive? " + (& { Import-Module $ModulePath -Force 3>$null; & (Get-Module ServiceAPI) { Test-ServiceApiInteractive } })

# A: zero vaults, unattended -> warning, no prompt, session credential kept
Import-Module $ModulePath -Force 3>$null
$w=$null; Set-ServiceCredential -Service a -Environment prod -AuthType Basic -Credential $cred -Force -WarningVariable w 3>$null
"A zero vaults: warned=[$(($w -join ' ') -match 'No vault')] session=[$($global:ServiceCredentials.ContainsKey('a-prod'))]"

# B: one vault, no default -> used automatically
Reg 'solo'
$w=$null; Set-ServiceCredential -Service b -Environment prod -AuthType Basic -Credential $cred -Force -WarningVariable w 3>$null
"B one vault : stored=[$([bool](Get-SecretInfo -Name 'b-default-prod' -Vault solo))] index=[$((Get-Content "$work/.local/share/ServiceAPI/credential-index.json" -Raw | ConvertFrom-Json).'b-prod'.default)]"

# C: two vaults, no default, unattended -> warning, no prompt, nothing stored
Reg 'second'
$w=$null; Set-ServiceCredential -Service c -Environment prod -AuthType Basic -Credential $cred -Force -WarningVariable w 3>$null
"C two vaults: warned=[$(($w -join ' ') -match 'Several vaults')] stored=[$([bool](Get-SecretInfo -Name 'c-default-prod'))] session=[$($global:ServiceCredentials.ContainsKey('c-prod'))]"

# D: recorded vault later unregistered -> read falls back with a warning, no crash
Set-ServiceCredential -Service d -Environment prod -AuthType Basic -Credential $cred -Vault second -Force
Unregister-SecretVault -Name second
Import-Module $ModulePath -Force 3>$null
$global:ServiceCredentials.Clear()
$w=$null; try { $h = Get-ServiceCredential -Service d -Environment prod -AuthType Basic -SessionOnly:$false -WarningVariable w 3>$null 2>$null } catch { $h = "threw: $($_.Exception.Message)" }
"D vault gone: result=[$(if ($h -is [hashtable]) {'headers'} else {$h})] warned=[$(($w -join ' ') -match 'not registered|Failed|No vault')]"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
