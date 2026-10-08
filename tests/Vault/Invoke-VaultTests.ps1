<#
.SYNOPSIS
    Vault-selection tests for ServiceAPI against two SecretManagement.KeePass key-file vaults.

.DESCRIPTION
    Covers the saved default, -Vault, the recorded-vault rule, scoped reads of a duplicate secret
    name, the legacy index migration and Get-/Set-ServiceVault. Needs Linux, PowerShell 7 and the
    Microsoft.PowerShell.SecretManagement and SecretManagement.KeePass modules. Uses a throwaway
    HOME; nothing outside the temp folder is changed.

        pwsh -NoProfile -File Invoke-VaultTests.ps1 -ModulePath <repo>/ServiceAPI.psd1
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'
# These tests point HOME at a throwaway folder. That isolates the module's data files and the
# SecretManagement registrations on Linux only; on Windows they would use the real profile.
if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('svt-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message)" }
}
function IdxFile { Join-Path $work '.local/share/ServiceAPI/credential-index.json' }
function Idx { Get-Content (IdxFile) -Raw | ConvertFrom-Json }

# --- register two KeePass vaults with key files only ---
foreach ($n in 'automation','local-systems') {
    $kdbx = Join-Path $work "$n.kdbx"; $key = Join-Path $work "$n.key"
    Register-KeePassSecretVault -Name $n -Path $kdbx -KeyPath $key -UseMasterPassword:$false -Create -WarningAction SilentlyContinue 2>&1 | Out-Null
}
"vaults registered: " + ((Get-SecretVault).Name -join ', ')

Import-Module $ModulePath -Force 3>$null
$cred = [pscredential]::new('svcuser', (ConvertTo-SecureString 'p@ss:word-1' -AsPlainText -Force))
$cred2 = [pscredential]::new('otheruser', (ConvertTo-SecureString 'second-secret' -AsPlainText -Force))

T 'Get-ServiceVault lists both, no default' { $v = @(Get-ServiceVault); ($v.Count -eq 2) -and -not ($v | Where-Object IsServiceDefault) }
T 'Set-ServiceVault rejects unregistered name' { try { Set-ServiceVault -Name nope; 'no throw' } catch { $_.Exception.Message -match 'not registered' } }
T 'Set-ServiceVault saves default' { Set-ServiceVault -Name AUTOMATION; (Get-ServiceVault | Where-Object IsServiceDefault).Name -ceq 'automation' }
T 'vault-config.json holds the name only' { (Get-Content (Join-Path $work '.local/share/ServiceAPI/vault-config.json') -Raw | ConvertFrom-Json).DefaultVault -ceq 'automation' }

# --- write goes to default; -Vault overrides; index records vault ---
T 'Set Basic -> default vault (automation)' {
    Set-ServiceCredential -Service svc -Environment prod -AuthType Basic -Credential $cred -Force
    $s = Get-Secret -Name 'svc-default-prod' -Vault automation -ErrorAction Stop
    ($s.UserName -eq 'svcuser') -and ((Idx).'svc-prod'.default -ceq 'automation')
}
T 'default secret NOT in the other vault' { -not (Get-SecretInfo -Name 'svc-default-prod' -Vault local-systems) }
T 'Set Basic -Vault local-systems (label alt)' {
    Set-ServiceCredential -Service svc -Environment prod -AuthType Basic -Label alt -Credential $cred2 -Vault 'local-systems' -Force
    ((Get-Secret -Name 'svc-alt-prod' -Vault 'local-systems').UserName -eq 'otheruser') -and ((Idx).'svc-prod'.alt -ceq 'local-systems')
}
T 'Set with unregistered -Vault warns and keeps session credential' {
    $w = $null
    Set-ServiceCredential -Service svc2 -Environment prod -AuthType Basic -Credential $cred -Vault nope -Force -WarningVariable w 3>$null
    ($w -join ' ') -match 'not registered' -and $global:ServiceCredentials.ContainsKey('svc2-prod')
}
T 'sticky write: no -Vault keeps label in its recorded vault' {
    Set-ServiceCredential -Service svc -Environment prod -AuthType Basic -Label alt -Credential $cred -Force
    ((Get-Secret -Name 'svc-alt-prod' -Vault 'local-systems').UserName -eq 'svcuser') -and -not (Get-SecretInfo -Name 'svc-alt-prod' -Vault automation)
}

# --- reads: scoped to recorded vault, duplicate names across vaults ---
Set-Secret -Name 'dup-x-prod' -Secret ([pscredential]::new('from-automation', (ConvertTo-SecureString 'a' -AsPlainText -Force))) -Vault automation
Set-Secret -Name 'dup-x-prod' -Secret ([pscredential]::new('from-local', (ConvertTo-SecureString 'b' -AsPlainText -Force))) -Vault 'local-systems'
& (Get-Module ServiceAPI) { Write-VaultIndex -ServiceKey 'dup-prod' -Label 'x' -Vault 'local-systems' }
function DecodeUser($h) { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($h['Authorization'] -replace '^Basic\s+',''))).Split(':')[0] }
T 'read uses the vault recorded for the label (dup name)' {
    $global:ServiceCredentials.Clear()
    (DecodeUser (Get-ServiceCredential -Service dup -Environment prod -AuthType Basic -Label x)) -eq 'from-local'
}
T 'read -Vault overrides the recorded vault' {
    $global:ServiceCredentials.Clear()
    (DecodeUser (Get-ServiceCredential -Service dup -Environment prod -AuthType Basic -Label x -Vault automation)) -eq 'from-automation'
}
T 'read of default label round-trips password containing a colon' {
    $global:ServiceCredentials.Clear()
    $h = Get-ServiceCredential -Service svc -Environment prod -AuthType Basic
    [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String(($h['Authorization'] -replace '^Basic\s+',''))) -ceq 'svcuser:p@ss:word-1'
}
T 'token string stored and read back (KeePass returns SecureString)' {
    & (Get-Module ServiceAPI) {
        Set-Secret -Name 'tok-default-prod' -Secret 'key1:secret1' -Vault 'local-systems'
        Write-VaultIndex -ServiceKey 'tok-prod' -Label 'default' -Vault 'local-systems'
    }
    $global:ServiceTokens.Clear()
    $h = Get-ServiceCredential -Service tok -Environment prod -AuthType Token
    $h['Authorization'] -match '^Basic '
}

# --- clear ---
T 'Clear removes from the recorded vault and the index' {
    Clear-ServiceCredential -Service svc -Environment prod -AuthType Basic -Label alt -Force
    -not (Get-SecretInfo -Name 'svc-alt-prod' -Vault 'local-systems') -and -not (Idx).'svc-prod'.alt
}
T 'Clear leaves the other label in its vault' {
    [bool](Get-SecretInfo -Name 'svc-default-prod' -Vault automation) -and ((Idx).'svc-prod'.default -ceq 'automation')
}
T 'Get-ServiceVault counts credentials per vault' {
    $v = Get-ServiceVault; ($v | Where-Object Name -eq automation).Credentials -ge 1
}
T 'Set-ServiceVault -Clear removes the saved default' { Set-ServiceVault -Clear; -not (Test-Path (Join-Path $work '.local/share/ServiceAPI/vault-config.json')) }
T 'write with 2 vaults, no default, non-prompting (unattended)' {
    # Simulated unattended: the resolver must not prompt, warn and return $null
    $r = & (Get-Module ServiceAPI) {
        $orig = Get-Command Test-ServiceApiInteractive
        function Test-ServiceApiInteractive { $false }
        $out = Resolve-ServiceVault -ServiceKey 'zzz-prod' -Label default -ForWrite -WarningAction SilentlyContinue
        Remove-Item Function:\Test-ServiceApiInteractive
        $out
    }
    $null -eq $r
}

# --- legacy index migration ---
T 'legacy array index is migrated on load to label -> vault' {
    Set-ServiceVault -Name automation
    '{"old-prod":["default","x"]}' | Set-Content (IdxFile)
    Import-Module $ModulePath -Force 3>$null
    $i = Idx
    ($i.'old-prod'.default -ceq 'automation') -and ($i.'old-prod'.x -ceq 'automation')
}
"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
