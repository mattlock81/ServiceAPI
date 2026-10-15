<#
.SYNOPSIS
    Tests that the AriaOidc browser login opens the portal and receives the courier's token.

.DESCRIPTION
    Drives Invoke-AriaOidcLogin down its browser path with the browser replaced inside the module
    and a background job standing in for the courier userscript. This proves the login can reach
    Open-ServiceApiBrowser, a private module function: a script block made with GetNewClosure()
    cannot, which broke the browser path before this was fixed. Needs no server, vault or SecretManagement.
    Uses a throwaway HOME. Run non-interactively:

        pwsh -NoProfile -NonInteractive -File Invoke-AriaOidcLoginTests.ps1 -ModulePath <repo>/ServiceAPI.psd1

    Placeholder values only. The IaaS bearer test finds nothing listening and falls back to the OIDC
    access token with a warning; that is expected and not what is under test.
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'

if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}

$work = Join-Path ([IO.Path]::GetTempPath()) ('aot-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS  $name" } else { $script:fail++; "FAIL  $name -> $r" } }
    catch { $script:fail++; "FAIL  $name -> EXC: $($_.Exception.Message)" }
}

Import-Module $ModulePath -Force 3>$null
$m = Get-Module ServiceAPI

# Replace the browser inside the module. The stand-in records the URL it was given and starts a
# job that posts a token response to the loopback listener, as the courier userscript would.
& $m {
    $script:OpenedUrl = $null
    Set-Item -Path 'function:script:Open-ServiceApiBrowser' -Value {
        param($Url)
        $script:OpenedUrl = $Url
        Start-Job -ScriptBlock {
            Start-Sleep -Milliseconds 800
            $body = @{ origin = 'http://127.0.0.1:18079'; access_token = 'AT-test'; refresh_token = 'RT-test'; expires_in = 3600 } | ConvertTo-Json
            Invoke-WebRequest 'http://127.0.0.1:47811/token' -Method Post -Body $body -ContentType 'application/json' `
                -Headers @{ 'X-Courier-Key' = 'aria-oidc-courier' } -UseBasicParsing | Out-Null
        } | Out-Null
        $true
    }
}

$login = $null
T 'Browser login opens the portal and returns the courier token pair' {
    $login = & $m {
        Invoke-AriaOidcLogin -BaseUrl 'http://127.0.0.1:18079' -Tenant 'aria-example' -TimeoutSeconds 60 3>$null
    }
    $script:login = $login
    ($login.RefreshToken -is [securestring]) -and ($login.Bearer -is [securestring]) -and ($login.ExpiresIn -eq 3600)
}
T 'The portal URL passed to the browser is the tenant automation page' {
    (& $m { $script:OpenedUrl }) -eq 'http://127.0.0.1:18079/tenant/aria-example/automation/'
}
T 'The bearer is the OIDC access token when the IaaS API cannot be reached' {
    $script:login.BearerMode -eq 'oidc'
}
T 'No browser available: the portal URL is printed instead' {
    & $m { Set-Item -Path 'function:script:Open-ServiceApiBrowser' -Value { param($Url) $script:OpenedUrl = $Url; $false } }
    $out = & $m {
        try { Invoke-AriaOidcLogin -BaseUrl 'http://127.0.0.1:18079' -Tenant 'aria-example' -TimeoutSeconds 30 3>$null 6>&1 } catch { $_.Exception.Message }
    } 2>&1 | Out-String
    ($out -match 'No browser could be opened') -and ($out -match '/tenant/aria-example/automation/')
}

"`nRESULT: $script:pass passed, $script:fail failed"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
if ($script:fail -gt 0) { exit 1 }
