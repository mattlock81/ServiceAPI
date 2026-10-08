<#
.SYNOPSIS
    End-to-end tests of ServiceAPI against the local test server (server.py).

.DESCRIPTION
    Start the server first:  python3 server.py ./certs   (after ./make-certs.sh ./certs)
    Run with a trust file for the test CAs and without prompts:
        SSL_CERT_FILE=./certs/roots.pem pwsh -NoProfile -NonInteractive -File Invoke-LocalTests.ps1 -ModulePath <repo>/ServiceAPI.psd1
    Uses a throwaway HOME and two KeePass key-file vaults. Nothing outside the temp folder is changed.
#>
param([Parameter(Mandatory)][string]$ModulePath)
$ErrorActionPreference = 'Stop'
# These tests point HOME at a throwaway folder. That isolates the module's data files and the
# SecretManagement registrations on Linux only; on Windows they would use the real profile.
if ($PSVersionTable.PSEdition -eq 'Desktop' -or (Test-Path Variable:\IsWindows) -and $IsWindows) {
    throw 'These tests are written for Linux (they isolate state through HOME). Run them on a Linux host or in WSL.'
}
$work = Join-Path ([IO.Path]::GetTempPath()) ('sle-' + [guid]::NewGuid().ToString('N').Substring(0,8))
New-Item -ItemType Directory -Path $work | Out-Null
$env:HOME = $work
$script:pass = 0; $script:fail = 0
function T($name, [scriptblock]$test) {
    try { $r = & $test; if ($r -eq $true) { $script:pass++; "PASS     $name" } else { $script:fail++; "FAIL     $name -> $r" } }
    catch { $script:fail++; "FAIL     $name -> EXC: $($_.Exception.Message)" }
}
function Throws($name, [scriptblock]$test, [string]$pattern = '.') {
    try { & $test | Out-Null; $script:fail++; "FAIL     $name -> no error" }
    catch { if ($_.Exception.Message -match $pattern) { $script:pass++; "PASS     $name ($($_.Exception.Message -replace '\s+',' ' | ForEach-Object { $_.Substring([Math]::Max(0,$_.Length-110)) }))" } else { $script:fail++; "FAIL     $name -> wrong error: $($_.Exception.Message)" } }
}
function Observe($name, [scriptblock]$test) {
    try { & $test | Out-Null; "OBSERVE  $name -> request SUCCEEDED" } catch { "OBSERVE  $name -> request FAILED: $(($_.Exception.Message -replace '\s+',' ')))" }
}

foreach ($n in 'testvault','testvault2') {
    Register-KeePassSecretVault -Name $n -Path (Join-Path $work "$n.kdbx") -KeyPath (Join-Path $work "$n.key") -UseMasterPassword:$false -Create 2>&1 | Out-Null
}
Import-Module $ModulePath -Force 3>$null
Set-ServiceVault -Name testvault

$base = 'http://127.0.0.1:18080'
foreach ($s in 'loc','tok','qp') { Register-CustomService -ServiceName $s -BaseUrl $base | Out-Null }
Register-CustomService -ServiceName tlsgood   -BaseUrl 'https://localhost:18443' | Out-Null
Register-CustomService -ServiceName tlsgoodip -BaseUrl 'https://127.0.0.1:18443' | Out-Null
Register-CustomService -ServiceName tlsself   -BaseUrl 'https://localhost:18445' | Out-Null
Register-CustomService -ServiceName tlswrong  -BaseUrl 'https://localhost:18446' | Out-Null
Register-CustomService -ServiceName tlsncip   -BaseUrl 'https://127.0.0.1:18444' | Out-Null
Register-CustomService -ServiceName tlsncdns  -BaseUrl 'https://localhost:18444' | Out-Null
$cred = [pscredential]::new('svcuser', (ConvertTo-SecureString 'p@ss:word-1' -AsPlainText -Force))
Invoke-RestMethod "$base/_reset" | Out-Null

"--- plain HTTP ---"
T 'None: GET echo, no Authorization header' { $r = Invoke-APIRequest -Service loc -Endpoint echo -AuthType None; ($r.method -eq 'GET') -and ($r.headers.PSObject.Properties.Name -notcontains 'Authorization') }
T 'None: POST sends a JSON body' { $r = Invoke-APIRequest -Service loc -Endpoint echo -Method Post -Body @{ a = 1; b = 'x' } -AuthType None; ($r.method -eq 'POST') -and (($r.body | ConvertFrom-Json).b -eq 'x') -and ($r.headers.'Content-Type' -match 'json') }
T 'None: PUT and DELETE' { ((Invoke-APIRequest -Service loc -Endpoint echo -Method Put -Body @{ k = 1 } -AuthType None).method -eq 'PUT') -and ((Invoke-APIRequest -Service loc -Endpoint echo -Method Delete -AuthType None).method -eq 'DELETE') }
T 'Basic: stored credential (session + vault testvault)' {
    Set-ServiceCredential -Service loc -Environment prod -AuthType Basic -Credential $cred -Force
    (Invoke-APIRequest -Service loc -Endpoint basic).ok -eq $true
}
T 'Basic: credential landed in the saved default vault only' { [bool](Get-SecretInfo -Name 'loc-default-prod' -Vault testvault) -and -not (Get-SecretInfo -Name 'loc-default-prod' -Vault testvault2) }
T 'Basic: read back from the vault after the session store is cleared' { $global:ServiceCredentials.Clear(); (Invoke-APIRequest -Service loc -Endpoint basic).ok -eq $true }
T 'Basic: -Vault testvault2 with a label stored there' {
    Set-ServiceCredential -Service loc -Environment prod -AuthType Basic -Label two -Credential $cred -Vault testvault2 -Force
    $global:ServiceCredentials.Clear()
    ((Invoke-APIRequest -Service loc -Endpoint basic -Label two -Vault testvault2).ok -eq $true) -and [bool](Get-SecretInfo -Name 'loc-two-prod' -Vault testvault2)
}
T 'Token (Bearer): ":secret" in the vault' {
    & (Get-Module ServiceAPI) { Set-Secret -Name 'tok-default-prod' -Secret ':tok-123' -Vault testvault; Write-VaultIndex -ServiceKey 'tok-prod' -Label 'default' -Vault 'testvault' }
    (Invoke-APIRequest -Service tok -Endpoint token -AuthType Token).scheme -eq 'Bearer'
}
T 'Token (Basic): "key:secret" under label kv' {
    & (Get-Module ServiceAPI) { Set-Secret -Name 'tok-kv-prod' -Secret 'key1:secret1' -Vault testvault; Write-VaultIndex -ServiceKey 'tok-prod' -Label 'kv' -Vault 'testvault' }
    (Invoke-APIRequest -Service tok -Endpoint token -AuthType Token -Label kv).scheme -eq 'Basic'
}
Throws 'Token: wrong token fails and is not retried' {
    & (Get-Module ServiceAPI) { Set-Secret -Name 'tok-bad-prod' -Secret ':nope' -Vault testvault; Write-VaultIndex -ServiceKey 'tok-prod' -Label 'bad' -Vault 'testvault' }
    Invoke-APIRequest -Service tok -Endpoint token -AuthType Token -Label bad
} '403|Forbidden|refresh|Re-authenticate'
T 'QueryParam: credential in the query string, none in a header' {
    Set-ServiceCredential -Service qp -Environment prod -AuthType Basic -Credential $cred -Force
    Invoke-RestMethod "$base/_reset" | Out-Null
    $r = Invoke-APIRequest -Service qp -AuthType QueryParam -Endpoint 'login?account={user}&passwd={pass}'
    $log = (Invoke-RestMethod "$base/_log") | Where-Object path -eq '/login' | Select-Object -Last 1
    ($r.sid -eq 'abc') -and ($r.had_authorization_header -eq $false) -and ($log.query -eq 'account=svcuser&passwd=p%40ss%3Aword-1')
}
Throws 'Error: 404 raises an error' { Invoke-APIRequest -Service loc -Endpoint missing -AuthType None } '404|Not Found'
Throws 'Error: 500 raises an error' { Invoke-APIRequest -Service loc -Endpoint boom -AuthType None } 'boom|500|Internal'
Throws 'Error: 406 with the default Accept header' { Invoke-APIRequest -Service loc -Endpoint text -AuthType None } '406|Acceptable'
T 'Accept */* header avoids the 406' { (Invoke-APIRequest -Service loc -Endpoint text -AuthType None -Headers @{ Accept = '*/*' }) -match 'plain text' }
T 'Direct -BaseUrl with AuthType None (no registration)' { (Invoke-APIRequest -BaseUrl $base -Endpoint echo -AuthType None).method -eq 'GET' }

"--- HTTPS (trust file: test CAs only) ---"
T 'HTTPS, trusted CA, DNS name' { (Invoke-APIRequest -Service tlsgood -Endpoint echo -AuthType None).method -eq 'GET' }
T 'HTTPS, trusted CA, IP address in SAN' { (Invoke-APIRequest -Service tlsgoodip -Endpoint echo -AuthType None).method -eq 'GET' }
Throws 'HTTPS, self-signed (untrusted root) is rejected, with the reason' { Invoke-APIRequest -Service tlsself -Endpoint echo -AuthType None } 'Certificate rejected: .*trusted root \(UntrustedRoot\)'
Throws 'HTTPS, trusted CA but wrong host name is rejected, with the reason' { Invoke-APIRequest -Service tlswrong -Endpoint echo -AuthType None } 'Certificate rejected: the host name \[localhost\] is not in the certificate'
Observe 'HTTPS, name-constrained CA + IP SAN, by IP' { Invoke-APIRequest -Service tlsncip -Endpoint echo -AuthType None }
Observe 'HTTPS, name-constrained CA + IP SAN, by DNS name' { Invoke-APIRequest -Service tlsncdns -Endpoint echo -AuthType None }
T 'Basic over HTTPS' {
    Set-ServiceCredential -Service tlsgood -Environment prod -AuthType Basic -Credential $cred -Force
    (Invoke-APIRequest -Service tlsgood -Endpoint basic).ok -eq $true
}

"--- AriaOidc courier listener ---"
T 'Listener serves the userscript and accepts a valid token post' {
    $port = 47811
    $payload = & (Get-Module ServiceAPI) {
        param($port)
        Wait-AriaCourierToken -Origin 'https://aria.example.com' -ScriptText '// courier' -Port $port -Key 'k1' -TimeoutSeconds 30 -AfterStart {
            Start-Job -ArgumentList $port -ScriptBlock {
                param($port)
                Start-Sleep -Milliseconds 800
                $js = Invoke-WebRequest "http://127.0.0.1:$port/aria-oidc-courier.user.js" -UseBasicParsing
                $body = @{ origin = 'https://aria.example.com'; access_token = 'AT'; refresh_token = 'RT' } | ConvertTo-Json
                Invoke-WebRequest "http://127.0.0.1:$port/token" -Method Post -Body $body -ContentType 'application/json' -Headers @{ 'X-Courier-Key' = 'k1' } -UseBasicParsing | Out-Null
                $js.Content
            } | Out-Null
        }.GetNewClosure()
    } $port
    ($payload.access_token -eq 'AT') -and ($payload.refresh_token -eq 'RT')
}
"`nRESULT: $script:pass passed, $script:fail failed (OBSERVE lines are findings, not assertions)"
Remove-Item $work -Recurse -Force -ErrorAction SilentlyContinue
