
function Invoke-AriaOidcProbe {
    <#
    .SYNOPSIS
        Diagnostic: reports which refresh call shapes and which bearer the Aria v9 tenant accepts.

    .DESCRIPTION
        Works against a service that already holds an AriaOidc token pair in
        $global:ServiceSSOTokens (run any Invoke-APIRequest -AuthType SSO call first). It then:

          1. runs every refresh call shape (Invoke-AriaOidcRefresh -Probe) and prints status and
             OAuth error for each;
          2. asks iaas/api/login whether it accepts the OIDC refresh token;
          3. calls four read-only endpoints with each bearer obtained and prints the HTTP status.

        No token, client id or secret is written to the host. Replaces the standalone listener
        harness. Not exported — run it inside the module scope:

            & (Get-Module ServiceAPI) { Invoke-AriaOidcProbe -Service aria-example }

    .PARAMETER Service
        The registered service name.

    .PARAMETER Environment
        The environment. Defaults to 'prod'.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 01-OCT-26

        CHANGE LOG
        1.0.0 | 01OCT26 | Initial version. Standalone harness verification stage moved into
                          the module as a private diagnostic.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod'
    )

    function Get-ProbeStatus {
        param([string]$Uri, [hashtable]$Headers)
        try {
            [int](Invoke-WebRequest -Uri $Uri -Headers $Headers -UseBasicParsing -ErrorAction Stop).StatusCode
        } catch {
            if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }
        }
    }

    $key   = New-ServiceKey -Service $Service -Environment $Environment
    $entry = $null
    if ($global:ServiceSSOTokens.ContainsKey($key)) { $entry = $global:ServiceSSOTokens[$key] }

    if (-not $entry -or $entry.Provider -ne 'AriaOidc' -or -not $entry.RefreshToken) {
        throw "No AriaOidc token pair is cached for [$key]. Make one SSO call first, for example: Invoke-APIRequest -Service $Service -Endpoint 'csp/gateway/am/api/loggedin/user' -AuthType SSO"
    }

    $baseUrl = $global:ServiceRegistry[$Service][$Environment].BaseUrl.TrimEnd('/')

    Write-Host "Cached state: bearer mode [$($entry.BearerMode)]; refresh mode [$($entry.RefreshMode)]; client id known: $([bool]$entry.ClientId)" -ForegroundColor Cyan

    Write-Host 'Refresh call shapes:' -ForegroundColor Cyan
    $ok = Invoke-AriaOidcRefresh -BaseUrl $baseUrl -RefreshToken $entry.RefreshToken -ClientId $entry.ClientId -Probe

    $bearers = [ordered]@{}
    if ($ok) { $bearers['oidc'] = $ok.Response.access_token }

    Write-Host 'IaaS login with the OIDC refresh token:' -ForegroundColor Cyan
    try {
        $iaas = Invoke-RestMethod -Method Post -Uri "$baseUrl/iaas/api/login" -ContentType 'application/json' `
            -Body (@{ refreshToken = (ConvertSecureStringToPlainText -SecureString $entry.RefreshToken) } | ConvertTo-Json -Compress) `
            -ErrorAction Stop
        if ($iaas.token) {
            Write-Host 'iaas/api/login -> 200 OK; IaaS bearer returned' -ForegroundColor Green
            $bearers['iaas'] = $iaas.token
        } else {
            Write-Host 'iaas/api/login -> 200 but no token in the response' -ForegroundColor Yellow
        }
    } catch {
        $code = if ($_.Exception.Response) { [int]$_.Exception.Response.StatusCode } else { -1 }
        Write-Host "iaas/api/login -> $code" -ForegroundColor Yellow
    }

    if ($bearers.Count -eq 0) {
        Write-Warning 'No bearer was obtained, so the endpoint checks were skipped.'
        return
    }

    Write-Host 'Endpoint checks (HTTP status):' -ForegroundColor Cyan
    foreach ($label in $bearers.Keys) {
        $headers = @{ Authorization = "Bearer $($bearers[$label])"; Accept = 'application/json' }
        foreach ($endpoint in 'csp/gateway/am/api/loggedin/user',
                              'iaas/api/projects?$top=1',
                              'deployment/api/deployments?size=1',
                              'blueprint/api/blueprints?size=1') {
            Write-Host ('{0,-5} {1,-42} -> {2}' -f $label, $endpoint, (Get-ProbeStatus -Uri "$baseUrl/$endpoint" -Headers $headers))
        }
    }
}
