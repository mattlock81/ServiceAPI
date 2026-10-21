function Invoke-PingFederateProbe {
    <#
    .SYNOPSIS
        Diagnostic for the PingFederate SSO provider: signs in and reports what PingFederate
        actually granted, without printing any token or claim value.

    .DESCRIPTION
        Runs the same login the provider uses (Set-ServiceCredential -AuthType SSO -Force) and
        then reports:

          - where the endpoints came from (discovery or the default paths) and the token endpoint
          - the client authentication method that worked (basic or post)
          - the scopes requested, and the scopes granted
          - whether a refresh token was issued, and when the access token expires
          - for each catalogued scope that was granted, which of its claims are present in the
            id_token and which are missing

        Only names are printed. Claim values, tokens and the client secret never reach the
        console or a stream, so the output is safe to paste into a ticket or a chat.

        Not exported. Run it from inside the module:
        & (Get-Module ServiceAPI) { Invoke-PingFederateProbe -Service ping }

    .PARAMETER Service
        The registered service name.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Vault
        Optional. The registered vault holding the client credential.

    .PARAMETER OidcRedirectPort
        Optional. The loopback port to use for this run, replacing the port saved with the service and
        the 8080 default. The redirect URI that results is shown in the report and must be registered
        on the PingFederate client.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-PingFederateProbe -Service ping }

        Signs in to ping-prod and reports scopes, claim names and token lifetime.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-PingFederateProbe -Service ping -Environment dev -Vault automation }

        Probes ping-dev with the client stored in the 'automation' vault.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-PingFederateProbe -Service ping -Verbose }

        Adds the verbose trace of discovery and the token calls.

    .OUTPUTS
        None. Writes a report to the host.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 21-OCT-26

        CHANGE LOG
        1.1.0 | 21OCT26 | Added -OidcRedirectPort, passed to Set-ServiceCredential for the sign-in, and a
                          Redirect URI line in the report so the URI can be checked against the client registration.
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: live diagnostic.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',

        [string]$Vault,

        [ValidateRange(1, 65535)]
        [int]$OidcRedirectPort
    )

    $entry = $null
    if ($global:ServiceRegistry.ContainsKey($Service) -and $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
        $entry = $global:ServiceRegistry[$Service][$Environment]
    }
    if (-not $entry -or $entry.SSOProvider -ne 'PingFederate') {
        throw "[$Service-$Environment] is not registered with -SSOProvider PingFederate."
    }

    $authority = if ($entry.OidcAuthority) { $entry.OidcAuthority } else { $entry.BaseUrl }
    $probeTransport = Resolve-ServiceTransportOptions -Service $Service -Environment $Environment -Vault $Vault -SkipCertificate
    $endpoint  = Get-PingFederateEndpoint -Authority $authority -TransportOptions $probeTransport

    Write-Host "Authority       : $authority"
    Write-Host "Endpoints from  : $($endpoint.Source)"
    Write-Host "Token endpoint  : $($endpoint.TokenEndpoint)"
    $redirectParams = @{ RedirectUri = $entry.OidcRedirectUri; PortOverridesUri = [bool]$PSBoundParameters.ContainsKey('OidcRedirectPort') }
    if ($PSBoundParameters.ContainsKey('OidcRedirectPort')) {
        $redirectParams['RedirectPort'] = $OidcRedirectPort
    } elseif ($entry.OidcRedirectPort) {
        $redirectParams['RedirectPort'] = [int]$entry.OidcRedirectPort
    }
    Write-Host "Redirect URI    : $(Resolve-PingFederateRedirectUri @redirectParams)"
    if ($endpoint.AuthMethods.Count -gt 0) {
        Write-Host "Advertised auth : $($endpoint.AuthMethods -join ', ')"
    }

    $params = @{ Service = $Service; Environment = $Environment; AuthType = 'SSO'; Force = $true }
    if ($Vault) { $params['Vault'] = $Vault }
    if ($PSBoundParameters.ContainsKey('OidcRedirectPort')) { $params['OidcRedirectPort'] = $OidcRedirectPort }
    Set-ServiceCredential @params

    $cached = $global:ServiceSSOTokens[(New-ServiceKey -Service $Service -Environment $Environment)]

    $requested = Resolve-PingFederateScope -Scope @($(if ($entry.OidcScope) { $entry.OidcScope } else { 'openid profile ad' }))
    Write-Host "Client auth     : $($cached.AuthMode)"
    Write-Host "Scope requested : $requested"
    Write-Host "Scope granted   : $($cached.Scope)"
    Write-Host "Refresh token   : $(if ($cached.RefreshToken) { 'issued' } else { 'not issued' })"
    Write-Host "Expires (UTC)   : $($cached.ExpiresAt.ToString('s'))"

    if (-not $cached.Claims) {
        Write-Host "id_token claims : none (no id_token was returned)" -ForegroundColor Yellow
        return
    }

    Write-Host "id_token claims : $((@($cached.Claims.Keys) | Sort-Object) -join ', ')"

    $catalogue = Resolve-PingFederateScope -Catalogue
    $granted   = $cached.Scope -split '\s+'
    foreach ($scopeName in $catalogue.Keys) {
        if ($scopeName -notin $granted -or $catalogue[$scopeName].Count -eq 0) { continue }

        $present = @($catalogue[$scopeName] | Where-Object { $cached.Claims.ContainsKey($_) })
        $absent  = @($catalogue[$scopeName] | Where-Object { -not $cached.Claims.ContainsKey($_) })
        $colour  = if ($absent.Count -eq 0) { 'Green' } else { 'Yellow' }
        Write-Host ("{0,-9} claims present: {1}; absent: {2}" -f $scopeName,
            $(if ($present) { $present -join ', ' } else { '-' }),
            $(if ($absent) { $absent -join ', ' } else { '-' })) -ForegroundColor $colour
    }
    Write-Host "A claim absent from the id_token may still be released by userinfo or only for some users." -ForegroundColor DarkGray
}
