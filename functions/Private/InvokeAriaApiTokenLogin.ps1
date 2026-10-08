function Invoke-AriaApiTokenLogin {
    <#
    .SYNOPSIS
        Obtains a verified bearer token for an Aria service from a stored API token, with no browser.

    .DESCRIPTION
        The orchestrator for the AriaApiToken SSO provider:

        1. Exchange the API token for a bearer (Invoke-AriaApiTokenExchange), trying the call
           shape that worked last time first.
        2. Choose the bearer by test, not by assumption: send it to the probe endpoint
           (Test-ServiceBearer). If it is not accepted, exchange the API token at
           iaas/api/login and test that instead.
        3. If neither is accepted, warn and use the first bearer, so endpoints that accept it
           still work.

        There is no refresh token to hold: the API token stays in the vault and is exchanged
        again whenever the bearer nears expiry, so a new process needs no interaction.

    .PARAMETER BaseUrl
        The Aria host root, for example https://aria.example.com.

    .PARAMETER ApiToken
        The API token as a SecureString.

    .PARAMETER Tenant
        Optional. The tenant name; enables the oauth-tenant exchange shape.

    .PARAMETER ExchangeMode
        Optional. The exchange shape that worked previously. Tried first.

    .PARAMETER ProbeEndpoint
        A relative endpoint that returns 2xx for any valid bearer. Defaults to
        'iaas/api/projects?$top=1'.

    .EXAMPLE
        $login = Invoke-AriaApiTokenLogin -BaseUrl 'https://aria.example.com' -ApiToken $apiToken
        $login.BearerMode

        Exchanges the API token and shows which kind of bearer the tenant accepted.

    .EXAMPLE
        $login = Invoke-AriaApiTokenLogin -BaseUrl 'https://aria.example.com' -ApiToken $apiToken `
            -Tenant 'aria-example' -ExchangeMode 'oauth-tenant'

        Tries the oauth-tenant shape first.

    .EXAMPLE
        $login = Invoke-AriaApiTokenLogin -BaseUrl 'https://aria.example.com' -ApiToken $apiToken `
            -ProbeEndpoint 'iaas/api/projects?$top=1' -Verbose

        Names the probe endpoint explicitly and shows the choice in the verbose stream.

    .OUTPUTS
        PSCustomObject with Bearer (SecureString), BearerMode (csp, oauth or iaas), ExpiresIn
        (seconds) and ExchangeMode (the call shape that produced the bearer).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 09-OCT-26

        CHANGE LOG
        1.0.0 | 09OCT26 | Initial version. AriaApiToken provider: exchange and verified bearer
                          selection. Not yet verified against a tenant.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [Parameter(Mandatory)]
        [securestring]$ApiToken,

        [string]$Tenant,

        [string]$ExchangeMode,

        [string]$ProbeEndpoint = 'iaas/api/projects?$top=1'
    )

    $BaseUrl = $BaseUrl.TrimEnd('/')

    $first  = Invoke-AriaApiTokenExchange -BaseUrl $BaseUrl -ApiToken $ApiToken -Tenant $Tenant -Mode $ExchangeMode
    $chosen = $first

    if (-not (Test-ServiceBearer -BaseUrl $BaseUrl -Endpoint $ProbeEndpoint -Token $first.Token)) {
        Write-Verbose "The $($first.Kind) bearer from [$($first.Mode)] was not accepted by [$ProbeEndpoint]."

        $accepted = $false
        if ($first.Mode -ne 'iaas-login') {
            try {
                $iaas = Invoke-AriaApiTokenExchange -BaseUrl $BaseUrl -ApiToken $ApiToken -Only 'iaas-login'
                if (Test-ServiceBearer -BaseUrl $BaseUrl -Endpoint $ProbeEndpoint -Token $iaas.Token) {
                    $chosen   = $iaas
                    $accepted = $true
                }
            } catch {
                Write-Verbose "iaas/api/login did not accept the API token: $($_.Exception.Message)"
            }
        }

        if (-not $accepted) {
            Write-Warning "Neither the exchanged access token nor an iaas/api/login token was accepted by [$ProbeEndpoint]. Using the first bearer; endpoints that accept it will still work."
        }
    }

    [PSCustomObject]@{
        Bearer       = $chosen.Token
        BearerMode   = $chosen.Kind
        ExpiresIn    = $chosen.ExpiresIn
        ExchangeMode = $chosen.Mode
    }
}
