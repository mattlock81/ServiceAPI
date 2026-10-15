function Get-PingFederateClient {
    <#
    .SYNOPSIS
        Reads the stored PingFederate OAuth client id and secret for a service.

    .DESCRIPTION
        Returns the client held under the Basic credential label 'oidcclient' for the service and
        environment, by way of Get-ServiceCredential -AuthType Basic, so it comes from the chosen
        vault, the session store, or an interactive prompt (which then stores it), in that order.
        The credential's user name is the client id and its password is the client secret. A
        Basic credential is used rather than a Token because a client secret can contain a colon.

    .PARAMETER Service
        The service name.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Vault
        Optional. The registered vault to read from (see Get-ServiceVault).

    .EXAMPLE
        $client = Get-PingFederateClient -Service ping

        Reads the client for ping-prod.

    .EXAMPLE
        $client = Get-PingFederateClient -Service ping -Environment dev -Vault automation

        Reads the client for ping-dev from the 'automation' vault.

    .EXAMPLE
        & (Get-Module ServiceAPI) { (Get-PingFederateClient -Service ping).ClientId }

        Confirms from outside the module which client id is stored, without showing the secret.

    .OUTPUTS
        PSCustomObject with ClientId (string) and ClientSecret (SecureString).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 15-OCT-26

        CHANGE LOG
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: client credential lookup.
    #>

    [CmdletBinding()]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',

        [string]$Vault
    )

    $headers = Get-ServiceCredential -Service $Service -Environment $Environment `
        -AuthType Basic -Label 'oidcclient' -Vault $Vault

    $b64     = ([string]$headers['Authorization']) -replace '^Basic\s+', ''
    $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
    $colon   = $decoded.IndexOf(':')

    if ($colon -lt 1) {
        throw "The PingFederate client for [$Service-$Environment] needs a client id as the user name. Store it with: Set-ServiceCredential -Service $Service -Environment $Environment -AuthType Basic -Label oidcclient (user name = client id, password = client secret)."
    }

    [PSCustomObject]@{
        ClientId     = $decoded.Substring(0, $colon)
        ClientSecret = ConvertTo-SecureString -String $decoded.Substring($colon + 1) -AsPlainText -Force
    }
}
