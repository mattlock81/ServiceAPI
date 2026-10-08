function Get-AriaApiToken {
    <#
    .SYNOPSIS
        Reads the stored Aria API token for a service as a SecureString.

    .DESCRIPTION
        Returns the API token held under the label 'apitoken' for the service and environment,
        by way of Get-ServiceCredential -AuthType Token, so it comes from the chosen vault,
        the session store, or an interactive prompt (which then stores it), in that order.
        This mirrors how the Aria provider reads its 'ssoidentity' credential.

        The token must be stored without a key: Set-ServiceCredential -AuthType Token stores
        the pasted value as it is. A value containing a colon would be read as key:secret and
        refused with a message saying how to correct it.

    .PARAMETER Service
        The service name.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Vault
        Optional. The registered vault to read from (see Get-ServiceVault).

    .EXAMPLE
        $apiToken = Get-AriaApiToken -Service aria

        Reads the API token for aria-prod.

    .EXAMPLE
        $apiToken = Get-AriaApiToken -Service aria -Environment qa -Vault automation

        Reads the API token for aria-qa from the 'automation' vault.

    .EXAMPLE
        & (Get-Module ServiceAPI) { (Get-AriaApiToken -Service aria).Length }

        Confirms from outside the module that a token is stored, without displaying it.

    .OUTPUTS
        System.Security.SecureString

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 09-OCT-26

        CHANGE LOG
        1.0.0 | 09OCT26 | Initial version. AriaApiToken provider: API token lookup.
    #>

    [CmdletBinding()]
    [OutputType([securestring])]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod',

        [string]$Vault
    )

    $headers = Get-ServiceCredential -Service $Service -Environment $Environment `
        -AuthType Token -Label 'apitoken' -Vault $Vault

    $authorization = [string]$headers['Authorization']
    if ($authorization -match '^Bearer\s+(?<token>\S+)$') {
        return (ConvertTo-SecureString -String $Matches['token'] -AsPlainText -Force)
    }

    throw "The API token for [$Service-$Environment] must be stored without a key. Store it with: Set-ServiceCredential -Service $Service -Environment $Environment -AuthType Token -Label apitoken (paste the token alone at the Token prompt; a token containing a colon cannot be stored this way)."
}
