function Invoke-SSOProviderToken {
    <#
    .SYNOPSIS
        Obtains a fresh access token from the specified SSO provider.

    .DESCRIPTION
        Dispatches a token acquisition call to the appropriate SSO provider CLI tool and returns
        the raw token string. Called internally by Set-ServiceCredential and Get-ServiceCredential.
        This function is not exported and is not intended for direct caller use.

        Supported providers:
            GCloud   — requires Google Cloud SDK (gcloud CLI)
            AzureCLI — requires Azure CLI (az CLI)

    .PARAMETER Provider
        The SSO provider name. Must match a supported provider in the dispatch switch.

    .EXAMPLE
        Invoke-SSOProviderToken -Provider GCloud
        Returns a fresh Google OAuth access token via gcloud.

    .EXAMPLE
        Invoke-SSOProviderToken -Provider AzureCLI
        Returns a fresh Azure AD access token via az CLI.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-MAY-26

        CHANGE LOG
        1.0.0 | 16MAY26 | Initial version. Centralises SSO provider token dispatch for
                          Set-ServiceCredential and Get-ServiceCredential.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Provider
    )

    $token = $null

    switch ($Provider) {
        'GCloud' {
            # Requires Google Cloud SDK — gcloud auth application-default login must have been run
            if (-not (Get-Command -Name gcloud -ErrorAction SilentlyContinue)) {
                throw "SSO provider [GCloud] requires the Google Cloud SDK. Install from https://cloud.google.com/sdk/docs/install"
            }
            $token = (gcloud auth application-default print-access-token 2>&1)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
                throw "GCloud token acquisition failed. Run: gcloud auth application-default login --client-id-file=<path> --scopes=<scopes>"
            }
        }

        'AzureCLI' {
            # Requires Azure CLI — az login must have been run
            if (-not (Get-Command -Name az -ErrorAction SilentlyContinue)) {
                throw "SSO provider [AzureCLI] requires the Azure CLI. Install from https://docs.microsoft.com/cli/azure/install-azure-cli"
            }
            $token = (az account get-access-token --query accessToken -o tsv 2>&1)
            if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($token)) {
                throw "AzureCLI token acquisition failed. Run: az login"
            }
        }

        default {
            throw "Unknown SSO provider [$Provider]. Supported providers: GCloud, AzureCLI."
        }
    }

    return $token.Trim()
}
