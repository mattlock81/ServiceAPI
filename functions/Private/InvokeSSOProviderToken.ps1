function Invoke-SSOProviderToken {
    <#
    .SYNOPSIS
        Obtains a fresh access token from the specified SSO provider.

    .DESCRIPTION
        Dispatches a token acquisition call to the appropriate SSO provider and returns
        the raw token string. Called internally by Set-ServiceCredential and Get-ServiceCredential.
        This function is not exported and is not intended for direct caller use.

        Supported providers:
            GCloud   — requires Google Cloud SDK (gcloud CLI)
            AzureCLI — requires Azure CLI (az CLI)
            Aria     — VMware Aria Automation. Requires -Credential (domain identity,
                       UserName in 'username@domain' or plain 'username' form) and
                       -Domain. Performs the two-step CSP refresh-token then IaaS
                       bearer-token exchange over REST — no CLI tool required.

    .PARAMETER Provider
        The SSO provider name. Must match a supported provider in the dispatch switch.

    .PARAMETER Credential
        Required only for the Aria provider. A PSCredential holding the domain identity
        (UserName) and password to exchange for an Aria bearer token. Ignored by all
        other providers.

    .PARAMETER Domain
        Required only for the Aria provider. The domain to submit alongside the
        username in the CSP refresh-token request body. Ignored by all other providers.

    .PARAMETER BaseUrl
        Required only for the Aria provider. The Aria Automation appliance base URL
        (e.g. https://aria.example.com) — the CSP and IaaS endpoints are appended to
        this. Ignored by all other providers.

    .EXAMPLE
        Invoke-SSOProviderToken -Provider GCloud
        Returns a fresh Google OAuth access token via gcloud.

    .EXAMPLE
        Invoke-SSOProviderToken -Provider AzureCLI
        Returns a fresh Azure AD access token via az CLI.

    .EXAMPLE
        Invoke-SSOProviderToken -Provider Aria -Credential $cred -Domain 'CorpDomain' -BaseUrl 'https://aria.example.com'
        Returns a fresh Aria bearer token via the CSP refresh-token / IaaS login exchange.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 12-AUG-26

        CHANGE LOG
        1.1.0 | 12AUG26 | Added Aria provider — two-step CSP refresh-token / IaaS
                          bearer-token REST exchange. Added optional -Credential, -Domain,
                          -BaseUrl parameters, unused by and non-breaking for GCloud and
                          AzureCLI. Errors routed through Write-ServiceApiHandledError for
                          consistency with the rest of the module.
        1.0.0 | 16MAY26 | Initial version. Centralises SSO provider token dispatch for
                          Set-ServiceCredential and Get-ServiceCredential.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Provider,

        # Aria only — ignored by GCloud and AzureCLI.
        [pscredential]$Credential,

        # Aria only — ignored by GCloud and AzureCLI.
        [string]$Domain,

        # Aria only — ignored by GCloud and AzureCLI.
        [string]$BaseUrl
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

        'Aria' {
            # REST-native provider — no CLI tool required. Caller (Set-ServiceCredential /
            # Get-ServiceCredential) resolves -Credential, -Domain, and -BaseUrl before dispatch.
            if (-not $Credential) {
                throw "SSO provider [Aria] requires -Credential."
            }
            if ([string]::IsNullOrWhiteSpace($Domain)) {
                throw "SSO provider [Aria] requires -Domain."
            }
            if ([string]::IsNullOrWhiteSpace($BaseUrl)) {
                throw "SSO provider [Aria] requires -BaseUrl."
            }

            $ariaUserName = $Credential.UserName
            if ($ariaUserName -match '@') {
                $ariaUserName = ($ariaUserName -split '@', 2)[0]
            }
            $ariaPassword = $Credential.GetNetworkCredential().Password

            # Step 1 — CSP refresh token (long-lived, ~90 day validity per Aria docs)
            $refreshBody = @{
                username = $ariaUserName
                password = $ariaPassword
                domain   = $Domain
            } | ConvertTo-Json

            try {
                $refreshResponse = Invoke-RestMethod -Method Post `
                    -Uri "$($BaseUrl.TrimEnd('/'))/csp/gateway/am/api/login?access_token" `
                    -ContentType 'application/json' `
                    -Body $refreshBody -ErrorAction Stop
            } catch {
                throw "Aria refresh token request failed — $_"
            }

            $refreshToken = $refreshResponse.refresh_token
            if ([string]::IsNullOrWhiteSpace($refreshToken)) {
                throw "Aria refresh token exchange returned no refresh_token. Check username/password/domain."
            }

            # Step 2 — IaaS bearer token, short-lived. Exact expiry window varies by tenancy —
            # caller applies its own cache expiry rather than trusting a fixed value here.
            $accessBody = @{ refreshToken = $refreshToken } | ConvertTo-Json

            try {
                $accessResponse = Invoke-RestMethod -Method Post `
                    -Uri "$($BaseUrl.TrimEnd('/'))/iaas/api/login" `
                    -ContentType 'application/json' `
                    -Body $accessBody -ErrorAction Stop
            } catch {
                throw "Aria bearer token request failed — $_"
            }

            $token = $accessResponse.token
            if ([string]::IsNullOrWhiteSpace($token)) {
                throw "Aria bearer token exchange returned no token."
            }
        }

        default {
            throw "Unknown SSO provider [$Provider]. Supported providers: GCloud, AzureCLI, Aria."
        }
    }

    return $token.Trim()
}
