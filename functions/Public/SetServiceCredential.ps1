function Set-ServiceCredential {
    <#
    .SYNOPSIS
        Stores a Basic Authentication credential or token for an API service, environment, or global fallback.

    .DESCRIPTION
        Supports token-based and Basic Auth. Basic credentials default to global unless -Service/-Environment are specified.
        Allows per-service or per-environment storage without requiring both parameters.
        Tokens require both -Service and -Environment to be set. Global tokens are not supported.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api), or 'global' for Basic Auth fallback only.

    .PARAMETER Credential
        A PSCredential object for Basic Authentication.

    .PARAMETER Token
        A SecureString representing a Personal Access Token or API key.

    .PARAMETER Environment
        The environment: qa, prod, dev, or global (for Basic Auth only).

    .PARAMETER Global
        Explicitly store credential as global fallback (Basic Auth only).

    .PARAMETER Force
        Overwrite existing values without confirmation.

    .EXAMPLE
        Set-ServiceCredential -Credential (Get-Credential)
        # Stores as global fallback

    .EXAMPLE
        Set-ServiceCredential -Service jira -Credential (Get-Credential)
        # Stores for jira service (all environments)

    .EXAMPLE
        Set-ServiceCredential -Service custom-api -Environment prod -Token (Read-Host -AsSecureString)
        # Stores token for custom-api in prod environment

    .EXAMPLE
        Set-ServiceCredential -Environment qa -Credential (Get-Credential)
        # Stores for all registered services in qa environment

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        2.0.0 | 27JAN26 | Refactored from Set-AtlassianCredential to support generalised API services.
        1.2.2 | 23JUN25 | Disallowed global PATs. Enforced service+environment requirement for PATs. Refined Basic Auth global logic.
        1.2.1 | 04JUN25 | Refined global resolution logic to ensure accurate key assignment.
        1.2.0 | 03JUN25 | Migrated variable scope from $module to $global for compatibility.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [pscredential]$Credential,
        [SecureString]$Token,
        [string]$Environment,
        [switch]$Global,
        [switch]$Force
    )

    # === Interactive fallback for Basic Auth if neither credential nor token is supplied ===
    if (-not $Credential -and -not $Token) {
        Write-Verbose "No Credential or Token supplied. Prompting for Basic Auth."
        $Credential = Invoke-CredentialPrompt -Service $Service -Environment $Environment
    }

    # === Disallow use of both Basic and Token in a single call ===
    if ($Credential -and $Token) {
        throw "You cannot supply both -Credential and -Token. Choose one."
    }

    # === Handle Token-based authentication ===
    if ($Token) {
        # Tokens must be scoped to a specific service and environment
        if (-not $Service -or -not $Environment -or $Service -eq 'global' -or $Environment -eq 'global') {
            throw "Tokens must be stored per service and environment. Global tokens are not supported."
        }

        $key = New-ServiceKey -Service $Service -Environment $Environment

        # Confirm overwrite unless -Force is specified
        if ($global:ServiceTokens.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Token for [$key] already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        # Store the token
        $global:ServiceTokens[$key] = $Token
        Write-Verbose "Stored token for [$key]."
        return
    }

    # === Handle Basic Auth credential logic ===
    $storingBasic = $Credential -ne $null

    # Determine whether this should be stored as a global fallback
    $isGlobal = $Global -or ($storingBasic -and -not ($Service -or $Environment))

    # === Store as global Basic Auth credential ===
    if ($isGlobal) {
        $key = New-ServiceKey -Global
        if ($global:ServiceCredentials.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Global Basic credential already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        $global:ServiceCredentials[$key] = $Credential
        Write-Verbose "Stored global Basic Auth credential."
        return
    }

    # === Store as service-global Basic Auth credential ===
    if ($Service -and -not $Environment) {
        $key = New-ServiceKey -Service $Service
        if ($global:ServiceCredentials.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Credential for [$key] already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        $global:ServiceCredentials[$key] = $Credential
        Write-Verbose "Stored Basic Auth credential for [$key]."
        return
    }

    # === Store as environment-wide Basic Auth credential across all registered services ===
    if ($Environment -and -not $Service) {
        foreach ($svc in $global:RegisteredServices) {
            $key = New-ServiceKey -Service $svc -Environment $Environment
            if ($global:ServiceCredentials.ContainsKey($key) -and -not $Force) {
                $confirm = Read-Host "Credential for [$key] already exists. Overwrite? (Y/N)"
                if ($confirm -ne 'Y') { continue }
            }

            $global:ServiceCredentials[$key] = $Credential
            Write-Verbose "Stored Basic Auth credential for [$key]."
        }
        return
    }

    # === Store as service+environment-specific Basic Auth credential ===
    if ($Service -and $Environment) {
        $key = New-ServiceKey -Service $Service -Environment $Environment
        if ($global:ServiceCredentials.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Credential for [$key] already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        $global:ServiceCredentials[$key] = $Credential
        Write-Verbose "Stored Basic Auth credential for [$key]."
    }
}
