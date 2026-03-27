function Set-ServiceCredential {
    <#
    .SYNOPSIS
        Stores Basic credentials or token credentials for a service.

    .DESCRIPTION
        Stores either Basic credentials or token credentials for a service.
        Basic credentials follow the existing global, service, environment, and service+environment
        storage behavior.

        Token credentials require both -Service and -Environment. The -Token parameter accepts either
        a plain string or a SecureString. Plain string tokens are converted internally to SecureString
        before storage. If the supplied token begins with 'Bearer ', that prefix is removed before
        storage so only the raw token value is persisted. Bearer header formatting is applied later
        when request headers are resolved.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, custom-api), or 'global' for Basic Auth fallback only.
        Required for token storage.

    .PARAMETER Credential
        A PSCredential object used for Basic authentication storage.

    .PARAMETER Token
        A token value to store for token-based authentication.
        Accepts either a plain string or a SecureString. A leading 'Bearer ' prefix is stripped
        automatically before storage.

    .PARAMETER Environment
        The environment: qa, prod, dev, or global (for Basic Auth only).
        Required for token storage.

    .PARAMETER Global
        Explicitly store credential as global fallback (Basic Auth only).

    .PARAMETER Force
        Overwrite existing values without confirmation when an existing credential or token is present.

    .EXAMPLE
        Set-ServiceCredential -Service jira -Environment prod
        Prompts interactively and stores Basic credentials for jira in prod.

    .EXAMPLE
        Set-ServiceCredential -Service cloudflare -Environment prod -Token 'cfat_xxxxx'
        Stores a raw token string for cloudflare in prod.

    .EXAMPLE
        Set-ServiceCredential -Service cloudflare -Environment prod -Token 'Bearer cfat_xxxxx'
        Strips the Bearer prefix and stores only the raw token value.

    .EXAMPLE
        $secure = ConvertTo-SecureString 'cfat_xxxxx' -AsPlainText -Force
        Set-ServiceCredential -Service cloudflare -Environment prod -Token $secure
        Stores a SecureString token for cloudflare in prod.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.1.0
        Date        : 28-MAR-26

        CHANGE LOG
        2.1.0 | 28MAR26 | Added plain string token input support and Bearer prefix normalization before storage.
        2.0.0 | 27JAN26 | Refactored from Set-AtlassianCredential to support generalised API services.
        1.2.2 | 23JUN25 | Disallowed global PATs. Enforced service+environment requirement for PATs. Refined Basic Auth global logic.
        1.2.1 | 04JUN25 | Refined global resolution logic to ensure accurate key assignment.
        1.2.0 | 03JUN25 | Migrated variable scope from $module to $global for compatibility.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [pscredential]$Credential,
        [object]$Token,
        [string]$Environment,
        [switch]$Global,
        [switch]$Force
    )

    $credentialSupplied = $PSBoundParameters.ContainsKey('Credential')
    $tokenSupplied = $PSBoundParameters.ContainsKey('Token')

    # === Prompt for Basic Auth only when neither Credential nor Token was supplied ===
    if (-not $credentialSupplied -and -not $tokenSupplied) {
        Write-Verbose "No Credential or Token supplied. Prompting for Basic Auth."
        $Credential = Invoke-CredentialPrompt -Service $Service -Environment $Environment
    }

    # === Disallow use of both Basic and Token in a single call ===
    if ($credentialSupplied -and $tokenSupplied) {
        throw "You cannot supply both -Credential and -Token. Choose one."
    }

    # === Handle Token-based authentication ===
    if ($tokenSupplied) {
        # Tokens must be scoped to a specific service and environment
        if (-not $Service -or -not $Environment -or $Service -eq 'global' -or $Environment -eq 'global') {
            throw "Tokens must be stored per service and environment. Global tokens are not supported."
        }

        $tokenValue = $null
        if ($Token -is [SecureString]) {
            $tokenValue = ConvertSecureStringToPlainText -SecureString $Token
        } elseif ($Token -is [string]) {
            $tokenValue = $Token
        } else {
            throw "Token must be either a SecureString or a string."
        }

        # Strip any Bearer prefix so only the raw token value is stored.
        if ($tokenValue.StartsWith('Bearer ', [System.StringComparison]::OrdinalIgnoreCase)) {
            $tokenValue = $tokenValue.Substring(7)
        }

        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw "Token value cannot be null or empty."
        }

        # Convert plain token text to SecureString before storing it in the token cache.
        $secureToken = ConvertTo-SecureString -String $tokenValue -AsPlainText -Force
        $key = New-ServiceKey -Service $Service -Environment $Environment

        # Confirm overwrite unless -Force is specified
        if ($global:ServiceTokens.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Token for [$key] already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        # Store the token
        $global:ServiceTokens[$key] = $secureToken
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
