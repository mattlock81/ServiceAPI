function Set-ServiceCredential {
    <#
    .SYNOPSIS
        Stores Basic, Token, or SSO credentials for a service.

    .DESCRIPTION
        Stores credentials for use with Invoke-APIRequest. Three authentication modes are supported.

        Basic Auth is the default. When neither -UseToken nor -UseSSO is specified, a PSCredential
        object is stored in the Basic Auth credential store. If no -Credential is supplied, the
        function prompts interactively. Basic credentials support global, service-global, environment-
        wide, and service+environment-specific storage.

        Token mode (-UseToken) stores a static long-lived Bearer token for a specific service and
        environment. The token value may be supplied inline as a plain string or SecureString. If no
        value is supplied, the function prompts interactively. Bearer prefix is stripped before storage.
        Token credentials require both -Service and -Environment. Global tokens are not supported.

        SSO mode (-UseSSO) obtains and stores a short-lived OAuth Bearer token using the configured
        SSO provider for the service. The provider is resolved from the service registry entry set
        via Register-CustomService -SSOProvider. If no provider is registered and none is supplied
        inline, the function prompts to register one. SSO tokens are stored with an expiry timestamp
        and refreshed automatically when stale. SSO credentials require both -Service and -Environment.
        Global SSO tokens are not supported.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, googleapi).
        Required for token and SSO storage. Optional for Basic Auth global storage.

    .PARAMETER Credential
        A PSCredential object for Basic Auth storage. If omitted, the function prompts interactively.

    .PARAMETER UseToken
        Switches to token-based credential storage. Accepts an optional inline token value as a
        plain string or SecureString. If no value is supplied, prompts interactively.
        Requires both -Service and -Environment.

    .PARAMETER UseSSO
        Switches to SSO-based credential storage. Accepts an optional inline provider name.
        If no provider is supplied, resolves from the service registry or prompts to register one.
        Requires both -Service and -Environment.

    .PARAMETER Environment
        The environment: qa, prod, dev, or global (Basic Auth only). Defaults to prod.
        Required for token and SSO storage.

    .PARAMETER Global
        Explicitly store credential as global fallback (Basic Auth only).

    .PARAMETER Force
        Overwrite existing values without confirmation.

    .EXAMPLE
        Set-ServiceCredential -Service jira -Environment prod
        Prompts interactively and stores Basic credentials for jira in prod.

    .EXAMPLE
        Set-ServiceCredential -Service cloudflare -Environment prod -UseToken 'cfat_xxxxx'
        Stores a raw token string for cloudflare in prod.

    .EXAMPLE
        Set-ServiceCredential -Service cloudflare -Environment prod -UseToken
        Prompts interactively for a token and stores it for cloudflare in prod.

    .EXAMPLE
        Set-ServiceCredential -Service googleapi -Environment prod -UseSSO
        Resolves the GCloud provider from the service registry, obtains a token, and stores it.

    .EXAMPLE
        Set-ServiceCredential -Service googleapi -Environment prod -UseSSO GCloud
        Explicitly specifies the GCloud provider, obtains a token, and stores it.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.2.0
        Date        : 16-MAY-26

        CHANGE LOG
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO-based token storage. SSO tokens are
                          obtained via provider dispatch, stored in $global:ServiceSSOTokens with
                          expiry metadata. -UseToken changed from [switch] to [string] to support
                          optional inline token value. Interactive prompt added for -UseToken when
                          no value is supplied.
        2.1.1 | 28MAR26 | Documentation refresh for module-level handled-error reporting and version consistency.
        2.1.0 | 28MAR26 | Added plain string token input support and Bearer prefix normalisation before storage.
        2.0.0 | 27JAN26 | Refactored from Set-AtlassianCredential to support generalised API services.
        1.2.2 | 23JUN25 | Disallowed global PATs. Enforced service+environment requirement for PATs.
        1.2.1 | 04JUN25 | Refined global resolution logic to ensure accurate key assignment.
        1.2.0 | 03JUN25 | Migrated variable scope from $module to $global for compatibility.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [pscredential]$Credential,

        # -UseToken accepts an optional inline token value (plain string or SecureString).
        # Presence alone activates token mode. Inline value bypasses interactive prompt.
        [AllowNull()][AllowEmptyString()]
        [object]$UseToken,

        # -UseSSO accepts an optional inline provider name.
        # Presence alone activates SSO mode. Inline value overrides registry provider lookup.
        [AllowNull()][AllowEmptyString()]
        [object]$UseSSO,

        [string]$Environment = 'prod',
        [switch]$Global,
        [switch]$Force
    )

    $useTokenMode = $PSBoundParameters.ContainsKey('UseToken')
    $useSSOMode   = $PSBoundParameters.ContainsKey('UseSSO')
    $credSupplied = $PSBoundParameters.ContainsKey('Credential')

    # === Disallow combining auth modes ===
    if ($useTokenMode -and $useSSOMode) {
        throw "You cannot specify both -UseToken and -UseSSO. Choose one authentication mode."
    }

    if (($useTokenMode -or $useSSOMode) -and $credSupplied) {
        throw "You cannot supply -Credential with -UseToken or -UseSSO. Choose one authentication mode."
    }

    # =========================================================================
    # TOKEN MODE — static long-lived Bearer token
    # =========================================================================
    if ($useTokenMode) {

        if (-not $Service -or $Service -eq 'global') {
            throw "Token storage requires -Service. Global tokens are not supported."
        }
        if (-not $Environment -or $Environment -eq 'global') {
            throw "Token storage requires -Environment. Global tokens are not supported."
        }

        # Resolve token value — inline, SecureString, or interactive prompt
        $tokenValue = $null

        if ($null -ne $UseToken -and $UseToken -isnot [string] -and $UseToken -is [SecureString]) {
            $tokenValue = ConvertSecureStringToPlainText -SecureString $UseToken
        } elseif (-not [string]::IsNullOrWhiteSpace([string]$UseToken)) {
            $tokenValue = [string]$UseToken
        } else {
            # No inline value supplied — prompt interactively
            Write-Host "Enter token for [$Service-$Environment]:" -ForegroundColor Cyan
            $secureInput = Read-Host -AsSecureString "Token"
            $tokenValue  = ConvertSecureStringToPlainText -SecureString $secureInput
        }

        # Strip Bearer prefix before storage — raw token value only
        if ($tokenValue.StartsWith('Bearer ', [System.StringComparison]::OrdinalIgnoreCase)) {
            $tokenValue = $tokenValue.Substring(7)
        }

        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw "Token value cannot be null or empty."
        }

        $secureToken = ConvertTo-SecureString -String $tokenValue -AsPlainText -Force
        $key         = New-ServiceKey -Service $Service -Environment $Environment

        if ($global:ServiceTokens.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Token for [$key] already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        $global:ServiceTokens[$key] = $secureToken
        Write-Verbose "Stored static token for [$key]."
        return
    }

    # =========================================================================
    # SSO MODE — short-lived OAuth Bearer token with expiry and provider dispatch
    # =========================================================================
    if ($useSSOMode) {

        if (-not $Service -or $Service -eq 'global') {
            throw "SSO token storage requires -Service. Global SSO tokens are not supported."
        }
        if (-not $Environment -or $Environment -eq 'global') {
            throw "SSO token storage requires -Environment. Global SSO tokens are not supported."
        }

        # Resolve the provider — inline value, registry lookup, or interactive prompt
        $provider = $null

        if (-not [string]::IsNullOrWhiteSpace([string]$UseSSO)) {
            # Provider supplied inline
            $provider = [string]$UseSSO
        } elseif ($global:ServiceRegistry.ContainsKey($Service) -and
                  $global:ServiceRegistry[$Service].ContainsKey($Environment) -and
                  $global:ServiceRegistry[$Service][$Environment].SSOProvider) {
            # Provider resolved from service registry
            $provider = $global:ServiceRegistry[$Service][$Environment].SSOProvider
            Write-Verbose "Resolved SSO provider [$provider] from service registry for [$Service-$Environment]."
        } else {
            # No provider found — prompt to register one
            Write-Warning "No SSO provider registered for [$Service-$Environment]."
            $register = Read-Host "Would you like to register an SSO provider for [$Service-$Environment]? (Y/N)"
            if ($register -ne 'Y') {
                throw "SSO provider is required. Register one via Register-CustomService -SSOProvider or supply inline."
            }

            Write-Host "Supported providers: GCloud, AzureCLI" -ForegroundColor Cyan
            $provider = Read-Host "Enter provider name"

            if ([string]::IsNullOrWhiteSpace($provider)) {
                throw "Provider name cannot be empty."
            }

            # Persist provider to service registry for future calls
            if ($global:ServiceRegistry.ContainsKey($Service) -and
                $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
                $global:ServiceRegistry[$Service][$Environment].SSOProvider = $provider
                Write-Verbose "Registered SSO provider [$provider] for [$Service-$Environment] in service registry."
            } else {
                Write-Warning "Service [$Service-$Environment] is not in the registry. Provider registered for this session only."
            }
        }

        # Obtain token via provider dispatch
        $tokenValue = Invoke-SSOProviderToken -Provider $provider

        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw "SSO provider [$provider] returned an empty token."
        }

        $key         = New-ServiceKey -Service $Service -Environment $Environment
        $secureToken = ConvertTo-SecureString -String $tokenValue -AsPlainText -Force

        # Store token with expiry timestamp and provider — used for lazy refresh in Get-ServiceCredential
        $global:ServiceSSOTokens[$key] = @{
            Token     = $secureToken
            ExpiresAt = [DateTime]::UtcNow.AddMinutes(55)
            Provider  = $provider
        }

        Write-Verbose "Stored SSO token for [$key] via provider [$provider]. Expires at [$($global:ServiceSSOTokens[$key].ExpiresAt)] UTC."
        return
    }

    # =========================================================================
    # BASIC AUTH MODE — default when neither -UseToken nor -UseSSO is specified
    # =========================================================================

    # Prompt interactively if no credential was supplied
    if (-not $credSupplied) {
        Write-Verbose "No Credential supplied. Prompting for Basic Auth."
        $Credential = Invoke-CredentialPrompt -Service $Service -Environment $Environment
    }

    # Determine whether this should be stored as a global fallback
    $isGlobal = $Global -or (-not $Service -and -not $Environment)

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

    # Store as service-global Basic Auth credential
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

    # Store as environment-wide Basic Auth credential across all registered services
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

    # Store as service+environment-specific Basic Auth credential
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
