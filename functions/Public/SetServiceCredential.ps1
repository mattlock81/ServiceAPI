function Set-ServiceCredential {
    <#
    .SYNOPSIS
        Stores Basic Auth, Token, or SSO credentials for a service.

    .DESCRIPTION
        Stores credentials for use with Invoke-APIRequest. The authentication type is
        specified via -AuthType (Basic, Token, or SSO). Defaults to Basic.

        Basic Auth (-AuthType Basic):
        Stores a PSCredential in the Basic Auth credential store. If no -Credential is
        supplied, the function prompts interactively. Supports global, service-global,
        environment-wide, and service+environment-specific storage.

        Token (-AuthType Token):
        Stores a static long-lived token for a specific service and environment. The token
        value may be supplied inline as a plain string or SecureString. If no value is
        supplied, the function prompts interactively. Bearer prefix is stripped before
        storage. Requires both -Service and -Environment. Global tokens are not supported.

        SSO (-AuthType SSO):
        Obtains and stores a short-lived OAuth Bearer token using the SSO provider
        configured for the service via Register-CustomService -SSOProvider. The provider
        is resolved from the service registry. SSO tokens are stored with an expiry
        timestamp and refreshed automatically when stale. Requires both -Service and
        -Environment. Global SSO tokens are not supported.

    .PARAMETER Service
        The API service name (e.g., jira, confluence, google).
        Required for Token and SSO storage. Optional for Basic Auth global storage.

    .PARAMETER AuthType
        The authentication type to store. Accepted values: Basic, Token, SSO.
        Defaults to Basic.

    .PARAMETER Credential
        A PSCredential object for Basic Auth storage. If omitted, prompts interactively.
        Only valid when -AuthType Basic is specified.

    .PARAMETER Label
        The vault label to store the credential under. Defaults to 'default'.
        Applies to Basic and Token auth types.

    .PARAMETER Environment
        The environment: qa, prod, dev, or global (Basic Auth only). Defaults to prod.
        Required for Token and SSO storage.

    .PARAMETER Global
        Explicitly store credential as global fallback (Basic Auth only).

    .PARAMETER Force
        Overwrite existing values without confirmation.

    .EXAMPLE
        Set-ServiceCredential -Service jira -Environment prod
        Prompts interactively and stores Basic Auth credentials for jira in prod.

    .EXAMPLE
        Set-ServiceCredential -Service jira -Environment prod -AuthType Basic -Label matt
        Prompts interactively and stores Basic Auth credentials under label 'matt'.

    .EXAMPLE
        Set-ServiceCredential -Service cloudflare -Environment prod -AuthType Token
        Prompts interactively for a token and stores it under the 'default' label.

    .EXAMPLE
        Set-ServiceCredential -Service google -Environment prod -AuthType SSO
        Resolves the GCloud provider from the service registry, obtains a token, and stores it.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.5.1
        Date        : 17-MAY-26

        CHANGE LOG
        2.5.1 | 17MAY26 | Fixed Token mode vault write — Set-Secret and Write-VaultIndex
                          now called from Set-ServiceCredential Token path. Previously tokens
                          were written to session store only and lost between sessions.
        2.5.0 | 17MAY26 | Replaced -UseToken and -UseSSO with -AuthType [ValidateSet] parameter.
                          Added -Label parameter for named vault credential storage. Auth mode
                          selection is now explicit and tab-completed. -SessionOnly not applicable
                          to Set-ServiceCredential — applies to Get-ServiceCredential only.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO-based token storage.
        2.1.0 | 28MAR26 | Added plain string token input support and Bearer prefix normalisation.
        2.0.0 | 27JAN26 | Refactored from Set-AtlassianCredential to support generalised API services.
        1.2.2 | 23JUN25 | Disallowed global PATs. Enforced service+environment requirement for PATs.
        1.2.1 | 04JUN25 | Refined global resolution logic to ensure accurate key assignment.
        1.2.0 | 03JUN25 | Migrated variable scope from $module to $global for compatibility.
    #>

    [CmdletBinding()]
    param (
        [ArgumentCompleter({
            param($cmd, $param, $word, $ast, $fakeBound)
            if ($global:RegisteredServices) {
                $global:RegisteredServices |
                    Where-Object { $_ -like "$word*" } |
                    ForEach-Object {
                        [System.Management.Automation.CompletionResult]::new(
                            $_, $_, 'ParameterValue', $_
                        )
                    }
            }
        })]
        [string]$Service,

        [ValidateSet('Basic', 'Token', 'SSO')]
        [string]$AuthType = 'Basic',

        [pscredential]$Credential,

        # Vault label — applies to Basic and Token auth types. Defaults to 'default'.
        [string]$Label = 'default',

        [string]$Environment = 'prod',
        [switch]$Global,
        [switch]$Force
    )

    # =========================================================================
    # TOKEN MODE
    # =========================================================================
    if ($AuthType -eq 'Token') {

        if (-not $Service -or $Service -eq 'global') {
            throw "Token storage requires -Service. Global tokens are not supported."
        }
        if (-not $Environment -or $Environment -eq 'global') {
            throw "Token storage requires -Environment. Global tokens are not supported."
        }

        # Prompt interactively — token is always entered via secure prompt
        Write-Host "Enter token for [$Service-$Environment] (Label: $Label):" -ForegroundColor Cyan
        $secureInput = Read-Host -AsSecureString "Token"
        $tokenValue  = ConvertSecureStringToPlainText -SecureString $secureInput

        if ([string]::IsNullOrWhiteSpace($tokenValue)) {
            throw "Token value cannot be null or empty."
        }

        # Strip Bearer prefix before storage — raw token value only
        if ($tokenValue.StartsWith('Bearer ', [System.StringComparison]::OrdinalIgnoreCase)) {
            $tokenValue = $tokenValue.Substring(7)
        }

        $secureToken = ConvertTo-SecureString -String $tokenValue -AsPlainText -Force
        $key         = New-ServiceKey -Service $Service -Environment $Environment

        if ($global:ServiceTokens.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Token for [$key] (Label: $Label) already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }

        # Always write to in-memory store for this session
        $global:ServiceTokens[$key] = $secureToken
        Write-Verbose "Stored token for [$key] under label [$Label] in session store."

        # Write to vault when SecretManagement is available
        if ($script:ServiceApiHasSecretManagement) {
            $vaultName = "$Service-$Label-$Environment"
            try {
                Set-Secret -Name $vaultName -Secret $tokenValue -Vault LocalStore -ErrorAction Stop
                Write-VaultIndex -ServiceKey $key -Label $Label
                Write-Verbose "Stored token for [$key] under label [$Label] in vault as [$vaultName]."
            } catch {
                Write-Warning "Failed to store token in vault — $_. Token retained in session store only."
            }
        }

        return
    }

    # =========================================================================
    # SSO MODE
    # =========================================================================
    if ($AuthType -eq 'SSO') {

        if (-not $Service -or $Service -eq 'global') {
            throw "SSO token storage requires -Service. Global SSO tokens are not supported."
        }
        if (-not $Environment -or $Environment -eq 'global') {
            throw "SSO token storage requires -Environment. Global SSO tokens are not supported."
        }

        # Resolve provider from service registry
        $provider = $null

        if ($global:ServiceRegistry.ContainsKey($Service) -and
            $global:ServiceRegistry[$Service].ContainsKey($Environment) -and
            $global:ServiceRegistry[$Service][$Environment].SSOProvider) {
            $provider = $global:ServiceRegistry[$Service][$Environment].SSOProvider
            Write-Verbose "Resolved SSO provider [$provider] from service registry for [$Service-$Environment]."
        } else {
            # No provider found — prompt to register one
            Write-Warning "No SSO provider registered for [$Service-$Environment]."
            $register = Read-Host "Would you like to register an SSO provider? (Y/N)"
            if ($register -ne 'Y') {
                throw "SSO provider is required. Register one via Register-CustomService -SSOProvider."
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
                Write-Verbose "Registered SSO provider [$provider] for [$Service-$Environment]."
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

        $global:ServiceSSOTokens[$key] = @{
            Token     = $secureToken
            ExpiresAt = [DateTime]::UtcNow.AddMinutes(55)
            Provider  = $provider
        }

        Write-Verbose "Stored SSO token for [$key] via provider [$provider]. Expires at [$($global:ServiceSSOTokens[$key].ExpiresAt)] UTC."
        return
    }

    # =========================================================================
    # BASIC AUTH MODE — default
    # =========================================================================

    # Prompt interactively if no credential was supplied
    if (-not $PSBoundParameters.ContainsKey('Credential')) {
        Write-Verbose "No Credential supplied. Prompting for Basic Auth."
        $Credential = Invoke-CredentialPrompt -Service $Service -Environment $Environment
    }

    # Determine whether this should be stored as a global fallback
    $isGlobal = $Global -or (-not $Service -and -not $Environment)

    if ($isGlobal) {
        $key = New-ServiceKey -Global
        if ($global:ServiceCredentials.ContainsKey($key) -and -not $Force) {
            $confirm = Read-Host "Global Basic Auth credential already exists. Overwrite? (Y/N)"
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
            $confirm = Read-Host "Credential for [$key] (Label: $Label) already exists. Overwrite? (Y/N)"
            if ($confirm -ne 'Y') { return }
        }
        $global:ServiceCredentials[$key] = $Credential
        Write-Verbose "Stored Basic Auth credential for [$key] under label [$Label]."
    }
}
