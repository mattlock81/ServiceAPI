function Get-ServiceConfig {
    <#
    .SYNOPSIS
        Resolves BaseUrl and headers for a service/environment.

    .DESCRIPTION
        Resolves the BaseUrl and headers to be used with REST API requests.
        BaseUrl may come from the supplied -BaseUrl parameter or the registered service
        configuration.

        Headers are built in layers:
        1. New-StandardHeaders provides the base set.
        2. Registered DefaultHeaders are overlaid — they take precedence over standard headers.
        3. Credential-derived headers are resolved via Get-ServiceCredential using the
           supplied -AuthType and -Label, only when Authorization is not already provided
           by DefaultHeaders.

        When DefaultHeaders already contains a non-empty Authorization value, credential
        resolution is skipped entirely regardless of -AuthType.

    .PARAMETER Service
        Service name to resolve.

    .PARAMETER AuthType
        The authentication type to resolve. Accepted values: Basic, Token, SSO.
        Defaults to Basic.

    .PARAMETER Label
        The vault label to retrieve. Defaults to 'default'.
        Applies to Basic and Token auth types.

    .PARAMETER Environment
        Environment to resolve. Defaults to prod.

    .PARAMETER BaseUrl
        Optional direct BaseUrl override. Required if the service/environment is not registered.

    .PARAMETER SessionOnly
        Bypasses vault lookup and storage. Passed through to Get-ServiceCredential.
        Ignored for SSO.

    .PARAMETER Endpoint
        Passed through to Get-ServiceCredential for vault test call validation.

    .EXAMPLE
        Get-ServiceConfig -Service jira -Environment prod
        Returns resolved configuration for jira in prod using Basic Auth.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -AuthType Token
        Returns resolved configuration using token credential resolution.

    .EXAMPLE
        Get-ServiceConfig -Service cloudflare -Environment prod -AuthType Token -Label work
        Returns resolved configuration using the 'work' labelled token credential.

    .EXAMPLE
        Get-ServiceConfig -Service google -Environment prod -AuthType SSO
        Returns resolved configuration using SSO credential resolution.

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.5.1
        Date        : 17-MAY-26

        CHANGE LOG
        2.5.1 | 17MAY26 | Added 'None' to -AuthType ValidateSet. Credential resolution
                          skipped entirely when AuthType is 'None' — suitable for
                          unauthenticated local services and listeners.
        2.5.0 | 17MAY26 | Replaced -UseToken and -UseSSO with -AuthType [ValidateSet] and
                          -Label parameters. Auth mode selection is now explicit and tab-completed.
        2.4.4 | 17MAY26 | Added -SessionOnly and -Endpoint pass-through to Get-ServiceCredential.
        2.4.0 | 17MAY26 | Added -UseSSO parameter for SSO credential resolution pass-through.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
        2.2.0 | 16MAY26 | Added -UseSSO parameter for SSO credential resolution pass-through.
        2.1.1 | 28MAR26 | Documentation refresh for centralised handled-error reporting.
        2.1.0 | 28MAR26 | Added registered DefaultHeaders precedence and skipped credential
                          lookup when Authorization is already supplied.
        2.0.0 | 27JAN26 | Refactored from Get-AtlassianConfig to support generalised API services.
        1.2.0 | 22AUG25 | Added support for custom service with -BaseUrl.
        1.1.5 | 23JUN25 | Added inline comments and enforced early fail for unimplemented -UseSSO flag.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
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

        [ValidateSet('Basic', 'Token', 'SSO', 'None')]
        [string]$AuthType = 'Basic',

        # Vault label — applies to Basic and Token auth types. Defaults to 'default'.
        [string]$Label = 'default',

        [string]$Environment = 'prod',
        [string]$BaseUrl,

        # Bypasses vault lookup and storage — passed through to Get-ServiceCredential. Ignored for SSO.
        [switch]$SessionOnly,

        # Passed through to Get-ServiceCredential for vault test call validation.
        [string]$Endpoint
    )

    try {
        $serviceConfig = $null

        # === Determine the BaseUrl ===
        if ($BaseUrl) {
            Write-Verbose "Using custom BaseUrl: $BaseUrl"
        } elseif ($global:ServiceRegistry.ContainsKey($Service) -and
                  $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
            $serviceConfig = $global:ServiceRegistry[$Service][$Environment]
            $BaseUrl = $serviceConfig.BaseUrl
            Write-Verbose "Resolved BaseUrl from registry: $BaseUrl"
        } else {
            throw "BaseUrl not defined for [$Service] in [$Environment] environment. Provide -BaseUrl or register the service first."
        }

        # === Start with standard headers ===
        $Headers = New-StandardHeaders -Service $Service

        # === Overlay registered DefaultHeaders ===
        if ($serviceConfig -and $null -ne $serviceConfig.DefaultHeaders) {
            if ($serviceConfig.DefaultHeaders -isnot [System.Collections.IDictionary]) {
                throw "DefaultHeaders for [$Service] in [$Environment] must be a hashtable or dictionary-compatible object."
            }
            foreach ($key in $serviceConfig.DefaultHeaders.Keys) {
                $Headers[$key] = $serviceConfig.DefaultHeaders[$key]
            }
        }

        # === Check whether DefaultHeaders already provides a non-empty Authorization value ===
        $hasAuthorizationHeader = $false
        foreach ($key in $Headers.Keys) {
            if ([string]::Equals([string]$key, 'Authorization', [System.StringComparison]::OrdinalIgnoreCase) -and
                -not [string]::IsNullOrWhiteSpace([string]$Headers[$key])) {
                $hasAuthorizationHeader = $true
                break
            }
        }

        # === Resolve credential-derived headers when Authorization is not already present ===
        if (-not $hasAuthorizationHeader -and $AuthType -ne 'None') {

            $credParams = @{
                Service     = $Service
                Environment = $Environment
                AuthType    = $AuthType
                Label       = $Label
            }

            if ($SessionOnly -and $AuthType -ne 'SSO') { $credParams['SessionOnly'] = $true }
            if ($Endpoint)                              { $credParams['Endpoint']    = $Endpoint }
            if ($BaseUrl)                               { $credParams['BaseUrl']     = $BaseUrl }

            $credentialHeaders = Get-ServiceCredential @credParams

            # Apply credential-derived headers only to keys not already defined
            foreach ($key in $credentialHeaders.Keys) {
                $headerExists = $false
                foreach ($existingKey in $Headers.Keys) {
                    if ([string]::Equals([string]$existingKey, [string]$key, [System.StringComparison]::OrdinalIgnoreCase)) {
                        $headerExists = $true
                        break
                    }
                }
                if (-not $headerExists) {
                    $Headers[$key] = $credentialHeaders[$key]
                }
            }
        } else {
            Write-Verbose "Skipping credential resolution — AuthType is '$AuthType'."
        }

        return @{
            Service     = $Service
            Environment = $Environment
            BaseUrl     = $BaseUrl
            Headers     = $Headers
        }

    } catch {
        Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical'
        return $null
    }
}
