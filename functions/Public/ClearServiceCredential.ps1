function Clear-ServiceCredential {
    <#
    .SYNOPSIS
        Clears stored Basic Auth or Token credentials for an API service/environment/global pair.

    .DESCRIPTION
        Supports targeted clearing of credentials by service and/or environment.
        Global credentials can be cleared with the -Global switch.
        Supports credential type filtering (Basic, Token, All).
        Global tokens are not supported and cannot be cleared.

    .PARAMETER Service
        The API service (e.g., jira, confluence, custom-api).

    .PARAMETER Environment
        Target environment (qa, prod, dev).

    .PARAMETER AuthType
        Credential type to clear: Basic, Token, All.

    .PARAMETER Global
        Clears the global fallback credential (Basic only).

    .PARAMETER Force
        Skips confirmation prompt.

    .EXAMPLE
        Clear-ServiceCredential -Service jira -Environment qa -AuthType All

    .EXAMPLE
        Clear-ServiceCredential -Global -AuthType Basic

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        2.0.0 | 27JAN26 | Refactored from Clear-AtlassianCredential to support generalised API services.
        1.2.3 | 23JUN25 | Removed global PAT support; added inline comments and improved verbose feedback.
        1.2.1 | 03JUN25 | Enforced key-based removal from unified credential stores.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [string]$Environment,

        [ValidateSet('Basic','Token','All')]
        [string]$AuthType = 'All',

        [switch]$Global,
        [switch]$Force
    )

    # Initialise list of matching credentials to clear
    $targets = @()

    # === Global credential clearing logic ===
    if ($Global) {
        # Only Basic Auth supports global storage
        if ($AuthType -in @('All','Basic')) {
            $key = New-ServiceKey -Global
            if ($global:ServiceCredentials.ContainsKey($key)) {
                $targets += @{ Type = 'Basic'; Key = $key }
            }
        }

        # Tokens cannot be global – warn if user tries to clear one
        if ($AuthType -in @('All','Token')) {
            Write-Warning "Global tokens are not supported and cannot be cleared."
        }
    }

    # === Targeted service/environment-based clearing ===
    if ($Service -or $Environment) {
        $services = if ($Service) { @($Service) } else { $global:RegisteredServices }
        $environments = if ($Environment) { @($Environment) } else { @('qa','prod','dev') }

        foreach ($svc in $services) {
            foreach ($env in $environments) {
                $key = New-ServiceKey -Service $svc -Environment $env

                if ($AuthType -in @('All','Basic') -and $global:ServiceCredentials.ContainsKey($key)) {
                    $targets += @{ Type = 'Basic'; Key = $key }
                }

                if ($AuthType -in @('All','Token') -and $global:ServiceTokens.ContainsKey($key)) {
                    $targets += @{ Type = 'Token'; Key = $key }
                }
            }
        }
    }

    # === Exit early if nothing matched ===
    if (-not $targets) {
        Write-Warning "No matching credentials found."
        return
    }

    # === Loop through and remove each matching credential ===
    foreach ($target in $targets) {
        $type = $target.Type
        $key  = $target.Key

        # Confirm removal unless -Force is specified
        if (-not $Force) {
            $confirm = Read-Host "Confirm removal of $type credential [$key]? (Y/N)"
            if ($confirm -ne 'Y') { continue }
        }

        # Remove from the appropriate global store
        switch ($type) {
            'Basic' { $null = $global:ServiceCredentials.Remove($key) }
            'Token' { $null = $global:ServiceTokens.Remove($key) }
        }

        Write-Verbose "Removed $type credential for [$key]."
    }
}
