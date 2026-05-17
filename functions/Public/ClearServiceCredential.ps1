function Clear-ServiceCredential {
    <#
    .SYNOPSIS
        Clears stored Basic Auth, Token, or SSO credentials for an API service/environment pair.

    .DESCRIPTION
        Supports targeted clearing of credentials by service and/or environment.
        Global credentials can be cleared with the -Global switch.
        Supports credential type filtering via -AuthType: Basic, Token, SSO, or All.

        Basic Auth credentials are stored in $global:ServiceCredentials.
        Token credentials are stored in $global:ServiceTokens.
        SSO credentials are stored in $global:ServiceSSOTokens.

        Global tokens and global SSO tokens are not supported and cannot be cleared via -Global.

    .PARAMETER Service
        The API service (e.g., jira, confluence, googleapi).

    .PARAMETER Environment
        Target environment (qa, prod, dev).

    .PARAMETER AuthType
        Credential type to clear: Basic, Token, SSO, or All. Defaults to All.

    .PARAMETER Global
        Clears the global fallback credential (Basic Auth only).

    .PARAMETER Force
        Skips confirmation prompt.

    .EXAMPLE
        Clear-ServiceCredential -Service jira -Environment qa -AuthType All
        Clears all credential types for jira in qa.

    .EXAMPLE
        Clear-ServiceCredential -Service googleapi -Environment prod -AuthType SSO
        Clears the SSO token for googleapi in prod.

    .EXAMPLE
        Clear-ServiceCredential -Global -AuthType Basic
        Clears the global Basic Auth fallback credential.

    .EXAMPLE
        Clear-ServiceCredential -Service cloudflare -Environment prod -AuthType Token
        Clears the static Bearer token for cloudflare in prod.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 2.5.0
        Date        : 17-MAY-26

        CHANGE LOG
        2.5.0 | 17MAY26 | No functional changes — -AuthType ValidateSet already consistent with
                          new unified auth model. Version bumped for release consistency.
        2.3.0 | 16MAY26 | Added [ArgumentCompleter] on -Service for tab completion from live registry.
        2.2.0 | 16MAY26 | Added SSO credential clearing support. Extended -AuthType ValidateSet to
                          include 'SSO'. Added SSO key removal from $global:ServiceSSOTokens in the
                          targeted clearing loop. Updated global block to warn that SSO tokens cannot
                          be global.
        2.0.0 | 27JAN26 | Refactored from Clear-AtlassianCredential to support generalised API services.
        1.2.3 | 23JUN25 | Removed global PAT support; added inline comments and improved verbose feedback.
        1.2.1 | 03JUN25 | Enforced key-based removal from unified credential stores.
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
        [string]$Environment,

        [ValidateSet('Basic', 'Token', 'SSO', 'All')]
        [string]$AuthType = 'All',

        [switch]$Global,
        [switch]$Force
    )

    $targets = [System.Collections.Generic.List[hashtable]]::new()

    # === Global credential clearing — Basic Auth only ===
    if ($Global) {
        if ($AuthType -in @('All', 'Basic')) {
            $key = New-ServiceKey -Global
            if ($global:ServiceCredentials.ContainsKey($key)) {
                $targets.Add(@{ Type = 'Basic'; Key = $key })
            }
        }

        # Tokens and SSO tokens cannot be stored globally
        if ($AuthType -in @('All', 'Token')) {
            Write-Warning "Global tokens are not supported and cannot be cleared."
        }
        if ($AuthType -in @('All', 'SSO')) {
            Write-Warning "Global SSO tokens are not supported and cannot be cleared."
        }
    }

    # === Targeted service/environment-based clearing ===
    if ($Service -or $Environment) {
        $services     = if ($Service)     { @($Service) }     else { $global:RegisteredServices }
        $environments = if ($Environment) { @($Environment) } else { @('qa', 'prod', 'dev') }

        foreach ($svc in $services) {
            foreach ($env in $environments) {
                $key = New-ServiceKey -Service $svc -Environment $env

                if ($AuthType -in @('All', 'Basic') -and $global:ServiceCredentials.ContainsKey($key)) {
                    $targets.Add(@{ Type = 'Basic'; Key = $key })
                }

                if ($AuthType -in @('All', 'Token') -and $global:ServiceTokens.ContainsKey($key)) {
                    $targets.Add(@{ Type = 'Token'; Key = $key })
                }

                if ($AuthType -in @('All', 'SSO') -and $global:ServiceSSOTokens.ContainsKey($key)) {
                    $targets.Add(@{ Type = 'SSO'; Key = $key })
                }
            }
        }
    }

    # Exit early if nothing matched
    if ($targets.Count -eq 0) {
        Write-Warning "No matching credentials found."
        return
    }

    # Remove each matched credential with optional confirmation
    foreach ($target in $targets) {
        $type = $target.Type
        $key  = $target.Key

        if (-not $Force) {
            $confirm = Read-Host "Confirm removal of $type credential [$key]? (Y/N)"
            if ($confirm -ne 'Y') { continue }
        }

        switch ($type) {
            'Basic' { $null = $global:ServiceCredentials.Remove($key) }
            'Token' { $null = $global:ServiceTokens.Remove($key) }
            'SSO'   { $null = $global:ServiceSSOTokens.Remove($key) }
        }

        Write-Verbose "Removed $type credential for [$key]."
    }
}
