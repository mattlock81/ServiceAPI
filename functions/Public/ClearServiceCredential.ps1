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

        For Basic and Token types, targeted clearing (i.e. -Service and/or -Environment
        supplied, not -Global) also removes the corresponding vault entry — labelled per
        -Label, defaulting to 'default' — via Remove-Secret, and updates
        credential-index.json via Remove-VaultIndex. Vault removal is skipped
        automatically if no matching label exists in the vault index for that
        service-environment key. SSO credentials are never vault-stored, so no vault
        removal is attempted for SSO.

        Global tokens and global SSO tokens are not supported and cannot be cleared via
        -Global. Global, service-global, and environment-wide Basic Auth credentials have
        no corresponding vault entry (see Set-ServiceCredential), so -Global clearing
        never touches the vault.

    .PARAMETER Service
        The API service (e.g., jira, confluence, googleapi).

    .PARAMETER Environment
        Target environment (qa, prod, dev).

    .PARAMETER AuthType
        Credential type to clear: Basic, Token, SSO, or All. Defaults to All.

    .PARAMETER Label
        The vault label to remove alongside the in-memory credential. Defaults to
        'default'. Applies to Basic and Token types during targeted clearing only.

    .PARAMETER Global
        Clears the global fallback credential (Basic Auth only).

    .PARAMETER Force
        Skips confirmation prompt.

    .EXAMPLE
        Clear-ServiceCredential -Service jira -Environment qa -AuthType All
        Clears all credential types for jira in qa, including matching vault entries
        under the 'default' label for Basic and Token.

    .EXAMPLE
        Clear-ServiceCredential -Service jira -Environment prod -AuthType Basic -Label matt
        Clears the in-memory Basic Auth credential for jira-prod and removes the
        jira-matt-prod vault entry.

    .EXAMPLE
        Clear-ServiceCredential -Service googleapi -Environment prod -AuthType SSO
        Clears the SSO token for googleapi in prod. No vault interaction — SSO is never
        vault-stored.

    .EXAMPLE
        Clear-ServiceCredential -Global -AuthType Basic
        Clears the global Basic Auth fallback credential. In-memory only — no vault entry
        exists for global credentials.

    .EXAMPLE
        Clear-ServiceCredential -Service cloudflare -Environment prod -AuthType Token
        Clears the static Bearer token for cloudflare in prod, in-memory and in the vault.

    .NOTES
        Author      : Matthew Sillett
        Version     : 2.6.0
        Date        : 17-AUG-26

        CHANGE LOG
        2.6.0 | 17AUG26 | Added -Label parameter and automatic vault removal for Basic and
                          Token credential types during targeted (-Service/-Environment)
                          clearing, via Remove-Secret and the new Remove-VaultIndex private
                          function. Previously Clear-ServiceCredential only removed
                          in-memory state, leaving vault-persisted credentials — including
                          those stored automatically by Set-ServiceCredential's Token path,
                          or offered interactively by Resolve-VaultCredential for Basic —
                          untouched. This meant a subsequent Get-ServiceCredential call
                          could silently re-resolve a "cleared" credential straight from
                          the vault. -Global clearing is unaffected — no vault key exists
                          for global/service-global/environment-wide storage.
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

        # Vault label to remove alongside the in-memory credential — applies to Basic and
        # Token types during targeted clearing. Defaults to 'default'.
        [string]$Label = 'default',

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
                    $targets.Add(@{ Type = 'Basic'; Key = $key; Service = $svc; Environment = $env })
                }

                if ($AuthType -in @('All', 'Token') -and $global:ServiceTokens.ContainsKey($key)) {
                    $targets.Add(@{ Type = 'Token'; Key = $key; Service = $svc; Environment = $env })
                }

                if ($AuthType -in @('All', 'SSO') -and $global:ServiceSSOTokens.ContainsKey($key)) {
                    $targets.Add(@{ Type = 'SSO'; Key = $key; Service = $svc; Environment = $env })
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

        # Remove from vault when SecretManagement is available — Basic/Token only.
        # SSO is never vault-stored (see Set-ServiceCredential). Global-scope targets
        # have no Service/Environment on the target object and are skipped implicitly,
        # since they have no valid vault key.
        if ($type -in @('Basic', 'Token') -and
            $script:ServiceApiHasSecretManagement -and
            $target.ContainsKey('Service') -and $target.ContainsKey('Environment')) {

            $vaultName  = "$($target.Service)-$Label-$($target.Environment)"
            $indexEntry = $global:ServiceApiVaultIndex[$key]

            if ($indexEntry -and $Label -in $indexEntry) {
                try {
                    Remove-Secret -Name $vaultName -Vault LocalStore -ErrorAction Stop
                    Remove-VaultIndex -ServiceKey $key -Label $Label
                    Write-Verbose "Removed $type credential for [$key] under label [$Label] from vault as [$vaultName]."
                } catch {
                    Write-Warning "Failed to remove vault secret [$vaultName] — $_."
                }
            } else {
                Write-Verbose "No vault entry found for [$key] under label [$Label] — nothing to remove from vault."
            }
        }
    }
}
