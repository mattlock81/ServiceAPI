function Resolve-VaultCredential {
    <#
    .SYNOPSIS
        Resolves a credential from the SecretManagement vault for a service and environment.

    .DESCRIPTION
        Handles the full vault credential resolution and interactive prompt flow when
        SecretManagement is available. Supports two authentication types:

        Token mode (AuthType = Token):
        Resolves a token credential stored as a plain "key:secret" or ":secret" string.
        The label may be a vault label or a raw token value — distinguished by the
        Test-IsTokenValue heuristic and vault index lookup. Returns a plain string;
        the caller builds the appropriate Basic or Bearer header based on key presence.

        Basic Auth mode (AuthType = Basic):
        Resolves a PSCredential stored natively in the vault. Label defaults to 'default'.
        Returns a PSCredential object; the caller builds the Basic Auth header directly.

        Both modes share the same resolution flow:
        1. Check vault index for the service-environment key.
        2. If found — retrieve from vault and return.
        3. If multiple labels — present selection list.
        4. If not found — run interactive prompt flow.
        5. Test call against the original endpoint to validate the credential.
        6. On success — offer vault storage and update credential index.
        7. On 401/403 — reprompt up to 3 times. Other errors — yellow warning.
        8. -SessionOnly bypasses vault lookup and storage entirely.

        Vault secret naming convention:
            {service}-{label}-{environment}
        Token secrets stored as plain string: "key:secret" or ":secret" (no key).
        Basic Auth secrets stored as PSCredential.

    .PARAMETER Service
        The service name.

    .PARAMETER Environment
        The environment (prod, qa, dev).

    .PARAMETER AuthType
        The authentication type — Token or Basic. Determines storage format and prompt style.
        Defaults to Token.

    .PARAMETER Label
        The credential label. Defaults to 'default'.
        For Token mode — may also be a raw token value distinguished by heuristic.
        For Basic mode — always treated as a vault label.

    .PARAMETER Endpoint
        The endpoint from the originating Invoke-APIRequest call — used for the test call.

    .PARAMETER BaseUrl
        The resolved BaseUrl for the service — used for the test call.

    .PARAMETER SessionOnly
        When set, bypasses vault lookup and storage. Prompts interactively and returns
        the credential for session use only.

    .OUTPUTS
        Token mode  — [string] plain "key:secret" value. Returns $null on cancellation.
        Basic mode  — [PSCredential] object. Returns $null on cancellation.

    .EXAMPLE
        Resolve-VaultCredential -Service opnsense -Environment prod -AuthType Token
        Resolves the default token credential for opnsense-prod from the vault.

    .EXAMPLE
        Resolve-VaultCredential -Service jira -Environment prod -AuthType Basic
        Resolves the default Basic Auth PSCredential for jira-prod from the vault.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.1.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.1.0 | 17MAY26 | Added -AuthType parameter (Token/Basic). Basic Auth path stores and
                          retrieves PSCredential objects natively via SecretManagement. Token
                          path unchanged — stores/retrieves plain "key:secret" strings. Both
                          paths share vault index, prompt flow, test call validation, and
                          vault write-back logic.
        1.0.0 | 17MAY26 | Initial version. Full vault resolution, interactive prompt, test call
                          validation, vault write-back, and credential index update.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Environment,

        [ValidateSet('Token', 'Basic')]
        [string]$AuthType = 'Token',

        [string]$Label = 'default',
        [string]$Endpoint,
        [string]$BaseUrl,
        [switch]$SessionOnly
    )

    $serviceKey = New-ServiceKey -Service $Service -Environment $Environment
    $vaultName  = "$Service-$Label-$Environment"
    $maxRetries = 3
    $isBasic    = $AuthType -eq 'Basic'

    # =========================================================================
    # VAULT LOOKUP — skip when -SessionOnly is set
    # =========================================================================
    if (-not $SessionOnly -and $script:ServiceApiHasSecretManagement) {

        # Token mode — determine whether label is a vault label or raw token value
        if (-not $isBasic) {
            $isRawToken = Test-IsTokenValue -Value $Label -ServiceKey $serviceKey
            if ($isRawToken) {
                Write-Verbose "Value [$Label] identified as raw token — using directly."
                return $Label
            }
        }

        $indexEntry = $global:ServiceApiVaultIndex[$serviceKey]

        if ($indexEntry -and $Label -in $indexEntry) {
            # Label exists in index — retrieve from vault
            Write-Verbose "Vault label [$Label] found for [$serviceKey]. Retrieving..."

            try {
                $secret = Get-Secret -Name $vaultName -ErrorAction Stop

                if ($isBasic) {
                    # Basic path expects PSCredential — convert SecureString or plain string if needed
                    if ($secret -is [PSCredential]) {
                        Write-Verbose "Retrieved Basic Auth PSCredential [$vaultName]."
                        return $secret
                    } elseif ($secret -is [System.Security.SecureString]) {
                        $plain    = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
                        )
                        $colonIdx = $plain.IndexOf(':')
                        $u        = if ($colonIdx -gt 0) { $plain.Substring(0, $colonIdx) } else { '' }
                        $p        = $plain.Substring($colonIdx + 1)
                        Write-Verbose "Retrieved SecureString [$vaultName] — converted to PSCredential."
                        return [PSCredential]::new($u, (ConvertTo-SecureString $p -AsPlainText -Force))
                    } else {
                        $plain    = [string]$secret
                        $colonIdx = $plain.IndexOf(':')
                        $u        = if ($colonIdx -gt 0) { $plain.Substring(0, $colonIdx) } else { '' }
                        $p        = $plain.Substring($colonIdx + 1)
                        Write-Verbose "Retrieved plain string [$vaultName] — converted to PSCredential."
                        return [PSCredential]::new($u, (ConvertTo-SecureString $p -AsPlainText -Force))
                    }
                } else {
                    # Token path expects plain string — convert PSCredential or SecureString if needed
                    if ($secret -is [PSCredential]) {
                        $u   = $secret.UserName
                        $p   = $secret.GetNetworkCredential().Password
                        $raw = if ([string]::IsNullOrWhiteSpace($u)) { ":${p}" } else { "${u}:${p}" }
                        Write-Verbose "Retrieved PSCredential [$vaultName] — converted to token string."
                        return $raw
                    } elseif ($secret -is [System.Security.SecureString]) {
                        $raw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
                        )
                        Write-Verbose "Retrieved SecureString [$vaultName] — converted to plain string."
                        return $raw
                    } else {
                        Write-Verbose "Retrieved token secret [$vaultName]."
                        return [string]$secret
                    }
                }
            } catch {
                Write-Warning "Failed to retrieve vault secret [$vaultName] — $_"
                # Fall through to interactive prompt
            }

        } elseif ($indexEntry -and $indexEntry.Count -gt 1) {
            # Multiple labels exist — present selection list
            Write-Host "`nMultiple credentials available for [$serviceKey]:" -ForegroundColor Cyan
            for ($i = 0; $i -lt $indexEntry.Count; $i++) {
                Write-Host "  [$($i + 1)] $($indexEntry[$i])"
            }

            $selection = Read-Host "Select credential (1-$($indexEntry.Count))"
            $idx       = [int]$selection - 1

            if ($idx -ge 0 -and $idx -lt $indexEntry.Count) {
                $selectedLabel = $indexEntry[$idx]
                $selectedVault = "$Service-$selectedLabel-$Environment"

                try {
                    $secret = Get-Secret -Name $selectedVault -ErrorAction Stop

                    if ($isBasic) {
                        if ($secret -is [PSCredential]) {
                            Write-Verbose "Retrieved Basic Auth PSCredential [$selectedVault]."
                            return $secret
                        } elseif ($secret -is [System.Security.SecureString]) {
                            $plain    = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
                            )
                            $colonIdx = $plain.IndexOf(':')
                            $u        = if ($colonIdx -gt 0) { $plain.Substring(0, $colonIdx) } else { '' }
                            $p        = $plain.Substring($colonIdx + 1)
                            return [PSCredential]::new($u, (ConvertTo-SecureString $p -AsPlainText -Force))
                        } else {
                            $plain    = [string]$secret
                            $colonIdx = $plain.IndexOf(':')
                            $u        = if ($colonIdx -gt 0) { $plain.Substring(0, $colonIdx) } else { '' }
                            $p        = $plain.Substring($colonIdx + 1)
                            return [PSCredential]::new($u, (ConvertTo-SecureString $p -AsPlainText -Force))
                        }
                    } else {
                        if ($secret -is [PSCredential]) {
                            $u   = $secret.UserName
                            $p   = $secret.GetNetworkCredential().Password
                            $raw = if ([string]::IsNullOrWhiteSpace($u)) { ":${p}" } else { "${u}:${p}" }
                            return $raw
                        } elseif ($secret -is [System.Security.SecureString]) {
                            $raw = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
                                [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($secret)
                            )
                            return $raw
                        } else {
                            return [string]$secret
                        }
                    }
                } catch {
                    Write-Warning "Failed to retrieve vault secret [$selectedVault] — $_"
                    # Fall through to interactive prompt
                }
            }
        }
    }

    # =========================================================================
    # INTERACTIVE PROMPT FLOW
    # =========================================================================
    $attempt   = 0
    $resolved  = $null

    while ($attempt -lt $maxRetries) {
        $attempt++

        $attemptSuffix = if ($attempt -gt 1) { " (attempt $attempt of $maxRetries)" } else { '' }
        Write-Host "`nEnter credentials for [$Service-$Environment]${attemptSuffix}:" -ForegroundColor Cyan

        if ($isBasic) {
            # Basic Auth — prompt for username and password as PSCredential
            $cred = Get-Credential -Message "Enter credentials for [$Service-$Environment]"

            if ($null -eq $cred) {
                Write-Warning "No credential supplied. Action cancelled."
                return $null
            }

            $resolvedForTest = $cred
        } else {
            # Token — prompt for key (nullable) and secret
            $keyInput    = Read-Host "Key (leave blank if not required)"
            $secretInput = Read-Host -AsSecureString "Password"
            $secretPlain = ConvertSecureStringToPlainText -SecureString $secretInput

            if ([string]::IsNullOrWhiteSpace($secretPlain)) {
                Write-Warning "No password supplied. Action cancelled."
                return $null
            }

            $encoded = if ([string]::IsNullOrWhiteSpace($keyInput)) {
                ":${secretPlain}"
            } else {
                "${keyInput}:${secretPlain}"
            }

            $resolvedForTest = $encoded
        }

        # =====================================================================
        # TEST CALL — validate the credential against the service endpoint
        # =====================================================================
        $testStatus = $null

        if (-not [string]::IsNullOrWhiteSpace($BaseUrl) -and -not [string]::IsNullOrWhiteSpace($Endpoint)) {
            try {
                # Build auth header based on auth type and key presence
                $authHeader = if ($isBasic) {
                    $b64 = [Convert]::ToBase64String(
                        [Text.Encoding]::ASCII.GetBytes(
                            "$($resolvedForTest.UserName):$($resolvedForTest.GetNetworkCredential().Password)"
                        )
                    )
                    "Basic $b64"
                } else {
                    $colonIdx   = $resolvedForTest.IndexOf(':')
                    $testKey    = if ($colonIdx -gt 0) { $resolvedForTest.Substring(0, $colonIdx) } else { '' }
                    $testSecret = $resolvedForTest.Substring($colonIdx + 1)

                    if ([string]::IsNullOrWhiteSpace($testKey)) {
                        "Bearer ${testSecret}"
                    } else {
                        $b64 = [Convert]::ToBase64String(
                            [Text.Encoding]::ASCII.GetBytes("${testKey}:${testSecret}")
                        )
                        "Basic $b64"
                    }
                }

                $testHdrs = @{
                    Authorization  = $authHeader
                    Accept         = 'application/json'
                    'Content-Type' = 'application/json'
                }
                $testUri = "$($BaseUrl.TrimEnd('/'))/$($Endpoint.TrimStart('/'))"
                Invoke-RestMethod -Uri $testUri -Headers $testHdrs -Method GET -ErrorAction Stop | Out-Null
                $testStatus = 200
            } catch {
                $testStatus = $_.Exception.Response.StatusCode.value__
            }
        } else {
            # No endpoint available for test — assume valid and proceed
            $testStatus = 200
        }

        # =====================================================================
        # OUTCOME HANDLING
        # =====================================================================
        if ($testStatus -eq 200) {
            Write-Host "Credentials valid." -ForegroundColor Cyan
            $resolved = $resolvedForTest
            break

        } elseif ($testStatus -in @(401, 403)) {
            Write-Host "Access denied (HTTP $testStatus). Please check your credentials." -ForegroundColor Red
            if ($attempt -ge $maxRetries) {
                Write-Warning "Maximum retries reached. Action cancelled."
                return $null
            }
            continue

        } else {
            Write-Host "Could not verify credentials (HTTP $testStatus). The service may be temporarily unavailable." -ForegroundColor Yellow
            $proceed = Read-Host "Proceed anyway? (Y/N)"
            if ($proceed -ne 'Y') {
                Write-Warning "Action cancelled."
                return $null
            }
            $resolved = $resolvedForTest
            break
        }
    }

    if ($null -eq $resolved) { return $null }

    # =========================================================================
    # VAULT STORAGE OFFER — skip when -SessionOnly is set
    # =========================================================================
    if (-not $SessionOnly -and $script:ServiceApiHasSecretManagement) {
        $store = Read-Host "Store credential in vault? (Y/n)"

        if ($store -eq 'Y') {
            $labelInput = Read-Host "Label [default]"
            if ([string]::IsNullOrWhiteSpace($labelInput)) { $labelInput = 'default' }

            $storeName = "$Service-$labelInput-$Environment"

            try {
                if ($isBasic) {
                    Set-Secret -Name $storeName -Secret $resolved -Vault LocalStore -ErrorAction Stop
                } else {
                    Set-Secret -Name $storeName -Secret $resolved -Vault LocalStore -ErrorAction Stop
                }
                Write-Verbose "Stored $AuthType credential in vault as [$storeName]."

                Write-VaultIndex -ServiceKey $serviceKey -Label $labelInput
                Write-Host "Credential stored as [$storeName]." -ForegroundColor Cyan
            } catch {
                Write-Warning "Failed to store credential in vault — $_"
            }
        }
    }

    return $resolved
}
