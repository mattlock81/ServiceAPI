function Resolve-VaultCredential {
    <#
    .SYNOPSIS
        Resolves a credential from the SecretManagement vault for a service and environment.

    .DESCRIPTION
        Handles the full vault credential resolution and interactive prompt flow for token-mode
        requests when SecretManagement is available. Called internally by Get-ServiceCredential
        when -UseToken is active and $script:ServiceApiHasSecretManagement is true.

        Resolution flow:
        1. Determine whether the supplied label value is a vault label or a raw token.
        2. If label — look up in vault index. If found, retrieve from vault and return.
        3. If label not found in vault, or raw token supplied — run interactive prompt flow.
        4. Interactive prompt: Enter key (nullable), Enter password (blank aborts).
        5. Test call against the original endpoint to validate the credential.
        6. On success — offer vault storage. On 401/403 — reprompt up to 3 times.
        7. On other errors — yellow warning, offer to proceed or cancel.
        8. If stored — write to vault and update credential index.

        Vault secret naming convention:
            {service}-{label}-{environment}
        Stored as a single encoded string: "key:secret" or ":secret" when key is null.

    .PARAMETER Service
        The service name.

    .PARAMETER Environment
        The environment (prod, qa, dev).

    .PARAMETER Label
        The credential label. Defaults to 'default'. May be a vault label or raw token value —
        distinguished by Test-IsTokenValue heuristic and vault index lookup.

    .PARAMETER Endpoint
        The endpoint from the originating Invoke-APIRequest call — used for the test call.

    .PARAMETER BaseUrl
        The resolved BaseUrl for the service — used for the test call.

    .PARAMETER SessionOnly
        When set, bypasses vault lookup and storage. Prompts interactively and returns a
        session-only encoded credential string.

    .OUTPUTS
        [string] — the resolved Basic Auth encoded value ("key:secret" plain, not Base64).
        The caller is responsible for Base64 encoding into the Authorization header.

        Returns $null if the user cancels (no password supplied or max retries exceeded).

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.0.0 | 17MAY26 | Initial version. Full vault resolution, interactive prompt, test call
                          validation, vault write-back, and credential index update.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)][string]$Service,
        [Parameter(Mandatory)][string]$Environment,
        [string]$Label = 'default',
        [string]$Endpoint,
        [string]$BaseUrl,
        [switch]$SessionOnly
    )

    $serviceKey = New-ServiceKey -Service $Service -Environment $Environment
    $vaultName  = "$Service-$Label-$Environment"
    $maxRetries = 3

    # =========================================================================
    # VAULT LOOKUP — skip when -SessionOnly is set
    # =========================================================================
    if (-not $SessionOnly -and $script:ServiceApiHasSecretManagement) {

        # Determine whether Label is a vault label or a raw token value
        $isRawToken = Test-IsTokenValue -Value $Label -ServiceKey $serviceKey

        if (-not $isRawToken) {
            # Check vault index for this label
            $indexEntry = $global:ServiceApiVaultIndex[$serviceKey]

            if ($indexEntry -and $Label -in $indexEntry) {
                # Label exists in index — retrieve from vault
                Write-Verbose "Vault label [$Label] found for [$serviceKey]. Retrieving..."

                try {
                    $raw = Get-Secret -Name $vaultName -AsPlainText -ErrorAction Stop
                    Write-Verbose "Retrieved vault secret [$vaultName]."
                    return $raw
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
                        $raw = Get-Secret -Name $selectedVault -AsPlainText -ErrorAction Stop
                        Write-Verbose "Retrieved vault secret [$selectedVault]."
                        return $raw
                    } catch {
                        Write-Warning "Failed to retrieve vault secret [$selectedVault] — $_"
                        # Fall through to interactive prompt
                    }
                }
            }
        } else {
            # Raw token supplied — treat as encoded value directly
            Write-Verbose "Value [$Label] identified as raw token — using directly."
            return $Label
        }
    }

    # =========================================================================
    # INTERACTIVE PROMPT FLOW
    # =========================================================================
    $attempt = 0
    $resolved = $null

    while ($attempt -lt $maxRetries) {
        $attempt++

        # Prompt for key (nullable) and secret (blank aborts)
        Write-Host "`nEnter credentials for [$Service-$Environment]$(if ($attempt -gt 1) { " (attempt $attempt of $maxRetries)" }):" -ForegroundColor Cyan

        $keyInput    = Read-Host "Key (leave blank if not required)"
        $secretInput = Read-Host -AsSecureString "Password"

        $secretPlain = ConvertSecureStringToPlainText -SecureString $secretInput

        # Blank password aborts
        if ([string]::IsNullOrWhiteSpace($secretPlain)) {
            Write-Warning "No password supplied. Action cancelled."
            return $null
        }

        # Build the encoded credential string — key may be null
        $encoded = if ([string]::IsNullOrWhiteSpace($keyInput)) {
            ":$secretPlain"
        } else {
            "$keyInput`:$secretPlain"
        }

        # =====================================================================
        # TEST CALL — validate the credential against the service endpoint
        # =====================================================================
        $testResult = $null
        $testStatus = $null

        if (-not [string]::IsNullOrWhiteSpace($BaseUrl) -and -not [string]::IsNullOrWhiteSpace($Endpoint)) {
            try {
                # Determine auth header type from key presence
                $colonIdx  = $encoded.IndexOf(':')
                $testKey   = if ($colonIdx -gt 0) { $encoded.Substring(0, $colonIdx) } else { '' }
                $testSecret = $encoded.Substring($colonIdx + 1)

                $authHeader = if ([string]::IsNullOrWhiteSpace($testKey)) {
                    "Bearer ${testSecret}"
                } else {
                    $b64 = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes("${testKey}:${testSecret}"))
                    "Basic $b64"
                }

                $testHdrs = @{
                    Authorization  = $authHeader
                    Accept         = 'application/json'
                    'Content-Type' = 'application/json'
                }
                $testUri    = "$($BaseUrl.TrimEnd('/'))/$($Endpoint.TrimStart('/'))"
                $testResult = Invoke-RestMethod -Uri $testUri -Headers $testHdrs -Method GET -ErrorAction Stop
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
            # Success
            Write-Host "Credentials valid." -ForegroundColor Cyan
            $resolved = $encoded
            break

        } elseif ($testStatus -in @(401, 403)) {
            # Access denied — reprompt
            Write-Host "Access denied (HTTP $testStatus). Please check your credentials." -ForegroundColor Red
            if ($attempt -ge $maxRetries) {
                Write-Warning "Maximum retries reached. Action cancelled."
                return $null
            }
            continue

        } else {
            # Other error — credential may still be valid
            Write-Host "Could not verify credentials (HTTP $testStatus). The service may be temporarily unavailable." -ForegroundColor Yellow
            $proceed = Read-Host "Proceed anyway? (Y/N)"
            if ($proceed -ne 'Y') {
                Write-Warning "Action cancelled."
                return $null
            }
            $resolved = $encoded
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
                Set-Secret -Name $storeName -Secret $resolved -Vault LocalStore -ErrorAction Stop
                Write-Verbose "Stored credential in vault as [$storeName]."

                # Update the credential index
                Write-VaultIndex -ServiceKey $serviceKey -Label $labelInput
                Write-Host "Credential stored as [$storeName]." -ForegroundColor Cyan
            } catch {
                Write-Warning "Failed to store credential in vault — $_"
            }
        }
    }

    return $resolved
}
