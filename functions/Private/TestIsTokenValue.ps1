function Test-IsTokenValue {
    <#
    .SYNOPSIS
        Determines whether a supplied -UseToken value is a raw token or a vault credential label.

    .DESCRIPTION
        Applies a heuristic to distinguish between raw token strings and short human-readable
        vault credential labels. Used by Resolve-VaultCredential to determine the resolution path.

        Rules applied in priority order:
        1. Vault index match — if the value exists as a label in the vault index, it is always
           a label regardless of other rules. Explicit vault match takes precedence.
        2. Known token prefix — values matching known API token prefixes are always raw tokens.
        3. Length threshold — values over 20 characters are assumed to be raw tokens.
        4. Non-alphanumeric characters — values containing characters outside [a-zA-Z0-9_-]
           are assumed to be raw tokens.
        5. Default — short alphanumeric strings not in the vault index are treated as labels,
           triggering a vault lookup or interactive prompt.

    .PARAMETER Value
        The string value supplied to -UseToken.

    .PARAMETER ServiceKey
        The service-environment key used to check the vault index (e.g., opnsense-prod).

    .OUTPUTS
        [bool] — $true if the value is a raw token, $false if it is a vault label.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 17-MAY-26

        CHANGE LOG
        1.0.0 | 17MAY26 | Initial version. Heuristic-based token vs label disambiguation
                          for -UseToken parameter resolution in vault-enabled sessions.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)][string]$Value,
        [string]$ServiceKey
    )

    # Rule 1 — Vault index match takes precedence — explicit label wins
    if ($ServiceKey -and $global:ServiceApiVaultIndex -and
        $global:ServiceApiVaultIndex.ContainsKey($ServiceKey) -and
        $Value -in $global:ServiceApiVaultIndex[$ServiceKey]) {
        return $false
    }

    # Rule 2 — Known token prefixes
    if ($Value -match '^(Bearer\s|cfat_|ghp_|xoxb-|ya29\.|eyJ)') {
        return $true
    }

    # Rule 3 — Length threshold (labels are rarely over 20 characters)
    if ($Value.Length -gt 20) {
        return $true
    }

    # Rule 4 — Non-alphanumeric characters typical of encoded tokens
    if ($Value -match '[^a-zA-Z0-9_\-]') {
        return $true
    }

    # Rule 5 — Default: short alphanumeric string not in vault index — treat as label
    return $false
}
