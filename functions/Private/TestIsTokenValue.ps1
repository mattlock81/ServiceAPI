function Test-IsTokenValue {
    <#
    .SYNOPSIS
        Determines whether a supplied -UseToken value is a raw token or a vault credential label.

    .DESCRIPTION
        Applies a heuristic to distinguish between raw token strings and short human-readable
        vault credential labels. Used by Resolve-VaultCredential to determine the resolution path.

        Rules applied in priority order:
        1. Vault index match: if the value exists as a label in the vault index, it is always
           a label regardless of other rules. Explicit vault match takes precedence.
        2. Known token prefix: values matching known API token prefixes are always raw tokens.
        3. Length threshold: values over 20 characters are assumed to be raw tokens.
        4. Non-alphanumeric characters: values containing characters outside [a-zA-Z0-9_-]
           are assumed to be raw tokens.
        5. Default: short alphanumeric strings not in the vault index are treated as labels,
           triggering a vault lookup or interactive prompt.

    .PARAMETER Value
        The string value supplied to -UseToken.

    .PARAMETER ServiceKey
        The service-environment key used to check the vault index (e.g., opnsense-prod).

    .OUTPUTS
        [bool] - $true if the value is a raw token, $false if it is a vault label.

    .EXAMPLE
        Test-IsTokenValue -Value 'cfat_AbCdEf123456'

        Returns $true. The 'cfat_' prefix is a known token prefix, so the value is treated as a raw
        token. The other recognised prefixes are 'Bearer ', 'ghp_', 'xoxb-', 'ya29.' and 'eyJ'.

    .EXAMPLE
        Test-IsTokenValue -Value 'default' -ServiceKey 'opnsense-prod'

        Returns $false. A short alphanumeric value that is not in the vault index is treated as a
        label, which triggers a vault lookup or an interactive prompt.

    .EXAMPLE
        Test-IsTokenValue -Value 'ci-service-account-token' -ServiceKey 'jira-prod'

        Returns $false when the vault index lists 'ci-service-account-token' for jira-prod, even
        though 24 characters would otherwise mark it as a token. An explicit vault match always wins.

    .EXAMPLE
        Test-IsTokenValue -Value 'abc+def/ghi=='

        Returns $true. A character outside letters, digits, underscore and hyphen marks the value as
        an encoded token.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.1.0 | 08OCT26 | Vault selection: the vault index match reads the label keys of the label-to-vault schema.
        1.0.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.0.1 | 06OCT26 | Added the help examples required by the CMF standard.
        1.0.0 | 17MAY26 | Initial version. Heuristic-based token vs label disambiguation
                          for -UseToken parameter resolution in vault-enabled sessions.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)][string]$Value,
        [string]$ServiceKey
    )

    # Rule 1: Vault index match takes precedence; explicit label wins
    if ($ServiceKey -and $global:ServiceApiVaultIndex -and
        $global:ServiceApiVaultIndex.ContainsKey($ServiceKey) -and
        $Value -in @($global:ServiceApiVaultIndex[$ServiceKey].Keys)) {
        return $false
    }

    # Rule 2: Known token prefixes
    if ($Value -match '^(Bearer\s|cfat_|ghp_|xoxb-|ya29\.|eyJ)') {
        return $true
    }

    # Rule 3: Length threshold (labels are rarely over 20 characters)
    if ($Value.Length -gt 20) {
        return $true
    }

    # Rule 4: Non-alphanumeric characters typical of encoded tokens
    if ($Value -match '[^a-zA-Z0-9_\-]') {
        return $true
    }

    # Rule 5: Default. A short alphanumeric string not in the vault index is treated as a label.
    return $false
}
