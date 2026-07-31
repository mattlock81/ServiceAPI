function Convert-VaultSecretToCredential {
    <#
    .SYNOPSIS
        Converts a raw SecretManagement vault secret into a PSCredential.

    .DESCRIPTION
        Accepts a vault secret in any of the three shapes SecretManagement may return
        for a Basic Auth entry — PSCredential, SecureString, or plain string — and
        normalises all three into a single PSCredential object.

        SecureString and plain string values are expected in "username:password" form.
        If no colon is present, the whole value is treated as the password with an
        empty username.

        Extracted from Resolve-VaultCredential to eliminate duplicated conversion logic
        that previously existed in both the single-label and multi-label vault lookup
        paths.

    .PARAMETER Secret
        The raw secret returned by Get-Secret. Accepts PSCredential, SecureString, or
        plain string.

    .OUTPUTS
        [PSCredential]

    .EXAMPLE
        Convert-VaultSecretToCredential -Secret $rawSecret
        Normalises a vault secret of any supported shape into a PSCredential.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 31-JUL-26

        CHANGE LOG
        1.0.0 | 31JUL26 | Initial version. Extracted from Resolve-VaultCredential to
                          remove duplicated PSCredential conversion logic between the
                          single-label and multi-label vault resolution paths.
    #>

    [CmdletBinding()]
    [OutputType([PSCredential])]
    param (
        [Parameter(Mandatory)]
        [object]$Secret
    )

    if ($Secret -is [PSCredential]) {
        return $Secret
    }

    $plain = if ($Secret -is [System.Security.SecureString]) {
        [System.Runtime.InteropServices.Marshal]::PtrToStringAuto(
            [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Secret)
        )
    } else {
        [string]$Secret
    }

    $colonIndex = $plain.IndexOf(':')
    $userName   = if ($colonIndex -gt 0) { $plain.Substring(0, $colonIndex) } else { '' }
    $password   = $plain.Substring($colonIndex + 1)

    return [PSCredential]::new($userName, (ConvertTo-SecureString $password -AsPlainText -Force))
}
