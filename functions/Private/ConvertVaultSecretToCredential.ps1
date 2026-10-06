function Convert-VaultSecretToCredential {
    <#
    .SYNOPSIS
        Converts a raw SecretManagement vault secret into a PSCredential.

    .DESCRIPTION
        Accepts a vault secret in any of the three shapes SecretManagement may return
        for a Basic Auth entry (PSCredential, SecureString, or plain string) and
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

    .EXAMPLE
        $secret = ConvertTo-SecureString 'svc-account:example-password' -AsPlainText -Force
        $cred   = Convert-VaultSecretToCredential -Secret $secret
        $cred.UserName

        A SecureString in "username:password" form becomes a PSCredential. The user name returned
        is 'svc-account'.

    .EXAMPLE
        $cred = Convert-VaultSecretToCredential -Secret 'example-api-key'
        $cred.UserName.Length

        A value with no colon is treated as the password with an empty user name, so the length
        returned is 0.

    .EXAMPLE
        $existing = [PSCredential]::new('svc-account', (ConvertTo-SecureString 'example-password' -AsPlainText -Force))
        [object]::ReferenceEquals($existing, (Convert-VaultSecretToCredential -Secret $existing))

        A PSCredential passes through unchanged, so the comparison returns $true.

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.2
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.0.1 | 06OCT26 | Added the help examples required by the CMF standard.
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
