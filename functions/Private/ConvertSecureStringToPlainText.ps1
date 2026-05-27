function ConvertSecureStringToPlainText {
    <#
    .SYNOPSIS
        Safely converts a SecureString to plain text.

    .DESCRIPTION
        Decrypts a SecureString to plain text using managed memory pointers.
        Automatically zeros memory after conversion for security.

    .PARAMETER SecureString
        The SecureString to decrypt.

    .EXAMPLE
        $token = ConvertSecureStringToPlainText -SecureString $secureToken

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        1.0.0 | 27JAN26 | Initial version extracted from credential functions.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [SecureString]$SecureString
    )

    try {
        $ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureString)
        $plainText = [System.Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
        return $plainText
    } finally {
        if ($ptr) {
            [System.Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
        }
    }
}
