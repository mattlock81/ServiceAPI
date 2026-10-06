function ConvertSecureStringToPlainText {
    <#
    .SYNOPSIS
        Safely converts a SecureString to plain text.

    .DESCRIPTION
        Decrypts a SecureString to plain text using managed memory pointers.
        Automatically zeros memory after conversion for security.

    .PARAMETER SecureString
        The SecureString to decrypt.

    .OUTPUTS
        System.String - the decrypted plain text value.

    .EXAMPLE
        $token = ConvertSecureStringToPlainText -SecureString $secureToken

        Decrypts a SecureString and returns the plain text value.

    .EXAMPLE
        $secure  = Read-Host 'Token' -AsSecureString
        $plain   = ConvertSecureStringToPlainText -SecureString $secure
        $headers = @{ Authorization = "Bearer $plain" }

        Builds a bearer header from a token read securely at the prompt. The plain text value
        must not be written to a log or to any output stream.

    .EXAMPLE
        $bearer = ConvertSecureStringToPlainText -SecureString $global:ServiceSSOTokens[$key].Token

        Converts the cached SecureString bearer of a service immediately before it is placed in an
        Authorization header.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
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
