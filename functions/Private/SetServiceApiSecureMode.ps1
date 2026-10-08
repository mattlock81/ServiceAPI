function Set-ServiceApiSecureMode {
    <#
    .SYNOPSIS
        Restricts a ServiceAPI data file or directory to the owning user on Linux.

    .DESCRIPTION
        On Linux, sets mode 0700 on a directory or 0600 on a file so that other local
        users cannot read the service registry or the vault index. Uses
        [System.IO.File]::SetUnixFileMode where the runtime provides it and falls back to
        the chmod binary otherwise. On Windows it does nothing, because the per-user
        profile locations are already protected by the profile ACLs.

        A failure to change the mode is reported as a warning and never stops the caller.

    .PARAMETER Path
        The file or directory to restrict. A path that does not exist is ignored.

    .EXAMPLE
        Set-ServiceApiSecureMode -Path $script:ServiceApiConfigPath

        Restricts the ServiceAPI config directory to the owner on Linux; no effect on Windows.

    .EXAMPLE
        Set-ServiceApiSecureMode -Path (Join-Path $script:ServiceApiVaultIndexPath 'credential-index.json')

        Restricts the vault index file to the owner on Linux; no effect on Windows.

    .OUTPUTS
        None.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Linux support: owner-only permissions for the
                          service registry and the vault index.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Path
    )

    if (-not $script:ServiceApiIsLinux) { return }
    if (-not (Test-Path -LiteralPath $Path)) { return }

    $isDirectory = Test-Path -LiteralPath $Path -PathType Container

    try {
        if ('System.IO.UnixFileMode' -as [type]) {
            $mode = if ($isDirectory) { 'UserRead, UserWrite, UserExecute' } else { 'UserRead, UserWrite' }
            [System.IO.File]::SetUnixFileMode($Path, [System.IO.UnixFileMode]$mode)
        } else {
            $octal = if ($isDirectory) { '700' } else { '600' }
            & chmod $octal -- $Path
            if ($LASTEXITCODE -ne 0) { throw "chmod exited with code $LASTEXITCODE." }
        }
        Write-Verbose "ServiceAPI: Restricted [$Path] to the owner."
    } catch {
        Write-Warning "ServiceAPI: Could not restrict permissions on [$Path]: $_"
    }
}
