function Test-ServiceApiInteractive {
    <#
    .SYNOPSIS
        Tests whether the session can prompt the user.

    .DESCRIPTION
        Returns $false when PowerShell was started with -NonInteractive or the environment is
        not user-interactive, and $true otherwise. Vault selection uses it to decide between
        prompting and failing fast.

    .EXAMPLE
        if (Test-ServiceApiInteractive) { Read-Host 'Choose a vault' }

        Prompts only when the session can.

    .EXAMPLE
        if (-not (Test-ServiceApiInteractive)) { Write-Warning 'Unattended run.' }

        Warns during an unattended run.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Test-ServiceApiInteractive }

        Checks the session from outside the module.

    .OUTPUTS
        System.Boolean

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Vault selection: interactive-session test.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param()

    if (-not [Environment]::UserInteractive) { return $false }

    $nonInteractive = [Environment]::GetCommandLineArgs() | Where-Object { $_ -match '^-noni' }
    return (-not $nonInteractive)
}
