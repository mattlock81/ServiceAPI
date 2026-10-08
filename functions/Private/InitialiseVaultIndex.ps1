function Initialise-VaultIndex {
    <#
    .SYNOPSIS
        Ensures the vault credential index file exists on first load.

    .DESCRIPTION
        Called once at module load when SecretManagement is detected. Checks for the
        existence of credential-index.json in the user's local AppData directory
        ($env:LOCALAPPDATA\ServiceAPI\). If absent, creates the directory and an empty
        index file. Never overwrites an existing index.

        Storing credential-index.json in LocalAppData ensures it is machine-local and
        consistent with the SecretManagement vault which also stores credentials locally.
        This prevents a roamed index referencing vault entries that do not exist on the
        current machine.

        The credential index tracks which named credentials exist in the vault per
        service-environment key. It never stores credential values, only labels.

    .OUTPUTS
        None. Creates credential-index.json as a side effect when it is absent.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Initialise-VaultIndex }

        Creates an empty credential-index.json in $env:LOCALAPPDATA\ServiceAPI\ when none exists, and
        returns without change when one does. The function is private, so it is run from module scope.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Initialise-VaultIndex -Verbose }

        Shows in the verbose stream whether the directory and index file were created or already present.

    .EXAMPLE
        Test-Path (Join-Path $env:LOCALAPPDATA 'ServiceAPI\credential-index.json')

        Confirms the index file exists after the module has loaded with SecretManagement present.
        Expected result: True.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.2.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.2.0 | 08OCT26 | Linux support: restrict the file and directory to the owner (700/600) through
                          Set-ServiceApiSecureMode.
        1.1.3 | 07OCT26 | File renamed from InitializeVaultIndex.ps1 to InitialiseVaultIndex.ps1 so
                          the file name matches the function name and the Australian/British
                          spelling convention. No code change.
        1.1.2 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.1.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
        1.1.0 | 17MAY26 | Moved credential-index.json from module config\ directory to
                          $env:LOCALAPPDATA\ServiceAPI\ via $script:ServiceApiVaultIndexPath
                          so the index remains machine-local, consistent with the vault store.
        1.0.1 | 17MAY26 | Renamed to Initialise-VaultIndex for British/Australian English.
        1.0.0 | 17MAY26 | Initial version.
    #>

    [CmdletBinding()]
    param()

    $indexDir  = $script:ServiceApiVaultIndexPath
    $indexPath = Join-Path -Path $indexDir -ChildPath 'credential-index.json'

    if (Test-Path -Path $indexPath -PathType Leaf) {
        Write-Verbose "ServiceAPI: credential-index.json found at: $indexPath"
        return
    }

    if (-not (Test-Path -Path $indexDir -PathType Container)) {
        New-Item -Path $indexDir -ItemType Directory -Force | Out-Null
        Write-Verbose "ServiceAPI: Created vault index directory: $indexDir"
        Set-ServiceApiSecureMode -Path $indexDir
    }

    try {
        '{}' | Set-Content -LiteralPath $indexPath -Encoding UTF8 -Force
        Write-Verbose "ServiceAPI: Created empty credential-index.json at: $indexPath"
        Set-ServiceApiSecureMode -Path $indexPath
    } catch {
        Write-Warning "ServiceAPI: Failed to create credential-index.json: $_"
    }
}
