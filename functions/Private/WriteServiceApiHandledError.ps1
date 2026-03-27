function Write-ServiceApiHandledError {
    <#
    .SYNOPSIS
        Reports handled ServiceAPI errors using Debug-Error when available.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [System.Management.Automation.ErrorRecord]$ErrorRecord,

        [ValidateSet('Critical', 'Warning', 'Informational', 'Debug')]
        [string]$Severity = 'Critical',

        [string]$Message
    )

    # Debug-Error is authoritative when available; local fallback stays intentionally lightweight.
    if ($script:ServiceApiHasDebugError) {
        Debug-Error -ErrorRecord $ErrorRecord -Severity $Severity
        return
    }

    $resolvedMessage = if ([string]::IsNullOrWhiteSpace($Message)) {
        $ErrorRecord.ToString()
    } else {
        # Add light context for fallback output without trying to replicate Debug-Error formatting.
        $trimmedMessage = $Message.TrimEnd()
        if ($trimmedMessage -match '[\.\:\;\!\?]$') {
            "$trimmedMessage $($ErrorRecord.Exception.Message)"
        } else {
            "$trimmedMessage. $($ErrorRecord.Exception.Message)"
        }
    }

    switch ($Severity) {
        'Critical' {
            Write-Error $resolvedMessage
        }
        'Warning' {
            Write-Warning $resolvedMessage
        }
        'Informational' {
            Write-Verbose $resolvedMessage
        }
        'Debug' {
            Write-Debug $resolvedMessage
        }
    }
}
