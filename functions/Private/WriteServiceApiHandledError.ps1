function Write-ServiceApiHandledError {
    <#
    .SYNOPSIS
        Reports handled ServiceAPI errors using Debug-Error when available.

    .DESCRIPTION
        The single reporting point for errors that a ServiceAPI function has caught and handled.

        When SYSCommon's Debug-Error was found at module import, it is authoritative: the error
        record and severity are passed to it and it logs the error, and for Critical severity
        throws (its documented behaviour). Debug-Error receives only the error record and the
        severity, so the optional -Message is not passed to it.

        When Debug-Error is not available, a lightweight local fallback reports the error by
        severity instead:

          Critical       Write-Error (a non-terminating error)
          Warning        Write-Warning
          Informational  Write-Verbose
          Debug          Write-Debug

        In the fallback, -Message is used as the reported text with the exception message appended.
        Without -Message the error record's own text is reported. The fallback does not try to
        reproduce Debug-Error's formatting.

        Not exported.

    .PARAMETER ErrorRecord
        The error record to report. In a catch block, pass $_.

    .PARAMETER Severity
        How serious the error is: Critical (the default), Warning, Informational or Debug. With
        Debug-Error, Critical logs and throws. In the local fallback each severity maps to the
        stream shown in the description.

    .PARAMETER Message
        Optional context placed in front of the exception message, for example 'SSO token refresh
        failed after 403.'. Used only by the local fallback; Debug-Error is not given it.

    .OUTPUTS
        None.

    .EXAMPLE
        try {
            Invoke-ServiceApiHttpRequest -Uri $uri -ErrorAction Stop
        } catch {
            Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical'
        }

        Reports a failed request. With Debug-Error loaded it logs the error and throws. Without it,
        the error is written with Write-Error.

    .EXAMPLE
        catch {
            Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Critical' -Message 'SSO token refresh failed after 403.'
        }

        Adds context to the reported error. The context appears in the local fallback output only.

    .EXAMPLE
        catch {
            Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Warning'
            return $null
        }

        Reports a recoverable error as a warning and lets the caller carry on with a null result.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.0 | 06OCT26 | Added complete comment-based help (description, parameter descriptions,
                          examples and notes). The function predates per-function versioning,
                          so the version is recorded from this entry.
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
