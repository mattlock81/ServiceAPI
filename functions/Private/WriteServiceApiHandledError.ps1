function Write-ServiceApiHandledError {
    <#
    .SYNOPSIS
        Reports handled ServiceAPI errors using Debug-Error when available.

    .DESCRIPTION
        The single reporting point for errors that a ServiceAPI function has caught and handled.

        When SYSCommon's Debug-Error was found at module import, it is authoritative: the error
        record and severity are passed to it and it logs the error, and for Critical severity
        throws (its documented behaviour). With SYSCommon 2.8.0 or later, -Message is passed to
        Debug-Error's own -Message parameter, which places it in front of the error in a single
        log entry. Older SYSCommon has no such parameter, so the module detects that and logs the
        context as its own entry through SYSCommon's Write-Log, at the same severity, before
        Debug-Error reports the error. That separate context line follows Debug-Error's own noise
        rule and is skipped for an HTTP 404 unless $DebugPreference is active. If Write-Log is
        unavailable, the context is written to the warning, verbose or debug stream by severity
        instead.

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
        Optional context describing what the caller was doing, for example 'SSO token refresh
        failed after 403.'. With SYSCommon 2.8.0 or later it is passed to Debug-Error -Message and
        appears in front of the error in one log entry. With older SYSCommon it is logged as a
        separate entry through Write-Log before the error is reported. In the local fallback it is
        placed in front of the exception message.

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

        Adds context to the reported error. With SYSCommon 2.8.0 or later the context and the error
        appear in one log entry. With older SYSCommon the context is logged as its own entry ahead
        of the error. In the local fallback it prefixes the exception message.

    .EXAMPLE
        catch {
            Write-ServiceApiHandledError -ErrorRecord $_ -Severity 'Warning'
            return $null
        }

        Reports a recoverable error as a warning and lets the caller carry on with a null result.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.0
        Date        : 07-OCT-26

        CHANGE LOG
        1.1.0 | 07OCT26 | Uses Debug-Error -Message when the installed SYSCommon provides it
                          (2.8.0 and later), so the context and the error share one log entry.
                          The module detects the parameter, so older SYSCommon keeps the 1.0.1
                          behaviour of logging the context separately through Write-Log. The local
                          fallback is unchanged.
        1.0.1 | 07OCT26 | Fixed -Message being silently dropped when Debug-Error is available.
                          The context is now logged as its own entry through Write-Log, at the
                          same severity and skipped for an HTTP 404 under Debug-Error's noise
                          rule, with a stream fallback when Write-Log is absent. The local
                          fallback is unchanged.
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

    # Debug-Error is authoritative when available.
    #   SYSCommon 2.8.0 and later: Debug-Error takes the caller context through -Message and logs it
    #   in front of the error in a single entry.
    #   Older SYSCommon: Debug-Error has no parameter for caller context, so the message is logged
    #   first as its own entry through SYSCommon's Write-Log (the logger Debug-Error itself uses),
    #   then Debug-Error reports the error. For Critical severity Debug-Error rethrows after
    #   logging; Write-Log does not throw, so the order keeps the context ahead of the error.
    if ($script:ServiceApiHasDebugError) {

        # Feature-detect -Message so ServiceAPI works with either SYSCommon generation
        $debugErrorCommand = Get-Command -Name Debug-Error -ErrorAction SilentlyContinue
        if (-not [string]::IsNullOrWhiteSpace($Message) -and $debugErrorCommand -and $debugErrorCommand.Parameters.ContainsKey('Message')) {
            Debug-Error -ErrorRecord $ErrorRecord -Severity $Severity -Message $Message
            return
        }

        if (-not [string]::IsNullOrWhiteSpace($Message)) {

            # Debug-Error treats an HTTP 404 as debug-only noise unless $DebugPreference is active.
            # The context line follows the same rule so an expected 404 stays quiet.
            $quiet404 = $false
            if ($ErrorRecord.Exception.PSObject.Properties['Response'] -and $ErrorRecord.Exception.Response) {
                $quiet404 = ([int]$ErrorRecord.Exception.Response.StatusCode -eq 404) -and ($DebugPreference -eq 'SilentlyContinue')
            }

            if (-not $quiet404) {
                $contextText = $Message.TrimEnd()
                $logCommand  = Get-Command -Name Write-Log -ErrorAction SilentlyContinue

                if ($logCommand -and $logCommand.Parameters.ContainsKey('Message') -and $logCommand.Parameters.ContainsKey('Severity')) {
                    Write-Log -Message $contextText -Severity $Severity
                } else {
                    # No usable Write-Log: use the standard streams. Never a second error, because
                    # Debug-Error reports the error itself.
                    switch ($Severity) {
                        'Critical'      { Write-Warning $contextText }
                        'Warning'       { Write-Warning $contextText }
                        'Informational' { Write-Verbose $contextText }
                        'Debug'         { Write-Debug $contextText }
                    }
                }
            }
        }

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
