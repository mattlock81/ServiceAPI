function Get-ServiceCurlPath {
    <#
    .SYNOPSIS
        Finds a curl built with OpenSSL for the Curl transport.

    .DESCRIPTION
        The Curl transport needs a curl whose TLS backend is OpenSSL (or LibreSSL or BoringSSL):
        that is what gives TLS 1.3 on hosts whose SChannel lacks it and reads PEM keys directly.
        The curl.exe that ships with Windows uses SChannel, so it is refused.

        Search order: the SERVICEAPI_CURL environment variable, then on Windows the curl bundled
        with Git for Windows (next to the git on the path, and the usual install folders), then
        any curl on the path. Each candidate is run with --version and must name an OpenSSL-family
        backend. The first match is cached for the session.

        Not exported.

    .PARAMETER Refresh
        Forget the cached path and search again.

    .EXAMPLE
        Get-ServiceCurlPath
        Returns the full path of a curl built with OpenSSL, or throws with guidance.

    .EXAMPLE
        $env:SERVICEAPI_CURL = 'C:\Tools\curl\bin\curl.exe'
        Get-ServiceCurlPath -Refresh

        Points the module at a specific curl and searches again.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Get-ServiceCurlPath -Verbose }

        Shows each candidate that was tried and why it was accepted or refused.

    .OUTPUTS
        System.String - the path of the curl executable.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.0.0 | 16OCT26 | Initial version. Finds and validates a curl built with OpenSSL.
    #>

    [CmdletBinding()]
    [OutputType([string])]
    param (
        [switch]$Refresh
    )

    if ($Refresh) { $script:ServiceApiCurlPath = $null }
    if ($script:ServiceApiCurlPath) { return $script:ServiceApiCurlPath }

    $candidates = New-Object System.Collections.Generic.List[string]

    if ($env:SERVICEAPI_CURL) { $candidates.Add($env:SERVICEAPI_CURL) }

    if ($script:ServiceApiIsWindows) {
        $git = Get-Command -Name git -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($git) {
            # ...\Git\cmd\git.exe or ...\Git\bin\git.exe -> ...\Git\mingw64\bin\curl.exe
            $gitRoot = Split-Path -Parent (Split-Path -Parent $git.Source)
            $candidates.Add((Join-Path $gitRoot 'mingw64\bin\curl.exe'))
            $candidates.Add((Join-Path $gitRoot 'mingw32\bin\curl.exe'))
        }
        foreach ($root in @($env:ProgramFiles, ${env:ProgramFiles(x86)})) {
            if ($root) { $candidates.Add((Join-Path $root 'Git\mingw64\bin\curl.exe')) }
        }
    }

    foreach ($found in @(Get-Command -Name curl -CommandType Application -ErrorAction SilentlyContinue)) {
        $candidates.Add($found.Source)
    }

    $refused = New-Object System.Collections.Generic.List[string]
    foreach ($candidate in ($candidates | Select-Object -Unique)) {
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            Write-Verbose "curl candidate [$candidate] does not exist."
            continue
        }
        try {
            $psi = [System.Diagnostics.ProcessStartInfo]::new()
            $psi.FileName               = $candidate
            $psi.Arguments              = '--version'
            $psi.UseShellExecute        = $false
            $psi.RedirectStandardOutput = $true
            $psi.RedirectStandardError  = $true
            $psi.CreateNoWindow         = $true
            $proc = [System.Diagnostics.Process]::Start($psi)
            $out  = $proc.StandardOutput.ReadToEnd()
            [void]$proc.WaitForExit(10000)
            $first = ($out -split "`r?`n")[0]
            if ($first -match 'OpenSSL|LibreSSL|BoringSSL') {
                Write-Verbose "curl accepted: [$candidate] ($first)"
                $script:ServiceApiCurlPath = $candidate
                return $candidate
            }
            Write-Verbose "curl refused: [$candidate] does not use OpenSSL ($first)"
            $refused.Add($candidate)
        } catch {
            Write-Verbose "curl candidate [$candidate] could not be run: $($_.Exception.Message)"
        }
    }

    $hint = if ($script:ServiceApiIsWindows) {
        "Install Git for Windows (it bundles an OpenSSL curl) or set SERVICEAPI_CURL to the full path of one. The curl.exe in System32 uses SChannel and cannot be used."
    } else {
        "Install curl built with OpenSSL (on RHEL-family hosts: dnf install curl) or set SERVICEAPI_CURL to the full path of one."
    }
    $tried = if ($refused.Count -gt 0) { " Refused (not OpenSSL): $($refused -join ', ')." } else { '' }
    throw "No curl built with OpenSSL was found for -Transport Curl.$tried $hint"
}
