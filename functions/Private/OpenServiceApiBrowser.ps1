function Open-ServiceApiBrowser {
    <#
    .SYNOPSIS
        Opens a URL in the user's default browser on Windows or Linux.

    .DESCRIPTION
        On Windows, opens the URL with Start-Process. On Linux, opens it with xdg-open when a
        graphical session is present (DISPLAY or WAYLAND_DISPLAY is set) and xdg-open is
        installed. On a headless host, or when xdg-open is missing, nothing is launched.

        The function returns $true when a browser launch was attempted and $false when the
        caller must show the URL to the user instead. It never throws.

    .PARAMETER Url
        The URL to open.

    .EXAMPLE
        if (-not (Open-ServiceApiBrowser -Url 'https://portal.example.com/')) {
            Write-Host 'Open https://portal.example.com/ in a browser.'
        }

        Opens the URL, or tells the user to open it when no browser could be launched.

    .OUTPUTS
        System.Boolean

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.0 | 08OCT26 | Initial version. Linux support: browser launch that works on Windows
                          and on Linux, with a headless fallback.
    #>

    [CmdletBinding()]
    [OutputType([bool])]
    param (
        [Parameter(Mandatory)]
        [string]$Url
    )

    try {
        if ($script:ServiceApiIsWindows) {
            Start-Process -FilePath $Url
            return $true
        }

        $hasDisplay = -not [string]::IsNullOrWhiteSpace($env:DISPLAY) -or
                      -not [string]::IsNullOrWhiteSpace($env:WAYLAND_DISPLAY)
        $opener = Get-Command -Name xdg-open -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1

        if ($hasDisplay -and $opener) {
            Start-Process -FilePath $opener.Source -ArgumentList $Url
            return $true
        }
    } catch {
        Write-Verbose "ServiceAPI: Could not launch a browser: $_"
    }

    return $false
}
