function New-StandardHeaders {
    <#
    .SYNOPSIS
        Creates standard HTTP headers for API requests.

    .DESCRIPTION
        Returns a hashtable containing common HTTP headers used across API requests.
        Includes Accept, Content-Type, X-Atlassian-Token (for compatibility), and User-Agent.

    .PARAMETER Service
        Optional service name to customise headers for specific services.

    .EXAMPLE
        $headers = New-StandardHeaders
        # Returns standard headers for general API use

    .EXAMPLE
        $headers = New-StandardHeaders -Service jira
        # Returns headers optimised for Jira API requests

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        1.0.0 | 27JAN26 | Initial version extracted from credential management functions.
    #>

    [CmdletBinding()]
    param (
        [string]$Service
    )

    $headers = @{
        "Accept"       = "application/json"
        "Content-Type" = "application/json"
        "User-Agent"   = "PowerShell-Script"
    }

    # Add X-Atlassian-Token header for Atlassian services
    $atlassianServices = @('jira', 'confluence', 'bitbucket', 'crowd', 'assets')
    if ($Service -in $atlassianServices) {
        $headers["X-Atlassian-Token"] = "no-check"
    }

    return $headers
}
