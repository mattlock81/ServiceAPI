function New-StandardHeaders {
    <#
    .SYNOPSIS
        Creates standard HTTP headers for API requests.

    .DESCRIPTION
        Returns a hashtable containing common HTTP headers used across API requests. It always
        includes Accept, Content-Type and User-Agent. X-Atlassian-Token ('no-check') is added only
        when -Service names an Atlassian service: jira, confluence, bitbucket, crowd or assets.

    .PARAMETER Service
        Optional service name to customise headers for specific services.

    .OUTPUTS
        System.Collections.Hashtable - the header names and values.

    .EXAMPLE
        $headers = New-StandardHeaders
        # Returns standard headers for general API use

    .EXAMPLE
        $headers = New-StandardHeaders -Service jira
        # Returns headers optimised for Jira API requests

    .EXAMPLE
        $headers = New-StandardHeaders -Service opnsense
        $headers.ContainsKey('X-Atlassian-Token')

        Returns False. The Atlassian token header is added only for jira, confluence, bitbucket,
        crowd and assets.

    .EXAMPLE
        $headers = New-StandardHeaders -Service confluence
        $headers['Authorization'] = "Bearer $token"

        Starts from the standard headers and adds an Authorization header for one request.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
                          Corrected the description: X-Atlassian-Token is added only for
                          Atlassian services, not for every request.
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
