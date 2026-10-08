
function Get-ServiceProbeEndpoint {
    <#
    .SYNOPSIS
        Resolves the endpoint used to test whether a bearer token is currently valid for a service.

    .DESCRIPTION
        A probe endpoint is a cheap, read-only endpoint that returns 2xx for any valid bearer
        the identity may use at all. It lets the module tell a stale token (probe fails) from an
        authorisation denial (probe succeeds while the real request is forbidden).

        Resolution order:

          1. The ProbeEndpoint stored on the service's registry entry (set with
             Register-CustomService -ProbeEndpoint). It is authoritative, because the operator
             knows the cheapest endpoint that proves the bearer is valid for that service.
          2. For the AriaOidc provider, the built-in default 'iaas/api/projects?$top=1'.
          3. Nothing ($null). Callers then skip the probe and fall back to a refresh.

        Not exported.

    .PARAMETER Service
        The registered service name.

    .PARAMETER Environment
        The environment. Defaults to 'prod'.

    .EXAMPLE
        Get-ServiceProbeEndpoint -Service aria

        Returns 'iaas/api/projects?$top=1' for an AriaOidc service with no explicit value.

    .EXAMPLE
        Get-ServiceProbeEndpoint -Service aria -Environment qa

        Returns the ProbeEndpoint registered for the qa environment, if one is set.

    .EXAMPLE
        $probe = Get-ServiceProbeEndpoint -Service jira
        if (-not $probe) { Write-Verbose 'No probe endpoint; the 403 retry falls back to a refresh.' }

        Shows the $null result for a service with no probe configured.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 08-OCT-26

        CHANGE LOG
        1.0.1 | 08OCT26 | Help examples: the example service name aihc is replaced with aria. No code change.
        1.0.0 | 06OCT26 | Initial version. Single source of truth for the probe endpoint,
                          shared by the SSO 403 retry and the AriaOidc bearer selection.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Service,

        [string]$Environment = 'prod'
    )

    if (-not $global:ServiceRegistry -or
        -not $global:ServiceRegistry.ContainsKey($Service) -or
        -not $global:ServiceRegistry[$Service].ContainsKey($Environment)) {
        return $null
    }

    $entry = $global:ServiceRegistry[$Service][$Environment]

    if ($entry.ProbeEndpoint) {
        return ([string]$entry.ProbeEndpoint).TrimStart('/')
    }

    if ($entry.SSOProvider -eq 'AriaOidc') {
        return 'iaas/api/projects?$top=1'
    }

    return $null
}
