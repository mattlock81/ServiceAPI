function New-ServiceKey {
    <#
    .SYNOPSIS
        Generates a standardised key for credential storage lookups.

    .DESCRIPTION
        Creates consistent key strings used throughout the module for credential dictionary storage.
        Handles service-environment pairs, global keys, and service-global patterns.

    .PARAMETER Service
        The service name (e.g., jira, confluence, custom-api).

    .PARAMETER Environment
        The environment name (e.g., qa, prod, dev).

    .PARAMETER Global
        If specified, returns 'global' regardless of other parameters.

    .EXAMPLE
        New-ServiceKey -Service jira -Environment prod
        # Returns: "jira-prod"

    .EXAMPLE
        New-ServiceKey -Service confluence
        # Returns: "confluence-global"

    .EXAMPLE
        New-ServiceKey -Global
        # Returns: "global"

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 27-JAN-26

        CHANGE LOG
        1.0.0 | 27JAN26 | Initial version to standardise key generation across functions.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [string]$Environment,
        [switch]$Global
    )

    if ($Global) {
        return 'global'
    }

    if ($Service -and $Environment) {
        return "$Service-$Environment"
    }

    if ($Service) {
        return "$Service-global"
    }

    if ($Environment) {
        # Environment-only keys are typically used for iteration
        return $Environment
    }

    # Fallback to global if nothing specified
    return 'global'
}
