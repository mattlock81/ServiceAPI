function Resolve-PingFederateScope {
    <#
    .SYNOPSIS
        Normalises a PingFederate scope list and checks it against the known scope catalogue.

    .DESCRIPTION
        Accepts scopes separated by spaces or commas, removes duplicates (keeping order), makes
        sure 'openid' is present, and returns the space-delimited string sent as the OAuth
        'scope' parameter. A scope that is not in the catalogue produces a warning and is still
        sent, because the scopes a PingFederate client may request change over time.

        The catalogue maps each known scope to the claims it releases. It is returned by
        -Catalogue so the diagnostic probe can show which claims a granted scope should have
        produced.

    .PARAMETER Scope
        One or more scope names, separated by spaces or commas. Defaults to 'openid profile ad'.

    .PARAMETER Catalogue
        Returns the scope catalogue (an ordered hashtable of scope to claim names) instead of
        resolving a scope string.

    .EXAMPLE
        Resolve-PingFederateScope -Scope 'profile, ad app'
        Returns 'openid profile ad app'.

    .EXAMPLE
        (Resolve-PingFederateScope -Catalogue)['ad']
        Returns the claims the 'ad' scope releases ('groups').

    .EXAMPLE
        Resolve-PingFederateScope -Scope 'openid ad bogus' -WarningVariable w
        Returns 'openid ad bogus' and warns that 'bogus' is not a catalogued scope.

    .OUTPUTS
        System.String, or System.Collections.Specialized.OrderedDictionary with -Catalogue.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 15-OCT-26

        CHANGE LOG
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: scope catalogue and normalisation.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Resolve')]
    param (
        [Parameter(ParameterSetName = 'Resolve')]
        [string[]]$Scope = @('openid', 'profile', 'ad'),

        [Parameter(Mandatory, ParameterSetName = 'Catalogue')]
        [switch]$Catalogue
    )

    $known = [ordered]@{
        'openid'  = @()
        'ad'      = @('groups')
        'app'     = @('app')
        'brf'     = @('brf')
        'camkeys' = @('camkeys')
        'coi'     = @('coi')
        'eci'     = @('eci')
        'lac'     = @('lac')
        'profile' = @('displayName', 'dutyOrg', 'email', 'employeeType', 'givenName',
                      'nationality', 'org', 'preferred_username', 'securityClearance')
        'rel'     = @('uid')
    }

    if ($Catalogue) { return $known }

    $names = [System.Collections.Generic.List[string]]::new()
    $names.Add('openid')
    foreach ($item in $Scope) {
        foreach ($name in ($item -split '[\s,]+')) {
            if ($name -and -not $names.Contains($name)) { $names.Add($name) }
        }
    }

    foreach ($name in $names) {
        if (-not $known.Contains($name)) {
            Write-Warning "Scope [$name] is not in the PingFederate scope catalogue. It will be sent as given; PingFederate rejects it if the client may not request it."
        }
    }

    return ($names -join ' ')
}
