function Invoke-CredentialPrompt {
    <#
    .SYNOPSIS
        Prompts user for credentials with contextual messaging.

    .DESCRIPTION
        Displays a credential prompt with appropriate messaging based on service and environment.
        Returns a PSCredential object for Basic Authentication.

    .PARAMETER Service
        Optional service name to include in the prompt message.

    .PARAMETER Environment
        Optional environment name to include in the prompt message.

    .OUTPUTS
        System.Management.Automation.PSCredential - the credential entered. Get-Credential returns
        $null when the prompt is cancelled.

    .EXAMPLE
        $cred = Invoke-CredentialPrompt
        # Prompts: "Enter credentials"

    .EXAMPLE
        $cred = Invoke-CredentialPrompt -Service jira -Environment prod
        # Prompts: "Enter credentials for jira (prod)"

    .EXAMPLE
        $cred = Invoke-CredentialPrompt -Environment qa
        # Prompts: "Enter credentials for qa environment"

    .EXAMPLE
        $cred = Invoke-CredentialPrompt -Service confluence
        if (-not $cred) { Write-Warning 'No credential was entered.'; return }

        Handles a cancelled prompt. A service name on its own gives "Enter credentials for confluence".

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Added the help examples and .OUTPUTS required by the CMF standard.
        1.0.0 | 27JAN26 | Initial version to consolidate credential prompting logic.
    #>

    [CmdletBinding()]
    param (
        [string]$Service,
        [string]$Environment
    )

    # Build contextual message
    $message = "Enter credentials"
    
    if ($Service -and $Environment) {
        $message += " for $Service ($Environment)"
    } elseif ($Service) {
        $message += " for $Service"
    } elseif ($Environment) {
        $message += " for $Environment environment"
    }

    return Get-Credential -Message $message
}
