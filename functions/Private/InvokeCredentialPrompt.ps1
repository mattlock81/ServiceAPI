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

    .EXAMPLE
        $cred = Invoke-CredentialPrompt
        # Prompts: "Enter credentials"

    .EXAMPLE
        $cred = Invoke-CredentialPrompt -Service jira -Environment prod
        # Prompts: "Enter credentials for jira (prod)"

    .NOTES
        Author      : Matthew Sillett
        Organisation: Australian Signals Directorate
        Version     : 1.0.0
        Date        : 27-JAN-26

        CHANGE LOG
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
