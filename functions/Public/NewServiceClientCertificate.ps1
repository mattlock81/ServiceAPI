function New-ServiceClientCertificate {
    <#
    .SYNOPSIS
        Describes a client certificate for ServiceAPI to present on a TLS connection.

    .DESCRIPTION
        Returns a small object that says where a client certificate and its private key live. It
        loads nothing and reads no secret: the certificate is opened when a request needs it.
        Pass the object to Invoke-APIRequest -ClientCertificate for one request, or to
        Register-CustomService -ClientCertificate to make it the default for a service.

        Three sources are supported:

          Pfx          A PKCS#12 (.pfx or .p12) file holding the certificate and key.
          Pem          A PEM certificate file and a separate PEM private key file (PKCS#8 or
                       traditional). The key may be encrypted. PowerShell 7 only on the .NET
                       transport; the curl transport reads PEM files on any edition.
          Store        A certificate in the Windows (or .NET) certificate store, chosen by
                       thumbprint or subject. The private key never leaves the store on the .NET
                       transport.

        A password or key passphrase is never stored in services.json. Supply it with -Password
        (kept in memory for the session only) or leave it out: when a file needs one, ServiceAPI
        reads it from the vault as the Basic credential labelled 'clientcert' for the service
        (the password is the secret; the user name is ignored), and prompts for it if it is not
        there.

    .PARAMETER PfxPath
        Path to a PKCS#12 file.

    .PARAMETER CertificatePath
        Path to the PEM certificate file (a chain in the same file is fine).

    .PARAMETER KeyPath
        Path to the PEM private key file.

    .PARAMETER Thumbprint
        Thumbprint of a certificate in the personal ('My') store. Spaces and colons are ignored.

    .PARAMETER Subject
        Subject of a certificate in the personal store: a full distinguished name such as
        'CN=svc-client' (exact match) or a plain name (substring match). The newest valid
        certificate with a private key is used.

    .PARAMETER Store
        CurrentUser (default) or LocalMachine. Used with -Thumbprint and -Subject.

    .PARAMETER Password
        Optional. The PFX password or the PEM key passphrase, as a SecureString. Held in memory
        only; never written to services.json.

    .EXAMPLE
        $cert = New-ServiceClientCertificate -PfxPath 'C:\certs\svc-client.pfx'
        Invoke-APIRequest -Service partner -Endpoint 'v1/status' -AuthType Certificate -ClientCertificate $cert

        Authenticates one request with a PFX file. The password comes from the vault.

    .EXAMPLE
        $cert = New-ServiceClientCertificate -CertificatePath ./svc.crt -KeyPath ./svc.key
        Invoke-APIRequest -Service partner -Endpoint 'v1/status' -AuthType Certificate -ClientCertificate $cert -Transport Curl

        Authenticates with a PEM pair over the curl/OpenSSL transport.

    .EXAMPLE
        $cert = New-ServiceClientCertificate -Thumbprint 'AB12 CD34 EF56 7890 AB12 CD34 EF56 7890 AB12 CD34'
        Register-CustomService -ServiceName partner -BaseUrl 'https://partner.example.com' -ClientCertificate $cert -Persistent

        Makes a store certificate the default for the service and persists the location, not a secret.

    .OUTPUTS
        PSCustomObject (ServiceApi.ClientCertificate) with Source, Path, KeyPath, Thumbprint,
        Subject, Store and Password.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.0.0 | 16OCT26 | Initial version. Client certificate descriptor for mutual TLS: PFX, PEM
                          pair or certificate store. Not yet verified against a real server.
    #>

    [CmdletBinding(DefaultParameterSetName = 'Pfx')]
    [OutputType([pscustomobject])]
    param (
        [Parameter(Mandatory, ParameterSetName = 'Pfx')]
        [string]$PfxPath,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [string]$CertificatePath,

        [Parameter(Mandatory, ParameterSetName = 'Pem')]
        [string]$KeyPath,

        [Parameter(Mandatory, ParameterSetName = 'Thumbprint')]
        [string]$Thumbprint,

        [Parameter(Mandatory, ParameterSetName = 'Subject')]
        [string]$Subject,

        [Parameter(ParameterSetName = 'Thumbprint')]
        [Parameter(ParameterSetName = 'Subject')]
        [ValidateSet('CurrentUser', 'LocalMachine')]
        [string]$Store = 'CurrentUser',

        [Parameter(ParameterSetName = 'Pfx')]
        [Parameter(ParameterSetName = 'Pem')]
        [securestring]$Password
    )

    $resolveFile = {
        param([string]$Path, [string]$What)
        if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
            throw "The $What file [$Path] was not found."
        }
        (Resolve-Path -LiteralPath $Path).ProviderPath
    }

    $spec = [ordered]@{
        PSTypeName = 'ServiceApi.ClientCertificate'
        Source     = $null
        Path       = $null
        KeyPath    = $null
        Thumbprint = $null
        Subject    = $null
        Store      = $null
        Password   = $null
    }

    switch ($PSCmdlet.ParameterSetName) {
        'Pfx' {
            $spec.Source   = 'Pfx'
            $spec.Path     = & $resolveFile $PfxPath 'PFX'
            $spec.Password = $Password
        }
        'Pem' {
            $spec.Source   = 'Pem'
            $spec.Path     = & $resolveFile $CertificatePath 'certificate'
            $spec.KeyPath  = & $resolveFile $KeyPath 'private key'
            $spec.Password = $Password
        }
        'Thumbprint' {
            $clean = ($Thumbprint -replace '[^0-9A-Fa-f]', '').ToUpperInvariant()
            if ($clean.Length -lt 40) {
                throw "The thumbprint [$Thumbprint] is not a valid SHA-1 thumbprint (40 hexadecimal characters)."
            }
            $spec.Source     = 'Store'
            $spec.Thumbprint = $clean
            $spec.Store      = $Store
        }
        'Subject' {
            $spec.Source  = 'Store'
            $spec.Subject = $Subject
            $spec.Store   = $Store
        }
    }

    [pscustomobject]$spec
}
