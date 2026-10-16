function Get-ServiceClientCertificate {
    <#
    .SYNOPSIS
        Opens a client certificate described by New-ServiceClientCertificate and returns it with its
        private key.

    .DESCRIPTION
        Resolves the descriptor to an X509Certificate2 that has a private key, ready for a TLS
        client handshake or for signing a client assertion.

          Pfx    The file is opened with the descriptor's password. With no password, an empty one is
                 tried first; if the file needs one it is read from the vault as the Basic
                 credential labelled 'clientcert' for the service (the password is the secret) and
                 the interactive prompt offers to store it.
          Pem    PowerShell 7 only (the Windows PowerShell 5.1 .NET Framework cannot import a PEM
                 private key). An encrypted key takes the passphrase the same way as a PFX. On
                 Windows the certificate is re-imported so SChannel can use the key for client
                 authentication.
          Store  The personal store of CurrentUser or LocalMachine, by thumbprint or subject. The
                 newest valid certificate with a private key wins. The key stays in the store.

        The result is cached for the session, keyed by the descriptor and the file's last write
        time, so a rotated file is picked up on the next request.

        Not exported.

    .PARAMETER Certificate
        The descriptor from New-ServiceClientCertificate.

    .PARAMETER Service
        Optional. The service name, used to look the password up in the vault.

    .PARAMETER Environment
        The environment. Defaults to prod.

    .PARAMETER Vault
        Optional. The registered vault to read the password from.

    .PARAMETER ForCurl
        The certificate is for the Curl transport. A PEM pair is then not imported into .NET (curl
        reads the files itself, so this also works on Windows PowerShell 5.1); an encrypted key's
        passphrase is still resolved. PFX and store certificates are opened as usual.

    .EXAMPLE
        $resolved = Get-ServiceClientCertificate -Certificate $spec -Service partner
        $resolved.Certificate.Thumbprint

        Opens the certificate and shows its thumbprint.

    .EXAMPLE
        $resolved = Get-ServiceClientCertificate -Certificate (New-ServiceClientCertificate -Thumbprint $tp)
        $resolved.Certificate.NotAfter

        Finds a store certificate and shows when it expires.

    .EXAMPLE
        & (Get-Module ServiceAPI) { (Get-ServiceClientCertificate -Certificate $spec -Service partner).Source }

        Confirms from outside the module which source the descriptor resolved from.

    .OUTPUTS
        PSCustomObject with Certificate (X509Certificate2), Thumbprint, Source, Spec (the
        descriptor) and Password (SecureString or $null, the secret that opened the file).

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.0.0 | 16OCT26 | Initial version. Client certificate loader for PFX, PEM and the certificate
                          store, with vault-backed passwords and a per-session cache.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [object]$Certificate,

        [string]$Service,

        [string]$Environment = 'prod',

        [string]$Vault,

        [switch]$ForCurl
    )

    if (-not $Certificate -or -not $Certificate.PSObject.Properties['Source']) {
        throw "The client certificate must come from New-ServiceClientCertificate."
    }

    Add-Type -AssemblyName System.Security -ErrorAction SilentlyContinue

    if (-not $script:ServiceApiClientCertCache) { $script:ServiceApiClientCertCache = @{} }

    $stamp = ''
    foreach ($file in @($Certificate.Path, $Certificate.KeyPath)) {
        if ($file -and (Test-Path -LiteralPath $file -PathType Leaf)) {
            $stamp += '|' + (Get-Item -LiteralPath $file).LastWriteTimeUtc.Ticks
        }
    }
    # A supplied password is part of the key (as a hash), so a wrong one is never answered from the cache
    $passwordKey = ''
    if ($Certificate.Password) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            $plain       = ConvertSecureStringToPlainText -SecureString $Certificate.Password
            $passwordKey = [BitConverter]::ToString($sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($plain)))
        } finally { $sha.Dispose() }
    }
    $cacheKey = (@($Certificate.Source, $Certificate.Path, $Certificate.KeyPath, $Certificate.Thumbprint,
                   $Certificate.Subject, $Certificate.Store, $passwordKey, [bool]$ForCurl) -join '|') + $stamp
    if ($script:ServiceApiClientCertCache.ContainsKey($cacheKey)) {
        return $script:ServiceApiClientCertCache[$cacheKey]
    }

    # The password: the descriptor's own, else the vault (Basic label 'clientcert'), else a prompt
    $getPassword = {
        if ($Service) {
            $headers = Get-ServiceCredential -Service $Service -Environment $Environment `
                -AuthType Basic -Label 'clientcert' -Vault $Vault
            $b64     = ([string]$headers['Authorization']) -replace '^Basic\s+', ''
            $decoded = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($b64))
            $colon   = $decoded.IndexOf(':')
            return (ConvertTo-SecureString -String $decoded.Substring($colon + 1) -AsPlainText -Force)
        }
        throw "The client certificate [$($Certificate.Path)] needs a password. Pass -Password to New-ServiceClientCertificate, or use -Service so it can be read from the vault (Basic credential, label 'clientcert')."
    }

    $x509     = $null
    $password = $Certificate.Password

    switch ($Certificate.Source) {

        'Pfx' {
            $open = {
                param($pw)
                if ($pw) { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.Path, $pw) }
                else     { [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($Certificate.Path, '') }
            }
            try {
                $x509 = & $open $password
            } catch [System.Security.Cryptography.CryptographicException] {
                if ($password) {
                    throw "The PFX file [$($Certificate.Path)] could not be opened with the supplied password: $($_.Exception.Message)"
                }
                $password = & $getPassword
                try {
                    $x509 = & $open $password
                } catch [System.Security.Cryptography.CryptographicException] {
                    throw "The PFX file [$($Certificate.Path)] could not be opened with the stored password: $($_.Exception.Message)"
                }
            }
        }

        'Pem' {
            if ($ForCurl) {
                # curl reads the PEM files itself; only the passphrase is needed here
                $keyHead = Get-Content -LiteralPath $Certificate.KeyPath -Raw
                if (($keyHead -match 'ENCRYPTED PRIVATE KEY' -or $keyHead -match 'Proc-Type:\s*4,ENCRYPTED') -and -not $password) {
                    $password = & $getPassword
                }
                break
            }
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                throw "A PEM private key cannot be imported by Windows PowerShell 5.1. Use PowerShell 7, convert the pair to a PFX (openssl pkcs12 -export -inkey key.pem -in cert.pem -out cert.pfx), or send the request with -Transport Curl, which reads PEM files directly."
            }
            $keyText   = Get-Content -LiteralPath $Certificate.KeyPath -Raw
            $encrypted = $keyText -match 'ENCRYPTED PRIVATE KEY' -or $keyText -match 'Proc-Type:\s*4,ENCRYPTED'
            $certType  = [System.Security.Cryptography.X509Certificates.X509Certificate2]
            if ($encrypted) {
                if (-not $password) { $password = & $getPassword }
                $plain = ConvertSecureStringToPlainText -SecureString $password
                try {
                    $x509 = $certType::CreateFromEncryptedPemFile($Certificate.Path, $plain, $Certificate.KeyPath)
                } catch {
                    throw "The PEM key [$($Certificate.KeyPath)] could not be decrypted with the supplied passphrase: $($_.Exception.Message)"
                }
            } else {
                $x509 = $certType::CreateFromPemFile($Certificate.Path, $Certificate.KeyPath)
            }
            # A key imported from PEM is ephemeral, which SChannel cannot use for client authentication
            if ($script:ServiceApiIsWindows) {
                $bytes = $x509.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, '')
                $x509  = $certType::new($bytes, '')
            }
        }

        'Store' {
            $location = [System.Security.Cryptography.X509Certificates.StoreLocation]$Certificate.Store
            $store    = [System.Security.Cryptography.X509Certificates.X509Store]::new('My', $location)
            try {
                $store.Open([System.Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly)
                $findType = [System.Security.Cryptography.X509Certificates.X509FindType]
                if ($Certificate.Thumbprint) {
                    $found = $store.Certificates.Find($findType::FindByThumbprint, $Certificate.Thumbprint, $false)
                } elseif ($Certificate.Subject -match '^\s*[A-Za-z]+=') {
                    $found = $store.Certificates.Find($findType::FindBySubjectDistinguishedName, $Certificate.Subject, $false)
                } else {
                    $found = $store.Certificates.Find($findType::FindBySubjectName, $Certificate.Subject, $false)
                }
                $usable = @($found | Where-Object { $_.HasPrivateKey } | Sort-Object -Property NotAfter -Descending)
                if ($usable.Count -eq 0) {
                    $what = if ($Certificate.Thumbprint) { "thumbprint [$($Certificate.Thumbprint)]" } else { "subject [$($Certificate.Subject)]" }
                    throw "No certificate with a private key and $what was found in the $($Certificate.Store) personal store."
                }
                # Prefer one that is currently valid
                $now   = [DateTime]::Now
                $valid = @($usable | Where-Object { $_.NotBefore -le $now -and $_.NotAfter -ge $now })
                $x509  = if ($valid.Count -gt 0) { $valid[0] } else { $usable[0] }
            } finally {
                $store.Close()
            }
        }

        default { throw "Unknown client certificate source [$($Certificate.Source)]." }
    }

    if ($x509) {
        if (-not $x509.HasPrivateKey) {
            throw "The client certificate [$($x509.Subject)] has no private key, so it cannot authenticate a connection."
        }
        if ($x509.NotAfter -lt [DateTime]::Now) {
            Write-Warning "The client certificate [$($x509.Subject)] expired on $($x509.NotAfter.ToString('yyyy-MM-dd')); the server will probably refuse it."
        }
    }

    $resolved = [pscustomobject]@{
        PSTypeName  = 'ServiceApi.ResolvedClientCertificate'
        Certificate = $x509
        Thumbprint  = $(if ($x509) { $x509.Thumbprint } else { '' })
        Source      = $Certificate.Source
        Spec        = $Certificate
        Password    = $password
    }
    $script:ServiceApiClientCertCache[$cacheKey] = $resolved
    Write-Verbose "Client certificate $(if ($x509) { "[$($x509.Subject)] " })opened from $($Certificate.Source)."
    return $resolved
}
