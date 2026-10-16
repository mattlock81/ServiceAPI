function Invoke-ServiceApiCurlRequest {
    <#
    .SYNOPSIS
        Sends one HTTP request through a curl built with OpenSSL and returns an HttpResponseMessage.

    .DESCRIPTION
        The Curl transport behind Invoke-ServiceApiHttpRequest. It exists for hosts whose SChannel
        lacks TLS 1.3 and for PEM client keys, which curl reads natively. It returns a synthetic
        System.Net.Http.HttpResponseMessage (status code, reason phrase, body and content type), so
        the caller shapes the result and the error surface exactly as it does for the .NET
        transport.

        Nothing sensitive reaches a command line, where any local user could read it. The URL,
        every header (Authorization included), the client certificate paths and passphrases and the
        CA bundle are passed to curl as a configuration read from standard input (-K -). A request
        body is written to a temporary file readable only by the current user, and the response body
        and headers to two more; all three are deleted afterwards. A client certificate from the
        certificate store is exported to a temporary PFX protected by a random password, because
        curl with OpenSSL cannot use the store; a non-exportable key therefore needs the .NET
        transport.

        Redirects are followed (up to five) as the .NET transport does, and curl forwards custom
        Authorization headers only to the original host. Server certificates are validated by
        OpenSSL against curl's own CA bundle, or -CaBundle: the .NET name-constraints workaround
        (ServiceApiCertValidator) does not apply, and is not needed, because OpenSSL accepts that
        chain shape.

        Not exported.

    .PARAMETER Method
        The HTTP method.

    .PARAMETER Uri
        The absolute request URI.

    .PARAMETER HeaderLine
        Request headers as 'Name: value' strings, Content-Type included. A value with a line
        break is refused.

    .PARAMETER BodyBytes
        The request body, if any.

    .PARAMETER TimeoutSec
        Seconds to wait for the whole request. Defaults to 100.

    .PARAMETER Certificate
        An opened client certificate from Get-ServiceClientCertificate, presented for mutual TLS.

    .PARAMETER CaBundle
        A PEM file of trusted CA certificates. Without it curl uses its own default trust store.

    .EXAMPLE
        $r = Invoke-ServiceApiCurlRequest -Method GET -Uri 'https://confluence.example.com/rest/api/space' -HeaderLine 'Accept: application/json'
        $r.StatusCode

        Sends a GET through curl/OpenSSL and shows the status code.

    .EXAMPLE
        $r = Invoke-ServiceApiCurlRequest -Method POST -Uri $uri -HeaderLine 'Content-Type: application/json' `
            -BodyBytes ([Text.Encoding]::UTF8.GetBytes('{"a":1}')) -Certificate $resolved -CaBundle ./roots.pem

        Sends a JSON body over mutual TLS, trusting the CAs in roots.pem.

    .EXAMPLE
        & (Get-Module ServiceAPI) { Invoke-ServiceApiCurlRequest -Method GET -Uri 'https://localhost:18449/whoami' -CaBundle ./roots.pem -Certificate $c -Verbose }

        Shows the curl path used and the exit code in the verbose output.

    .OUTPUTS
        System.Net.Http.HttpResponseMessage

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 16-OCT-26

        CHANGE LOG
        1.0.0 | 16OCT26 | Initial version. curl/OpenSSL transport with the HttpClient error surface.
                          Secrets travel on standard input and in owner-only temporary files, never on the
                          command line. Not yet verified against a real server.
    #>

    [CmdletBinding()]
    [OutputType([System.Net.Http.HttpResponseMessage])]
    param (
        [Parameter(Mandatory)]
        [string]$Method,

        [Parameter(Mandatory)]
        [string]$Uri,

        [string[]]$HeaderLine,

        [byte[]]$BodyBytes,

        [ValidateRange(1, 3600)]
        [int]$TimeoutSec = 100,

        [object]$Certificate,

        [string]$CaBundle
    )

    Add-Type -AssemblyName System.Net.Http -ErrorAction SilentlyContinue

    $curl        = Get-ServiceCurlPath
    $loggableUri = ([uri]$Uri).GetLeftPart([System.UriPartial]::Path)

    # curl config strings: backslash and double quote are escaped, and a line break would split the
    # setting, so it is refused rather than escaped
    $q = {
        param([string]$Value)
        if ($Value -match "[\r\n]") { throw "A value passed to curl contains a line break and was refused." }
        '"' + ($Value -replace '\\', '\\' -replace '"', '\"' -replace "`t", '\t') + '"'
    }

    $tempDir  = [System.IO.Path]::GetTempPath()
    $token    = [guid]::NewGuid().ToString('N')
    $tempFiles = New-Object System.Collections.Generic.List[string]
    $newTemp  = {
        param([string]$Suffix)
        $path = Join-Path $tempDir "svcapi-$token.$Suffix"
        New-Item -ItemType File -Path $path -Force | Out-Null
        Set-ServiceApiSecureMode -Path $path
        $tempFiles.Add($path)
        $path
    }

    try {
        $bodyFile    = $null
        $headerFile  = & $newTemp 'hdr'
        $outputFile  = & $newTemp 'out'

        $lines = New-Object System.Collections.Generic.List[string]
        $lines.Add('silent')
        $lines.Add('show-error')
        $lines.Add('globoff')
        $lines.Add('location')
        $lines.Add('max-redirs = 5')
        $lines.Add('compressed')
        $lines.Add("max-time = $TimeoutSec")
        $lines.Add("connect-timeout = $([Math]::Min($TimeoutSec, 30))")
        $lines.Add('url = ' + (& $q $Uri))
        $lines.Add('dump-header = ' + (& $q $headerFile))
        $lines.Add('write-out = "%{http_code}"')

        $verb = $Method.ToUpperInvariant()
        if ($verb -eq 'HEAD') {
            $lines.Add('head')
        } else {
            $lines.Add('output = ' + (& $q $outputFile))
            $lines.Add('request = ' + (& $q $verb))
        }

        foreach ($header in $HeaderLine) {
            if ($header) { $lines.Add('header = ' + (& $q $header)) }
        }

        if ($null -ne $BodyBytes -and $BodyBytes.Length -gt 0) {
            $bodyFile = & $newTemp 'in'
            [System.IO.File]::WriteAllBytes($bodyFile, $BodyBytes)
            $lines.Add('data-binary = ' + (& $q ('@' + $bodyFile)))
        }

        if ($CaBundle) { $lines.Add('cacert = ' + (& $q $CaBundle)) }

        if ($Certificate) {
            $spec = $Certificate.Spec
            $pass = $null
            if ($Certificate.Password) { $pass = ConvertSecureStringToPlainText -SecureString $Certificate.Password }

            switch ($Certificate.Source) {
                'Pem' {
                    $lines.Add('cert = ' + (& $q $spec.Path))
                    $lines.Add('key = '  + (& $q $spec.KeyPath))
                    if ($pass) { $lines.Add('pass = ' + (& $q $pass)) }
                }
                'Pfx' {
                    $lines.Add('cert-type = "P12"')
                    $lines.Add('cert = ' + (& $q $spec.Path))
                    $lines.Add('pass = ' + (& $q ([string]$pass)))
                }
                'Store' {
                    # curl with OpenSSL cannot read the certificate store, so hand it an owner-only temporary PFX
                    $randomBytes = New-Object byte[] 24
                    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
                    try { $rng.GetBytes($randomBytes) } finally { $rng.Dispose() }
                    $random = [Convert]::ToBase64String($randomBytes)
                    try {
                        $pfxBytes = $Certificate.Certificate.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Pfx, $random)
                    } catch {
                        throw "The private key of [$($Certificate.Certificate.Subject)] cannot be exported, and curl with OpenSSL cannot use the certificate store directly. Use -Transport DotNet for this certificate, or import it with an exportable key."
                    }
                    $pfxFile = & $newTemp 'p12'
                    [System.IO.File]::WriteAllBytes($pfxFile, $pfxBytes)
                    $lines.Add('cert-type = "P12"')
                    $lines.Add('cert = ' + (& $q $pfxFile))
                    $lines.Add('pass = ' + (& $q $random))
                }
            }
        }

        $config = ($lines -join "`n") + "`n"

        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName               = $curl
        $psi.Arguments              = '-K -'
        $psi.UseShellExecute        = $false
        $psi.RedirectStandardInput  = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError  = $true
        $psi.CreateNoWindow         = $true

        Write-Verbose "HTTP $verb $loggableUri (curl)"
        $proc = [System.Diagnostics.Process]::Start($psi)
        try {
            $stdoutTask = $proc.StandardOutput.ReadToEndAsync()
            $stderrTask = $proc.StandardError.ReadToEndAsync()

            $configBytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($config)
            $proc.StandardInput.BaseStream.Write($configBytes, 0, $configBytes.Length)
            $proc.StandardInput.BaseStream.Flush()
            $proc.StandardInput.Close()

            if (-not $proc.WaitForExit(($TimeoutSec + 20) * 1000)) {
                try { $proc.Kill() } catch { }
                $timeoutException = [System.Net.Http.HttpRequestException]::new("The request to [$loggableUri] timed out after $TimeoutSec seconds.")
                throw [System.Management.Automation.ErrorRecord]::new($timeoutException, 'ServiceApiHttpTransport', [System.Management.Automation.ErrorCategory]::ConnectionError, $loggableUri)
            }
            $exitCode = $proc.ExitCode
            $stdout   = $stdoutTask.GetAwaiter().GetResult()
            $stderr   = $stderrTask.GetAwaiter().GetResult()
        } finally {
            $proc.Dispose()
        }
        Write-Verbose "curl exit code $exitCode"

        if ($exitCode -ne 0) {
            # curl's message is already free of the URL's query string; take its first line only
            $detail = (($stderr -split "`r?`n") | Where-Object { $_ } | Select-Object -First 1)
            $detail = ($detail -replace '\?[^\s"'']*', '?...')
            $message = if ($exitCode -eq 28) {
                "The request to [$loggableUri] timed out after $TimeoutSec seconds."
            } else {
                $hint = switch ($exitCode) {
                    60      { ' Install the issuing CA in curl''s trust store or pass -CaBundle.' }
                    { $_ -in 58, 59, 64, 66, 77, 83 } { ' Check the client certificate, its key and passphrase, and the CA bundle.' }
                    { $_ -in 35, 56 } { ' If the server requires a client certificate, check that one is supplied and trusted by the server.' }
                    default { '' }
                }
                "The request to [$loggableUri] failed (curl exit code ${exitCode}): $detail$hint"
            }
            $failure = [System.Net.Http.HttpRequestException]::new($message)
            throw [System.Management.Automation.ErrorRecord]::new($failure, 'ServiceApiHttpTransport', [System.Management.Automation.ErrorCategory]::ConnectionError, $loggableUri)
        }

        # Status code, reason phrase and content type
        $statusCode = 0
        [void][int]::TryParse(($stdout.Trim()), [ref]$statusCode)
        if ($statusCode -lt 100) { throw "curl returned no HTTP status for [$loggableUri]." }

        $reason      = $null
        $contentType = $null
        $headerText  = [System.IO.File]::ReadAllText($headerFile)
        $blocks      = @($headerText -split "(?:\r?\n){2,}" | Where-Object { $_.Trim() })
        if ($blocks.Count -gt 0) {
            $lastBlock = $blocks[$blocks.Count - 1] -split "`r?`n"
            if ($lastBlock[0] -match '^HTTP/\S+\s+\d{3}\s*(.*)$') { $reason = $Matches[1].Trim() }
            foreach ($line in $lastBlock) {
                if ($line -match '^(?i)content-type:\s*(.+)$') { $contentType = $Matches[1].Trim() }
            }
        }

        $bytes = New-Object byte[] 0
        if ($verb -ne 'HEAD' -and (Test-Path -LiteralPath $outputFile)) {
            $bytes = [System.IO.File]::ReadAllBytes($outputFile)
        }

        $response = [System.Net.Http.HttpResponseMessage]::new([System.Net.HttpStatusCode]$statusCode)
        if ($reason) { try { $response.ReasonPhrase = $reason } catch { } }
        $response.Content = [System.Net.Http.ByteArrayContent]::new($bytes)
        if ($contentType) {
            try {
                $media = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($contentType)
                if (-not $media.CharSet) { $media.CharSet = 'utf-8' }   # .NET Framework would otherwise assume ISO-8859-1
                $response.Content.Headers.ContentType = $media
            } catch { }
        } else {
            $response.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse('text/plain; charset=utf-8')
        }
        return $response
    } finally {
        foreach ($file in $tempFiles) {
            Remove-Item -LiteralPath $file -Force -ErrorAction SilentlyContinue
        }
    }
}
