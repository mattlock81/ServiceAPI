
function Invoke-ServiceApiHttpRequest {
    <#
    .SYNOPSIS
        Certificate-aware replacement for Invoke-RestMethod used by every ServiceAPI request.

    .DESCRIPTION
        Invoke-RestMethod cannot accept a per-request certificate validation callback, so it
        cannot reach hosts whose certificate chain trips the .NET name-constraints false
        positive: a leaf certificate that carries IP-address subject alternative names, issued
        by a CA whose permitted subtrees are DNS-only. OpenSSL and CryptoAPI accept such chains.
        The .NET chain engine does not. An internal Aria CA produces exactly this shape.

        This function sends the request through a shared HttpClient whose validation callback
        is a compiled C# class (ServiceApiCertValidator). A PowerShell script block cannot be
        used for the callback because it executes on the .NET TLS handshake thread, where no
        Runspace is available. The validator behaves as follows:

          1. When the platform reports no policy errors, the certificate is accepted unchanged.
          2. Otherwise a second chain is built with IgnoreInvalidName set. The chain must still
             end in a trusted root, intermediates the server sent are honoured even when they
             are absent from a local store, and revocation is not checked (CRL and OCSP
             endpoints are normally unreachable from a restricted network).
          3. The host name is then matched against the certificate itself: DNS names (exact or
             a single left-most-label wildcard) for a name, or iPAddress entries for an IP
             literal.

        The output and error surface match Invoke-RestMethod so existing catch blocks keep
        working: JSON responses are returned as objects, a non-2xx response throws an
        ErrorRecord whose ErrorDetails.Message is the response body and whose
        Exception.Response is the HttpResponseMessage (so
        Exception.Response.StatusCode.value__ works), and a GetResponseStream() script method
        is attached so SYSCommon's Debug-Error can log the body on PowerShell 7.

        Only the scheme, host and path of a request are ever written to the verbose stream,
        because a QueryParam request carries credentials in its query string.

        Known limitation: on Windows PowerShell 5.1, ConvertFrom-Json rejects a JSON document
        larger than about 2 MB, where Invoke-RestMethod does not.

    .PARAMETER Uri
        The absolute request URI.

    .PARAMETER Method
        The HTTP method. Defaults to GET.

    .PARAMETER Headers
        Request headers. A Content-Type entry is applied to the request body rather than the
        request headers, as Invoke-RestMethod does.

    .PARAMETER Body
        The request body. A string is sent as supplied (JSON unless -ContentType says
        otherwise), a dictionary is sent as application/x-www-form-urlencoded, and a byte array
        is sent as binary.

    .PARAMETER ContentType
        The body content type. Overrides a Content-Type entry in -Headers.

    .PARAMETER TimeoutSec
        Seconds to wait for the response. Defaults to 100.

    .PARAMETER StatusCodeVariable
        Name of a variable to set, in the caller's scope, to the integer HTTP status code of
        the response (including a non-2xx response, before the error is thrown).

    .EXAMPLE
        Invoke-ServiceApiHttpRequest -Uri 'https://aria.example.com/iaas/api/about'

        Sends a GET request and returns the parsed JSON response as an object.

    .EXAMPLE
        $body = @{ refreshToken = $refreshToken } | ConvertTo-Json -Compress
        Invoke-ServiceApiHttpRequest -Method POST -Uri 'https://aria.example.com/iaas/api/login' `
            -ContentType 'application/json' -Body $body

        Sends a JSON body and returns the parsed response.

    .EXAMPLE
        Invoke-ServiceApiHttpRequest -Method POST -Uri 'https://aria.example.com/oidc/oauth2/token' `
            -Body @{ grant_type = 'refresh_token'; refresh_token = $rt }

        Sends a dictionary body as application/x-www-form-urlencoded.

    .EXAMPLE
        try {
            Invoke-ServiceApiHttpRequest -Uri $uri -Headers $headers -StatusCodeVariable status -ErrorAction Stop | Out-Null
        } catch {
            $status = [int]$_.Exception.Response.StatusCode
            $body   = $_.ErrorDetails.Message
        }

        Reads the status code on success through -StatusCodeVariable and on failure from the
        error surface, together with the response body.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.1.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.1.1 | 06OCT26 | Replaced em dashes with ASCII punctuation and reworded the affected
                          sentences, so the source is plain ASCII and loads on Windows PowerShell 5.1.
        1.1.0 | 06OCT26 | Added a fast path when the platform reports no policy errors,
                          intermediates the server sent as chain material, wildcard and IP
                          address subject alternative name matching, bounds-checked SAN parsing,
                          a shared HttpClient, -StatusCodeVariable, query-string-safe verbose
                          output and a guard against recompiling the validator on re-import.
        1.0.0 | 06OCT26 | Initial version. Replaces Invoke-RestMethod with a certificate-aware
                          HttpClient call and an Invoke-RestMethod-compatible error surface.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Uri,

        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS')]
        [string]$Method = 'GET',

        [System.Collections.IDictionary]$Headers,

        [object]$Body,

        [string]$ContentType,

        [ValidateRange(1, 3600)]
        [int]$TimeoutSec = 100,

        [string]$StatusCodeVariable
    )

    # =========================================================================
    # One-time session setup: assembly, validator type, shared client
    # =========================================================================
    if (-not $script:ServiceApiHttpClient) {

        Add-Type -AssemblyName System.Net.Http

        if (-not ('ServiceApiCertValidator' -as [type])) {

            # C# 5 syntax only: Windows PowerShell 5.1 compiles with the .NET Framework compiler.
            $validatorSource = @'
using System;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Security.Cryptography.X509Certificates;
using System.Text;

public static class ServiceApiCertValidator
{
    public static readonly Func<HttpRequestMessage, X509Certificate2, X509Chain, SslPolicyErrors, bool> Callback = Validate;

    private static bool ReadLength(byte[] d, ref int pos, out int length)
    {
        length = 0;
        if (pos >= d.Length) return false;
        int b = d[pos++];
        if ((b & 0x80) == 0) { length = b; return true; }
        int n = b & 0x7F;
        if (n == 0 || n > 4 || pos + n > d.Length) return false;
        int len = 0;
        for (int i = 0; i < n; i++) len = (len << 8) | d[pos++];
        if (len < 0) return false;
        length = len;
        return true;
    }

    public static bool SanMatchesHost(X509Certificate2 cert, string host)
    {
        if (cert == null || string.IsNullOrEmpty(host)) return false;

        IPAddress hostIp;
        bool hostIsIp = IPAddress.TryParse(host, out hostIp);
        byte[] hostIpBytes = hostIsIp ? hostIp.GetAddressBytes() : null;

        foreach (X509Extension ext in cert.Extensions)
        {
            if (ext.Oid == null || ext.Oid.Value != "2.5.29.17") continue;   // subjectAltName

            byte[] d = ext.RawData;
            int pos = 0;
            if (d.Length == 0 || d[pos++] != 0x30) return false;
            int seqLen;
            if (!ReadLength(d, ref pos, out seqLen)) return false;
            int end = pos + seqLen;
            if (end > d.Length) return false;

            while (pos < end)
            {
                int tag = d[pos++];
                int l;
                if (!ReadLength(d, ref pos, out l) || pos + l > end) return false;

                if (tag == 0x82 && !hostIsIp)                                 // dNSName
                {
                    string name = Encoding.ASCII.GetString(d, pos, l);
                    if (string.Equals(name, host, StringComparison.OrdinalIgnoreCase)) return true;

                    // One left-most-label wildcard, with at least two labels after it.
                    if (name.StartsWith("*.", StringComparison.Ordinal) && name.IndexOf('.', 2) > 0)
                    {
                        int dot = host.IndexOf('.');
                        if (dot > 0 && string.Equals(name.Substring(1), host.Substring(dot), StringComparison.OrdinalIgnoreCase)) return true;
                    }
                }
                else if (tag == 0x87 && hostIsIp && l == hostIpBytes.Length)  // iPAddress
                {
                    bool same = true;
                    for (int i = 0; i < l; i++)
                    {
                        if (d[pos + i] != hostIpBytes[i]) { same = false; break; }
                    }
                    if (same) return true;
                }
                pos += l;
            }
        }
        return false;
    }

    public static bool Validate(HttpRequestMessage msg, X509Certificate2 cert, X509Chain chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;              // platform validation already succeeded
        if (cert == null || msg == null || msg.RequestUri == null) return false;
        if ((errors & SslPolicyErrors.RemoteCertificateNotAvailable) != 0) return false;

        using (X509Chain c = new X509Chain())
        {
            c.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            c.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
            c.ChainPolicy.VerificationFlags = X509VerificationFlags.IgnoreInvalidName;

            // Intermediates the server sent are honoured even when no local store holds them.
            // ExtraStore supplies chain material only; it never makes a certificate trusted.
            if (chain != null)
            {
                foreach (X509ChainElement element in chain.ChainElements)
                {
                    c.ChainPolicy.ExtraStore.Add(element.Certificate);
                }
            }

            if (!c.Build(cert)) return false;                          // a trusted root is still required
        }

        return SanMatchesHost(cert, msg.RequestUri.DnsSafeHost);
    }
}
'@

            # Windows PowerShell 5.1 does not load System.Net.Http by default, so it must be
            # referenced. PowerShell 7 already has it, and passing the reference breaks the compile.
            if ($PSVersionTable.PSEdition -eq 'Desktop') {
                Add-Type -TypeDefinition $validatorSource -ReferencedAssemblies 'System.Net.Http'
            } else {
                Add-Type -TypeDefinition $validatorSource
            }
        }

        $handler = [System.Net.Http.HttpClientHandler]::new()
        $handler.UseCookies                = $false
        $handler.AllowAutoRedirect         = $true
        $handler.MaxAutomaticRedirections  = 5
        $handler.AutomaticDecompression    = [System.Net.DecompressionMethods]::GZip -bor [System.Net.DecompressionMethods]::Deflate
        $handler.ServerCertificateCustomValidationCallback = [ServiceApiCertValidator]::Callback

        $client = [System.Net.Http.HttpClient]::new($handler)
        $client.Timeout = [System.Threading.Timeout]::InfiniteTimeSpan   # per-request timeout below
        $script:ServiceApiHttpClient = $client
    }

    # =========================================================================
    # Build the request
    # =========================================================================
    $request = [System.Net.Http.HttpRequestMessage]::new([System.Net.Http.HttpMethod]::new($Method.ToUpperInvariant()), $Uri)

    # A Content-Type entry belongs to the body, not the request headers, the same way
    # Invoke-RestMethod treats it. For a request without a body it is ignored.
    $effectiveContentType = $ContentType
    if ($Headers) {
        foreach ($headerName in @($Headers.Keys)) {
            $headerValue = [string]$Headers[$headerName]
            if ([string]::Equals([string]$headerName, 'Content-Type', [System.StringComparison]::OrdinalIgnoreCase)) {
                if (-not $effectiveContentType) { $effectiveContentType = $headerValue }
                continue
            }
            [void]$request.Headers.TryAddWithoutValidation([string]$headerName, $headerValue)
        }
    }

    if ($null -ne $Body) {
        if ($Body -is [System.Collections.IDictionary]) {
            $encodedPairs = foreach ($key in $Body.Keys) {
                '{0}={1}' -f [uri]::EscapeDataString([string]$key), [uri]::EscapeDataString([string]$Body[$key])
            }
            $request.Content = [System.Net.Http.StringContent]::new(($encodedPairs -join '&'), [System.Text.Encoding]::UTF8, 'application/x-www-form-urlencoded')
        } elseif ($Body -is [byte[]]) {
            $request.Content = [System.Net.Http.ByteArrayContent]::new($Body)
        } else {
            $request.Content = [System.Net.Http.StringContent]::new([string]$Body, [System.Text.Encoding]::UTF8, 'application/json')
        }

        # Honour a caller-supplied content type, including any parameters it carries
        if ($effectiveContentType -and $Body -isnot [System.Collections.IDictionary]) {
            try {
                $request.Content.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::Parse($effectiveContentType)
            } catch {
                Write-Verbose "Content type [$effectiveContentType] could not be parsed; the default for the body type is used."
            }
        }
    }

    # The query string is never logged: a QueryParam request carries credentials in it.
    $loggableUri = $request.RequestUri.GetLeftPart([System.UriPartial]::Path)
    Write-Verbose "HTTP $($Method.ToUpperInvariant()) $loggableUri"

    # =========================================================================
    # Send
    # =========================================================================
    $cts = [System.Threading.CancellationTokenSource]::new([TimeSpan]::FromSeconds($TimeoutSec))
    try {
        $response = $script:ServiceApiHttpClient.SendAsync(
            $request,
            [System.Net.Http.HttpCompletionOption]::ResponseContentRead,
            $cts.Token
        ).GetAwaiter().GetResult()
    } catch {
        # Surface the root cause: HttpRequestException's own message is generic, and the
        # useful detail (for example the TLS failure) is several exceptions down.
        $detail   = @()
        $inner    = $_.Exception
        while ($inner) {
            if ($inner.Message -and $detail -notcontains $inner.Message) { $detail += $inner.Message }
            $inner = $inner.InnerException
        }

        if ($cts.IsCancellationRequested) {
            $message = "The request to [$loggableUri] timed out after $TimeoutSec seconds."
        } else {
            $message = "The request to [$loggableUri] failed: $($detail -join ' -> ')"
        }

        $transportException = [System.Net.Http.HttpRequestException]::new($message, $_.Exception)
        $transportRecord    = [System.Management.Automation.ErrorRecord]::new(
            $transportException,
            'ServiceApiHttpTransport',
            [System.Management.Automation.ErrorCategory]::ConnectionError,
            $loggableUri
        )
        throw $transportRecord
    } finally {
        $cts.Dispose()
        $request.Dispose()
    }

    # =========================================================================
    # Read and shape the response
    # =========================================================================
    $statusCode   = [int]$response.StatusCode
    $responseText = $response.Content.ReadAsStringAsync().GetAwaiter().GetResult()

    if ($StatusCodeVariable) {
        Set-Variable -Name $StatusCodeVariable -Value $statusCode -Scope 1
    }

    if (-not $response.IsSuccessStatusCode) {

        # Same error surface as Invoke-RestMethod, so existing catch blocks keep working:
        #   $_.ErrorDetails.Message                    the response body
        #   $_.Exception.Response.StatusCode.value__   the status code
        #   $_.Exception.Response.GetResponseStream()  the body as a stream (for Debug-Error)
        $message   = "Response status code does not indicate success: $statusCode ($($response.ReasonPhrase))."
        $exception = [System.Net.Http.HttpRequestException]::new($message)
        Add-Member -InputObject $exception -NotePropertyName Response -NotePropertyValue $response -Force

        $bodyBytes = [System.Text.Encoding]::UTF8.GetBytes([string]$responseText)
        $null = $response | Add-Member -MemberType ScriptMethod -Name GetResponseStream -Value {
            [System.IO.MemoryStream]::new($bodyBytes)
        }.GetNewClosure() -Force

        $errorRecord = [System.Management.Automation.ErrorRecord]::new(
            $exception,
            'ServiceApiHttpRequest',
            [System.Management.Automation.ErrorCategory]::InvalidResult,
            $loggableUri
        )
        if (-not [string]::IsNullOrEmpty($responseText)) {
            $errorRecord.ErrorDetails = [System.Management.Automation.ErrorDetails]::new($responseText)
        }

        # The response stays undisposed on this path because the error record refers to it.
        throw $errorRecord
    }

    $mediaType = $null
    if ($response.Content -and $response.Content.Headers.ContentType) {
        $mediaType = $response.Content.Headers.ContentType.MediaType
    }
    $response.Dispose()

    if ([string]::IsNullOrWhiteSpace($responseText)) { return $null }

    # JSON becomes an object, as Invoke-RestMethod does. Anything else is returned as text.
    if ($mediaType -match 'json' -or $responseText.TrimStart() -match '^[\{\[]') {
        try {
            return ($responseText | ConvertFrom-Json)
        } catch {
            Write-Verbose "The response was not valid JSON; it is returned as text. $($_.Exception.Message)"
            return $responseText
        }
    }

    return $responseText
}
