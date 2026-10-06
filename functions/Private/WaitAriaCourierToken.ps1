
function Wait-AriaCourierToken {
    <#
    .SYNOPSIS
        Starts a loopback listener and waits for the courier userscript to deliver an Aria
        OIDC token response.

    .DESCRIPTION
        Binds 127.0.0.1 only. Two requests are served:

          GET  /aria-oidc-courier.user.js  returns the rendered courier script, so it can be
                                           installed once by opening the URL in a browser that
                                           runs Violentmonkey.
          POST /token                      accepted only when the caller is loopback, carries
                                           the X-Courier-Key header, sends at most 64 KB, names
                                           the expected origin and supplies both an
                                           access_token and a refresh_token. The first valid
                                           post ends the wait.

        Anything else receives 403 or 404 and is ignored. An optional -AfterStart script block
        runs once the listener is accepting (used to open the portal in the browser).

        Not exported.

    .PARAMETER Origin
        The expected Aria origin (scheme and host), compared with the origin the courier sends.

    .PARAMETER ScriptText
        The rendered courier script to serve (from Get-AriaCourierScript).

    .PARAMETER Port
        Loopback port. Defaults to 47811 and must match the courier script.

    .PARAMETER Key
        Required X-Courier-Key value. Must match the courier script.

    .PARAMETER TimeoutSeconds
        Maximum time to wait. Defaults to 300.

    .PARAMETER AfterStart
        Optional script block run after the listener starts.

    .OUTPUTS
        PSCustomObject — the accepted payload (origin, access_token, refresh_token,
        expires_in, scope).

    .EXAMPLE
        $script  = Get-AriaCourierScript -BaseUrl 'https://aria.example.com'
        $payload = Wait-AriaCourierToken -Origin 'https://aria.example.com' -ScriptText $script

        Starts the listener on the default port and waits up to 300 seconds for the courier to
        deliver a token response. The first valid post ends the wait and is returned.

    .EXAMPLE
        $payload = Wait-AriaCourierToken -Origin $origin -ScriptText $script -TimeoutSeconds 120 -AfterStart {
            Start-Process 'https://aria.example.com/tenant/my-tenant/automation/'
        }

        Opens the portal in the default browser once the listener is accepting, so no request can
        arrive before it is ready.

    .EXAMPLE
        Invoke-WebRequest -Uri 'http://127.0.0.1:47811/aria-oidc-courier.user.js' -UseBasicParsing

        While the listener is running, fetches the rendered courier script. Opening that URL in a
        browser that runs Violentmonkey offers to install it.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.1
        Date        : 06-OCT-26

        CHANGE LOG
        1.0.1 | 06OCT26 | Added the three help examples required by the CMF standard.
        1.0.0 | 01OCT26 | Initial version. Listener logic extracted from Invoke-AriaOidcLogin and
                          extended to serve the courier script for one-time install.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$Origin,

        [Parameter(Mandatory)]
        [string]$ScriptText,

        [ValidateRange(1024, 65535)]
        [int]$Port = 47811,

        [string]$Key = 'aria-oidc-courier',

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [scriptblock]$AfterStart
    )

    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://127.0.0.1:$Port/")

    try {
        $listener.Start()
    } catch {
        throw "AriaOidc could not listen on 127.0.0.1:$Port (is another listener already running?) — $($_.Exception.Message)"
    }

    $scriptBytes = [Text.Encoding]::UTF8.GetBytes($ScriptText)
    $deadline    = (Get-Date).AddSeconds($TimeoutSeconds)

    try {
        if ($AfterStart) { & $AfterStart }

        while ($true) {
            $task = $listener.GetContextAsync()
            while (-not $task.AsyncWaitHandle.WaitOne(500)) {
                if ((Get-Date) -ge $deadline) {
                    throw "Timed out after $TimeoutSeconds seconds waiting for the Aria login. Check the courier userscript is installed and enabled, then reload the portal tab."
                }
            }

            $ctx      = $task.GetAwaiter().GetResult()
            $req      = $ctx.Request
            $res      = $ctx.Response
            $accepted = $null

            try {
                if (-not [Net.IPAddress]::IsLoopback($req.RemoteEndPoint.Address)) {
                    $res.StatusCode = 403
                }
                elseif ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq '/aria-oidc-courier.user.js') {
                    $res.StatusCode      = 200
                    $res.ContentType     = 'text/javascript; charset=utf-8'
                    $res.ContentLength64 = $scriptBytes.Length
                    $res.OutputStream.Write($scriptBytes, 0, $scriptBytes.Length)
                }
                elseif ($req.HttpMethod -eq 'POST' -and
                        $req.Url.AbsolutePath -eq '/token' -and
                        $req.Headers['X-Courier-Key'] -eq $Key -and
                        $req.ContentLength64 -gt 0 -and $req.ContentLength64 -le 65536) {

                    $reader  = [IO.StreamReader]::new($req.InputStream, [Text.Encoding]::UTF8)
                    $payload = $reader.ReadToEnd() | ConvertFrom-Json

                    if ($payload.origin -eq $Origin -and $payload.access_token -and $payload.refresh_token) {
                        $accepted       = $payload
                        $res.StatusCode = 204
                    } else {
                        $res.StatusCode = 403
                    }
                }
                else {
                    $res.StatusCode = 404
                }
            } catch {
                $res.StatusCode = 400
            } finally {
                $res.Close()
            }

            if ($accepted) { return $accepted }
        }
    } finally {
        $listener.Stop()
        $listener.Close()
    }
}
