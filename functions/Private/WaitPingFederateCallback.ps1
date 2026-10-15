function Wait-PingFederateCallback {
    <#
    .SYNOPSIS
        Starts a loopback listener and waits for PingFederate to redirect the browser back with an
        authorization code.

    .DESCRIPTION
        Listens on the host and port of the redirect URI, which must be a loopback address
        (127.0.0.1 or localhost) over http. Only a GET to the redirect path is considered, only
        from a loopback client, and only when the 'state' value equals the one this login sent;
        anything else gets a 404 or 400 and is ignored, so a stray or forged request cannot end
        the wait. An 'error' answer with the right state throws with the OAuth error and its
        description. The first valid answer ends the wait and the listener is stopped.

        The optional -AfterStart script block runs once the listener is accepting, and is used to
        open the browser, so the redirect cannot arrive before the listener is ready.

        Not exported.

    .PARAMETER RedirectUri
        The redirect URI registered on the PingFederate client, for example
        http://127.0.0.1:47812/callback.

    .PARAMETER State
        The state value sent in the authorization request.

    .PARAMETER TimeoutSeconds
        Maximum time to wait. Defaults to 300.

    .PARAMETER AuthorizationUrl
        Optional. The PingFederate authorization URL. When supplied, it is opened in the default
        browser once the listener is accepting; if no browser can be launched (headless Linux) the
        URL is printed instead, to be opened in a browser on this same host.

    .PARAMETER AfterStart
        Optional script block run after the listener starts.

    .EXAMPLE
        $code = Wait-PingFederateCallback -RedirectUri 'http://127.0.0.1:47812/callback' -State $state
        Waits up to 300 seconds for the redirect and returns the authorization code.

    .EXAMPLE
        $code = Wait-PingFederateCallback -RedirectUri $uri -State $state -TimeoutSeconds 120 -AuthorizationUrl $authUrl
        Opens the browser once the listener is accepting.

    .EXAMPLE
        Wait-PingFederateCallback -RedirectUri 'https://example.com/cb' -State $state
        Throws: the redirect URI must be an http loopback address.

    .OUTPUTS
        System.String - the authorization code.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 15-OCT-26

        CHANGE LOG
        1.0.0 | 15OCT26 | Initial version. PingFederate provider: loopback redirect listener.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$RedirectUri,

        [Parameter(Mandatory)]
        [string]$State,

        [ValidateRange(30, 1800)]
        [int]$TimeoutSeconds = 300,

        [string]$AuthorizationUrl,

        [scriptblock]$AfterStart
    )

    $uri = $null
    if (-not [uri]::TryCreate($RedirectUri, [UriKind]::Absolute, [ref]$uri) -or
        $uri.Scheme -ne 'http' -or $uri.Host -notin @('127.0.0.1', 'localhost')) {
        throw "The PingFederate redirect URI must be an http loopback address (127.0.0.1 or localhost), for example http://127.0.0.1:47812/callback. Got [$RedirectUri]."
    }

    $listener = [Net.HttpListener]::new()
    $listener.Prefixes.Add("http://$($uri.Host):$($uri.Port)/")

    try {
        $listener.Start()
    } catch {
        throw "PingFederate login could not listen on $($uri.Host):$($uri.Port) (is another listener already running?): $($_.Exception.Message)"
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $page     = '<!doctype html><html><head><meta charset="utf-8"><title>ServiceAPI</title></head><body><p>Sign-in complete. You can close this tab.</p></body></html>'

    try {
        if ($AuthorizationUrl) {
            # Opened here rather than in an -AfterStart closure: a closure made with
            # GetNewClosure() cannot see the module's private functions.
            Write-Host "PingFederate login: sign in in the browser that is opening. Waiting up to $TimeoutSeconds seconds..." -ForegroundColor Cyan
            if (-not (Open-ServiceApiBrowser -Url $AuthorizationUrl)) {
                Write-Host "No browser could be opened on this host. Open this URL in a browser on this same host (the redirect goes to $RedirectUri):" -ForegroundColor Yellow
                Write-Host $AuthorizationUrl
            }
        }
        if ($AfterStart) { & $AfterStart }

        while ($true) {
            $task = $listener.GetContextAsync()
            while (-not $task.AsyncWaitHandle.WaitOne(500)) {
                if ((Get-Date) -ge $deadline) {
                    throw "Timed out after $TimeoutSeconds seconds waiting for the PingFederate login. Complete the sign-in in the browser that opened, and check the redirect URI registered on the client is exactly [$RedirectUri]."
                }
            }

            $ctx    = $task.GetAwaiter().GetResult()
            $req    = $ctx.Request
            $res    = $ctx.Response
            $result = $null

            try {
                if (-not [Net.IPAddress]::IsLoopback($req.RemoteEndPoint.Address)) {
                    $res.StatusCode = 403
                }
                elseif ($req.HttpMethod -eq 'GET' -and $req.Url.AbsolutePath -eq $uri.AbsolutePath) {
                    $query = [Web.HttpUtility]::ParseQueryString($req.Url.Query)

                    if ($query['state'] -ne $State) {
                        $res.StatusCode = 400
                    }
                    elseif ($query['error']) {
                        $desc = [string]$query['error_description']
                        if ($desc.Length -gt 200) { $desc = $desc.Substring(0, 200) }
                        $result = [PSCustomObject]@{ Error = [string]$query['error']; Description = $desc; Code = $null }
                        $res.StatusCode = 400
                    }
                    elseif ($query['code']) {
                        $result = [PSCustomObject]@{ Error = $null; Description = $null; Code = [string]$query['code'] }
                        $bytes = [Text.Encoding]::UTF8.GetBytes($page)
                        $res.StatusCode      = 200
                        $res.ContentType     = 'text/html; charset=utf-8'
                        $res.ContentLength64 = $bytes.Length
                        $res.OutputStream.Write($bytes, 0, $bytes.Length)
                    }
                    else {
                        $res.StatusCode = 400
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

            if ($result) {
                if ($result.Error) {
                    throw "PingFederate refused the login: $($result.Error)$(if ($result.Description) { " ($($result.Description))" })."
                }
                return $result.Code
            }
        }
    } finally {
        $listener.Stop()
        $listener.Close()
    }
}
