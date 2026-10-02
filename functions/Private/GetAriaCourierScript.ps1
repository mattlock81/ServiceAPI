
function Get-AriaCourierScript {
    <#
    .SYNOPSIS
        Renders the Violentmonkey courier userscript for a registered Aria service.

    .DESCRIPTION
        The courier runs inside the Aria portal page and forwards the SPA's own
        /oidc/oauth2/token response to the loopback listener (Wait-AriaCourierToken). The SPA
        keeps its tokens in memory only, so intercepting that response is the only way to
        obtain them.

        The script is held here as a template so the portal origin is rendered from the
        service registry at run time and is never committed to source control. It contains no
        secrets: the key is only a header the listener requires, so that ordinary websites —
        which cannot send a custom header cross-origin without a preflight the listener
        refuses — cannot post to it.

        Not exported. The listener serves the rendered script for a one-time install.

    .PARAMETER BaseUrl
        The Aria Automation host root. Only the scheme and host are used.

    .PARAMETER Port
        The loopback port the courier posts to. Defaults to 47811.

    .PARAMETER Key
        The value of the X-Courier-Key header. Must match the listener.

    .OUTPUTS
        System.String — the userscript source.

    .NOTES
        Author      : Matthew Sillett
        Version     : 1.0.0
        Date        : 01-OCT-26

        CHANGE LOG
        1.0.0 | 01OCT26 | Initial version. Template moved into the module from the standalone
                          userscript so it ships with the AriaOidc provider.
    #>

    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [string]$BaseUrl,

        [ValidateRange(1024, 65535)]
        [int]$Port = 47811,

        [string]$Key = 'aria-oidc-courier'
    )

    $origin = ([uri]$BaseUrl).GetLeftPart([UriPartial]::Authority)

    $template = @'
// ==UserScript==
// @name         Aria OIDC token courier (ServiceAPI)
// @namespace    serviceapi
// @version      1.0.0
// @description  Forwards the Aria portal's own /oidc/oauth2/token response to the ServiceAPI loopback listener on 127.0.0.1. Nothing leaves the machine.
// @match        __ORIGIN__/*
// @run-at       document-start
// @grant        unsafeWindow
// @grant        GM_xmlhttpRequest
// @connect      127.0.0.1
// ==/UserScript==

(function () {
  'use strict';

  const W          = unsafeWindow;
  const LISTENER   = 'http://127.0.0.1:__PORT__/token';
  const KEY        = '__KEY__';
  const TOKEN_PATH = '/oidc/oauth2/token';

  function forward(bodyText) {
    let tok;
    try { tok = JSON.parse(bodyText); } catch (e) { return; }
    if (!tok || !tok.access_token) return;

    GM_xmlhttpRequest({
      method: 'POST',
      url: LISTENER,
      headers: { 'Content-Type': 'application/json', 'X-Courier-Key': KEY },
      data: JSON.stringify({
        origin:        W.location.origin,
        access_token:  tok.access_token,
        refresh_token: tok.refresh_token || null,
        expires_in:    tok.expires_in || null,
        scope:         tok.scope || null
      }),
      timeout: 5000,
      onload:    (r) => console.info('[aria-courier] token response forwarded; listener replied HTTP ' + r.status),
      onerror:   ()  => console.info('[aria-courier] listener not reachable on ' + LISTENER),
      ontimeout: ()  => console.info('[aria-courier] listener timed out')
    });
  }

  // The SPA's token call may use fetch or XMLHttpRequest — hook both.
  const origFetch = W.fetch;
  W.fetch = function (...args) {
    const p = origFetch.apply(this, args);
    try {
      const a   = args[0];
      const url = typeof a === 'string' ? a : (a && (a.url || String(a)));
      if (url && url.indexOf(TOKEN_PATH) !== -1) {
        p.then((r) => (r.ok ? r.clone().text() : null)).then((t) => { if (t) forward(t); }).catch(() => {});
      }
    } catch (e) { /* never interfere with the page */ }
    return p;
  };

  const XHR      = W.XMLHttpRequest;
  const origOpen = XHR.prototype.open;
  const origSend = XHR.prototype.send;

  XHR.prototype.open = function (method, url) {
    this.__ariaTok = String(url).indexOf(TOKEN_PATH) !== -1;
    return origOpen.apply(this, arguments);
  };

  XHR.prototype.send = function () {
    if (this.__ariaTok) {
      this.addEventListener('load', () => {
        try {
          if (this.status !== 200) return;
          const body = this.responseType === 'json'
            ? JSON.stringify(this.response)
            : (this.responseType === '' || this.responseType === 'text') ? this.responseText : null;
          if (body) forward(body);
        } catch (e) { /* ignore */ }
      });
    }
    return origSend.apply(this, arguments);
  };
})();
'@

    $template.Replace('__ORIGIN__', $origin).Replace('__PORT__', [string]$Port).Replace('__KEY__', $Key)
}
