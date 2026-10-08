#!/usr/bin/env python3
"""Local test server for ServiceAPI end-to-end tests.

HTTP  18080 / 18081 / 18082        plain (18081 and 18082 emulate other Aria deployments, see below)
HTTPS 18443 good / 18444 nc / 18445 selfsigned / 18446 wrongname   (certificates from make-certs.sh)

Routes (all ports):
  /echo            any method; returns method, path, query, headers and body as JSON
  /basic           Basic svcuser:p@ss:word-1 required (401 none, 403 wrong)
  /token           Bearer tok-123, or Basic key1:secret1, required (401 none, 403 wrong)
  /login           ?account=svcuser&passwd=p@ss:word-1 returns {"sid": "abc"}; 403 otherwise
  /text            text/plain; 406 unless Accept allows it (like Artifactory admin endpoints)
  /forbidden       403 JSON    /missing 404 JSON    /boom 500 JSON
  /_log            last 50 requests;  /_reset clears the log

Aria API token emulation (for the AriaApiToken provider). The deployment "personality" differs by port:
  18080 csp    csp-authorize and iaas-login work; only iaas tokens are accepted by the probe endpoint
  18081 oauth  oauth-tenant and iaas-login work; oauth and iaas tokens are accepted
  18082 iaas   only iaas-login works; iaas tokens are accepted
The API token 'api-token-valid' is accepted; anything else is refused with HTTP 400.
  POST /csp/gateway/am/api/auth/api-tokens/authorize   form refresh_token=...
  POST /oauth/tenant/<tenant>/token                    form grant_type=refresh_token&refresh_token=...
  POST /iaas/api/login                                 json {"refreshToken": "..."}
  GET  /iaas/api/projects                              probe endpoint; needs an accepted Bearer token
"""
import base64, json, ssl, sys, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

VALID_API_TOKEN = 'api-token-valid'
COUNTER = [0]
ACCEPTED = {'csp': ('iaas-',), 'oauth': ('oauth-', 'iaas-'), 'iaas': ('iaas-',)}

LOG = []
LOCK = threading.Lock()
USER, PASSWORD = 'svcuser', 'p@ss:word-1'

class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def log_message(self, *a): pass

    def _send(self, code, body, ctype='application/json'):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _handle(self):
        u = urlsplit(self.path)
        n = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(n).decode('utf-8', 'replace') if n else ''
        hdrs = {k: v for k, v in self.headers.items()}
        entry = {'method': self.command, 'path': u.path, 'query': u.query, 'headers': hdrs, 'body': body}
        if not u.path.startswith('/_'):
            with LOCK:
                LOG.append(entry); del LOG[:-50]
        auth = self.headers.get('Authorization', '')
        p = u.path
        if p == '/_log':   return self._send(200, LOG)
        if p == '/_reset': LOG.clear(); return self._send(200, {'ok': True})
        if p == '/echo':   return self._send(200, entry)
        if p == '/basic':
            if not auth: return self._send(401, {'error': 'no credentials'})
            want = 'Basic ' + base64.b64encode(f'{USER}:{PASSWORD}'.encode()).decode()
            return self._send(200, {'ok': True, 'user': USER}) if auth == want else self._send(403, {'error': 'bad credentials'})
        if p == '/token':
            if not auth: return self._send(401, {'error': 'no credentials'})
            good = ('Bearer tok-123', 'Basic ' + base64.b64encode(b'key1:secret1').decode())
            return self._send(200, {'ok': True, 'scheme': auth.split(' ')[0]}) if auth in good else self._send(403, {'error': 'bad token'})
        if p == '/login':
            q = parse_qs(u.query)
            if q.get('account') == [USER] and q.get('passwd') == [PASSWORD]:
                return self._send(200, {'sid': 'abc', 'had_authorization_header': bool(auth)})
            return self._send(403, {'error': 'bad login'})
        if p == '/text':
            acc = self.headers.get('Accept', '')
            if 'text/plain' in acc or '*/*' in acc: return self._send(200, 'plain text body', 'text/plain')
            return self._send(406, {'error': 'not acceptable'})
        # ---- Aria API token emulation ----
        mode = getattr(self.server, 'personality', 'csp')
        def issue(prefix):
            with LOCK:
                COUNTER[0] += 1
                return f'{prefix}{COUNTER[0]}'
        if self.command == 'POST' and p == '/csp/gateway/am/api/auth/api-tokens/authorize':
            if mode != 'csp': return self._send(404, {'error': 'not found'})
            tok = (parse_qs(body).get('refresh_token') or [''])[0]
            if tok != VALID_API_TOKEN: return self._send(400, {'message': 'Invalid refresh token'})
            return self._send(200, {'access_token': issue('csp-'), 'token_type': 'bearer', 'expires_in': 1799})
        if self.command == 'POST' and p.startswith('/oauth/tenant/') and p.endswith('/token'):
            if mode != 'oauth': return self._send(404, {'error': 'not found'})
            form = parse_qs(body)
            if form.get('grant_type') != ['refresh_token'] or form.get('refresh_token') != [VALID_API_TOKEN]:
                return self._send(400, {'error': 'invalid_grant'})
            return self._send(200, {'access_token': issue('oauth-'), 'token_type': 'Bearer', 'expires_in': 1799})
        if self.command == 'POST' and p == '/iaas/api/login':
            try: tok = json.loads(body).get('refreshToken')
            except Exception: tok = None
            if tok != VALID_API_TOKEN: return self._send(400, {'message': 'Invalid refresh token'})
            return self._send(200, {'tokenType': 'Bearer', 'token': issue('iaas-')})
        if p == '/iaas/api/projects':
            bearer = auth.split(' ', 1)[1] if auth.startswith('Bearer ') else ''
            if not bearer: return self._send(401, {'error': 'no credentials'})
            if bearer.startswith(ACCEPTED.get(mode, ())): return self._send(200, {'content': [], 'totalElements': 0})
            return self._send(403, {'error': 'token not accepted'})
        if p == '/forbidden': return self._send(403, {'error': 'forbidden'})
        if p == '/boom':      return self._send(500, {'error': 'boom'})
        return self._send(404, {'error': 'not found', 'path': p})

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = _handle

def serve(port, cert=None, personality='csp'):
    srv = ThreadingHTTPServer(('127.0.0.1', port), H)
    srv.personality = personality
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(f'{cert[0]}.pem', f'{cert[0]}.key')
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

if __name__ == '__main__':
    certs = sys.argv[1]
    serve(18080)
    serve(18081, personality='oauth')
    serve(18082, personality='iaas')
    for port, name in ((18443, 'good'), (18444, 'nc'), (18445, 'selfsigned'), (18446, 'wrongname')):
        serve(port, (f'{certs}/{name}',))
    print('ready', flush=True)
    threading.Event().wait()
