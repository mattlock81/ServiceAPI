#!/usr/bin/env python3
"""Mock PingFederate for the PingFederate SSO provider tests. Not a real identity provider:
tokens are unsigned and every value here is a throwaway test value.

Ports (the "personality" differs by port):
  18090  both     client_secret_basic and client_secret_post accepted, refresh tokens issued
  18091  post     client_secret_basic is refused with invalid_client; client_secret_post accepted
  18092  norefresh  as 18090 but no refresh_token is issued
  18093  badnonce   as 18090 but the id_token carries the wrong nonce

Client: id 'test-client', secret 'secret:with:colons'. The client may request openid, profile, ad
and app; a requested scope outside that set is left out of the granted 'scope'.

Routes:
  GET  /.well-known/openid-configuration
  GET  /as/authorization.oauth2   validates the request, then redirects to redirect_uri with a code
  POST /as/token.oauth2           authorization_code and refresh_token grants
  GET  /_log                      the token-endpoint requests seen (grant type and auth method only)
  GET  /_reset                    clears the log and revokes every refresh token
"""
import base64, json, sys, threading, time, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode

CLIENT_ID, CLIENT_SECRET = 'test-client', 'secret:with:colons'
ALLOWED = {'openid', 'profile', 'ad', 'app'}
LOCK = threading.Lock()
CODES, REFRESH, LOG = {}, {}, []

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def make_jwt(claims):
    head = b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())
    return head + '.' + b64(json.dumps(claims).encode()) + '.x'

def make_handler(port, personality):
    issuer = f'http://127.0.0.1:{port}'

    class H(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'
        def log_message(self, *a): pass

        def _send(self, code, body, headers=None):
            data = json.dumps(body).encode()
            self.send_response(code)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _oauth_error(self, code, error, desc=''):
            self._send(code, {'error': error, 'error_description': desc})

        def do_GET(self):
            u = urlsplit(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items()}

            if u.path == '/.well-known/openid-configuration':
                return self._send(200, {
                    'issuer': issuer,
                    'authorization_endpoint': issuer + '/as/authorization.oauth2',
                    'token_endpoint': issuer + '/as/token.oauth2',
                    'userinfo_endpoint': issuer + '/idp/userinfo.openid',
                    'token_endpoint_auth_methods_supported': ['client_secret_basic', 'client_secret_post'],
                })

            if u.path == '/as/authorization.oauth2':
                if q.get('client_id') != CLIENT_ID or q.get('response_type') != 'code' or not q.get('redirect_uri') or not q.get('state') or not q.get('nonce'):
                    return self._oauth_error(400, 'invalid_request', 'bad authorization request')
                code = secrets.token_urlsafe(12)
                with LOCK:
                    CODES[code] = {'nonce': q['nonce'], 'redirect_uri': q['redirect_uri'], 'scope': q.get('scope', '')}
                target = q['redirect_uri'] + '?' + urlencode({'code': code, 'state': q['state']})
                self.send_response(302)
                self.send_header('Location', target)
                self.send_header('Content-Length', '0')
                self.end_headers()
                return

            if u.path == '/_log':
                with LOCK:
                    return self._send(200, list(LOG))
            if u.path == '/_reset':
                with LOCK:
                    LOG.clear(); REFRESH.clear(); CODES.clear()
                return self._send(200, {'ok': True})
            return self._send(404, {'error': 'not_found'})

        def do_POST(self):
            u = urlsplit(self.path)
            if u.path != '/as/token.oauth2':
                return self._send(404, {'error': 'not_found'})

            length = int(self.headers.get('Content-Length') or 0)
            form = {k: v[0] for k, v in parse_qs(self.rfile.read(length).decode()).items()}

            # Client authentication
            auth, method = self.headers.get('Authorization', ''), None
            if auth.startswith('Basic '):
                try:
                    cid, _, sec = base64.b64decode(auth[6:]).decode().partition(':')
                    from urllib.parse import unquote
                    cid, sec = unquote(cid), unquote(sec)
                    if cid == CLIENT_ID and sec == CLIENT_SECRET:
                        method = 'basic'
                except Exception:
                    pass
            elif form.get('client_id') == CLIENT_ID and form.get('client_secret') == CLIENT_SECRET:
                method = 'post'

            with LOCK:
                LOG.append({'grant': form.get('grant_type'), 'auth': method or 'none'})

            if method is None or (method == 'basic' and personality == 'post'):
                return self._oauth_error(401, 'invalid_client', 'client authentication failed')

            grant = form.get('grant_type')
            with LOCK:
                if grant == 'authorization_code':
                    rec = CODES.pop(form.get('code'), None)
                    if not rec or rec['redirect_uri'] != form.get('redirect_uri'):
                        return self._oauth_error(400, 'invalid_grant', 'code not valid')
                    scope, nonce = rec['scope'], rec['nonce']
                elif grant == 'refresh_token':
                    rec = REFRESH.get(form.get('refresh_token'))
                    if not rec:
                        return self._oauth_error(400, 'invalid_grant', 'refresh token not valid')
                    scope, nonce = rec['scope'], None
                else:
                    return self._oauth_error(400, 'unsupported_grant_type')

                granted = ' '.join(s for s in scope.split() if s in ALLOWED)
                resp = {'access_token': 'at-' + secrets.token_urlsafe(8), 'token_type': 'Bearer', 'expires_in': 3600, 'scope': granted}
                if personality != 'norefresh':
                    rt = 'rt-' + secrets.token_urlsafe(8)
                    REFRESH[rt] = {'scope': scope}
                    resp['refresh_token'] = rt

            if 'openid' in granted.split():
                claims = {'iss': issuer, 'aud': CLIENT_ID, 'sub': 'svc-test', 'exp': int(time.time()) + 3600, 'iat': int(time.time())}
                if nonce:
                    claims['nonce'] = 'wrong-nonce' if personality == 'badnonce' else nonce
                if 'ad' in granted.split():
                    claims['groups'] = ['CN=Group One,OU=Test', 'CN=Group Two,OU=Test']
                if 'profile' in granted.split():
                    claims.update({'displayName': 'Test Account', 'email': 'svc-test@example.invalid', 'preferred_username': 'svc-test'})
                resp['id_token'] = make_jwt(claims)

            self._send(200, resp)

    return H

def serve(port, personality):
    srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(port, personality))
    threading.Thread(target=srv.serve_forever, daemon=True).start()

if __name__ == '__main__':
    for port, personality in ((18090, 'both'), (18091, 'post'), (18092, 'norefresh'), (18093, 'badnonce')):
        serve(port, personality)
    print('pingfed mock ready', flush=True)
    threading.Event().wait()
