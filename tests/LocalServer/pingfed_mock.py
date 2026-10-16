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

Certificate client authentication (only when a certificate directory from make-client-certs.sh is
given: python3 pingfed_mock.py <certdir>):
  private_key_jwt   a client_assertion signed by client-rsa.crt (RS256) or client-ec.crt (ES256) is
                    accepted on every port; the audience must be the token endpoint or the issuer
  18094  tls        HTTPS, client certificate OPTIONAL at the TLS layer (the authorization endpoint
                    needs none); the token endpoint accepts only a client certificate issued by the
                    test CA with CN svc-client-rsa (tls_client_auth). Secret methods are refused.

Routes:
  GET  /.well-known/openid-configuration
  GET  /as/authorization.oauth2   validates the request, then redirects to redirect_uri with a code
  POST /as/token.oauth2           authorization_code and refresh_token grants
  GET  /_log                      the token-endpoint requests seen (grant type and auth method only)
  GET  /_reset                    clears the log and revokes every refresh token
"""
import base64, json, ssl, sys, threading, time, secrets
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs, urlencode

CLIENT_ID, CLIENT_SECRET = 'test-client', 'secret:with:colons'
CERTDIR = sys.argv[1] if len(sys.argv) > 1 else None
SEEN_JTI = set()
PUBKEYS = {}
if CERTDIR:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, ec
    from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
    for alg, name in (('RS256', 'client-rsa.crt'), ('ES256', 'client-ec.crt')):
        with open(f'{CERTDIR}/{name}', 'rb') as f:
            PUBKEYS[alg] = x509.load_pem_x509_certificate(f.read()).public_key()


def b64d(text):
    return base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))


def verify_assertion(token, issuer):
    """True when token is a valid, unused client assertion for CLIENT_ID."""
    if not PUBKEYS:
        return False
    try:
        head_b64, body_b64, sig_b64 = token.split('.')
        head, body = json.loads(b64d(head_b64)), json.loads(b64d(body_b64))
        signing_input = f'{head_b64}.{body_b64}'.encode()
        sig = b64d(sig_b64)
        if body.get('iss') != CLIENT_ID or body.get('sub') != CLIENT_ID:
            return False
        aud = body.get('aud')
        aud = aud if isinstance(aud, list) else [aud]
        if not ({issuer, issuer + '/as/token.oauth2'} & set(aud)):
            return False
        if int(body.get('exp', 0)) < time.time() or not body.get('jti'):
            return False
        with LOCK:
            if body['jti'] in SEEN_JTI:
                return False
            SEEN_JTI.add(body['jti'])
        key = PUBKEYS.get(head.get('alg'))
        if key is None:
            return False
        if head['alg'] == 'RS256':
            key.verify(sig, signing_input, padding.PKCS1v15(), hashes.SHA256())
        else:
            if len(sig) != 64:
                return False
            r, sv = int.from_bytes(sig[:32], 'big'), int.from_bytes(sig[32:], 'big')
            key.verify(encode_dss_signature(r, sv), signing_input, ec.ECDSA(hashes.SHA256()))
        return True
    except Exception:
        return False
ALLOWED = {'openid', 'profile', 'ad', 'app'}
LOCK = threading.Lock()
CODES, REFRESH, LOG = {}, {}, []

def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()

def make_jwt(claims):
    head = b64(json.dumps({'alg': 'none', 'typ': 'JWT'}).encode())
    return head + '.' + b64(json.dumps(claims).encode()) + '.x'

def make_handler(port, personality, scheme='http', host='127.0.0.1'):
    issuer = f'{scheme}://{host}:{port}'

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
            if form.get('client_assertion'):
                if form.get('client_assertion_type') == 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer' \
                        and form.get('client_id') in (None, CLIENT_ID) and verify_assertion(form['client_assertion'], issuer):
                    method = 'jwt'
            elif personality == 'tls':
                peer = None
                try:
                    peer = self.connection.getpeercert()
                except Exception:
                    pass
                cn = None
                for rdn in (peer or {}).get('subject', ()):
                    for key, value in rdn:
                        if key == 'commonName':
                            cn = value
                if form.get('client_id') == CLIENT_ID and cn == 'svc-client-rsa':
                    method = 'tls'
            elif auth.startswith('Basic '):
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

            if method is None or (method == 'basic' and personality == 'post') or (personality == 'tls' and method != 'tls'):
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

def serve_tls(port):
    class Tls(ThreadingHTTPServer):
        daemon_threads = True

        def handle_error(self, request, client_address):
            pass
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f'{CERTDIR}/server.crt', f'{CERTDIR}/server.key')
    ctx.load_verify_locations(f'{CERTDIR}/ca.crt')
    ctx.verify_mode = ssl.CERT_OPTIONAL
    srv = Tls(('127.0.0.1', port), make_handler(port, 'tls', 'https', 'localhost'))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True, do_handshake_on_connect=False)
    threading.Thread(target=srv.serve_forever, daemon=True).start()


def serve(port, personality):
    srv = ThreadingHTTPServer(('127.0.0.1', port), make_handler(port, personality))
    threading.Thread(target=srv.serve_forever, daemon=True).start()

if __name__ == '__main__':
    for port, personality in ((18090, 'both'), (18091, 'post'), (18092, 'norefresh'), (18093, 'badnonce')):
        serve(port, personality)
    if CERTDIR:
        serve_tls(18094)
    print('pingfed mock ready', flush=True)
    threading.Event().wait()
