#!/usr/bin/env python3
"""Mutual-TLS test server for the client-certificate and curl transport tests.

    mtls_server.py <certdir>          certdir comes from make-client-certs.sh

HTTPS ports on 127.0.0.1 (all use server.crt for localhost and 127.0.0.1):
  18447  client certificate REQUIRED (must be issued by ca.crt)
  18448  client certificate OPTIONAL (reports whether one was presented)
  18449  client certificate REQUIRED, TLS 1.3 only

Every route answers JSON and echoes what the server saw:
  {"client_cn": "...", "client_presented": true, "tls": "TLSv1.3", "method": "POST",
   "path": "/whoami", "body": "...", "headers": {...}}
The path /status/<code> answers that status, for error-surface tests.
The path /sleep/<seconds> waits that long before answering, so a test can inspect the running client.
"""
import json, ssl, sys, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

CERTDIR = sys.argv[1] if len(sys.argv) > 1 else '.'


def make_context(mode, tls13_only):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(f'{CERTDIR}/server.crt', f'{CERTDIR}/server.key')
    ctx.load_verify_locations(f'{CERTDIR}/ca.crt')
    ctx.verify_mode = mode
    if tls13_only:
        ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    return ctx


class H(BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'

    def log_message(self, *a):
        pass

    def _client_cn(self):
        try:
            cert = self.connection.getpeercert()
        except Exception:
            return None
        if not cert:
            return None
        for rdn in cert.get('subject', ()):
            for key, value in rdn:
                if key == 'commonName':
                    return value
        return None

    def _handle(self):
        length = int(self.headers.get('Content-Length') or 0)
        body = self.rfile.read(length).decode('utf-8', 'replace') if length else ''
        cn = self._client_cn()
        code = 200
        if self.path.startswith('/status/'):
            try:
                code = int(self.path.split('/')[2])
            except ValueError:
                code = 400
        if self.path.startswith('/sleep/'):
            try:
                time.sleep(min(float(self.path.split('/')[2].split('?')[0]), 30))
            except ValueError:
                pass
        data = json.dumps({
            'client_cn': cn,
            'client_presented': cn is not None,
            'tls': self.connection.version(),
            'method': self.command,
            'path': self.path.split('?')[0],
            'query': self.path.split('?', 1)[1] if '?' in self.path else '',
            'body': body,
            'headers': {k: v for k, v in self.headers.items()},
        }).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        if self.command != 'HEAD':
            self.wfile.write(data)

    do_GET = do_POST = do_PUT = do_DELETE = do_PATCH = do_HEAD = _handle


class Server(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, port, ctx):
        super().__init__(('127.0.0.1', port), H)
        # Handshake in the handler thread, not in the accept loop, so a bad client cannot stall it
        self.socket = ctx.wrap_socket(self.socket, server_side=True, do_handshake_on_connect=False)

    def handle_error(self, request, client_address):
        pass   # failed handshakes (rejected client certificates) are expected in the tests


def serve(port, mode, tls13_only=False):
    srv = Server(port, make_context(mode, tls13_only))
    threading.Thread(target=srv.serve_forever, daemon=True).start()


if __name__ == '__main__':
    serve(18447, ssl.CERT_REQUIRED)
    serve(18448, ssl.CERT_OPTIONAL)
    serve(18449, ssl.CERT_REQUIRED, tls13_only=True)
    print('mtls ready', flush=True)
    threading.Event().wait()
