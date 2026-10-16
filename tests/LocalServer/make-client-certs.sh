#!/usr/bin/env bash
# Generates throwaway certificates for the client-certificate and curl transport tests.
#
#   make-client-certs.sh <outdir>
#
# Produces, in <outdir> (all test values, never use them anywhere real):
#   ca.crt / ca.key                    the test CA that signs everything below
#   server.crt / server.key            TLS server certificate for localhost and 127.0.0.1
#   client-rsa.crt / client-rsa.key    RSA client certificate (CN=svc-client-rsa), PKCS#8 key, no passphrase
#   client-rsa.enc.key                 the same key, encrypted (passphrase below)
#   client-rsa.pfx                     PKCS#12 with the key, passphrase below
#   client-rsa-nopass.pfx              PKCS#12 with an empty passphrase
#   client-ec.crt / client-ec.key      ECDSA P-256 client certificate (CN=svc-client-ec), PKCS#8 key
#   untrusted.crt / untrusted.key      self-signed client certificate the CA did not issue
#   roots.pem                          the CA certificate, for SSL_CERT_FILE and -CaBundle
set -euo pipefail

out="${1:?usage: make-client-certs.sh <outdir>}"
mkdir -p "$out"
cd "$out"

PASS='client-pass-1'
DAYS=3650
q() { openssl "$@" >/dev/null 2>&1; }

# --- CA --------------------------------------------------------------------
q req -x509 -newkey rsa:2048 -nodes -keyout ca.key -out ca.crt -days "$DAYS" -subj "/CN=ServiceAPI Test CA"
cp ca.crt roots.pem

# --- Server ----------------------------------------------------------------
q req -newkey rsa:2048 -nodes -keyout server.key -out server.csr -subj "/CN=localhost"
printf 'subjectAltName=DNS:localhost,IP:127.0.0.1\nextendedKeyUsage=serverAuth\n' > server.ext
q x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days "$DAYS" -extfile server.ext

# --- RSA client ------------------------------------------------------------
printf 'keyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n' > client.ext
q req -newkey rsa:2048 -nodes -keyout client-rsa.key -out client-rsa.csr -subj "/CN=svc-client-rsa"
q x509 -req -in client-rsa.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-rsa.crt -days "$DAYS" -extfile client.ext
# openssl 3 writes a PKCS#8 key already; normalise anyway so every tool sees the same format
q pkcs8 -topk8 -nocrypt -in client-rsa.key -out client-rsa.p8 && mv client-rsa.p8 client-rsa.key
q pkcs8 -topk8 -in client-rsa.key -out client-rsa.enc.key -passout "pass:$PASS" -v2 aes-256-cbc
q pkcs12 -export -inkey client-rsa.key -in client-rsa.crt -certfile ca.crt -out client-rsa.pfx -passout "pass:$PASS" -name svc-client-rsa
q pkcs12 -export -inkey client-rsa.key -in client-rsa.crt -certfile ca.crt -out client-rsa-nopass.pfx -passout "pass:" -name svc-client-rsa

# --- EC client -------------------------------------------------------------
q ecparam -name prime256v1 -genkey -noout -out client-ec.sec1
q pkcs8 -topk8 -nocrypt -in client-ec.sec1 -out client-ec.key && rm client-ec.sec1
q req -new -key client-ec.key -out client-ec.csr -subj "/CN=svc-client-ec"
q x509 -req -in client-ec.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out client-ec.crt -days "$DAYS" -extfile client.ext

# --- Untrusted client (self-signed, not issued by the CA) -------------------
q req -x509 -newkey rsa:2048 -nodes -keyout untrusted.key -out untrusted.crt -days "$DAYS" -subj "/CN=svc-untrusted"

rm -f ./*.csr ./*.ext ./*.srl
chmod 600 ./*.key ./*.pfx
echo "certificates written to $out (test passphrase: $PASS)"
