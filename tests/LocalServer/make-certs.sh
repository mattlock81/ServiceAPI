#!/usr/bin/env bash
# Creates the test certificates in the directory given as $1 (created if absent).
# ca1       : ordinary test CA (trusted via SSL_CERT_FILE in the tests)
# good      : leaf from ca1, SAN DNS:localhost + IP:127.0.0.1
# wrongname : leaf from ca1, SAN DNS:wrong.example only
# ca2       : CA with nameConstraints permitting DNS:localhost only
# nc        : leaf from ca2, SAN DNS:localhost + IP:127.0.0.1 (the name-constraints case)
# selfsigned: self-signed leaf, not issued by any trusted CA
set -euo pipefail
D="${1:?usage: make-certs.sh <dir>}"; mkdir -p "$D"; cd "$D"
mkca() { # name subj extra
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.pem" -subj "/CN=$2" -days 30 \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" ${3:+-addext "$3"} 2>/dev/null
}
mkleaf() { # name ca san
  openssl req -newkey rsa:2048 -nodes -keyout "$1.key" -out "$1.csr" -subj "/CN=localhost" 2>/dev/null
  printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n' "$3" > "$1.ext"
  openssl x509 -req -in "$1.csr" -CA "$2.pem" -CAkey "$2.key" -CAcreateserial -out "$1.pem" -days 30 -extfile "$1.ext" 2>/dev/null
}
mkca ca1 "Test CA 1"
mkca ca2 "Test CA 2 (name constrained)" "nameConstraints=critical,permitted;DNS:localhost"
mkleaf good ca1 "DNS:localhost,IP:127.0.0.1"
mkleaf wrongname ca1 "DNS:wrong.example"
mkleaf nc ca2 "DNS:localhost,IP:127.0.0.1"
openssl req -x509 -newkey rsa:2048 -nodes -keyout selfsigned.key -out selfsigned.pem -subj "/CN=localhost" -days 30 \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" 2>/dev/null
cat ca1.pem ca2.pem > roots.pem
echo "certificates written to $D"
