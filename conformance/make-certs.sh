#!/usr/bin/env bash
#
# Generates a throwaway CA and a server certificate for the sample identity server, so that the
# conformance suite's Java server — which has no reason to trust the ASP.NET development
# certificate — can call it over HTTPS.
#
# Everything lands in certs/, which is gitignored. Delete that folder to start over. This material
# is for local conformance runs only and must never be used for anything else.
set -euo pipefail

HOSTNAME_="${CONFORMANCE_OP_HOST:-zeekayda.localtest.me}"
CERT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/certs"
DAYS=825

if [[ -f "${CERT_DIR}/server.pem" && -f "${CERT_DIR}/ca.pem" ]]; then
    echo "make-certs: certs/ already populated for ${HOSTNAME_}; delete the folder to regenerate."
    exit 0
fi

mkdir -p "${CERT_DIR}"
cd "${CERT_DIR}"

echo "make-certs: generating a local CA"
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days "${DAYS}" \
    -keyout ca.key -out ca.pem \
    -subj "/CN=ZeeKayDa.Auth conformance local CA" \
    -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null

echo "make-certs: generating a server certificate for ${HOSTNAME_}"
openssl req -newkey rsa:2048 -nodes -sha256 \
    -keyout server.key -out server.csr \
    -subj "/CN=${HOSTNAME_}" 2>/dev/null

cat > server.ext <<EXT
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:${HOSTNAME_}
EXT

openssl x509 -req -in server.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
    -out server.pem -days "${DAYS}" -sha256 -extfile server.ext 2>/dev/null

rm -f server.csr server.ext ca.srl

# The signing key is read by Kestrel running as the current user; nothing else should see it.
chmod 600 server.key ca.key

echo "make-certs: wrote ${CERT_DIR}/{ca.pem,server.pem,server.key}"
