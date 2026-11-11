#!/usr/bin/env bash
# Regenerates the self-signed TLS material of the local status-list-server
# (assets/crypto/status-list/). Test-only: never use these keys anywhere else.
#
# What it writes:
#   ca.crt        - the CA that signs the leaf; mounted into Keycloak as PEM
#                   (token-status plugin) and bundled into truststore.jks
#                   (OpenID4VP plugin's x5c-chain validation)
#   ca.key        - the CA private key (kept to re-issue the leaf)
#   tls.crt       - the leaf, valid for DNS:status-list
#   tls.key       - the leaf's PKCS#8 private key (nginx + JWT signing)
#   chain.crt     - leaf + CA, the chain the server signs tokens with
#   truststore.jks - JKS truststore holding ca.crt (password: changeit)
#
# The leaf's DNS SAN must match the compose service name the plugins use
# (`status-list`); everything runs inside the compose network at
# https://status-list:8443 (see docker-compose.yml).
set -euo pipefail
IFS=$'\n\t'

OUT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DAYS=3650

cd "$OUT"

openssl ecparam -name prime256v1 -genkey -noout -out ca.key
openssl req -x509 -new -key ca.key -sha256 -days "$DAYS" \
  -subj "/CN=status-list e2e CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -addext "subjectKeyIdentifier=hash" \
  -out ca.crt

openssl ecparam -name prime256v1 -genkey -noout -out tls.key
openssl pkcs8 -topk8 -nocrypt -in tls.key -out tls.key.pk8
mv tls.key.pk8 tls.key

openssl req -new -key tls.key -subj "/CN=status-list" -out tls.csr
openssl x509 -req -in tls.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -days "$DAYS" -sha256 \
  -extfile <(printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature,keyEncipherment" \
    "extendedKeyUsage=serverAuth,clientAuth" \
    "subjectAltName=DNS:status-list") \
  -out tls.crt
rm -f tls.csr ca.srl

cat tls.crt ca.crt > chain.crt

rm -f truststore.jks
keytool -importcert -noprompt -alias statuslist-ca \
  -file ca.crt -keystore truststore.jks -storetype JKS -storepass changeit >/dev/null

chmod 0644 ca.crt tls.crt chain.crt truststore.jks
chmod 0600 ca.key tls.key

echo "Regenerated status-list TLS material in $OUT"
