#!/bin/sh
#
# Copyright SecureKey Technologies Inc. All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#

set -e


echo "Generating edv Test PKI"

cd /opt/workspace/edv
mkdir -p test/bdd/fixtures/keys/tls
tmp=$(mktemp)
echo "subjectKeyIdentifier=hash
authorityKeyIdentifier = keyid,issuer
extendedKeyUsage = serverAuth
keyUsage = Digital Signature, Key Encipherment
subjectAltName = @alt_names
[alt_names]
DNS.1 = localhost
DNS.2 = edv.example.com
DNS.3 = third.party.oidc.provider.example.com
DNS.4 = auth.rest.hydra.example.com
DNS.5 = auth.trustbloc.local
DNS.6 = oidc.provider.example.com
DNS.7 = testnet.orb.local" >> "$tmp"

CERT_CA="test/bdd/fixtures/keys/tls/ec-cacert.pem"
if [ ! -f "$CERT_CA" ]; then
#create CA
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-cakey.pem
openssl req -new -x509 -key test/bdd/fixtures/keys/tls/ec-cakey.pem -subj "/C=CA/ST=ON/O=Example Internet CA Inc.:CA Sec/OU=CA Sec" -out test/bdd/fixtures/keys/tls/ec-cacert.pem
else
    echo "Skipping CA generation - already exists"
fi

#create TLS creds
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/tls/ec-key.pem
openssl req -new -key test/bdd/fixtures/keys/tls/ec-key.pem -subj "/C=CA/ST=ON/O=Example Inc.:edv/OU=edv/CN=localhost" -out test/bdd/fixtures/keys/tls/ec-key.csr
openssl x509 -req -in test/bdd/fixtures/keys/tls/ec-key.csr -CA test/bdd/fixtures/keys/tls/ec-cacert.pem -CAkey test/bdd/fixtures/keys/tls/ec-cakey.pem -CAcreateserial -extfile "$tmp" -out test/bdd/fixtures/keys/tls/ec-pubCert.pem -days 365


mkdir -p test/bdd/fixtures/keys/session_cookies
openssl rand -out test/bdd/fixtures/keys/session_cookies/auth.key 32
openssl rand -out test/bdd/fixtures/keys/session_cookies/enc.key 32

#create private key for GNAP signer
openssl ecparam -name prime256v1 -genkey -noout -out test/bdd/fixtures/keys/gnap-priv-key.pem

echo "done generating edv PKI"
