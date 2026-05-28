#!/usr/bin/env bash
# Generate a self-signed dev TLS cert for the local DoH endpoint.
#
# Output:
#   tls/ca.pem        - local CA cert (install once into OS / browser trust store)
#   tls/ca.key        - local CA private key (DO NOT distribute)
#   tls/cert.pem      - resolver leaf cert (SAN: localhost, 127.0.0.1, dns.local.test)
#   tls/key.pem       - resolver leaf private key
#
# Install the CA so your browser / OS trusts the DoH endpoint:
#   macOS:    sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain tls/ca.pem
#   Linux:    sudo cp tls/ca.pem /usr/local/share/ca-certificates/xgg-dev-ca.crt && sudo update-ca-certificates
#   Firefox:  Settings → Privacy & Security → View Certificates → Authorities → Import → tls/ca.pem
#             (Firefox uses its own trust store and is the recommended browser for internal testing)
#
# The leaf cert is good for 825 days (Apple's max). Re-run this script to renew.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
TLS_DIR="$ROOT/tls"
mkdir -p "$TLS_DIR"
cd "$TLS_DIR"

# Helpful: append dns.local.test → 127.0.0.1 to /etc/hosts manually if you want a friendlier name.

if [ ! -f ca.key ]; then
  echo "→ generating local CA"
  openssl genrsa -out ca.key 4096
  openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
    -subj "/CN=XGenGuardian Dev CA/O=XGenGuardian/OU=Dev" \
    -out ca.pem
else
  echo "→ reusing existing CA (delete tls/ca.* to regenerate)"
fi

echo "→ generating leaf key"
openssl genrsa -out key.pem 2048

echo "→ generating leaf CSR"
openssl req -new -key key.pem \
  -subj "/CN=dns.local.test/O=XGenGuardian/OU=Dev" \
  -out leaf.csr

# Extra hosts (DNS names) and IPs added to SAN via env vars. Examples:
#   PUBLIC_IP=135.181.79.27
#   EXTRA_DNS="dns.xgenguardian.com,dns2.xgenguardian.com"
EXTRA_DNS="${EXTRA_DNS:-}"
PUBLIC_IP="${PUBLIC_IP:-}"

{
  echo "authorityKeyIdentifier = keyid,issuer"
  echo "basicConstraints       = CA:FALSE"
  echo "keyUsage               = digitalSignature, keyEncipherment"
  echo "extendedKeyUsage       = serverAuth"
  echo "subjectAltName         = @alt_names"
  echo
  echo "[alt_names]"
  echo "DNS.1 = dns.local.test"
  echo "DNS.2 = localhost"
  i=3
  IFS=',' read -ra EXTRAS <<< "$EXTRA_DNS"
  for d in "${EXTRAS[@]}"; do
    [ -z "$d" ] && continue
    echo "DNS.$i = $d"
    i=$((i+1))
  done
  echo "IP.1  = 127.0.0.1"
  echo "IP.2  = ::1"
  if [ -n "$PUBLIC_IP" ]; then
    echo "IP.3  = $PUBLIC_IP"
  fi
} > leaf.ext

echo "→ signing leaf cert"
openssl x509 -req -in leaf.csr -CA ca.pem -CAkey ca.key -CAcreateserial \
  -out cert.pem -days 825 -sha256 -extfile leaf.ext

rm -f leaf.csr leaf.ext ca.srl

echo
echo "✓ certs ready in $TLS_DIR"
echo
echo "Next steps:"
echo "  1. Trust the CA in your OS / browser (see this script header)."
echo "  2. Optionally add to /etc/hosts:"
echo "       127.0.0.1   dns.local.test"
echo "  3. The resolver will read tls/cert.pem and tls/key.pem on startup."
