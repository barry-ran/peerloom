#!/usr/bin/env bash
# Only disposable test CA/keys; never production credentials. Generated into build output.
set -euo pipefail
root=$1
mkdir -p "$root/res/raw" "$root/assets"
temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp/ca.key" -out "$root/res/raw/peerloom_test_ca.pem" -days 3 -subj '/CN=Peerloom disposable test CA' > /dev/null 2>&1
for kind in valid wrong; do
  san='IP:127.0.0.1'
  [[ "$kind" != wrong ]] || san='DNS:wrong.example.invalid'
  openssl req -newkey rsa:2048 -nodes -keyout "$temp/$kind.key" -out "$temp/$kind.csr" -subj "/CN=Peerloom $kind test" > /dev/null 2>&1
  printf 'subjectAltName=%s\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' "$san" > "$temp/ext"
  openssl x509 -req -in "$temp/$kind.csr" -CA "$root/res/raw/peerloom_test_ca.pem" -CAkey "$temp/ca.key" -CAcreateserial -out "$temp/$kind.pem" -days 2 -extfile "$temp/ext" > /dev/null 2>&1
  openssl pkcs12 -export -out "$root/assets/$kind.p12" -inkey "$temp/$kind.key" -in "$temp/$kind.pem" -certfile "$root/res/raw/peerloom_test_ca.pem" -passout pass:peerloom-test-only > /dev/null 2>&1
done
openssl req -x509 -newkey rsa:2048 -nodes -keyout "$temp/untrusted.key" -out "$temp/untrusted.pem" -days 2 -subj '/CN=Untrusted test only' -addext 'subjectAltName=IP:127.0.0.1' > /dev/null 2>&1
openssl pkcs12 -export -out "$root/assets/untrusted.p12" -inkey "$temp/untrusted.key" -in "$temp/untrusted.pem" -passout pass:peerloom-test-only > /dev/null 2>&1
rm -f "$root/res/raw/peerloom_test_ca.srl"
