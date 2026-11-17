#!/usr/bin/env bash
# Import existing PEM keys without changing the signing identity.
set -euo pipefail
umask 077

key_dir=${1:?Signing directory required}
test -n "${COSIGN_PRIVATE_KEY:-}" || { echo 'Signing key is missing.' >&2; exit 1; }
mkdir -m 700 "${key_dir}"
trap 'rm -f "${key_dir}/input.pem"' EXIT
printf '%s\n' "${COSIGN_PRIVATE_KEY}" > "${key_dir}/input.pem"
unset COSIGN_PRIVATE_KEY
export COSIGN_PASSWORD=${COSIGN_PASSWORD:-}

case "$(head -n 1 "${key_dir}/input.pem")" in
  '-----BEGIN PRIVATE KEY-----'|'-----BEGIN EC PRIVATE KEY-----'|'-----BEGIN RSA PRIVATE KEY-----')
    cosign import-key-pair --key "${key_dir}/input.pem" --output-key-prefix "${key_dir}/cosign"
    ;;
  '-----BEGIN ENCRYPTED COSIGN PRIVATE KEY-----'|'-----BEGIN ENCRYPTED SIGSTORE PRIVATE KEY-----')
    cp "${key_dir}/input.pem" "${key_dir}/cosign.key"
    ;;
  *) echo 'Unsupported signing key format.' >&2; exit 1 ;;
esac

cosign public-key --key "${key_dir}/cosign.key" > "${key_dir}/cosign.pub"
printf 'Signing public key SHA-256 (DER): '
openssl pkey -pubin -in "${key_dir}/cosign.pub" -outform DER | sha256sum
