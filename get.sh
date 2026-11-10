#!/usr/bin/env bash
# Instala la última versión publicada de cf-unblock-dns:
#   curl -fsSL https://raw.githubusercontent.com/zarko379/cf-unblock-dns/main/get.sh | sudo bash
# Las opciones se pasan al instalador: ... | sudo bash -s -- -y
# Una vez instalado, para actualizar: sudo cfu update
set -euo pipefail

REPO=zarko379/cf-unblock-dns

fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Ejecútalo como root: curl -fsSL https://raw.githubusercontent.com/$REPO/main/get.sh | sudo bash"
command -v curl >/dev/null || fail "Falta curl (apt-get install curl)."
case "$(uname -m)" in
    x86_64) arch=amd64 ;;
    aarch64 | arm64) arch=arm64 ;;
    armv6l | armv7l) arch=arm ;;
    *) fail "Arquitectura no soportada: $(uname -m)" ;;
esac

package="cf-unblock-dns-linux-$arch.tar.gz"
base="https://github.com/$REPO/releases/latest/download"
work="$(mktemp -d /var/tmp/cf-unblock-dns.XXXXXX)"
trap 'rm -rf "$work"' EXIT

echo "[INFO] Descargando $package..."
curl -fsSL -o "$work/$package" "$base/$package"
curl -fsSL -o "$work/SHA256SUMS" "$base/SHA256SUMS"
curl -fsSL -o "$work/SHA256SUMS.sig" "$base/SHA256SUMS.sig"
# Firma Ed25519 de SHA256SUMS (la misma clave que comprueba cfu update).
cat >"$work/release.pub" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEARSAaUfPsxSV/cZAEJpeB9q+dqDJzG7dK7sGt7vMkhd8=
-----END PUBLIC KEY-----
EOF
command -v openssl >/dev/null || fail "Falta openssl para verificar la firma (apt-get install openssl)."
openssl pkeyutl -verify -pubin -inkey "$work/release.pub" -rawin \
    -in "$work/SHA256SUMS" -sigfile "$work/SHA256SUMS.sig" >/dev/null 2>&1 \
    || fail "La firma de la versión no es válida; no se instala nada."
(cd "$work" && tr -d '\r' <SHA256SUMS | grep " $package\$" | sha256sum -c --quiet -) \
    || fail "La suma SHA-256 no coincide."
mkdir "$work/pkg"
tar -xzf "$work/$package" -C "$work/pkg" --no-same-owner

# Con "curl | bash" la entrada es la tubería: las preguntas se leen del terminal.
if [[ ! -t 0 ]] && { : </dev/tty; } 2>/dev/null; then
    bash "$work/pkg/install.sh" "$@" </dev/tty
else
    bash "$work/pkg/install.sh" "$@"
fi
