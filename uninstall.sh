#!/usr/bin/env bash
# Desinstala cf-unblock-dns y devuelve Pi-hole a su upstream y DNSSEC anteriores.
#   sudo cfu uninstall      (o sudo /opt/cf-unblock-dns/uninstall.sh)
set -euo pipefail

NAME=cf-unblock-dns
STATE_DIR=/etc/$NAME
DEFAULT_UPSTREAMS='["127.0.0.1#5335"]'

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[AVISO] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || fail "Ejecuta este script como root (sudo cfu uninstall)."
command -v pihole-FTL >/dev/null || fail "No se encuentra pihole-FTL."

upstreams=$DEFAULT_UPSTREAMS
if [[ -s $STATE_DIR/previous-upstreams.json ]]; then
    upstreams="$(cat "$STATE_DIR/previous-upstreams.json")"
fi
if [[ $upstreams == "[]" ]] || grep -qF '#5336' <<<"$upstreams"; then
    upstreams=$DEFAULT_UPSTREAMS
fi

info "Restaurando el upstream de Pi-hole: $upstreams"
pihole-FTL --config dns.upstreams "$upstreams" >/dev/null
if [[ -s $STATE_DIR/previous-dnssec && "$(cat "$STATE_DIR/previous-dnssec")" == true ]]; then
    info "Restaurando dns.dnssec=true en Pi-hole."
    pihole-FTL --config dns.dnssec true >/dev/null
fi
systemctl restart pihole-FTL
sleep 2
answer="$(dig +time=3 +tries=2 @127.0.0.1 example.com A +short 2>/dev/null || true)"
if grep -qE '^[0-9]+(\.[0-9]+){3}$' <<<"$answer"; then
    info "Pi-hole resuelve con el upstream restaurado."
else
    warn "Pi-hole no resuelve con $upstreams; revisa Unbound antes de seguir usando la red."
fi

# También los restos de la versión anterior (bpasserr-dns), si quedara alguno.
for name in "$NAME" bpasserr-dns; do
    systemctl disable --now "$name-autoupdate.timer" "$name.service" "$name-update.service" "$name-update.timer" \
        >/dev/null 2>&1 || true
    rm -rf /etc/systemd/system/"$name"{.service,-update.service,-update.timer,.service.d,-update.service.d}
    rm -f /etc/systemd/system/"$name"-autoupdate.{service,timer}
    rm -rf "/opt/$name" "/var/lib/$name" "/etc/$name" "/etc/default/$name"
done
systemctl daemon-reload
rm -f /usr/local/bin/cfu

# Ajustes propios de Unbound (Pi-hole ya está restaurado): se retiran y se
# recarga conservando la caché.
removed=0
for conf in /etc/unbound/unbound.conf.d/$NAME.conf /etc/unbound/unbound.conf.d/bpasserr.conf; do
    [[ -f $conf ]] && { rm -f "$conf"; removed=1; }
done
if ((removed)); then
    if unbound-checkconf >/dev/null 2>&1 && unbound-control reload_keep_cache >/dev/null 2>&1; then
        info "Retirados los ajustes de Unbound (vuelve a sus valores por defecto)."
    else
        systemctl restart unbound || warn "Revisa Unbound: systemctl status unbound"
    fi
fi

info "cf-unblock-dns desinstalado. Se conservan la cuenta $NAME y las copias /var/backups/pihole.toml.$NAME-*."
info "Unbound conserva su validación DNSSEC: es compatible con la de Pi-hole."
