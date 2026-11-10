#!/usr/bin/env bash
# Diagnóstico de cf-unblock-dns (también: cfu check).
# Uso: check.sh [DOMINIO]          solo lectura; con DOMINIO (en Cloudflare) simula un
#                                  bloqueo dentro del selector y hace HTTPS real
#      check.sh --simular DOMINIO  bloqueo simulado de extremo a extremo: añade las IPs del
#                                  dominio a la lista manual, comprueba lo que devuelven el
#                                  proxy y Pi-hole, carga la web por esas IPs y las retira
# Sin pipefail: los "comando | grep -q" darían falsos fallos por SIGPIPE.
set -u

INSTALL_DIR=/opt/cf-unblock-dns
DATA_DIR=/var/lib/cf-unblock-dns
EXTRA_LIST=/etc/cf-unblock-dns/extra-blocked.txt
failures=0

ok() { printf '  [OK]    %s\n' "$*"; }
bad() {
    printf '  [FALLO] %s\n' "$*"
    failures=$((failures + 1))
}
note() { printf '  [AVISO] %s\n' "$*"; }
section() { printf '\n== %s ==\n' "$*"; }

ipv4_answers() {  # ipv4_answers PUERTO DOMINIO
    dig +short +time=2 +tries=2 @127.0.0.1 -p "$1" "$2" A 2>/dev/null | grep -E '^[0-9]+(\.[0-9]+){3}$' | sort
}

simulate() {
    local domain=$1 backup had_list=0 original proxied pihole ttl ip out
    [[ $EUID -eq 0 ]] || { echo "Ejecuta --simular como root."; exit 1; }
    section "Bloqueo simulado de $domain"
    original="$(ipv4_answers 5335 "$domain")"
    [[ -n $original ]] || { bad "$domain no tiene registros A"; return; }
    echo "  IPs reales (Unbound): $(echo $original)"

    backup="$(mktemp)"
    [[ -f $EXTRA_LIST ]] && { had_list=1; cp -a "$EXTRA_LIST" "$backup"; }
    # La lista manual se restaura siempre, también si se corta la sesión.
    # shellcheck disable=SC2064
    if ((had_list)); then
        trap "cp -a '$backup' '$EXTRA_LIST'; rm -f '$backup'" EXIT
    else
        trap "rm -f '$EXTRA_LIST' '$backup'" EXIT
    fi
    trap 'exit 130' INT TERM HUP
    install -d -m 0755 "$(dirname "$EXTRA_LIST")"
    { ((had_list)) && cat "$backup"; echo "# check.sh --simular $domain (temporal)"; echo "$original"; } >"$EXTRA_LIST.tmp"
    mv "$EXTRA_LIST.tmp" "$EXTRA_LIST"
    sleep 2  # el proxy relee la lista cada segundo

    proxied="$(ipv4_answers 5336 "$domain")"
    echo "  Proxy devuelve:       $(echo $proxied)"
    if [[ -z $proxied || -n "$(comm -12 <(echo "$original") <(echo "$proxied"))" ]]; then
        bad "el proxy no sustituyó todas las IPs (¿está $domain en Cloudflare?)"
        echo "  Se retira la lista temporal."
        return
    fi
    ok "el proxy sustituye las IPs bloqueadas"

    pihole="$(ipv4_answers 53 "$domain")"
    if [[ $pihole != "$proxied" ]]; then
        ttl="$(dig +noall +answer +time=2 @127.0.0.1 "$domain" A 2>/dev/null | awk 'NR == 1 {print $2}')"
        echo "  Pi-hole tiene en caché la respuesta anterior; esperando $((${ttl:-0} + 1)) s a que caduque..."
        sleep $((${ttl:-0} + 1))
        ipv4_answers 53 "$domain" >/dev/null  # Pi-hole puede servir una vez la respuesta caducada
        sleep 1
        pihole="$(ipv4_answers 53 "$domain")"
    fi
    echo "  Pi-hole devuelve:     $(echo $pihole)"
    if [[ $pihole == "$proxied" ]]; then ok "los dispositivos reciben las IPs sustitutas"; else bad "Pi-hole devuelve otras IPs"; fi

    for ip in $proxied; do
        out="$(curl -s --max-time 8 --resolve "$domain:443:$ip" -w '\nHTTP=%{http_code} %{time_total}s' "https://$domain/cdn-cgi/trace" 2>&1)"
        if [[ $out =~ HTTP=([2-4][0-9][0-9])\ ([0-9.]+)s ]]; then
            ok "HTTPS por $ip: HTTP ${BASH_REMATCH[1]} en ${BASH_REMATCH[2]} s $(grep -m1 '^colo=' <<<"$out")"
        else
            bad "HTTPS por $ip falló: $(tail -1 <<<"$out")"
        fi
    done
    echo "  Se retira la lista temporal."
}

if [[ ${1:-} == --simular ]]; then
    [[ -n ${2:-} ]] || { echo "Uso: check.sh --simular DOMINIO"; exit 2; }
    simulate "$2"
    echo
    if ((failures)); then echo "$failures comprobación(es) fallida(s)."; exit 1; fi
    echo "Todo correcto."
    exit 0
fi

section "Servicios"
for unit in pihole-FTL unbound cf-unblock-dns cf-unblock-dns-update; do
    state="$(systemctl is-active "$unit" 2>/dev/null)"
    if [[ $state == active ]]; then ok "$unit activo"; else bad "$unit: ${state:-desconocido}"; fi
done

section "Puertos"
ss -Hlnup 2>/dev/null | grep -E ':(53|5335|5336)\s' | awk '{print "  udp " $4 "  " $6}'
ss -Hlntp 2>/dev/null | grep -E ':(53|5335|5336)\s' | awk '{print "  tcp " $4 "  " $6}'

section "Pi-hole"
upstreams="$(pihole-FTL --config dns.upstreams 2>/dev/null)"
if grep -qF '127.0.0.1#5336' <<<"$upstreams"; then ok "upstream: $upstreams"; else bad "upstream: $upstreams (debería ser 127.0.0.1#5336)"; fi
dnssec="$(pihole-FTL --config dns.dnssec 2>/dev/null)"
if [[ $dnssec == false ]]; then
    ok "dns.dnssec=false (Unbound valida)"
else
    bad "dns.dnssec=$dnssec: Pi-hole pide firmas en todas las consultas y el proxy no puede reescribir"
fi

section "Resolución de example.com"
for target in "Unbound:5335" "Proxy:5336" "Pi-hole:53"; do
    name=${target%%:*}
    port=${target##*:}
    started=$(date +%s%N)
    answer="$(dig +time=2 +tries=1 @127.0.0.1 -p "$port" example.com A +short 2>/dev/null | tr '\n' ' ')"
    elapsed=$((($(date +%s%N) - started) / 1000000))
    if [[ $answer =~ [0-9]+\.[0-9]+ ]]; then ok "$name ($port): $answer(${elapsed} ms)"; else bad "$name ($port) no responde"; fi
done
if dig +tcp +time=2 +tries=1 @127.0.0.1 -p 5336 example.com A +short 2>/dev/null | grep -q '\.'; then
    ok "Proxy por TCP"
else
    bad "Proxy por TCP no responde"
fi

section "Unbound"
tcp_slots="$(unbound-checkconf -o incoming-num-tcp 2>/dev/null)"
if [[ ${tcp_slots:-0} -ge 64 ]]; then ok "conexiones TCP simultáneas: $tcp_slots"; else note "conexiones TCP simultáneas: ${tcp_slots:-?} (ejecuta sudo cfu config y acepta ajustar Unbound)"; fi
status="$(dig +time=3 +tries=1 @127.0.0.1 -p 5335 dnssec-failed.org A 2>/dev/null | grep -o 'status: [A-Z]*')"
if [[ $status == "status: SERVFAIL" ]]; then ok "rechaza firmas no válidas (dnssec-failed.org)"; else bad "dnssec-failed.org devolvió '${status:-sin respuesta}': Unbound no valida DNSSEC"; fi
if dig +time=3 +tries=1 +dnssec @127.0.0.1 -p 5335 cloudflare.com A 2>/dev/null | grep -qE '^;; flags:.* ad'; then
    ok "valida respuestas firmadas (bit AD)"
else
    bad "Unbound no marcó cloudflare.com como validado"
fi
# dnssec-failed.org es el dominio de prueba que este mismo script consulta.
validation_failures="$(journalctl -u unbound --since -24h --no-pager -o cat 2>/dev/null \
    | grep 'validation failure' | grep -v 'dnssec-failed\.org')"
if [[ -n $validation_failures ]]; then
    note "$(wc -l <<<"$validation_failures") fallo(s) de validación DNSSEC en 24 h (dominios con DNSSEC roto); últimos:"
    tail -3 <<<"$validation_failures" | cut -c1-160 | sed 's/^/          /'
fi

section "Versión, actualizaciones y avisos"
echo "  $("$INSTALL_DIR/cfu" version)"
if systemctl is-enabled --quiet cf-unblock-dns-autoupdate.timer 2>/dev/null; then
    ok "actualización automática activada (próxima: $(systemctl show -p NextElapseUSecRealtime --value cf-unblock-dns-autoupdate.timer))"
    last="$(journalctl -u cf-unblock-dns-autoupdate -n 1 --no-pager -o cat 2>/dev/null | grep -v '^--')"
    [[ -n $last ]] && echo "  Última ejecución: $last"
else
    note "actualización automática desactivada (sudo cfu config para activarla; a mano: sudo cfu update)"
fi
if [[ -s /etc/cf-unblock-dns/notify-url ]]; then
    ok "avisos activados (prueba: sudo cfu alerts test)"
else
    note "avisos desactivados (sudo cfu config para añadir una URL de ntfy o Telegram)"
fi

section "Respuestas Cloudflare a través del proxy"
max_ttl="$(dig +time=2 +tries=1 @127.0.0.1 -p 5336 www.cloudflare.com A +noall +answer 2>/dev/null | awk '{print $2}' | sort -n | tail -1)"
if [[ -n $max_ttl && $max_ttl -le 30 ]]; then ok "TTL limitado a ${max_ttl}s"; else note "TTL observado: ${max_ttl:-sin respuesta}"; fi

section "Datos y estado del proxy"
"$INSTALL_DIR/cfu" status --data-dir "$DATA_DIR" || failures=$((failures + 1))

section "Registro reciente del proxy"
journalctl -u cf-unblock-dns -n 15 --no-pager -o cat 2>/dev/null | sed 's/^/  /'
section "Registro reciente del actualizador"
journalctl -u cf-unblock-dns-update -n 5 --no-pager -o cat 2>/dev/null | sed 's/^/  /'

if [[ $# -ge 1 ]]; then
    section "Autoprueba: bloqueo simulado de $1"
    if ! (cd / && runuser -u cf-unblock-dns -- "$INSTALL_DIR/cfu" serve --self-test "$1"); then
        bad "la autoprueba con $1 no verificó ninguna sustitución"
    fi
fi

echo
if ((failures)); then
    echo "$failures comprobación(es) fallida(s)."
    exit 1
fi
echo "Todo correcto."
