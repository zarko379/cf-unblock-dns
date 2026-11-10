#!/usr/bin/env bash
# Instala cf-unblock-dns entre Pi-hole (puerto 53) y Unbound (127.0.0.1:5335).
# No toca gateway, rutas, ip_forward, iptables/nftables ni Proxmox.
#
# Con terminal pregunta cada opción (con la configuración actual por defecto);
# sin terminal o con -y la conserva. Volver a ejecutarlo actualiza o reconfigura:
#   sudo cfu config        (o sudo /opt/cf-unblock-dns/install.sh)
# Si encuentra la versión anterior (BPasserr DNS, /opt/bpasserr-dns), migra su
# configuración y datos y la retira.
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
NAME=cf-unblock-dns
INSTALL_DIR=/opt/$NAME
DATA_DIR=/var/lib/$NAME
STATE_DIR=/etc/$NAME
DEFAULTS_FILE=/etc/default/$NAME
COMMAND_LINK=/usr/local/bin/cfu
PIHOLE_CONFIG=/etc/pihole/pihole.toml
BACKUP_DIR=/var/backups
PIHOLE_FIRST_BACKUP="$BACKUP_DIR/pihole.toml.$NAME-before"
SERVICE_USER=$NAME
UNBOUND_PORT=5335
PROXY_PORT=5336
PROXY_UPSTREAM="127.0.0.1#$PROXY_PORT"
UNITS=($NAME-update.service $NAME.service)
AUTO_SERVICE=$NAME-autoupdate.service
AUTO_TIMER=$NAME-autoupdate.timer
UNBOUND_CONF=/etc/unbound/unbound.conf.d/$NAME.conf

# Versión anterior con el nombre BPasserr DNS: se migra y se retira.
OLD_NAME=bpasserr-dns
OLD_INSTALL_DIR=/opt/$OLD_NAME
OLD_DATA_DIR=/var/lib/$OLD_NAME
OLD_STATE_DIR=/etc/$OLD_NAME
OLD_DEFAULTS_FILE=/etc/default/$OLD_NAME
OLD_UNBOUND_CONF=/etc/unbound/unbound.conf.d/bpasserr.conf

LIST_BASE=https://hayahora.futbol/estado
# Unbound atiende 10 conexiones TCP a la vez por defecto; el proxy abre una por
# cada consulta TCP de Pi-hole y en ráfagas se quedaba corto (errores EOF).
UNBOUND_TCP_SLOTS=256

info() { printf '[INFO] %s\n' "$*"; }
warn() { printf '[AVISO] %s\n' "$*" >&2; }
fail() { printf '[ERROR] %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Uso: sudo bash install.sh [opciones]

Sin opciones y con terminal, el instalador pregunta cada ajuste.
  -y, --yes                 no preguntar: conservar la configuración actual
  --list NOMBRE|URL         lista de bloqueos: any, movistar, digi, vodafone,
                            orange, masmovil o una URL
  --interval SEGUNDOS       segundos entre descargas de la lista (5-3600)
  --max-ttl SEGUNDOS        TTL máximo de respuestas Cloudflare (0 = sin límite)
  --local-detection si|no   detectar cortes desde este equipo
  --tune-unbound si|no      más conexiones TCP y registro de fallos DNSSEC en Unbound
  --auto-update si|no       instalar solo las versiones nuevas (revisa una vez por semana)
  --notify-url URL|no       avisos si algo falla: tema de ntfy (https://ntfy.sh/TEMA) o
                            https://api.telegram.org/botTOKEN/sendMessage?chat_id=ID
  -h, --help                esta ayuda
EOF
}

normalize_yes_no() {  # normalize_yes_no VALOR -> yes|no
    case "${1,,}" in
        s | si | sí | y | yes | 1 | true) echo yes ;;
        n | no | 0 | false) echo no ;;
        *) return 1 ;;
    esac
}

list_url() {  # list_url NOMBRE|URL
    case "${1,,}" in
        any | todos) echo "$LIST_BASE/blocked-any.txt" ;;
        movistar | digi | vodafone | orange | masmovil) echo "$LIST_BASE/blocked-${1,,}.txt" ;;
        https://*) echo "$1" ;;
        *) return 1 ;;
    esac
}

# --- Opciones de la línea de órdenes -----------------------------------------

ASSUME_YES=0
opt_url="" opt_interval="" opt_ttl="" opt_local="" opt_tune="" opt_auto="" opt_notify=""
while (($#)); do
    case "$1" in
        -y | --yes) ASSUME_YES=1 ;;
        --list) opt_url="$(list_url "${2:-}")" || fail "Lista no válida: ${2:-}"; shift ;;
        --interval) opt_interval="${2:-}"; shift ;;
        --max-ttl) opt_ttl="${2:-}"; shift ;;
        --local-detection) opt_local="$(normalize_yes_no "${2:-}")" || fail "Usa si o no en --local-detection"; shift ;;
        --tune-unbound) opt_tune="$(normalize_yes_no "${2:-}")" || fail "Usa si o no en --tune-unbound"; shift ;;
        --auto-update) opt_auto="$(normalize_yes_no "${2:-}")" || fail "Usa si o no en --auto-update"; shift ;;
        --notify-url)
            case "${2:-}" in
                no | none | ninguna) opt_notify=none ;;
                https://?* | http://?*) opt_notify=$2 ;;
                *) fail "--notify-url debe ser una URL http(s) o no" ;;
            esac
            shift
            ;;
        -h | --help) usage; exit 0 ;;
        *) usage >&2; fail "Opción desconocida: $1" ;;
    esac
    shift
done
[[ -z $opt_interval || $opt_interval =~ ^[0-9]+$ && $opt_interval -ge 5 && $opt_interval -le 3600 ]] \
    || fail "--interval debe estar entre 5 y 3600"
[[ -z $opt_ttl || $opt_ttl =~ ^[0-9]+$ && $opt_ttl -le 86400 ]] || fail "--max-ttl debe ser un número de segundos"
INTERACTIVE=0
[[ -t 0 && $ASSUME_YES -eq 0 ]] && INTERACTIVE=1

resolves() {  # resolves SERVIDOR PUERTO [opciones de dig]
    local server=$1 port=$2 answer
    shift 2
    answer="$(dig +time=2 +tries=2 "$@" @"$server" -p "$port" example.com A +short 2>/dev/null || true)"
    grep -qE '^[0-9]+(\.[0-9]+){3}$' <<<"$answer"
}

# --- Comprobaciones previas: no cambian nada ---------------------------------

[[ $EUID -eq 0 ]] || fail "Ejecuta este instalador como root."
for file in "${UNITS[@]}" check.sh uninstall.sh; do
    [[ -f "$SCRIPT_DIR/$file" ]] || fail "Falta $file junto a install.sh."
done
BINARY="$SCRIPT_DIR/cfu"
if [[ ! -x $BINARY ]]; then
    if command -v go >/dev/null && [[ -f $SCRIPT_DIR/go.mod ]]; then
        info "Compilando cfu con $(go version | cut -d' ' -f3)."
        (cd "$SCRIPT_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o cfu .) \
            || fail "No se pudo compilar cfu."
    else
        fail "Falta el binario cfu. Descarga un paquete de https://github.com/zarko379/cf-unblock-dns/releases o compílalo con 'go build -o cfu .'."
    fi
fi
"$BINARY" version >/dev/null 2>&1 || fail "El binario cfu no se ejecuta en este sistema (¿arquitectura distinta?)."
[[ -f $PIHOLE_CONFIG ]] || fail "No se encuentra $PIHOLE_CONFIG; se requiere Pi-hole v6."
command -v pihole-FTL >/dev/null || fail "No se encuentra pihole-FTL."
command -v systemctl >/dev/null || fail "No se encuentra systemctl."

ftl_environment="$(systemctl show -p Environment --value pihole-FTL 2>/dev/null || true)"
if [[ -n "${FTLCONF_dns_upstreams:-}" || $ftl_environment == *FTLCONF_dns_upstreams* ]]; then
    fail "FTLCONF_dns_upstreams está definido y hace que el upstream de Pi-hole sea de solo lectura."
fi
nat_rules="$(iptables -t nat -S 2>/dev/null || true)"
if [[ $nat_rules == *SOCKS_PROXY* ]]; then
    fail "Aún existen reglas iptables del BPasserr original (SOCKS_PROXY). Desinstálalo antes de continuar."
fi
if systemctl is-active --quiet redsocks 2>/dev/null; then
    fail "Redsocks (BPasserr original) sigue activo. Desinstálalo antes de continuar."
fi

missing=()
command -v dig >/dev/null || missing+=(dnsutils)
[[ -s /etc/ssl/certs/ca-certificates.crt ]] || missing+=(ca-certificates)
command -v curl >/dev/null || missing+=(curl)
if ((${#missing[@]})); then
    info "Instalando: ${missing[*]}"
    apt-get update
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
fi

resolves 127.0.0.1 "$UNBOUND_PORT" \
    || fail "Unbound no responde en 127.0.0.1:$UNBOUND_PORT. Revisa: systemctl status unbound"

port_owner="$(ss -Hlnup "sport = :$PROXY_PORT" 2>/dev/null || true)"
if [[ -n $port_owner ]] && ! systemctl is-active --quiet "$NAME.service" \
    && ! systemctl is-active --quiet "$OLD_NAME.service"; then
    fail "El puerto $PROXY_PORT ya lo usa otro programa: $port_owner"
fi

# --- Configuración -------------------------------------------------------------

MIGRATING=0
[[ -d $OLD_INSTALL_DIR || -f /etc/systemd/system/$OLD_NAME.service ]] && MIGRATING=1

# Valores actuales (o por defecto en una instalación nueva). El fichero se lee
# línea a línea, sin ejecutarlo; si solo existe el de la versión anterior, se
# toman de ahí (sus claves empiezan por BPASSERR_ en vez de CFU_).
cur_url="$LIST_BASE/blocked-any.txt" cur_interval=15 cur_ttl=30 cur_local=yes cur_tune=yes cur_auto=yes
NOTIFY_FILE=$STATE_DIR/notify-url
cur_notify=""
[[ -s $NOTIFY_FILE ]] && cur_notify="$(head -1 "$NOTIFY_FILE")"
base_args="--listen 127.0.0.1 --port $PROXY_PORT --upstream 127.0.0.1 --upstream-port $UNBOUND_PORT"
saved_file="" prefix=CFU
if [[ -f $DEFAULTS_FILE ]]; then
    saved_file=$DEFAULTS_FILE
elif [[ -f $OLD_DEFAULTS_FILE ]]; then
    saved_file=$OLD_DEFAULTS_FILE prefix=BPASSERR
fi
if [[ -n $saved_file ]]; then
    value() { sed -n "s/^${prefix}_$1=//p" "$saved_file" | tail -1 | tr -d '"'; }
    saved_url="$(value BLOCKED_URL)"
    saved_interval="$(value UPDATE_INTERVAL)"
    saved_args="$(value DNS_ARGS)"
    # Una instalación anterior sin esta opción la deja desactivada: -y no
    # debe activar actualizaciones automáticas por su cuenta.
    saved_auto="$(value AUTO_UPDATE)"
    cur_auto=no
    [[ $saved_auto == yes ]] && cur_auto=yes
    [[ $saved_url == https://* ]] && cur_url=$saved_url
    [[ $saved_interval =~ ^[0-9]+$ ]] && cur_interval=$saved_interval
    [[ $saved_args =~ --cloudflare-max-ttl[=\ ]+([0-9]+) ]] && cur_ttl=${BASH_REMATCH[1]}
    [[ $saved_args == *--no-local-detection* ]] && cur_local=no
    # Otras opciones que se hubieran puesto a mano se conservan.
    saved_base="$(sed -E 's/--cloudflare-max-ttl[= ]+[0-9]+//; s/--no-local-detection//; s/  +/ /g; s/^ //; s/ $//' <<<"$saved_args")"
    [[ -n $saved_base ]] && base_args=$saved_base
fi
cfg_url=${opt_url:-$cur_url}
cfg_interval=${opt_interval:-$cur_interval}
cfg_ttl=${opt_ttl:-$cur_ttl}
cfg_local=${opt_local:-$cur_local}
cfg_tune=${opt_tune:-$cur_tune}
cfg_auto=${opt_auto:-$cur_auto}
cfg_notify=${opt_notify:-$cur_notify}
[[ $cfg_notify == none ]] && cfg_notify=""

shown_url() {  # oculta el token o el tema: la URL da acceso a los avisos
    [[ -z $1 ]] && { echo "sin avisos"; return; }
    sed -E 's#^(https?://[^/]+/).*#\1…#' <<<"$1"
}

ask_notify() {  # ask_notify ACTUAL
    local answer
    {
        echo "Avisos si algo deja de funcionar (Unbound, el proxy, Pi-hole o la lista):"
        echo "  ntfy:     https://ntfy.sh/UN-TEMA-DIFICIL-DE-ADIVINAR  (app ntfy en el móvil)"
        echo "  Telegram: https://api.telegram.org/botTOKEN/sendMessage?chat_id=ID"
        echo "  Escribe 'no' para desactivarlos; Intro deja $(shown_url "$1")."
    } >&2
    while true; do
        read -r -p "URL de avisos: " answer || true
        [[ -z $answer ]] && { echo "$1"; return 0; }
        [[ ${answer,,} == no ]] && { echo ""; return 0; }
        [[ $answer == https://?* || $answer == http://?* ]] && { echo "$answer"; return 0; }
        echo "  Escribe una URL http(s), 'no' o pulsa Intro." >&2
    done
}

ask() {  # ask PREGUNTA DEFECTO -> respuesta (o DEFECTO si se pulsa Intro)
    local answer=""
    read -r -p "$1 [$2]: " answer || true
    echo "${answer:-$2}"
}

ask_yes_no() {  # ask_yes_no PREGUNTA DEFECTO(yes|no)
    local shown answer
    shown=$([[ $2 == yes ]] && echo s || echo n)
    while true; do
        answer="$(ask "$1 (s/n)" "$shown")"
        normalize_yes_no "$answer" && return 0
        echo "  Responde s o n." >&2
    done
}

ask_number() {  # ask_number PREGUNTA DEFECTO MIN MAX
    local answer
    while true; do
        answer="$(ask "$1" "$2")"
        [[ $answer =~ ^[0-9]+$ && $answer -ge $3 && $answer -le $4 ]] && { echo "$answer"; return 0; }
        echo "  Escribe un número entre $3 y $4." >&2
    done
}

ask_list() {  # ask_list URL_ACTUAL
    local names=(any movistar digi vodafone orange masmovil) labels=("Todos los operadores (recomendado)" Movistar DIGI Vodafone Orange MásMóvil)
    local current=7 i answer url
    for i in "${!names[@]}"; do
        [[ $1 == "$LIST_BASE/blocked-${names[$i]}.txt" ]] && current=$((i + 1))
    done
    {
        echo "Lista de IPs bloqueadas (hayahora.futbol):"
        for i in "${!names[@]}"; do printf '  %d) %s\n' $((i + 1)) "${labels[$i]}"; done
        echo "  7) Otra URL"
    } >&2
    while true; do
        answer="$(ask "Elige" "$current")"
        if [[ $answer =~ ^[1-6]$ ]]; then
            echo "$LIST_BASE/blocked-${names[$((answer - 1))]}.txt"
            return 0
        fi
        if [[ $answer == 7 ]]; then
            url="$(ask "URL de la lista" "$([[ $current == 7 ]] && echo "$1" || echo https://)")"
            [[ $url == https://?* ]] && { echo "$url"; return 0; }
            echo "  La URL debe empezar por https://" >&2
            continue
        fi
        echo "  Elige un número del 1 al 7." >&2
    done
}

if ((INTERACTIVE)); then
    echo
    echo "=== cf-unblock-dns: configuración ==="
    echo "Pulsa Intro para dejar el valor entre corchetes."
    echo
    [[ -z $opt_url ]] && cfg_url="$(ask_list "$cfg_url")"
    [[ -z $opt_interval ]] && cfg_interval="$(ask_number "Segundos entre descargas de la lista" "$cfg_interval" 5 3600)"
    [[ -z $opt_ttl ]] && cfg_ttl="$(ask_number "TTL máximo de las respuestas de Cloudflare en segundos (0 = sin límite)" "$cfg_ttl" 0 86400)"
    [[ -z $opt_local ]] && cfg_local="$(ask_yes_no "¿Detectar cortes desde este equipo además de la lista?" "$cfg_local")"
    [[ -z $opt_tune ]] && cfg_tune="$(ask_yes_no "¿Ajustar Unbound ($UNBOUND_TCP_SLOTS conexiones TCP y registro de fallos DNSSEC)?" "$cfg_tune")"
    [[ -z $opt_auto ]] && cfg_auto="$(ask_yes_no "¿Instalar solo las versiones nuevas? (revisa una vez por semana; si fallan, vuelve a la anterior)" "$cfg_auto")"
    [[ -z $opt_notify ]] && cfg_notify="$(ask_notify "$cfg_notify")"
    echo
    echo "Resumen:"
    echo "  Lista de bloqueos:        $cfg_url"
    echo "  Descarga cada:            $cfg_interval s"
    echo "  TTL máximo Cloudflare:    $([[ $cfg_ttl == 0 ]] && echo "sin límite" || echo "$cfg_ttl s")"
    echo "  Detección desde aquí:     $([[ $cfg_local == yes ]] && echo sí || echo no)"
    echo "  Ajustar Unbound:          $([[ $cfg_tune == yes ]] && echo sí || echo no)"
    echo "  Actualizar solo:          $([[ $cfg_auto == yes ]] && echo "sí, una vez por semana" || echo no)"
    echo "  Avisos:                   $(shown_url "$cfg_notify")"
    [[ "$(ask_yes_no "¿Instalar con esta configuración?" yes)" == yes ]] || { info "Cancelado; no se ha cambiado nada."; exit 0; }
    echo
fi
dns_args="$base_args --cloudflare-max-ttl $cfg_ttl"
[[ $cfg_local == no ]] && dns_args="$dns_args --no-local-detection"

# --- Ficheros y servicios ----------------------------------------------------

if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    useradd --system --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin "$SERVICE_USER"
fi

install -d -o root -g root -m 0755 "$INSTALL_DIR" "$STATE_DIR"
# Legible por todos: cfu status funciona sin sudo (solo contiene la lista,
# contadores y los nombres reescritos hoy).
install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0755 "$DATA_DIR"
if ((MIGRATING)); then
    # Se copian (no se mueven): la versión anterior sigue intacta hasta que la
    # nueva funcione. -n no sobrescribe lo que ya tenga la nueva.
    info "Migrando datos y estado de $OLD_NAME (lista manual, upstream previo de Pi-hole)."
    if [[ -d $OLD_STATE_DIR ]]; then cp -an "$OLD_STATE_DIR/." "$STATE_DIR/"; fi
    if [[ -d $OLD_DATA_DIR ]]; then cp -an "$OLD_DATA_DIR/." "$DATA_DIR/"; fi
    chown -R "$SERVICE_USER:$SERVICE_USER" "$DATA_DIR"
fi
# Se copia también el instalador, para reconfigurar con: sudo cfu config
if [[ ! $SCRIPT_DIR -ef $INSTALL_DIR ]]; then
    # install escribe un fichero nuevo: el servicio en marcha no se ve afectado hasta reiniciarlo.
    install -o root -g root -m 0755 "$BINARY" "$INSTALL_DIR/cfu"
    install -o root -g root -m 0755 "$SCRIPT_DIR/install.sh" "$SCRIPT_DIR/check.sh" "$SCRIPT_DIR/uninstall.sh" "$INSTALL_DIR/"
    install -o root -g root -m 0644 "${UNITS[@]/#/$SCRIPT_DIR/}" "$INSTALL_DIR/"
fi
ln -sfn "$INSTALL_DIR/cfu" "$COMMAND_LINK"
install -o root -g root -m 0644 "${UNITS[@]/#/$SCRIPT_DIR/}" /etc/systemd/system/
cat >"$DEFAULTS_FILE.tmp" <<EOF
# Configuración de cf-unblock-dns. La escribe el instalador: para cambiarla
# ejecuta  sudo cfu config  y responde a las preguntas.
CFU_DNS_ARGS="$dns_args"
CFU_BLOCKED_URL=$cfg_url
CFU_UPDATE_INTERVAL=$cfg_interval
CFU_AUTO_UPDATE=$cfg_auto
EOF
chmod 0644 "$DEFAULTS_FILE.tmp"
mv "$DEFAULTS_FILE.tmp" "$DEFAULTS_FILE"
# La URL de avisos puede llevar un token: solo la leen root y el servicio.
if [[ -n $cfg_notify ]]; then
    printf '%s\n' "$cfg_notify" >"$NOTIFY_FILE.tmp"
    chown "root:$SERVICE_USER" "$NOTIFY_FILE.tmp"
    chmod 0640 "$NOTIFY_FILE.tmp"
    mv "$NOTIFY_FILE.tmp" "$NOTIFY_FILE"
else
    rm -f "$NOTIFY_FILE"
fi
info "Configuración guardada: lista $(basename "$cfg_url"), cada ${cfg_interval} s, TTL $cfg_ttl, detección local $([[ $cfg_local == yes ]] && echo sí || echo no), actualización automática $([[ $cfg_auto == yes ]] && echo sí || echo no), avisos: $(shown_url "$cfg_notify")."

# Actualización automática. El servicio lo lanza solo el temporizador: este
# instalador puede estar ejecutándose dentro de él (cfu update), así que
# nunca lo arranca ni lo reinicia; solo gestiona el .timer.
cat >"/etc/systemd/system/$AUTO_SERVICE" <<EOF
[Unit]
Description=cf-unblock-dns: install the latest release (cfu update)
Wants=network-online.target
After=network-online.target

[Service]
Type=oneshot
ExecStart=$INSTALL_DIR/cfu update
TimeoutStartSec=15min
EOF
cat >"/etc/systemd/system/$AUTO_TIMER" <<'EOF'
[Unit]
Description=cf-unblock-dns: weekly check for a new release

[Timer]
OnCalendar=Sun 04:00
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF
chmod 0644 "/etc/systemd/system/$AUTO_SERVICE" "/etc/systemd/system/$AUTO_TIMER"
if [[ ! -f $STATE_DIR/extra-blocked.txt ]]; then
    cat >"$STATE_DIR/extra-blocked.txt" <<'EOF'
# IPs o rangos que cf-unblock-dns debe tratar como bloqueados además de la lista
# descargada (una entrada por línea; # para comentarios). Se aplica en 1 s.
# Solo afecta a direcciones de Cloudflare.
EOF
    chmod 0644 "$STATE_DIR/extra-blocked.txt"
fi
systemctl daemon-reload

info "Descargando las listas iniciales; Pi-hole aún no cambia."
# cfu lee la URL de $DEFAULTS_FILE.
(cd / && runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/cfu" list update) \
    || fail "No se pudieron obtener los datos iniciales. Pi-hole no se ha modificado."

apply_lxc_compat() {
    local unit=$1
    install -d -m 0755 "/etc/systemd/system/$unit.d"
    cat >"/etc/systemd/system/$unit.d/lxc-compat.conf" <<'EOF'
# Este contenedor no permite a systemd crear espacios de nombres de montaje
# (LXC sin "nesting"); se mantiene el usuario sin privilegios.
[Service]
PrivateTmp=no
ProtectSystem=no
ProtectHome=no
ReadWritePaths=
RestrictNamespaces=no
EOF
    systemctl daemon-reload
}

# Durante la migración, si la versión nueva no arranca se vuelve a la anterior,
# cuyos ficheros siguen en su sitio hasta el final.
OLD_STOPPED=0
fail_service() {
    if ((OLD_STOPPED)); then
        warn "Volviendo a la versión anterior ($OLD_NAME)."
        systemctl disable --now "${UNITS[@]}" 2>/dev/null || true
        systemctl enable --now "$OLD_NAME-update.service" "$OLD_NAME.service" 2>/dev/null || true
    fi
    fail "$@"
}

start_unit() {
    local unit=$1 old
    if ((MIGRATING)); then
        # Se para el servicio antiguo justo antes de arrancar su sustituto, que
        # usa el mismo puerto; disable evita que ambos arranquen tras reiniciar.
        old=${unit/#$NAME/$OLD_NAME}
        if systemctl cat "$old" >/dev/null 2>&1; then
            systemctl disable --now "$old" >/dev/null 2>&1 || true
            OLD_STOPPED=1
        fi
    fi
    systemctl enable "$unit" >/dev/null 2>&1 || fail_service "No se pudo habilitar $unit."
    systemctl restart "$unit" || true
    sleep 3
    systemctl is-active --quiet "$unit" && return 0
    if [[ "$(systemctl show -p ExecMainStatus --value "$unit")" == 226 ]]; then
        warn "$unit no puede usar el aislamiento de systemd en este LXC; se aplica una configuración compatible."
        apply_lxc_compat "$unit"
        systemctl restart "$unit" || true
        sleep 3
        systemctl is-active --quiet "$unit" && return 0
    fi
    journalctl -u "$unit" -n 20 --no-pager >&2 || true
    fail_service "$unit no arrancó. Pi-hole no se ha modificado."
}

for unit in "${UNITS[@]}"; do
    start_unit "$unit"
done

for _ in $(seq 1 10); do
    resolves 127.0.0.1 "$PROXY_PORT" && break
    sleep 1
done
resolves 127.0.0.1 "$PROXY_PORT" \
    || fail_service "El proxy no resuelve a través de Unbound (UDP). Pi-hole no se ha modificado."
resolves 127.0.0.1 "$PROXY_PORT" +tcp \
    || fail_service "El proxy no resuelve a través de Unbound (TCP). Pi-hole no se ha modificado."
info "Proxy comprobado en 127.0.0.1:$PROXY_PORT (UDP y TCP)."

if ((MIGRATING)); then
    systemctl disable --now "$OLD_NAME.service" "$OLD_NAME-update.service" "$OLD_NAME-update.timer" >/dev/null 2>&1 || true
    rm -rf /etc/systemd/system/"$OLD_NAME"{.service,-update.service,-update.timer,.service.d,-update.service.d}
    systemctl daemon-reload
    rm -rf "$OLD_INSTALL_DIR" "$OLD_DATA_DIR" "$OLD_STATE_DIR" "$OLD_DEFAULTS_FILE"
    for backup in "$BACKUP_DIR"/pihole.toml.bpasserr-*; do
        [[ -e $backup ]] || continue
        mv -n "$backup" "$BACKUP_DIR/pihole.toml.$NAME-${backup##*/pihole.toml.bpasserr-}"
    done
    if id -u "$OLD_NAME" >/dev/null 2>&1; then
        userdel "$OLD_NAME" 2>/dev/null || warn "No se pudo borrar la cuenta $OLD_NAME."
    fi
    info "Versión anterior ($OLD_NAME) retirada: servicios, ficheros y cuenta."
fi

if [[ $cfg_auto == yes ]]; then
    systemctl enable --now "$AUTO_TIMER" >/dev/null 2>&1 \
        || warn "No se pudo activar $AUTO_TIMER; actualiza a mano con: sudo cfu update"
    info "Actualización automática activada: $(systemctl show -p NextElapseUSecRealtime --value "$AUTO_TIMER" 2>/dev/null || echo "una vez por semana")."
else
    systemctl disable --now "$AUTO_TIMER" >/dev/null 2>&1 || true
fi

# --- Pi-hole -----------------------------------------------------------------

current_upstreams="$(pihole-FTL --config dns.upstreams)" || fail "No se pudo leer dns.upstreams de Pi-hole."
current_dnssec="$(pihole-FTL --config dns.dnssec)" || fail "No se pudo leer dns.dnssec de Pi-hole."

# --- DNSSEC: Pi-hole dejará de validar, así que Unbound debe hacerlo ---------
#
# Justo tras arrancar, Unbound puede fallar unos segundos al construir la
# cadena DNSSEC y recuerda esos fallos ~60 s. Por eso la comprobación de que
# está vivo no valida (+cd) y la de que valida DNSSEC se reintenta hasta 75 s.

unbound_alive() {  # responde, aunque la validación aún esté en frío
    resolves 127.0.0.1 "$UNBOUND_PORT" +cd
}

unbound_validates_once() {
    local bogus unchecked signed re=';; flags:[a-z ]* ad[ ;]'
    bogus="$(dig +time=3 +tries=1 @127.0.0.1 -p "$UNBOUND_PORT" dnssec-failed.org A 2>/dev/null || true)"
    unchecked="$(dig +time=3 +tries=1 +cd @127.0.0.1 -p "$UNBOUND_PORT" dnssec-failed.org A 2>/dev/null || true)"
    signed="$(dig +time=3 +tries=1 +dnssec @127.0.0.1 -p "$UNBOUND_PORT" cloudflare.com A 2>/dev/null || true)"
    # SERVFAIL al validar pero NOERROR sin validar: el fallo es de DNSSEC, no de red.
    [[ $bogus == *"status: SERVFAIL"* && $unchecked == *"status: NOERROR"* && $signed =~ $re ]]
}

unbound_validates() {  # unbound_validates [SEGUNDOS]
    local deadline=$((SECONDS + ${1:-0}))
    while true; do
        unbound_validates_once && return 0
        ((SECONDS < deadline)) || return 1
        sleep 3
    done
}

unbound_wait_alive() {
    for _ in $(seq 1 20); do
        unbound_alive && return 0
        sleep 1
    done
    return 1
}

# Aplica la configuración: recarga conservando la caché (sin arranque en frío)
# y, si no se puede, reinicia.
unbound_apply() {
    unbound-checkconf >/dev/null 2>&1 || return 1
    if unbound-control reload_keep_cache >/dev/null 2>&1; then
        unbound_wait_alive && return 0
    fi
    systemctl restart unbound && unbound_wait_alive
}

ensure_unbound_dnssec() {
    local anchor=/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf created=0
    unbound_validates 75 && return 0
    if [[ -n "$(unbound-checkconf -o auto-trust-anchor-file 2>/dev/null)$(unbound-checkconf -o trust-anchor-file 2>/dev/null)" \
        || -e $anchor ]]; then
        [[ $current_dnssec == true ]] && fail "Unbound tiene ancla de confianza pero no valida DNSSEC; \
desactivar el DNSSEC de Pi-hole dejaría la red sin validación. Revisa Unbound. Pi-hole no se ha modificado."
        warn "Unbound no valida DNSSEC (Pi-hole tampoco lo hacía)."
        return 0
    fi
    info "Unbound no valida DNSSEC: falta su ancla de confianza. Se activa la de Debian."
    if [[ -f $anchor.bak ]]; then
        mv "$anchor.bak" "$anchor"
    else
        printf 'server:\n    auto-trust-anchor-file: "/var/lib/unbound/root.key"\n' >"$anchor"
        created=1
    fi
    # El ancla nueva necesita reiniciar (unbound-helper la prepara al arrancar).
    if unbound-checkconf >/dev/null 2>&1 && systemctl restart unbound && unbound_wait_alive && unbound_validates 75; then
        info "Unbound valida DNSSEC (rechaza dnssec-failed.org, marca cloudflare.com como validado)."
        return 0
    fi
    if ((created)); then rm -f "$anchor"; else mv "$anchor" "$anchor.bak"; fi
    systemctl restart unbound || true
    [[ $current_dnssec == true ]] && fail "No se pudo activar DNSSEC en Unbound (revertido). \
Pi-hole no se ha modificado: desactivar su DNSSEC dejaría la red sin validación."
    warn "No se pudo activar DNSSEC en Unbound (revertido)."
}

if [[ $current_dnssec == true ]] || [[ $current_upstreams != *"$PROXY_UPSTREAM"* ]]; then
    ensure_unbound_dnssec
elif ! unbound_validates 75; then
    warn "Unbound no valida DNSSEC. Comprueba /etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf"
fi

# --- Ajustes de Unbound (fichero propio; nunca se edita pi-hole.conf) ----------

tune_unbound() {
    local desired validated=0 had=0 had_old=0 ok=0 effective
    desired="$(mktemp)"
    cat >"$desired" <<EOF
# Gestionado por el instalador de cf-unblock-dns.
server:
    # Registra en el journal los fallos de validación DNSSEC con su motivo.
    val-log-level: 2
    # El proxy abre una conexión TCP por consulta TCP de Pi-hole; con las 10
    # por defecto Unbound cerraba conexiones en las ráfagas.
    incoming-num-tcp: $UNBOUND_TCP_SLOTS
EOF
    if [[ ! -f $OLD_UNBOUND_CONF && -f $UNBOUND_CONF ]] && cmp -s "$desired" "$UNBOUND_CONF"; then
        rm -f "$desired"
        info "Unbound ya tiene los ajustes ($UNBOUND_TCP_SLOTS conexiones TCP); no se recarga."
        return 0
    fi
    unbound_validates_once && validated=1
    if [[ -f $UNBOUND_CONF ]]; then
        cp -a "$UNBOUND_CONF" "$UNBOUND_CONF.prev"
        had=1
    fi
    # El fichero de la versión anterior se sustituye por el nuevo en la misma
    # recarga (".prev" no termina en .conf, así que Unbound no lo incluye).
    if [[ -f $OLD_UNBOUND_CONF ]]; then
        mv "$OLD_UNBOUND_CONF" "$OLD_UNBOUND_CONF.prev"
        had_old=1
    fi
    install -o root -g root -m 0644 "$desired" "$UNBOUND_CONF"
    rm -f "$desired"
    if unbound_apply; then
        effective="$(unbound-control get_option incoming-num-tcp 2>/dev/null || true)"
        ok=1
        [[ $effective == "$UNBOUND_TCP_SLOTS" ]] || ok=0
        # Si validaba DNSSEC antes, tiene que seguir haciéndolo.
        if ((ok && validated)) && ! unbound_validates 75; then ok=0; fi
    fi
    if ((ok)); then
        rm -f "$UNBOUND_CONF.prev" "$OLD_UNBOUND_CONF.prev"
        info "Unbound ajustado: $UNBOUND_TCP_SLOTS conexiones TCP simultáneas y registro de fallos DNSSEC."
        return 0
    fi
    if ((had)); then mv "$UNBOUND_CONF.prev" "$UNBOUND_CONF"; else rm -f "$UNBOUND_CONF"; fi
    if ((had_old)); then mv "$OLD_UNBOUND_CONF.prev" "$OLD_UNBOUND_CONF"; fi
    unbound_apply || systemctl restart unbound || true
    warn "Unbound no funcionó con los nuevos ajustes (efectivo: ${effective:-?}); se ha restaurado su configuración anterior."
}

if [[ $cfg_tune == yes ]]; then
    tune_unbound
elif [[ -f $OLD_UNBOUND_CONF && ! -f $UNBOUND_CONF ]]; then
    # Mismo contenido con el nombre nuevo; Unbound lo leerá en su próxima recarga.
    mv "$OLD_UNBOUND_CONF" "$UNBOUND_CONF"
fi
if [[ ! -s $STATE_DIR/previous-upstreams.json ]]; then
    if grep -qF "$PROXY_UPSTREAM" <<<"$current_upstreams"; then
        printf '%s\n' '["127.0.0.1#5335"]' >"$STATE_DIR/previous-upstreams.json"
    else
        # "[ 127.0.0.1#5335, ... ]" -> ["127.0.0.1#5335", ...]
        items="$(tr -d "[]\"'" <<<"$current_upstreams" | tr ', \t' '\n\n\n' | sed '/^$/d')"
        if [[ -z $items ]]; then
            echo '[]'
        else
            printf '[%s]\n' "$(sed 's/.*/"&"/' <<<"$items" | paste -sd, -)"
        fi >"$STATE_DIR/previous-upstreams.json"
    fi
fi
[[ -s $STATE_DIR/previous-dnssec ]] || printf '%s\n' "$current_dnssec" >"$STATE_DIR/previous-dnssec"

if [[ $current_upstreams == *"$PROXY_UPSTREAM"* && $current_dnssec == false ]]; then
    resolves 127.0.0.1 53 || warn "Pi-hole no responde a la prueba DNS; revisa: systemctl status pihole-FTL"
    info "Pi-hole ya usa $PROXY_UPSTREAM; no se modifica ni se reinicia."
    info "Instalación actualizada ($("$INSTALL_DIR/cfu" version))."
    info "Diagnóstico: cfu check · Configuración: sudo cfu config · Actualizar: sudo cfu update · Ayuda: cfu help"
    exit 0
fi

install -d -m 0755 "$BACKUP_DIR"
if [[ ! -e $PIHOLE_FIRST_BACKUP ]]; then
    cp -a "$PIHOLE_CONFIG" "$PIHOLE_FIRST_BACKUP"
    chmod 0600 "$PIHOLE_FIRST_BACKUP"
fi
RUN_BACKUP="$BACKUP_DIR/pihole.toml.$NAME-$(date +%Y%m%d-%H%M%S)"
cp -a "$PIHOLE_CONFIG" "$RUN_BACKUP"
chmod 0600 "$RUN_BACKUP"
info "Copia de seguridad de Pi-hole: $RUN_BACKUP"

restore_pihole() {
    warn "Restaurando la configuración previa de Pi-hole desde $RUN_BACKUP."
    systemctl stop pihole-FTL || true
    cp -a "$RUN_BACKUP" "$PIHOLE_CONFIG"
    systemctl start pihole-FTL || true
}

if [[ $current_dnssec == true ]]; then
    info "Desactivando la validación DNSSEC propia de Pi-hole: Unbound ya valida, y con ella activa"
    info "Pi-hole pediría firmas (bit DO) en todas las consultas y el proxy no podría sustituir ninguna IP."
    pihole-FTL --config dns.dnssec false >/dev/null \
        || { restore_pihole; fail "No se pudo cambiar dns.dnssec."; }
fi

info "Configurando Pi-hole para usar $PROXY_UPSTREAM (antes: $current_upstreams)."
pihole-FTL --config dns.upstreams "[\"$PROXY_UPSTREAM\"]" >/dev/null \
    || { restore_pihole; fail "No se pudo cambiar dns.upstreams."; }
[[ "$(pihole-FTL --config dns.upstreams)" == *"$PROXY_UPSTREAM"* ]] \
    || { restore_pihole; fail "Pi-hole no aceptó el nuevo upstream."; }

if ! systemctl restart pihole-FTL; then
    restore_pihole
    fail "No arrancó Pi-hole; se restauró su configuración anterior."
fi
ok=0
for _ in $(seq 1 15); do
    if resolves 127.0.0.1 53; then
        ok=1
        break
    fi
    sleep 1
done
if ((!ok)); then
    restore_pihole
    fail "La prueba DNS de Pi-hole falló; se restauró su configuración anterior."
fi

info "Instalación lista: dispositivos -> Pi-hole :53 -> cf-unblock-dns 127.0.0.1:$PROXY_PORT -> Unbound 127.0.0.1:$UNBOUND_PORT"
info "Diagnóstico: cfu check · Configuración: sudo cfu config · Actualizar: sudo cfu update"
info "Desinstalar: sudo cfu uninstall · Ayuda: cfu help"
