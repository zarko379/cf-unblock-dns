# cf-unblock-dns

Proxy DNS para Pi-hole 6 + Unbound que esquiva los bloqueos indiscriminados de IPs de Cloudflare (los cortes de LaLiga que tiran webs legítimas) sin VPN, sin WARP, sin iptables y sin convertir el LXC en gateway.

Escrito en Go: un único binario estático, sin Python ni otras dependencias en el LXC. Sustituye a una versión anterior en Python (BPasserr DNS), de la que el instalador migra solo una instalación existente. Todo se maneja con la orden `cfu`. Ver [Rendimiento](#rendimiento).

```text
Dispositivo → Pi-hole :53 → cf-unblock-dns 127.0.0.1:5336 → Unbound 127.0.0.1:5335 → DNS autoritativo
                                  └→ IP Cloudflare bloqueada → vecina del mismo prefijo, verificada por TLS
```

## Cómo funciona

Cloudflare sirve cualquier web desde cualquiera de sus direcciones anycast: el servidor elige el sitio por el SNI de TLS, no por la IP. Si el operador corta una IP compartida, otra IP del mismo prefijo sirve la misma web. cf-unblock-dns aplica esa idea en la respuesta DNS:

1. Unbound resuelve y valida DNSSEC como siempre. El proxy recibe su respuesta.
2. Cada dirección A/AAAA y cada `ipv4hint`/`ipv6hint` de los registros HTTPS/SVCB que esté en un prefijo oficial de Cloudflare se considera bloqueada si:
   - aparece en la lista pública de [hayahora.futbol](https://hayahora.futbol) (se consulta cada 15 s con peticiones condicionales), o
   - **no acepta conexiones TCP/443 desde el propio LXC**. El LXC está en la misma línea que tus dispositivos, así que ve el bloqueo de tu operador al instante, aunque la lista aún no lo recoja. Si ninguna dirección de su /24 responde en el 443 (servicios no web de Cloudflare como NTP o WARP), no se considera un bloqueo y se deja en paz durante una hora.
3. Para cada dirección bloqueada busca la vecina más cercana que no esté en la lista ni caída, y solo la usa tras completar desde el LXC un handshake TLS con certificado válido para el nombre consultado. Las direcciones de la lista pueden saltar a otro bloque del mismo prefijo; las detectadas localmente solo a una vecina de su propio /24. Si hay varias, se buscan en paralelo. La primera verificación de un nombre cuesta unos 15–50 ms; después queda en caché 5 minutos.
4. La sustitución se hace en el propio paquete: mismo tamaño, mismo orden y mismas opciones EDNS. Se borra el bit `AD`, porque la IP nueva ya no coincide con la firma DNSSEC.
5. Toda respuesta con direcciones Cloudflare sale con TTL ≤ 30 s, aunque no se haya cambiado nada, para que un corte nuevo llegue a los clientes en segundos. Unbound conserva su caché con el TTL original.

Si no hay candidata verificada, se devuelve la respuesta original. Fuera de Cloudflare no se cambia nada.

### Comparación con xdp.es

El proxy de [xdp.es](https://xdp.es) es público ([Oihalitz/xdp-dns-evadeproxy](https://github.com/Oihalitz/xdp-dns-evadeproxy), MIT). cf-unblock-dns sigue sus mismos principios sin compartir código:

| | xdp.es | cf-unblock-dns |
|---|---|---|
| Fuente de bloqueos | hayahora.futbol (IPv4) + sonda residencial propia | hayahora.futbol + detección desde tu propia línea (IPv4 e IPv6) |
| IP sustituta | vecina más cercana del mismo /24 no listada | igual, pero verificada con TLS para el nombre desde tu red |
| A, AAAA y hints HTTPS/SVCB | sí | sí |
| TTL de respuestas Cloudflare | ≤ 30 s | ≤ 30 s (configurable) |
| Consultas con DNSSEC (`DO`) | se reescriben igualmente | se devuelven intactas |
| Dónde resuelve | su servidor en Madrid | tu Unbound local, sin terceros |

No se pretende una equivalencia exacta con xdp.es ni se garantiza disponibilidad: depende de que Cloudflare siga sirviendo los sitios en direcciones no bloqueadas.

## Limitaciones

- Solo se actúa sobre los rangos oficiales de Cloudflare. Otras CDN bloqueadas (Fastly, Akamai, etc.) no se tocan.
- La detección local y la verificación TLS necesitan que el LXC tenga salida a Internet en esa familia. Si el LXC no tiene IPv6, las respuestas AAAA solo reciben el límite de TTL. Los clientes con IPv6 seguirán usando IPv4 si la IPv6 está cortada.
- Las consultas que piden DNSSEC (`DO`) no se reescriben: una IP cambiada nunca validaría. Los clientes habituales (navegadores, Windows, Android) no la piden.
- Pi-hole debe tener su DNSSEC desactivado (`dns.dnssec=false`); lo valida Unbound. El instalador lo ajusta y guarda el valor anterior.
- Con el optimizador de caché de Pi-hole (`dns.cache.optimizer`, activo por defecto), tras caducar una respuesta Pi-hole puede servirla una última vez mientras la refresca. Si quieres que un corte se note aún antes: `pihole-FTL --config dns.cache.optimizer -1`.
- Una verificación TLS correcta no garantiza que toda la web funcione igual; `check.sh DOMINIO` hace además una petición HTTPS real.
- Si Unbound tarda más de 4 s (servidores autoritativos lentos), el proxy no contesta en vez de devolver un error: el dispositivo reintenta y Unbound responde desde su caché. Si Unbound está caído, sí devuelve SERVFAIL.

## Requisitos

- LXC Debian/Ubuntu con Pi-hole v6 en el puerto 53 y Unbound en `127.0.0.1:5335` (amd64, arm64 o arm).
- Salida HTTPS desde el LXC. No hace falta Python ni Go; el instalador añade `dnsutils`, `ca-certificates` y `curl` si faltan.

## Instalación

En el LXC, como root:

```bash
curl -fsSL https://raw.githubusercontent.com/zarko379/cf-unblock-dns/main/get.sh | sudo bash
```

Descarga el paquete de la última [versión publicada](https://github.com/zarko379/cf-unblock-dns/releases) para tu arquitectura, comprueba su firma y su SHA-256 y lanza el asistente. No hay que editar ningún fichero:

```text
=== cf-unblock-dns: configuración ===
Lista de IPs bloqueadas (hayahora.futbol):
  1) Todos los operadores (recomendado)
  2) Movistar  3) DIGI  4) Vodafone  5) Orange  6) MásMóvil  7) Otra URL
Segundos entre descargas de la lista [15]:
TTL máximo de las respuestas de Cloudflare en segundos (0 = sin límite) [30]:
¿Detectar cortes desde este equipo además de la lista? (s/n) [s]:
¿Ajustar Unbound (256 conexiones TCP y registro de fallos DNSSEC)? (s/n) [s]:
¿Instalar solo las versiones nuevas? (revisa una vez por semana; si fallan, vuelve a la anterior) (s/n) [s]:
Avisos si algo deja de funcionar (Unbound, el proxy, Pi-hole o la lista):
URL de avisos:
```

Para no contestar nada (valores recomendados): `... | sudo bash -s -- -y`. También acepta `--list movistar`, `--interval 30`, `--max-ttl 30`, `--local-detection si|no`, `--tune-unbound si|no`, `--auto-update si|no` y `--notify-url URL|no`.

### Qué hace el instalador

1. Comprueba Pi-hole v6, que Unbound responde, que el puerto 5336 está libre y que no quedan restos del BPasserr original (Redsocks/iptables).
2. Instala `cfu` en `/opt/cf-unblock-dns` (con el enlace `/usr/local/bin/cfu`) y la cuenta sin privilegios `cf-unblock-dns`, y descarga las listas iniciales.
3. Arranca `cf-unblock-dns.service` y `cf-unblock-dns-update.service`. Si el LXC no permite el aislamiento de systemd (contenedor sin *nesting*), aplica una configuración compatible.
4. Comprueba el proxy por UDP y TCP.
5. Comprueba que Unbound valida DNSSEC, porque Pi-hole dejará de hacerlo. Si no valida por faltarle el ancla de confianza de Debian (`root-auto-trust-anchor-file.conf`, a veces renombrado a `.bak`), la reactiva, reinicia Unbound y verifica que rechaza `dnssec-failed.org`; si algo falla, lo revierte y no toca Pi-hole.
6. Solo entonces toca Pi-hole: guarda una copia de `pihole.toml`, pone `dns.dnssec=false` si hacía falta y cambia el upstream a `127.0.0.1#5336`. Si Pi-hole no arranca o no resuelve, restaura la copia.

No cambia `ip_forward`, rutas, gateway, iptables/nftables ni Proxmox. De Unbound solo toca el ancla de confianza y su propio fichero. Si Pi-hole ya apunta al proxy, no lo toca ni lo reinicia.

Si aceptas "Ajustar Unbound", crea `/etc/unbound/unbound.conf.d/cf-unblock-dns.conf` (nunca toca `pi-hole.conf`) con 256 conexiones TCP simultáneas —con las 10 por defecto Unbound cerraba conexiones en las ráfagas— y el registro de los fallos de validación DNSSEC con su motivo. Solo recarga Unbound si el fichero cambia (conservando su caché), comprueba que resuelve y sigue validando, y si no lo deshace.

**Desde BPasserr DNS (3.x):** si encuentra `/opt/bpasserr-dns`, copia su configuración, la lista manual, los datos y el upstream previo de Pi-hole; para cada servicio antiguo justo antes de arrancar el nuevo (el corte es de un segundo) y, cuando el proxy nuevo responde, borra servicios, ficheros y cuenta antiguos. Si el nuevo no arranca, vuelve a poner en marcha el antiguo.

## Uso

```text
cfu status              estado: lista, webs desbloqueadas hoy y errores con Unbound
cfu check [DOMINIO]     diagnóstico completo (con DOMINIO, simula un bloqueo)
cfu config              cambiar la configuración (el mismo asistente, con los valores actuales)
cfu update              actualizar cf-unblock-dns a la última versión
cfu update --check      solo comprobar si hay una versión nueva
cfu list update         descargar ya la lista de IPs bloqueadas (se hace sola cada 15 s)
cfu alerts test         enviar un aviso de prueba
cfu uninstall           desinstalar
cfu version             versión instalada
```

Las órdenes que necesitan root (`check`, `config`, `update`, `list update`, `alerts`, `uninstall`) se relanzan solas con `sudo`; `status`, `version` y `update --check` funcionan con cualquier usuario.

### Actualizar

```bash
sudo cfu update
```

Consulta la última versión publicada en GitHub; si es más nueva que la instalada, descarga el paquete de tu arquitectura, comprueba la firma Ed25519 de `SHA256SUMS` con la clave pública que lleva el propio `cfu` instalado, comprueba el SHA-256 del paquete y ejecuta su instalador con `-y`, que conserva toda la configuración, la lista manual y el estado de Pi-hole. Sin firma válida no instala nada. Si la instalación falla, reinstala la versión que había. `--force` reinstala aunque ya esté al día.

Con la actualización automática activada (pregunta del asistente, o `cfu config -y --auto-update si`), el temporizador `cf-unblock-dns-autoupdate.timer` ejecuta `cfu update` los domingos hacia las 4:00 (con hasta 2 h de margen aleatorio, y al arrancar si se perdió una ejecución). Las instalaciones anteriores a la 4.1.0 la tienen desactivada hasta que la actives. `cfu check` muestra la próxima ejecución y el resultado de la última.

**Qué protege la firma**: `cfu update` solo acepta versiones firmadas con la clave del mantenedor, aunque alguien modificase los ficheros de una versión en GitHub. `get.sh` comprueba la misma firma, pero su clave pública viene del mismo repositorio, así que en una instalación nueva protege frente a ficheros alterados, no frente a alguien que controle la cuenta de GitHub. Si la clave privada se perdiera, las instalaciones existentes rechazarían las versiones nuevas: habría que reinstalar una vez con `get.sh` (que lleva la clave nueva).

### Avisos

Si das una URL en el asistente, el actualizador comprueba cada 5 minutos que Unbound, el proxy y Pi-hole responden y que la lista se descarga. Tras dos comprobaciones fallidas seguidas envía un aviso, y otro cuando se recupera. Los avisos se envían resolviendo el nombre directamente con Unbound (no dependen de Pi-hole ni del proxy) y, si no se pueden enviar, se reintentan en la siguiente comprobación.

- **ntfy** (recomendado, sin cuenta): instala la app ntfy, suscríbete a un tema difícil de adivinar y usa `https://ntfy.sh/ESE-TEMA`.
- **Telegram**: crea un bot con @BotFather y usa `https://api.telegram.org/botTOKEN/sendMessage?chat_id=TU_ID`.

La URL se guarda en `/etc/cf-unblock-dns/notify-url`, legible solo por root y el servicio. Para probarla: `cfu alerts test`.

### Comprobación

```bash
sudo cfu check                               # servicios, puertos, Pi-hole, DNSSEC, TTL, estado
sudo cfu check www.cloudflare.com            # además simula un bloqueo en el selector y hace HTTPS real
sudo cfu check --simular www.cloudflare.com  # bloqueo simulado de extremo a extremo (ver abajo)
journalctl -u cf-unblock-dns -f              # verás "Respuesta modificada para ..."
```

"Respuesta modificada" se registra como mucho una vez por minuto para cada dominio y cambio; el total queda en los contadores de `status.json`.

`--simular` añade temporalmente las IPs del dominio a la lista manual y comprueba que el proxy y Pi-hole devuelven otras IPs y que la web carga por ellas. Al terminar, o si se interrumpe, deja la lista como estaba. Puede esperar hasta 31 s a que caduque la caché de Pi-hole. Solo tiene sentido con dominios servidos por Cloudflare.

El proxy escribe cada 30 s su estado (contadores, conectividad, última reescritura y las cifras del día) en `/var/lib/cf-unblock-dns/status.json`. `cfu status` muestra las webs desbloqueadas hoy y los errores con Unbound del día; esas cifras se conservan aunque el proxy se reinicie (por ejemplo, al actualizar).

### Lista manual

`/etc/cf-unblock-dns/extra-blocked.txt`: IPs o rangos que quieras tratar como bloqueados además de la lista descargada, uno por línea. Se aplica en un segundo, sin reiniciar nada.

### Desinstalación

```bash
sudo cfu uninstall
```

Devuelve Pi-hole al upstream y al valor de DNSSEC que tenía antes de instalar, comprueba que resuelve y elimina servicios, temporizadores, ficheros, la orden `cfu` y el fichero de ajustes de Unbound (recargándolo sin perder su caché). Se conservan la cuenta `cf-unblock-dns` y las copias `/var/backups/pihole.toml.cf-unblock-dns-*`.

## Rendimiento

Medido el 2026-11-03 en el LXC de producción (Proxmox, 4 núcleos, 2 GB, Debian 13), con un generador de carga UDP local contra cada servicio durante 5 s, 30 dominios ya en la caché de Unbound. La versión Python anterior estaba en el puerto de producción; la Go, una instancia temporal en otro puerto con los mismos datos.

| Consultas simultáneas | Unbound solo | Python | Go | Go frente a Python |
|---|---|---|---|---|
| 1 | 46.235 q/s · p50 0,020 ms | 4.122 q/s · p50 0,224 ms | 11.534 q/s · p50 0,081 ms | 2,8× q/s, latencia 2,8× menor |
| 8 | 149.946 q/s | 4.555 q/s · p50 1,68 ms · p99 3,35 ms | 31.555 q/s · p50 0,22 ms · p99 0,91 ms | 6,9× |
| 32 | 162.246 q/s | 4.498 q/s · p50 6,88 ms · p99 11,1 ms | 43.538 q/s · p50 0,69 ms · p99 1,98 ms | 9,7× |
| Reescritura, 1 | — | 2.232 q/s · p50 0,433 ms | 9.561 q/s · p50 0,099 ms | 4,3× |
| Reescritura, 8 | — | 2.269 q/s · p50 3,45 ms | 29.315 q/s · p50 0,233 ms | 12,9× |

| Recursos | Python | Go |
|---|---|---|
| CPU por consulta (8 simultáneas) | 310 µs | 53 µs (5,8× menos) |
| CPU por respuesta reescrita (8 simultáneas) | 558 µs | 70 µs (8× menos) |
| Memoria del proxy en reposo / bajo carga | 31 MB / 31 MB | 8–12 MB / 15–18 MB |
| Memoria del actualizador | ~26 MB | ~13 MB |
| Hilos del proxy | 15–25 | 9–13 |
| Arranque hasta la primera respuesta | ~0,16 s | ~0,05 s |
| Retardo añadido sobre Unbound (1 consulta) | +0,20 ms | +0,06 ms |

Python no pasa de ~4.500 consultas/s porque el GIL lo limita a un núcleo; Go usa todos. En las filas de reescritura, Python además escribía una línea en el journal por cada respuesta (la versión Go limita ese mensaje a uno por minuto por dominio), lo que explica parte de esa diferencia. Con la carga de una casa (decenas de consultas por segundo) ninguno de los dos se acerca a su límite, así que la diferencia práctica es menor latencia por consulta, menos memoria y CPU, y margen de sobra en picos. Elegir una IP sustituta la primera vez sigue costando lo que tarda el handshake TLS con Cloudflare (15–30 ms), igual en ambas versiones: depende de la red, no del lenguaje.

## Desarrollo

```bash
go vet ./...
go test ./...                       # pruebas sin red (también en GitHub Actions en cada push)
python -m py_compile deploy.py release.py
bash -n install.sh uninstall.sh check.sh get.sh
```

**Probar en el LXC sin publicar** (desde Windows o cualquier equipo con Go y `paramiko`):

```bash
python -m pip install -r requirements-dev.txt
cp .env.example .env        # SSH_HOST, SSH_USER y la contraseña o la clave
python deploy.py info       # estado del LXC, sin cambios
python deploy.py install    # compila para el uname -m del LXC, sube, ejecuta install.sh -y y el diagnóstico
python deploy.py check | simulate DOMINIO | logs
```

`deploy.py` lee `.env` sin mostrar nunca sus valores y enmascara cualquier contraseña en la salida; la huella del servidor queda en `.ssh_known_hosts` (ambos en `.gitignore`). `install --as-version 3.99.0` sube un binario que dice ser esa versión, para probar `cfu update` contra la última publicada.

**Publicar una versión**: sube `var version` en `main.go`, haz commit y push a `main`, espera a que GitHub Actions esté en verde y ejecuta `python release.py`. Pasa las pruebas, compila `cfu` para amd64, arm64 y arm, empaqueta cada uno con los scripts y los servicios, genera `SHA256SUMS` y lo firma (`SHA256SUMS.sig`), crea la etiqueta `vX.Y.Z` y publica la versión con `gh`. `release.py --dry-run` solo genera los paquetes en `dist/release`.

Una versión publicada no se modifica nunca: cualquier corrección es una versión nueva (las cachés de GitHub siguen sirviendo los ficheros antiguos un tiempo).

La clave de firma es `%LOCALAPPDATA%\cf-unblock-dns\release-signing.key` (o `CFU_SIGNING_KEY`) y nunca va al repositorio; la pública está en `selfupdate.go` y `get.sh`. `go run ./tools/signrelease public CLAVE` la muestra.

Código: `dnswire.go` (formato DNS), `policy.go` (lista, prefijos y lista manual), `probe.go` (TCP, TLS, conectividad, bloques no web), `selector.go` (vecinas y sondas), `rewrite.go` (reescritura en el paquete), `proxy.go` (UDP/TCP, estado), `update.go` (actualizador), `selftest.go` (autoprueba y `status`), `selfupdate.go` (`cfu update` y firma), `alerts.go` (comprobaciones y avisos), `main.go` (órdenes de `cfu`), `tools/signrelease` (firma de versiones).
