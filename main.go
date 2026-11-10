// Command cfu (cf-unblock-dns) is a local DNS policy proxy between Pi-hole and Unbound.
//
// Pi-hole forwards to it; it forwards the untouched query to Unbound and, in
// the answer, rewrites in place A/AAAA records and HTTPS/SVCB address hints
// that point to a blocked Cloudflare address with a neighbouring address of
// the same prefix. A replacement is only used after this host has completed
// a TLS handshake with it for the queried name.
//
// An address counts as blocked when it is on the downloaded list or when it
// does not accept TCP connections from this host: the LXC sits on the same
// ISP line as the clients, so it sees the block first-hand.
//
// See usageText for the subcommands.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// version is the release number, shown by `version`, the logs and status.json.
// It is a variable so a build can stamp another one: -ldflags "-X main.version=…".
var version = "4.1.0"

const (
	installDir   = "/opt/cf-unblock-dns"
	dataDir      = "/var/lib/cf-unblock-dns"
	stateDir     = "/etc/cf-unblock-dns"
	defaultsFile = "/etc/default/cf-unblock-dns"
	serviceUser  = "cf-unblock-dns"
)

const usageText = `cfu: cf-unblock-dns, sustituye en las respuestas DNS las IPs de Cloudflare bloqueadas.

Uso: cfu ORDEN [opciones]

  cfu status              estado: lista, webs desbloqueadas hoy, errores
  cfu check [DOMINIO]     diagnóstico completo (con DOMINIO, simula un bloqueo)
  cfu config              cambiar la configuración (asistente)
  cfu update              actualizar cf-unblock-dns a la última versión
  cfu update --check      solo comprobar si hay una versión nueva
  cfu list update         descargar ya la lista de IPs bloqueadas (se hace sola)
  cfu alerts test         enviar un aviso de prueba a la URL configurada
  cfu uninstall           desinstalar y devolver Pi-hole a su configuración
  cfu version             versión instalada
  cfu serve [opciones]    proxy DNS (lo arranca el servicio; cfu serve -h)

Las órdenes que necesitan root se relanzan solas con sudo.
`

func main() {
	os.Exit(dispatch(os.Args[1:]))
}

func dispatch(args []string) int {
	if len(args) == 0 {
		fmt.Print(usageText)
		return 0
	}
	if needsRoot(args) && !isRootOrService(args) {
		return elevate(args)
	}
	switch args[0] {
	case "serve":
		return runProxy(args[1:])
	case "update":
		return runSelfUpdate(args[1:])
	case "list":
		if len(args) > 1 && args[1] == "update" {
			return runListUpdate(args[2:])
		}
		fmt.Fprint(os.Stderr, "Uso: cfu list update [--loop SEGUNDOS] [--verbose]\n")
		return 2
	case "alerts":
		if len(args) > 1 && args[1] == "test" {
			return runAlertTest()
		}
		fmt.Fprint(os.Stderr, "Uso: cfu alerts test\n")
		return 2
	case "status":
		return runStatus(args[1:])
	case "check":
		return runInstalledScript("check.sh", args[1:])
	case "config":
		return runInstalledScript("install.sh", args[1:])
	case "uninstall":
		return runInstalledScript("uninstall.sh", args[1:])
	case "version", "--version", "-version", "-v":
		fmt.Println("cf-unblock-dns " + version)
		return 0
	case "help", "-h", "-help", "--help":
		fmt.Print(usageText)
		return 0
	}
	if strings.HasPrefix(args[0], "-") {
		// Options without a subcommand (e.g. --self-test DOMINIO) belong to the proxy.
		return runProxy(args)
	}
	fmt.Fprintf(os.Stderr, "Orden desconocida: %s\n\n%s", args[0], usageText)
	return 2
}

func seconds(value float64) time.Duration { return time.Duration(value * float64(time.Second)) }

// needsRoot reports whether an order changes the installation or reads
// root-only files (Pi-hole's configuration, the journal, the alert URL).
func needsRoot(args []string) bool {
	switch args[0] {
	case "check", "config", "uninstall", "alerts":
		return true
	case "list":
		return len(args) > 1 && args[1] == "update"
	case "update":
		for _, arg := range args[1:] {
			if arg == "--check" || arg == "-check" || arg == "-h" || arg == "--help" {
				return false
			}
		}
		return true
	}
	return false
}

// isRootOrService: root, or the service account for the orders it runs
// itself (the updater loop and the installer's first download).
func isRootOrService(args []string) bool {
	if runtime.GOOS != "linux" || os.Geteuid() == 0 {
		return true
	}
	current, err := user.Current()
	return err == nil && current.Username == serviceUser && (args[0] == "list" || args[0] == "alerts")
}

// elevate runs the same order again through sudo.
func elevate(args []string) int {
	self, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if _, err := exec.LookPath("sudo"); err != nil {
		fmt.Fprintf(os.Stderr, "cfu %s necesita root: ejecútalo como root.\n", args[0])
		return 1
	}
	return runAttached("sudo", append([]string{self}, args...)...)
}

// runInstalledScript runs one of the installed shell scripts with the
// terminal attached (the installer asks questions).
func runInstalledScript(name string, args []string) int {
	path := filepath.Join(installDir, name)
	if _, err := os.Stat(path); err != nil {
		fmt.Fprintf(os.Stderr, "No se encuentra %s: ¿está instalado cf-unblock-dns?\n", path)
		return 1
	}
	return runAttached("bash", append([]string{path}, args...)...)
}

func runAttached(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return exit.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

// readDefaults parses the KEY=value lines of the installer's configuration
// file without executing it. Missing files yield an empty map.
func readDefaults(path string) map[string]string {
	values := map[string]string{}
	raw, err := os.ReadFile(path)
	if err != nil {
		return values
	}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		key, value, found := strings.Cut(line, "=")
		if !found || line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && (value[0] == '"' || value[0] == '\'') && value[len(value)-1] == value[0] {
			value = value[1 : len(value)-1]
		}
		values[strings.TrimSpace(key)] = value
	}
	return values
}

// setting returns an environment variable or, when unset, its value in the
// configuration file (manual runs do not get the service's environment).
func setting(name string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return readDefaults(defaultsFile)[name]
}

func runListUpdate(args []string) int {
	flags := flag.NewFlagSet("cfu list update", flag.ExitOnError)
	loop := flags.Float64("loop", 0, "repetir cada SEGUNDOS (mínimo 5)")
	verbose := flags.Bool("verbose", false, "registro detallado")
	_ = flags.Parse(args)

	// Run as the service account so the data files keep their owner.
	if os.Geteuid() == 0 {
		if _, err := user.Lookup(serviceUser); err == nil {
			self, err := os.Executable()
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return 1
			}
			cmd := append([]string{"-u", serviceUser, "--", self, "list", "update"}, args...)
			return runAttached("runuser", cmd...)
		}
	}

	level := "INFO"
	if *verbose {
		level = "DEBUG"
	}
	_ = configureLogging(level)
	updater := newUpdater()
	if *loop > 0 {
		updater.Health = newHealthMonitor(updater.ListOK)
		updater.Loop(seconds(max(5, *loop)))
		return 0
	}
	entries, err := updater.Update()
	if err != nil {
		if errors.Is(err, fs.ErrPermission) {
			errorf("Sin permiso para escribir %s: ejecuta  sudo cfu list update", updater.DataFile)
		} else {
			errorf("Fallo al actualizar (se conservan los datos actuales): %v", err)
		}
		return 1
	}
	infof("Lista de IPs bloqueadas al día: %d entradas (%s).", entries, updater.BlockedURL)
	return 0
}

func runStatus(args []string) int {
	fs := flag.NewFlagSet("cfu status", flag.ExitOnError)
	dir := fs.String("data-dir", dataDir, "directorio de datos")
	_ = fs.Parse(args)
	return printStatus(*dir)
}

func runProxy(args []string) int {
	fs := flag.NewFlagSet("cfu serve", flag.ExitOnError)
	listen := fs.String("listen", "127.0.0.1", "dirección de escucha")
	port := fs.Int("port", 5336, "puerto de escucha")
	upstreamHost := fs.String("upstream", "127.0.0.1", "dirección de Unbound")
	upstreamPort := fs.Int("upstream-port", 5335, "puerto de Unbound")
	dataPath := fs.String("data", filepath.Join(dataDir, "data.json"), "datos de la lista y prefijos")
	extraPath := fs.String("extra-blocked", filepath.Join(stateDir, "extra-blocked.txt"),
		"lista manual de IPs/rangos a tratar como bloqueados (una por línea)")
	statusFile := fs.String("status-file", filepath.Join(dataDir, "status.json"), "fichero de estado")
	timeout := fs.Float64("timeout", 4.0, "espera máxima a Unbound (s)")
	cloudflareTTL := fs.Int("cloudflare-max-ttl", defaultCloudflareMaxTTL,
		"TTL máximo para respuestas con direcciones Cloudflare; 0 lo desactiva")
	rewrittenTTL := fs.Int("rewritten-ttl", defaultRewrittenTTL, "TTL de las respuestas reescritas")
	noLocal := fs.Bool("no-local-detection", false,
		"usar solo la lista descargada, sin comprobar conectividad desde este equipo")
	reachTimeout := fs.Float64("reachability-timeout", reachabilityTimeout.Seconds(), "espera de la comprobación TCP (s)")
	probeTimeoutFlag := fs.Float64("probe-timeout", probeTimeout.Seconds(), "espera de cada sonda TLS (s)")
	budget := fs.Float64("probe-budget", probeBudget.Seconds(), "tiempo máximo para elegir candidata (s)")
	selfTestDomain := fs.String("self-test", "", "simula un bloqueo de DOMINIO y prueba la sustitución")
	logLevel := fs.String("log-level", "INFO", "DEBUG, INFO, WARNING o ERROR")
	_ = fs.Parse(args)
	if *rewrittenTTL < 1 || *cloudflareTTL < 0 {
		fmt.Fprintln(os.Stderr, "--rewritten-ttl debe ser >= 1 y --cloudflare-max-ttl >= 0")
		return 2
	}
	if err := configureLogging(*logLevel); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}

	upstream := &Upstream{net.JoinHostPort(*upstreamHost, strconv.Itoa(*upstreamPort)), seconds(*timeout)}
	data := newPolicyData(*dataPath, *extraPath)
	if *selfTestDomain != "" {
		return selfTest(*selfTestDomain, upstream, data, seconds(*probeTimeoutFlag))
	}

	families := newFamilyMonitor()
	families.Refresh(data.Get())
	var reach *Reachability
	if !*noLocal {
		reach = newReachability(families)
		reach.Timeout = seconds(*reachTimeout)
	}
	selector := newCandidateSelector(TLSProber{seconds(*probeTimeoutFlag)}.Probe, reach)
	selector.Budget = seconds(*budget)
	proxy := newDNSProxy(upstream, data, selector, reach, families,
		RewriteOptions{uint32(*cloudflareTTL), uint32(*rewrittenTTL)})

	address := net.JoinHostPort(*listen, strconv.Itoa(*port))
	udpAddr, err := net.ResolveUDPAddr("udp", address)
	if err != nil {
		errorf("Dirección de escucha no válida %s: %v", address, err)
		return 1
	}
	udp, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		errorf("No se pudo escuchar en %s/udp: %v", address, err)
		return 1
	}
	tcp, err := net.Listen("tcp", address)
	if err != nil {
		errorf("No se pudo escuchar en %s/tcp: %v", address, err)
		return 1
	}
	if *statusFile != "" {
		if info, err := os.Stat(filepath.Dir(*statusFile)); err != nil || !info.IsDir() {
			*statusFile = ""
		}
	}

	if *statusFile != "" {
		proxy.Stats.RestoreToday(*statusFile)
	}
	stop := make(chan struct{})
	go proxy.maintenance(stop, *statusFile)
	go func() { _ = proxy.ServeUDP(udp) }()
	go func() { _ = proxy.ServeTCP(tcp) }()
	localDetection := "activada"
	if reach == nil {
		localDetection = "desactivada"
	}
	infof("cf-unblock-dns %s escuchando en %s UDP/TCP; upstream %s; TTL Cloudflare <= %ds; detección local %s",
		version, address, upstream.Address, *cloudflareTTL, localDetection)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, os.Interrupt)
	<-signals
	infof("Deteniendo proxy DNS")
	close(stop)
	udp.Close()
	tcp.Close()
	return 0
}
