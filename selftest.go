package main

import (
	"bufio"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

var coloPattern = regexp.MustCompile(`(?m)^colo=(\w+)`)

// httpsTrace fetches /cdn-cgi/trace through an address with SNI/Host hostname.
func httpsTrace(hostname string, a netip.Addr) (int, string, error) {
	conn, err := net.DialTimeout("tcp", netip.AddrPortFrom(a, 443).String(), 5*time.Second)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(8 * time.Second))
	client := tls.Client(conn, &tls.Config{ServerName: hostname, MinVersion: tls.VersionTLS12})
	request := "GET /cdn-cgi/trace HTTP/1.1\r\nHost: " + hostname +
		"\r\nUser-Agent: cf-unblock-dns-selftest\r\nConnection: close\r\n\r\n"
	if _, err := client.Write([]byte(request)); err != nil {
		return 0, "", err
	}
	reader := bufio.NewReader(client)
	var body strings.Builder
	buf := make([]byte, 4096)
	for body.Len() < 65536 {
		n, err := reader.Read(buf)
		body.Write(buf[:n])
		if err != nil {
			break
		}
	}
	text := body.String()
	status := 0
	if fields := strings.Fields(strings.SplitN(text, "\r\n", 2)[0]); len(fields) > 1 {
		status, _ = strconv.Atoi(fields[1])
	}
	colo := "?"
	if match := coloPattern.FindStringSubmatch(text); match != nil {
		colo = match[1]
	}
	return status, colo, nil
}

func yesNo(value bool) string {
	if value {
		return "sí"
	}
	return "no"
}

func selfTest(hostname string, upstream *Upstream, data *PolicyData, probeTimeout time.Duration) int {
	hostname = sniHostname(hostname)
	if hostname == "" {
		fmt.Println("Nombre no válido para SNI")
		return 2
	}
	families := newFamilyMonitor()
	policy := data.Get()
	families.Refresh(policy)
	reach := newReachability(families)
	selector := newCandidateSelector(TLSProber{probeTimeout}.Probe, reach)
	fmt.Printf("Datos: %d entradas bloqueadas, %d prefijos Cloudflare\n", policy.BlockedCount(), len(policy.cloudflare))
	fmt.Printf("Conectividad: IPv4 %s, IPv6 %s\n", yesNo(families.Online(4)), yesNo(families.Online(6)))

	var addresses []netip.Addr
	for _, qtype := range []uint16{typeA, typeAAAA} {
		response, err := upstream.Exchange(buildQuery(hostname, qtype), false)
		if err != nil {
			fmt.Printf("%s: error consultando Unbound: %v\n", typeName(qtype), err)
			continue
		}
		msg, err := parseMessage(response)
		if err != nil {
			fmt.Printf("%s: respuesta no válida: %v\n", typeName(qtype), err)
			continue
		}
		for _, r := range msg.Records {
			if r.Section == 1 && (r.Type == typeA && r.RDLength == 4 || r.Type == typeAAAA && r.RDLength == 16) {
				addresses = append(addresses, slotAddr(response, addrSlot{r.RDataOffset, r.RDLength, r.Type}))
			}
		}
	}
	if len(addresses) == 0 {
		fmt.Printf("%s no tiene registros A/AAAA\n", hostname)
		return 2
	}
	verified, seen := 0, 0
	for _, a := range addresses {
		prefix, isCF := policy.CloudflarePrefix(a)
		where := "fuera de Cloudflare"
		if isCF {
			where = "Cloudflare " + prefix.String()
		}
		listed := "no listada"
		if policy.IsListed(a) {
			listed = "en la lista"
		}
		tcp := "SIN CONEXIÓN"
		if tcpConnect(a, 443, 2*time.Second) {
			tcp = "OK"
		}
		fmt.Printf("\n%s: %s, %s, TCP/443 %s\n", a, where, listed, tcp)
		if !isCF {
			continue
		}
		if !families.Online(familyOf(a)) {
			fmt.Printf("  IPv%d no disponible desde este equipo: no se puede verificar\n", familyOf(a))
			continue
		}
		seen++
		started := time.Now()
		candidate, ok := selector.Choose(hostname, a, policy.WithExtraBlocked([]netip.Addr{a}), nil, false)
		elapsed := time.Since(started).Milliseconds()
		if !ok {
			fmt.Printf("  Simulando bloqueo: sin candidata verificada (%d ms)\n", elapsed)
			continue
		}
		fmt.Printf("  Simulando bloqueo: candidata %s verificada por TLS en %d ms\n", candidate, elapsed)
		status, colo, err := httpsTrace(hostname, candidate)
		if err != nil {
			fmt.Printf("  HTTPS GET /cdn-cgi/trace vía %s: error %v\n", candidate, err)
			continue
		}
		fmt.Printf("  HTTPS GET /cdn-cgi/trace vía %s: HTTP %d, colo=%s\n", candidate, status, colo)
		if status >= 200 && status < 500 {
			verified++
		}
	}
	if seen == 0 {
		fmt.Println("\nNinguna dirección verificable está en Cloudflare; prueba con otro dominio.")
		return 2
	}
	fmt.Printf("\nResultado: %d/%d sustituciones funcionan de extremo a extremo\n", verified, seen)
	if verified == 0 {
		return 1
	}
	return 0
}

// printStatus summarizes data.json, update-state.json and status.json for check.sh.
func printStatus(dataDir string) int {
	code := 0
	var data struct {
		UpdatedAt    string   `json:"updated_at"`
		Blocked      []string `json:"blocked"`
		CloudflareV4 []string `json:"cloudflare_v4"`
		CloudflareV6 []string `json:"cloudflare_v6"`
	}
	if raw, err := os.ReadFile(filepath.Join(dataDir, "data.json")); err != nil {
		fmt.Printf("  [FALLO] datos: %v\n", err)
		code = 1
	} else if err := json.Unmarshal(raw, &data); err != nil {
		fmt.Printf("  [FALLO] datos: %v\n", err)
		code = 1
	} else {
		age := "?"
		if updated, err := time.Parse(time.RFC3339Nano, data.UpdatedAt); err == nil {
			age = fmt.Sprintf("%.0f min", time.Since(updated).Minutes())
		}
		fmt.Printf("  Lista: %d entradas bloqueadas; prefijos Cloudflare: %d IPv4 / %d IPv6; último cambio hace %s\n",
			len(data.Blocked), len(data.CloudflareV4), len(data.CloudflareV6), age)
	}
	if state := loadJSONMap(filepath.Join(dataDir, "update-state.json")); state != nil {
		fmt.Printf("  Última comprobación de la lista hace %.0f s\n", unixNow()-stateFloat(state, "checked_at"))
	}
	var status struct {
		UpdatedAt      string          `json:"updated_at"`
		Implementation string          `json:"implementation"`
		Version        string          `json:"version"`
		Families       map[string]bool `json:"families_online"`
		Counters       map[string]int  `json:"counters"`
		LastRewrite    json.RawMessage `json:"last_rewrite"`
		Today          DayStats        `json:"today"`
	}
	raw, err := os.ReadFile(filepath.Join(dataDir, "status.json"))
	if err == nil {
		err = json.Unmarshal(raw, &status)
	}
	if err != nil {
		fmt.Printf("  [AVISO] estado del proxy no disponible: %v\n", err)
		return code
	}
	implementation := status.Implementation
	if implementation == "" {
		implementation = "python"
	}
	if status.Version != "" {
		implementation += " " + status.Version
	}
	fmt.Printf("  Estado (%s, versión %s): IPv4 %s, IPv6 %s\n", status.UpdatedAt, implementation,
		yesNo(status.Families["ipv4"]), yesNo(status.Families["ipv6"]))
	if len(status.Counters) == 0 {
		fmt.Println("  Contadores: sin consultas aún")
	} else {
		keys := make([]string, 0, len(status.Counters))
		for k := range status.Counters {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = fmt.Sprintf("%s=%d", k, status.Counters[k])
		}
		fmt.Println("  Contadores: " + strings.Join(parts, ", "))
	}
	printToday(status.Today)
	if len(status.LastRewrite) > 0 && string(status.LastRewrite) != "null" {
		fmt.Printf("  Última reescritura: %s\n", status.LastRewrite)
	}
	return code
}

// printToday shows today's unblocked sites and Unbound errors.
func printToday(today DayStats) {
	if today.Date != localDate() {
		return
	}
	c := today.Counters
	fmt.Printf("  Hoy: %d consultas; %d respuestas con IPs sustituidas en %d webs\n",
		c["queries"], c["rewritten_responses"], len(today.Domains))
	if len(today.Domains) > 0 {
		names := topDomains(today.Domains, 15)
		parts := make([]string, len(names))
		for i, name := range names {
			parts[i] = fmt.Sprintf("%s (%d)", name, today.Domains[name])
		}
		more := ""
		if len(today.Domains) > len(names) {
			more = fmt.Sprintf(" y %d más", len(today.Domains)-len(names))
		}
		fmt.Printf("  Webs desbloqueadas hoy: %s%s\n", strings.Join(parts, ", "), more)
	}
	fmt.Printf("  Errores con Unbound hoy: %d de conexión (SERVFAIL), %d sin respuesta a tiempo\n",
		c["upstream_failures"], c["upstream_timeouts"])
}
