package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxInflightQueries = 1024
	tcpIdleTimeout     = 10 * time.Second
	statusInterval     = 30 * time.Second
	summaryInterval    = 600 * time.Second
	familyInterval     = 60 * time.Second
)

// maxDailyDomains caps the per-day list of rewritten names.
const maxDailyDomains = 500

type Stats struct {
	mu          sync.Mutex
	counters    map[string]int
	lastRewrite map[string]any
	today       DayStats
}

// DayStats survives restarts (it is saved in status.json and reloaded) so
// "today" means the calendar day, not the time since the last update.
type DayStats struct {
	Date     string         `json:"date"`
	Counters map[string]int `json:"counters"`
	Domains  map[string]int `json:"rewritten_domains"`
}

func newStats() *Stats { return &Stats{counters: map[string]int{}} }

func localDate() string { return time.Now().Format("2006-01-02") }

// rollDay must be called with the lock held.
func (s *Stats) rollDay() {
	if date := localDate(); s.today.Date != date {
		s.today = DayStats{Date: date, Counters: map[string]int{}, Domains: map[string]int{}}
	}
}

func (s *Stats) Inc(name string, amount int) {
	s.mu.Lock()
	s.counters[name] += amount
	s.rollDay()
	s.today.Counters[name] += amount
	s.mu.Unlock()
}

// AddRewrite counts a rewritten answer for a name in today's list.
func (s *Stats) AddRewrite(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollDay()
	if _, known := s.today.Domains[name]; known || len(s.today.Domains) < maxDailyDomains {
		s.today.Domains[name]++
	}
}

func (s *Stats) Today() DayStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rollDay()
	out := DayStats{Date: s.today.Date, Counters: map[string]int{}, Domains: map[string]int{}}
	for k, v := range s.today.Counters {
		out.Counters[k] = v
	}
	for k, v := range s.today.Domains {
		out.Domains[k] = v
	}
	return out
}

// RestoreToday reloads today's figures from a previous status.json.
func (s *Stats) RestoreToday(statusFile string) {
	raw, err := os.ReadFile(statusFile)
	if err != nil {
		return
	}
	var saved struct {
		Today DayStats `json:"today"`
	}
	if json.Unmarshal(raw, &saved) != nil || saved.Today.Date != localDate() {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.today = saved.Today
	if s.today.Counters == nil {
		s.today.Counters = map[string]int{}
	}
	if s.today.Domains == nil {
		s.today.Domains = map[string]int{}
	}
}

func (s *Stats) Snapshot() map[string]int {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make(map[string]int, len(s.counters))
	for k, v := range s.counters {
		out[k] = v
	}
	return out
}

func (s *Stats) SetLastRewrite(value map[string]any) {
	s.mu.Lock()
	s.lastRewrite = value
	s.mu.Unlock()
}

func (s *Stats) LastRewrite() map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lastRewrite
}

var errUpstreamTimeout = errors.New("tiempo de espera agotado")

type Upstream struct {
	Address string
	Timeout time.Duration
}

func (u *Upstream) Exchange(wire []byte, tcp bool) ([]byte, error) {
	var (
		response []byte
		err      error
	)
	if tcp {
		response, err = u.tcp(wire)
		var netErr net.Error
		if err != nil && !(errors.As(err, &netErr) && netErr.Timeout()) {
			// Unbound closes TCP connections it has no slot for (EOF or reset);
			// one retry usually lands on a free one.
			response, err = u.tcp(wire)
		}
	} else {
		response, err = u.udp(wire)
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return nil, errUpstreamTimeout
	}
	return response, err
}

func (u *Upstream) udp(wire []byte) ([]byte, error) {
	conn, err := net.Dial("udp", u.Address)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.Timeout))
	if _, err := conn.Write(wire); err != nil {
		return nil, err
	}
	bufp := udpBuffers.Get().(*[]byte)
	defer udpBuffers.Put(bufp)
	buf := *bufp
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n >= 12 && buf[0] == wire[0] && buf[1] == wire[1] && buf[2]&0x80 != 0 {
			return append([]byte(nil), buf[:n]...), nil
		}
	}
}

var udpBuffers = sync.Pool{New: func() any {
	buf := make([]byte, 65535)
	return &buf
}}

func (u *Upstream) tcp(wire []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", u.Address, u.Timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(u.Timeout))
	frame := make([]byte, 2+len(wire))
	binary.BigEndian.PutUint16(frame, uint16(len(wire)))
	copy(frame[2:], wire)
	if _, err := conn.Write(frame); err != nil {
		return nil, err
	}
	var header [2]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	data := make([]byte, binary.BigEndian.Uint16(header[:]))
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}
	if len(data) < 12 || data[0] != wire[0] || data[1] != wire[1] {
		return nil, errors.New("respuesta TCP no válida")
	}
	return data, nil
}

type DNSProxy struct {
	Upstream *Upstream
	Data     *PolicyData
	Selector *CandidateSelector
	Reach    *Reachability
	Families *FamilyMonitor
	Options  RewriteOptions
	Stats    *Stats
	slots    chan struct{}

	logMu      sync.Mutex
	lastLogged *lru[string, time.Time]
}

// rewriteLogInterval limits "Respuesta modificada" to once per name, type and
// change: under load every answer is rewritten and the journal would flood.
const rewriteLogInterval = time.Minute

func newDNSProxy(upstream *Upstream, data *PolicyData, selector *CandidateSelector, reach *Reachability,
	families *FamilyMonitor, opts RewriteOptions) *DNSProxy {
	return &DNSProxy{
		Upstream: upstream, Data: data, Selector: selector, Reach: reach, Families: families, Options: opts,
		Stats: newStats(), slots: make(chan struct{}, maxInflightQueries),
		lastLogged: newLRU[string, time.Time](maxCacheEntries),
	}
}

func (p *DNSProxy) shouldLog(key string) bool {
	p.logMu.Lock()
	defer p.logMu.Unlock()
	if last, ok := p.lastLogged.Get(key); ok && time.Since(last) < rewriteLogInterval {
		return false
	}
	p.lastLogged.Set(key, time.Now())
	return true
}

// Handle returns the answer for one query, or nil when nothing should be sent.
func (p *DNSProxy) Handle(wire []byte, tcp bool) []byte {
	p.Stats.Inc("queries", 1)
	query, parsed := parseQuery(wire)
	response, err := p.Upstream.Exchange(wire, tcp)
	if errors.Is(err, errUpstreamTimeout) {
		// Unbound keeps resolving and caches the answer; staying silent
		// makes the client retry instead of showing an error.
		p.Stats.Inc("upstream_timeouts", 1)
		name := "una consulta"
		if parsed {
			name = query.QName
		}
		warnf("Unbound tarda más de %.0f s con %s; sin respuesta para que el cliente reintente", p.Upstream.Timeout.Seconds(), name)
		return nil
	}
	if err != nil {
		p.Stats.Inc("upstream_failures", 1)
		errorf("Error consultando Unbound en %s: %v", p.Upstream.Address, err)
		return servfailFor(wire)
	}
	if !parsed {
		p.Stats.Inc("unparsed_queries", 1)
		return response
	}
	if !isProcessedQType(query.QType) {
		return response
	}
	if query.DNSSECOK {
		p.Stats.Inc("dnssec_ok_passthrough", 1)
		return response
	}
	online := func(int) bool { return true }
	if p.Families != nil {
		online = p.Families.Online
	}
	result := p.rewriteSafely(query, response, online)
	if result.Cloudflare {
		p.Stats.Inc("cloudflare_responses", 1)
	}
	if len(result.Detected) > 0 {
		p.Stats.Inc("locally_detected", len(result.Detected))
	}
	switch {
	case len(result.Substitutions) > 0:
		p.Stats.Inc("rewritten_responses", 1)
		p.Stats.AddRewrite(strings.TrimSuffix(query.QName, "."))
		p.Stats.Inc("rewritten_addresses", len(result.Substitutions))
		old := make([]netip.Addr, 0, len(result.Substitutions))
		for a := range result.Substitutions {
			old = append(old, a)
		}
		sortAddrs(old)
		parts := make([]string, 0, len(old))
		changes := map[string]string{}
		for _, a := range old {
			reason := "detección local"
			if result.Listed[a] {
				reason = "lista"
			}
			parts = append(parts, fmt.Sprintf("%s -> %s (%s)", a, result.Substitutions[a], reason))
			changes[a.String()] = result.Substitutions[a].String()
		}
		detail := strings.Join(parts, ", ")
		if p.shouldLog(query.QName + " " + typeName(query.QType) + " " + detail) {
			infof("Respuesta modificada para %s %s: %s", query.QName, typeName(query.QType), detail)
		}
		p.Stats.SetLastRewrite(map[string]any{"at": nowISO(), "name": query.QName, "changes": changes})
	case len(result.Listed) > 0 || len(result.Detected) > 0:
		p.Stats.Inc("unrewritten_blocked", 1)
	}
	return result.Wire
}

// rewriteSafely falls back to Unbound's answer if anything goes wrong.
func (p *DNSProxy) rewriteSafely(query QueryInfo, response []byte, online func(int) bool) (result RewriteResult) {
	defer func() {
		if recovered := recover(); recovered != nil {
			errorf("Error procesando la respuesta para %s (%v); se devuelve sin cambios", query.QName, recovered)
			p.Stats.Inc("rewrite_errors", 1)
			result = RewriteResult{Wire: response}
		}
	}()
	return rewriteResponse(query, response, p.Data.Get(), p.Selector, p.Options, p.Reach, online)
}

func (p *DNSProxy) ServeUDP(conn *net.UDPConn) error {
	buf := make([]byte, 65535)
	for {
		n, client, err := conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		select {
		case p.slots <- struct{}{}:
		default:
			p.Stats.Inc("dropped", 1)
			continue
		}
		go func(wire []byte, client netip.AddrPort) {
			defer func() { <-p.slots }()
			if response := p.Handle(wire, false); response != nil {
				_, _ = conn.WriteToUDPAddrPort(response, client)
			}
		}(append([]byte(nil), buf[:n]...), client)
	}
}

func (p *DNSProxy) ServeTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return nil
			}
			continue
		}
		go p.serveTCPConn(conn)
	}
}

func (p *DNSProxy) serveTCPConn(conn net.Conn) {
	defer conn.Close()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(tcpIdleTimeout))
		var header [2]byte
		if _, err := io.ReadFull(conn, header[:]); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(header[:])
		if length == 0 {
			return
		}
		wire := make([]byte, length)
		if _, err := io.ReadFull(conn, wire); err != nil {
			return
		}
		select {
		case p.slots <- struct{}{}:
		case <-time.After(p.Upstream.Timeout):
			p.Stats.Inc("dropped", 1)
			return
		}
		response := p.Handle(wire, true)
		<-p.slots
		if response == nil {
			return
		}
		frame := make([]byte, 2+len(response))
		binary.BigEndian.PutUint16(frame, uint16(len(response)))
		copy(frame[2:], response)
		_ = conn.SetWriteDeadline(time.Now().Add(p.Upstream.Timeout))
		if _, err := conn.Write(frame); err != nil {
			return
		}
	}
}

func nowISO() string { return time.Now().Format("2006-01-02T15:04:05-0700") }

func writeJSONAtomic(path string, payload any, indent bool) error {
	var (
		data []byte
		err  error
	)
	if indent {
		data, err = json.MarshalIndent(payload, "", "  ")
	} else {
		data, err = json.Marshal(payload)
	}
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err = tmp.Write(data); err == nil {
		err = tmp.Sync()
	}
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Chmod(name, 0o644)
	}
	if err == nil {
		err = os.Rename(name, path)
	}
	if err != nil {
		os.Remove(name)
	}
	return err
}

// maintenance refreshes connectivity, writes status.json and logs a periodic summary.
func (p *DNSProxy) maintenance(stop <-chan struct{}, statusFile string) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var nextFamily, nextStatus time.Time
	nextSummary := time.Now().Add(summaryInterval)
	lastSummary := ""
	for {
		select {
		case <-stop:
			return
		case now := <-ticker.C:
			if !now.Before(nextFamily) {
				nextFamily = now.Add(familyInterval)
				go p.Families.Refresh(p.Data.Get())
			}
			if statusFile != "" && !now.Before(nextStatus) {
				nextStatus = now.Add(statusInterval)
				p.writeStatus(statusFile)
			}
			if !now.Before(nextSummary) {
				nextSummary = now.Add(summaryInterval)
				if summary := formatCounters(p.Stats.Snapshot()); summary != lastSummary {
					lastSummary = summary
					infof("Resumen: %s", summary)
				}
			}
		}
	}
}

func formatCounters(counters map[string]int) string {
	keys := make([]string, 0, len(counters))
	for k := range counters {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, counters[k])
	}
	return strings.Join(parts, ", ")
}

func (p *DNSProxy) writeStatus(path string) {
	policy := p.Data.Get()
	var dataUpdated any
	if updated := p.Data.UpdatedAt(); updated != "" {
		dataUpdated = updated
	}
	reachSize := 0
	if p.Reach != nil {
		reachSize = p.Reach.Size()
	}
	var lastRewrite any
	if last := p.Stats.LastRewrite(); last != nil {
		lastRewrite = last
	}
	status := map[string]any{
		"updated_at":          nowISO(),
		"pid":                 os.Getpid(),
		"implementation":      "go",
		"version":             version,
		"counters":            p.Stats.Snapshot(),
		"families_online":     p.Families.Snapshot(),
		"blocked_entries":     policy.BlockedCount(),
		"cloudflare_prefixes": len(policy.cloudflare),
		"data_updated_at":     dataUpdated,
		"candidate_cache":     p.Selector.Size(),
		"reachability_cache":  reachSize,
		"last_rewrite":        lastRewrite,
		"today":               p.Stats.Today(),
	}
	if err := writeJSONAtomic(path, status, true); err != nil {
		errorf("No se pudo escribir %s: %v", path, err)
	}
}
