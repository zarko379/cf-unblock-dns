package main

// Health checks run inside the updater loop (no extra timer, no journal
// noise) and, when a URL is configured, send an alert after two failed
// rounds in a row and a recovery message when it works again.

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"net/http"
	neturl "net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	notifyURLFile        = stateDir + "/notify-url"
	healthInterval       = 5 * time.Minute
	failuresBeforeAlert  = 2
	listStaleAfter       = 30 * time.Minute
	unboundAddress       = "127.0.0.1:5335"
	maxPendingAlertLines = 20
)

type healthCheck struct {
	Name string
	Run  func() error
}

// dnsAnswers checks that a resolver answers example.com/A with NOERROR and
// at least one record.
func dnsAnswers(address string) func() error {
	return func() error {
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			if lastErr = queryOnce(address); lastErr == nil {
				return nil
			}
		}
		return lastErr
	}
}

func queryOnce(address string) error {
	conn, err := net.DialTimeout("udp", address, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	query := buildQuery("example.com", 1)
	if _, err := conn.Write(query); err != nil {
		return err
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("sin respuesta: %v", err)
	}
	answer := buf[:n]
	if n < 12 || answer[0] != query[0] || answer[1] != query[1] {
		return fmt.Errorf("respuesta no válida")
	}
	if rcode := answer[3] & 0x0f; rcode != 0 {
		return fmt.Errorf("código de respuesta %d", rcode)
	}
	if binary.BigEndian.Uint16(answer[6:]) == 0 {
		return fmt.Errorf("respuesta vacía")
	}
	return nil
}

// HealthMonitor debounces failures and queues the messages to send.
type HealthMonitor struct {
	Checks  []healthCheck
	Host    string
	URL     func() string // read on every round: changes apply without restarting
	Send    func(url, title, message string) error
	Now     func() time.Time
	mu      sync.Mutex
	streak  map[string]int
	alerted map[string]bool
	pending []string
	lastRun time.Time
}

func newHealthMonitor(listOK func() error) *HealthMonitor {
	host, _ := os.Hostname()
	return &HealthMonitor{
		Checks: []healthCheck{
			{"Unbound (" + unboundAddress + ")", dnsAnswers(unboundAddress)},
			{"proxy cf-unblock-dns (127.0.0.1:5336)", dnsAnswers("127.0.0.1:5336")},
			{"Pi-hole (puerto 53)", dnsAnswers("127.0.0.1:53")},
			{"descarga de la lista de bloqueos", listOK},
		},
		Host: host,
		URL:  readNotifyURL,
		Send: sendNotification,
		Now:  time.Now,
	}
}

// Due reports whether a new round should run.
func (m *HealthMonitor) Due() bool {
	return m.lastRun.IsZero() || m.Now().Sub(m.lastRun) >= healthInterval
}

// Run performs one round of checks and tries to deliver queued messages.
func (m *HealthMonitor) Run() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.streak == nil {
		m.streak, m.alerted = map[string]int{}, map[string]bool{}
	}
	m.lastRun = m.Now()
	for _, check := range m.Checks {
		err := check.Run()
		if err != nil {
			m.streak[check.Name]++
			if m.streak[check.Name] == failuresBeforeAlert && !m.alerted[check.Name] {
				m.alerted[check.Name] = true
				warnf("Comprobación fallida dos veces seguidas: %s: %v", check.Name, err)
				m.queue(fmt.Sprintf("FALLO: %s: %v", check.Name, err))
			}
			continue
		}
		m.streak[check.Name] = 0
		if m.alerted[check.Name] {
			m.alerted[check.Name] = false
			infof("Comprobación recuperada: %s", check.Name)
			m.queue("RECUPERADO: " + check.Name + " vuelve a funcionar")
		}
	}
	m.flush()
}

func (m *HealthMonitor) queue(line string) {
	m.pending = append(m.pending, m.Now().Format("15:04")+" "+line)
	if len(m.pending) > maxPendingAlertLines {
		m.pending = m.pending[len(m.pending)-maxPendingAlertLines:]
	}
}

// flush sends the queued lines; on failure they are kept for the next round
// (the notification may fail precisely because DNS or the network is down).
func (m *HealthMonitor) flush() {
	if len(m.pending) == 0 {
		return
	}
	url := m.URL()
	if url == "" {
		m.pending = nil
		return
	}
	title := "cf-unblock-dns en " + m.Host
	if err := m.Send(url, title, strings.Join(m.pending, "\n")); err != nil {
		warnf("No se pudo enviar el aviso (se reintentará): %v", err)
		return
	}
	m.pending = nil
}

func readNotifyURL() string {
	raw, err := os.ReadFile(notifyURLFile)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(raw))
}

// alertClient resolves names through Unbound directly: an alert about
// Pi-hole or the proxy must not depend on them.
var alertClient = &http.Client{
	Timeout: 15 * time.Second,
	Transport: &http.Transport{
		DialContext: (&net.Dialer{
			Timeout: 10 * time.Second,
			Resolver: &net.Resolver{
				PreferGo: true,
				Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
					return (&net.Dialer{Timeout: 3 * time.Second}).DialContext(ctx, network, unboundAddress)
				},
			},
		}).DialContext,
		TLSHandshakeTimeout: 10 * time.Second,
	},
}

// notificationRequest builds a Telegram sendMessage request (form with
// chat_id and text) or, for any other URL such as an ntfy topic, a plain
// text POST with a Title header.
func notificationRequest(url, title, message string) (*http.Request, error) {
	parsed, err := neturl.Parse(url)
	if err != nil || parsed.Scheme != "https" && parsed.Scheme != "http" {
		return nil, fmt.Errorf("URL de avisos no válida")
	}
	if parsed.Host == "api.telegram.org" {
		chat := parsed.Query().Get("chat_id")
		if chat == "" || !strings.HasSuffix(parsed.Path, "/sendMessage") {
			return nil, fmt.Errorf("la URL de Telegram debe ser https://api.telegram.org/bot<TOKEN>/sendMessage?chat_id=<ID>")
		}
		form := neturl.Values{"chat_id": {chat}, "text": {title + "\n" + message}}
		parsed.RawQuery = ""
		request, err := http.NewRequest(http.MethodPost, parsed.String(), strings.NewReader(form.Encode()))
		if err != nil {
			return nil, err
		}
		request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return request, nil
	}
	request, err := http.NewRequest(http.MethodPost, url, strings.NewReader(message))
	if err != nil {
		return nil, err
	}
	request.Header.Set("Title", title)
	request.Header.Set("Content-Type", "text/plain; charset=utf-8")
	return request, nil
}

func sendNotification(url, title, message string) error {
	request, err := notificationRequest(url, title, message)
	if err != nil {
		return err
	}
	request.Header.Set("User-Agent", userAgent)
	response, err := alertClient.Do(request)
	if err != nil {
		// Never print the URL: it may contain a token.
		return fmt.Errorf("%s: %v", request.URL.Host, unwrapURLError(err))
	}
	response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode > 299 {
		return fmt.Errorf("%s respondió HTTP %d", request.URL.Host, response.StatusCode)
	}
	return nil
}

func unwrapURLError(err error) error {
	if urlErr, ok := err.(*neturl.Error); ok {
		return urlErr.Err
	}
	return err
}

func runAlertTest() int {
	url := readNotifyURL()
	if url == "" {
		fmt.Println("No hay URL de avisos configurada. Añádela con:  sudo cfu config")
		return 1
	}
	host, _ := os.Hostname()
	if err := sendNotification(url, "cf-unblock-dns en "+host, "Aviso de prueba: los avisos funcionan."); err != nil {
		fmt.Fprintf(os.Stderr, "No se pudo enviar el aviso: %v\n", err)
		return 1
	}
	fmt.Println("Aviso de prueba enviado.")
	return 0
}

// topDomains returns up to n domains sorted by count, then name.
func topDomains(counts map[string]int, n int) []string {
	names := make([]string, 0, len(counts))
	for name := range counts {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		if counts[names[i]] != counts[names[j]] {
			return counts[names[i]] > counts[names[j]]
		}
		return names[i] < names[j]
	})
	if len(names) > n {
		names = names[:n]
	}
	return names
}
