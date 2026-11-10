package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHealthMonitorAlertsAfterTwoFailuresAndOnRecovery(t *testing.T) {
	failing := true
	var sent []string
	now := time.Date(2026, 11, 10, 12, 0, 0, 0, time.Local)
	monitor := &HealthMonitor{
		Checks: []healthCheck{{"proxy", func() error {
			if failing {
				return errors.New("sin respuesta")
			}
			return nil
		}}},
		Host: "pihole",
		URL:  func() string { return "https://ntfy.example/tema" },
		Send: func(_, title, message string) error {
			sent = append(sent, title+"|"+message)
			return nil
		},
		Now: func() time.Time { return now },
	}
	monitor.Run()
	if len(sent) != 0 {
		t.Fatalf("avisó tras un solo fallo: %v", sent)
	}
	monitor.Run()
	if len(sent) != 1 || !strings.Contains(sent[0], "FALLO: proxy") || !strings.HasPrefix(sent[0], "cf-unblock-dns en pihole|") {
		t.Fatalf("aviso tras dos fallos = %v", sent)
	}
	monitor.Run()
	if len(sent) != 1 {
		t.Fatalf("repitió el aviso mientras seguía fallando: %v", sent)
	}
	failing = false
	monitor.Run()
	if len(sent) != 2 || !strings.Contains(sent[1], "RECUPERADO: proxy") {
		t.Fatalf("aviso de recuperación = %v", sent)
	}
}

func TestHealthMonitorRetriesUndeliveredAlerts(t *testing.T) {
	deliver := false
	var sent []string
	monitor := &HealthMonitor{
		Checks: []healthCheck{{"Pi-hole", func() error { return errors.New("caído") }}},
		URL:    func() string { return "https://ntfy.example/tema" },
		Send: func(_, _, message string) error {
			if !deliver {
				return errors.New("sin red")
			}
			sent = append(sent, message)
			return nil
		},
		Now: time.Now,
	}
	monitor.Run()
	monitor.Run() // alert queued, delivery fails
	deliver = true
	monitor.Run()
	if len(sent) != 1 || !strings.Contains(sent[0], "FALLO: Pi-hole") {
		t.Fatalf("el aviso pendiente no se reenvió: %v", sent)
	}
}

func TestHealthMonitorWithoutURLSendsNothing(t *testing.T) {
	monitor := &HealthMonitor{
		Checks: []healthCheck{{"x", func() error { return errors.New("mal") }}},
		URL:    func() string { return "" },
		Send:   func(string, string, string) error { t.Fatal("no debería enviar"); return nil },
		Now:    time.Now,
	}
	monitor.Run()
	monitor.Run()
	if len(monitor.pending) != 0 {
		t.Fatal("sin URL no deben acumularse avisos")
	}
}

func TestNotificationRequestFormats(t *testing.T) {
	request, err := notificationRequest("https://ntfy.sh/mi-tema", "Título", "texto")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(request.Body)
	if request.Method != http.MethodPost || string(body) != "texto" || request.Header.Get("Title") != "Título" {
		t.Fatalf("ntfy: %s %q %q", request.Method, body, request.Header.Get("Title"))
	}

	request, err = notificationRequest("https://api.telegram.org/bot123:ABC/sendMessage?chat_id=42", "Título", "texto")
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(request.Body)
	form, _ := url.ParseQuery(string(body))
	if form.Get("chat_id") != "42" || form.Get("text") != "Título\ntexto" || request.URL.RawQuery != "" ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
		t.Fatalf("telegram: %q %s", body, request.URL)
	}
	if _, err := notificationRequest("https://api.telegram.org/bot123:ABC/sendMessage", "t", "m"); err == nil {
		t.Fatal("aceptó una URL de Telegram sin chat_id")
	}
	if _, err := notificationRequest("ftp://x", "t", "m"); err == nil {
		t.Fatal("aceptó una URL que no es http(s)")
	}
}

func TestSendNotificationPostsToServer(t *testing.T) {
	var got string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		got = r.Header.Get("Title") + "|" + string(body)
	}))
	defer server.Close()
	if err := sendNotification(server.URL+"/tema", "cf-unblock-dns en x", "FALLO"); err != nil {
		t.Fatal(err)
	}
	if got != "cf-unblock-dns en x|FALLO" {
		t.Fatalf("el servidor recibió %q", got)
	}
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer failing.Close()
	err := sendNotification(failing.URL+"/secreto", "t", "m")
	if err == nil || strings.Contains(err.Error(), "secreto") {
		t.Fatalf("error = %v (no debe mostrar la ruta de la URL)", err)
	}
}

func TestDailyStatsSurviveRestart(t *testing.T) {
	stats := newStats()
	stats.Inc("upstream_failures", 2)
	stats.AddRewrite("example.com")
	stats.AddRewrite("example.com")
	stats.AddRewrite("otra.es")
	path := filepath.Join(t.TempDir(), "status.json")
	if err := writeJSONAtomic(path, map[string]any{"today": stats.Today()}, true); err != nil {
		t.Fatal(err)
	}
	restarted := newStats()
	restarted.RestoreToday(path)
	today := restarted.Today()
	if today.Counters["upstream_failures"] != 2 || today.Domains["example.com"] != 2 || today.Domains["otra.es"] != 1 {
		t.Fatalf("tras reiniciar: %+v", today)
	}
	if got := topDomains(today.Domains, 1); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("topDomains = %v", got)
	}

	old := map[string]any{"today": DayStats{Date: "2000-01-01", Counters: map[string]int{"queries": 9}}}
	if err := writeJSONAtomic(path, old, true); err != nil {
		t.Fatal(err)
	}
	fresh := newStats()
	fresh.RestoreToday(path)
	if fresh.Today().Counters["queries"] != 0 {
		t.Fatal("se cargaron contadores de otro día")
	}
}

func TestDailyDomainsAreCapped(t *testing.T) {
	stats := newStats()
	for i := 0; i < maxDailyDomains+50; i++ {
		stats.AddRewrite(strings.Repeat("a", i%40+1) + "." + string(rune('a'+i%26)) + ".es" + string(rune('0'+i%10)) + string(rune('A'+i/26%26)))
	}
	if n := len(stats.Today().Domains); n > maxDailyDomains {
		t.Fatalf("%d dominios guardados", n)
	}
}

func TestVerifySignatureFailsClosed(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	key := base64.StdEncoding.EncodeToString(public)
	sums := []byte(strings.Repeat("ab", 32) + "  " + packageName("amd64") + "\n")
	signature := ed25519.Sign(private, sums)
	if err := verifySignature(key, sums, signature); err != nil {
		t.Fatalf("firma correcta rechazada: %v", err)
	}
	tampered := append([]byte(nil), sums...)
	tampered[0] = 'c'
	if verifySignature(key, tampered, signature) == nil {
		t.Fatal("aceptó un SHA256SUMS modificado")
	}
	otherPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	if verifySignature(base64.StdEncoding.EncodeToString(otherPublic), sums, signature) == nil {
		t.Fatal("aceptó la firma con otra clave")
	}
	if verifySignature(key, sums, nil) == nil || verifySignature(key, sums, signature[:10]) == nil {
		t.Fatal("aceptó una firma vacía o cortada")
	}
	if _, err := base64.StdEncoding.DecodeString(releasePublicKey); err != nil {
		t.Fatalf("la clave pública integrada no es base64: %v", err)
	}
}

func TestNeedsRoot(t *testing.T) {
	cases := map[string]bool{
		"status": false, "version": false, "update --check": false, "update": true,
		"list update": true, "check": true, "config": true, "uninstall": true, "alerts test": true, "serve": false,
	}
	for command, want := range cases {
		if got := needsRoot(strings.Fields(command)); got != want {
			t.Errorf("needsRoot(%q) = %v", command, got)
		}
	}
}
