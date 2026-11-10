package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"
)

const (
	cloudflareV4URL          = "https://www.cloudflare.com/ips-v4"
	cloudflareV6URL          = "https://www.cloudflare.com/ips-v6"
	cloudflareRefreshSeconds = 24 * 3600
	cloudflareRetrySeconds   = 600
	emptyListGraceSeconds    = 30 * 60
	maxPayload               = 2_000_000
	projectURL               = "https://github.com/" + repoSlug
)

var userAgent = "cf-unblock-dns/" + version + " (+" + projectURL + ")"

// Broader entries than these are not plausible single-site blocks.
var minPrefixLen = map[int]int{4: 8, 6: 20}

// Published at cloudflare.com/ips (checked 2026-11). Used only when there is
// no previous data and the download fails, so a first install still works.
var (
	fallbackCloudflareV4 = []string{
		"103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
		"104.24.0.0/14", "108.162.192.0/18", "131.0.72.0/22", "141.101.64.0/18",
		"162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
		"190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
	}
	fallbackCloudflareV6 = []string{
		"2400:cb00::/32", "2405:8100::/32", "2405:b500::/32", "2606:4700::/32",
		"2803:f800::/32", "2a06:98c0::/29", "2c0f:f248::/32",
	}
)

type Updater struct {
	// Health, when set, runs the health checks from the loop.
	Health      *HealthMonitor
	lastSuccess time.Time
	BlockedURL  string
	DataFile    string
	Fetch       func(url, etag, lastModified string) (body *string, newETag, newLastModified string, err error)
	Now         func() float64
}

func newUpdater() *Updater {
	blockedURL := setting("CFU_BLOCKED_URL")
	if blockedURL == "" {
		blockedURL = "https://hayahora.futbol/estado/blocked-any.txt"
	}
	dataFile := os.Getenv("CFU_DATA_FILE")
	if dataFile == "" {
		dataFile = filepath.Join(dataDir, "data.json")
	}
	return &Updater{BlockedURL: blockedURL, DataFile: dataFile, Fetch: httpFetch, Now: unixNow}
}

func unixNow() float64 { return float64(time.Now().UnixNano()) / 1e9 }

var httpClient = &http.Client{Timeout: 20 * time.Second}

// httpFetch returns a nil body when the server answers 304 Not Modified.
func httpFetch(url, etag, lastModified string) (*string, string, string, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, "", "", err
	}
	request.Header.Set("User-Agent", userAgent)
	if etag != "" {
		request.Header.Set("If-None-Match", etag)
	}
	if lastModified != "" {
		request.Header.Set("If-Modified-Since", lastModified)
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, "", "", err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotModified {
		return nil, etag, lastModified, nil
	}
	if response.StatusCode != http.StatusOK {
		return nil, "", "", fmt.Errorf("HTTP %d al descargar %s", response.StatusCode, url)
	}
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxPayload+1))
	if err != nil {
		return nil, "", "", err
	}
	if len(payload) > maxPayload {
		return nil, "", "", fmt.Errorf("respuesta demasiado grande al descargar %s", url)
	}
	text := string(payload)
	return &text, response.Header.Get("ETag"), response.Header.Get("Last-Modified"), nil
}

// parseNetworkList turns a downloaded list into sorted, unique CIDRs.
func parseNetworkList(text string) ([]string, error) {
	if strings.HasPrefix(strings.TrimLeft(text, " \t\r\n"), "<") {
		return nil, errors.New("el contenido parece HTML, no una lista de IPs")
	}
	seen := map[netip.Prefix]bool{}
	invalid := 0
	for _, rawLine := range strings.Split(text, "\n") {
		line := strings.TrimSpace(strings.SplitN(rawLine, "#", 2)[0])
		if line == "" {
			continue
		}
		network, err := parseNetwork(line)
		if err != nil || network.Bits() < minPrefixLen[familyOf(network.Addr())] {
			invalid++
			if invalid <= 5 {
				if len(line) > 80 {
					line = line[:80]
				}
				warnf("Entrada de red ignorada: %q", line)
			}
			continue
		}
		seen[network] = true
	}
	if invalid > max(5, len(seen)/10) {
		return nil, fmt.Errorf("%d entradas no válidas; el contenido no parece una lista de IPs", invalid)
	}
	networks := make([]netip.Prefix, 0, len(seen))
	for network := range seen {
		networks = append(networks, network)
	}
	sort.Slice(networks, func(i, j int) bool {
		a, b := networks[i], networks[j]
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c < 0
		}
		return a.Bits() < b.Bits()
	})
	out := make([]string, len(networks))
	for i, network := range networks {
		out[i] = network.String()
	}
	return out, nil
}

type policyContent struct {
	Blocked      []string
	CloudflareV4 []string
	CloudflareV6 []string
}

func (c policyContent) equal(other policyContent) bool {
	return slices.Equal(c.Blocked, other.Blocked) && slices.Equal(c.CloudflareV4, other.CloudflareV4) &&
		slices.Equal(c.CloudflareV6, other.CloudflareV6)
}

type dataFileOut struct {
	UpdatedAt    string   `json:"updated_at"`
	Source       string   `json:"source"`
	Blocked      []string `json:"blocked"`
	CloudflareV4 []string `json:"cloudflare_v4"`
	CloudflareV6 []string `json:"cloudflare_v6"`
}

func loadJSONMap(path string) map[string]any {
	raw, err := os.ReadFile(path)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			warnf("No se pudo leer %s: %v", path, err)
		}
		return nil
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		warnf("No se pudo leer %s: %v", path, err)
		return nil
	}
	return data
}

func validPrevious(data map[string]any) *policyContent {
	if data == nil {
		return nil
	}
	lists := map[string][]string{}
	for _, key := range []string{"blocked", "cloudflare_v4", "cloudflare_v6"} {
		raw, ok := data[key].([]any)
		if !ok {
			warnf("Los datos existentes no son válidos; se regeneran")
			return nil
		}
		values := make([]string, 0, len(raw))
		for _, item := range raw {
			value, ok := item.(string)
			if !ok {
				warnf("Los datos existentes no son válidos; se regeneran")
				return nil
			}
			if _, err := parseNetwork(value); err != nil {
				warnf("Los datos existentes no son válidos; se regeneran")
				return nil
			}
			values = append(values, value)
		}
		lists[key] = values
	}
	if len(lists["cloudflare_v4"]) == 0 || len(lists["cloudflare_v6"]) == 0 {
		return nil
	}
	return &policyContent{lists["blocked"], lists["cloudflare_v4"], lists["cloudflare_v6"]}
}

func stateString(state map[string]any, key string) string {
	value, _ := state[key].(string)
	return value
}

func stateFloat(state map[string]any, key string) float64 {
	value, _ := state[key].(float64)
	return value
}

func nullable(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (u *Updater) updateBlocked(previous *policyContent, state map[string]any, now float64) ([]string, error) {
	var previousBlocked []string
	havePrevious := previous != nil
	if havePrevious {
		previousBlocked = previous.Blocked
	}
	etag, lastModified := "", ""
	if havePrevious && stateString(state, "blocked_url") == u.BlockedURL {
		etag, lastModified = stateString(state, "blocked_etag"), stateString(state, "blocked_last_modified")
	}
	text, newETag, newLastModified, err := u.Fetch(u.BlockedURL, etag, lastModified)
	if err != nil {
		return nil, err
	}
	if text == nil {
		if !havePrevious {
			return nil, errors.New("respuesta 304 sin datos previos")
		}
		return previousBlocked, nil
	}
	blocked, err := parseNetworkList(*text)
	if err != nil {
		return nil, err
	}
	remember := func() {
		state["blocked_url"] = u.BlockedURL
		state["blocked_etag"] = nullable(newETag)
		state["blocked_last_modified"] = nullable(newLastModified)
		delete(state, "blocked_empty_since")
	}
	if len(blocked) > 0 || len(previousBlocked) == 0 {
		remember()
		return blocked, nil
	}
	// Empty list while we hold entries: keep them unless it stays empty.
	emptySince, ok := state["blocked_empty_since"].(float64)
	if !ok {
		emptySince = now
		state["blocked_empty_since"] = now
	}
	if now-emptySince >= emptyListGraceSeconds {
		infof("La lista lleva %d min vacía; se acepta", int((now-emptySince)/60))
		remember()
		return []string{}, nil
	}
	// No ETag stored, so the next run downloads again and re-evaluates.
	delete(state, "blocked_etag")
	delete(state, "blocked_last_modified")
	warnf("La lista de bloqueos llegó vacía; se conservan %d entradas previas", len(previousBlocked))
	return previousBlocked, nil
}

func (u *Updater) fetchCloudflare() ([]string, []string, error) {
	var lists [2][]string
	for i, url := range []string{cloudflareV4URL, cloudflareV6URL} {
		text, _, _, err := u.Fetch(url, "", "")
		if err != nil {
			return nil, nil, err
		}
		body := ""
		if text != nil {
			body = *text
		}
		networks, err := parseNetworkList(body)
		if err != nil {
			return nil, nil, err
		}
		want := 4 + 2*i
		for _, value := range networks {
			if p, _ := netip.ParsePrefix(value); familyOf(p.Addr()) == want {
				lists[i] = append(lists[i], value)
			}
		}
	}
	if len(lists[0]) == 0 || len(lists[1]) == 0 {
		return nil, nil, errors.New("lista de prefijos Cloudflare vacía")
	}
	return lists[0], lists[1], nil
}

func (u *Updater) updateCloudflare(previous *policyContent, state map[string]any, now float64) ([]string, []string) {
	if previous != nil && now-stateFloat(state, "cloudflare_fetched_at") < cloudflareRefreshSeconds {
		return previous.CloudflareV4, previous.CloudflareV6
	}
	v4, v6, err := u.fetchCloudflare()
	if err != nil {
		state["cloudflare_fetched_at"] = now - cloudflareRefreshSeconds + cloudflareRetrySeconds
		if previous != nil {
			warnf("No se pudieron actualizar los prefijos Cloudflare (%v); se conservan los actuales", err)
			return previous.CloudflareV4, previous.CloudflareV6
		}
		warnf("No se pudieron descargar los prefijos Cloudflare (%v); se usa la lista integrada", err)
		return append([]string(nil), fallbackCloudflareV4...), append([]string(nil), fallbackCloudflareV6...)
	}
	state["cloudflare_fetched_at"] = now
	return v4, v6
}

// Update runs one refresh and returns the number of blocked entries.
func (u *Updater) Update() (int, error) {
	now := u.Now()
	stateFile := filepath.Join(filepath.Dir(u.DataFile), "update-state.json")
	previous := validPrevious(loadJSONMap(u.DataFile))
	state := loadJSONMap(stateFile)
	if state == nil {
		state = map[string]any{}
	}
	blocked, err := u.updateBlocked(previous, state, now)
	if err != nil {
		return 0, err
	}
	v4, v6 := u.updateCloudflare(previous, state, now)
	content := policyContent{blocked, v4, v6}
	if previous == nil || !previous.equal(content) {
		payload := dataFileOut{
			UpdatedAt:    time.Now().UTC().Format("2006-01-02T15:04:05.000000-07:00"),
			Source:       u.BlockedURL,
			Blocked:      blocked,
			CloudflareV4: v4,
			CloudflareV6: v6,
		}
		if err := writeJSONAtomic(u.DataFile, payload, false); err != nil {
			return 0, err
		}
		infof("Datos actualizados: %d redes bloqueadas, %d prefijos Cloudflare IPv4 y %d IPv6", len(blocked), len(v4), len(v6))
	} else {
		debugf("Sin cambios en los datos")
	}
	state["checked_at"] = now
	if err := writeJSONAtomic(stateFile, state, false); err != nil {
		return 0, err
	}
	return len(blocked), nil
}

func (u *Updater) Loop(interval time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGTERM, os.Interrupt)
	lastError := ""
	for {
		_, err := u.Update()
		if err == nil {
			u.lastSuccess = time.Now()
		}
		if u.Health != nil && u.Health.Due() {
			u.Health.Run()
		}
		if err != nil {
			if message := err.Error(); message != lastError {
				errorf("Fallo al actualizar (se conservan los datos actuales): %s", message)
				lastError = message
			}
		} else {
			if lastError != "" {
				infof("Actualización recuperada")
			}
			lastError = ""
		}
		select {
		case <-stop:
			return
		case <-time.After(interval):
		}
	}
}

// ListOK fails when the list has not been checked successfully for a while.
func (u *Updater) ListOK() error {
	if u.lastSuccess.IsZero() {
		return fmt.Errorf("aún no se ha descargado en esta ejecución")
	}
	if age := time.Since(u.lastSuccess); age > listStaleAfter {
		return fmt.Errorf("última descarga correcta hace %.0f min", age.Minutes())
	}
	return nil
}
