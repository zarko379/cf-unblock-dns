package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

type fakeAnswer struct {
	body *string
	etag string
	err  error
}

func text(value string) *string { return &value }

type fakeFetcher struct {
	answers map[string][]fakeAnswer
	calls   [][2]string
}

func (f *fakeFetcher) fetch(url, etag, _ string) (*string, string, string, error) {
	f.calls = append(f.calls, [2]string{url, etag})
	queue := f.answers[url]
	if len(queue) == 0 {
		return nil, "", "", errors.New("sin respuesta preparada para " + url)
	}
	answer := queue[0]
	f.answers[url] = queue[1:]
	return answer.body, answer.etag, "", answer.err
}

const blockedURL = "https://hayahora.futbol/estado/blocked-any.txt"

func testUpdater(t *testing.T) *Updater {
	t.Helper()
	return &Updater{BlockedURL: blockedURL, DataFile: filepath.Join(t.TempDir(), "data.json")}
}

func run(t *testing.T, u *Updater, now float64, answers map[string][]fakeAnswer) (*fakeFetcher, int, error) {
	t.Helper()
	fetcher := &fakeFetcher{answers: answers}
	u.Fetch = fetcher.fetch
	u.Now = func() float64 { return now }
	count, err := u.Update()
	return fetcher, count, err
}

func stored(t *testing.T, u *Updater) dataFileOut {
	t.Helper()
	raw, err := os.ReadFile(u.DataFile)
	if err != nil {
		t.Fatal(err)
	}
	var data dataFileOut
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return data
}

func cloudflareAnswers() map[string][]fakeAnswer {
	return map[string][]fakeAnswer{
		cloudflareV4URL: {{body: text("104.16.0.0/13\n")}},
		cloudflareV6URL: {{body: text("2606:4700::/32\n")}},
	}
}

func with(answers map[string][]fakeAnswer, url string, list ...fakeAnswer) map[string][]fakeAnswer {
	answers[url] = list
	return answers
}

func TestParserAcceptsIPv4IPv6AndCIDR(t *testing.T) {
	parsed, err := parseNetworkList("# comment\n104.21.1.10\n104.21.0.0/16\n2606:4700::/32\ninvalid-entry\n")
	if err != nil || !equalStrings(parsed, []string{"104.21.0.0/16", "104.21.1.10/32", "2606:4700::/32"}) {
		t.Fatalf("%v %v", parsed, err)
	}
}

func TestParserRejectsHTMLAndGarbage(t *testing.T) {
	garbage := ""
	for i := 0; i < 20; i++ {
		garbage += "bad\n"
	}
	broad := ""
	for i := 0; i < 6; i++ {
		broad += "0.0.0.0/0\n"
	}
	for _, input := range []string{"<html><body>error</body></html>", garbage, broad} {
		if _, err := parseNetworkList(input); err == nil {
			t.Fatalf("aceptado: %q", input)
		}
	}
}

func TestUpdateFullCycle(t *testing.T) {
	u := testUpdater(t)
	_, count, err := run(t, u, 1_000_000, with(cloudflareAnswers(), blockedURL,
		fakeAnswer{body: text("104.21.1.10\n2606:4700:4700::1111\n"), etag: `"e1"`}))
	if err != nil || count != 2 {
		t.Fatalf("%d %v", count, err)
	}
	first := stored(t, u)
	if !equalStrings(first.CloudflareV4, []string{"104.16.0.0/13"}) || !equalStrings(first.CloudflareV6, []string{"2606:4700::/32"}) {
		t.Fatalf("%+v", first)
	}
	info, _ := os.Stat(u.DataFile)

	// 304 with the stored ETag: no rewrite, Cloudflare not fetched again within 24 h.
	fetcher, _, err := run(t, u, 1_000_100, map[string][]fakeAnswer{blockedURL: {{body: nil, etag: `"e1"`}}})
	if err != nil || len(fetcher.calls) != 1 || fetcher.calls[0] != [2]string{blockedURL, `"e1"`} {
		t.Fatalf("%v %v", fetcher.calls, err)
	}
	if after, _ := os.Stat(u.DataFile); !after.ModTime().Equal(info.ModTime()) {
		t.Fatal("data.json reescrito sin cambios")
	}

	// A download failure or malformed content keeps the data.
	if _, _, err := run(t, u, 1_000_200, map[string][]fakeAnswer{blockedURL: {{err: errors.New("HTTP 500")}}}); err == nil {
		t.Fatal("se esperaba un error")
	}
	if _, _, err := run(t, u, 1_000_300, map[string][]fakeAnswer{blockedURL: {{body: text("<html>")}}}); err == nil {
		t.Fatal("se esperaba un error")
	}
	if !equalStrings(stored(t, u).Blocked, first.Blocked) {
		t.Fatal("datos perdidos")
	}
}

func TestEmptyListIsOnlyAcceptedAfterGracePeriod(t *testing.T) {
	u := testUpdater(t)
	run(t, u, 1_000_000, with(cloudflareAnswers(), blockedURL, fakeAnswer{body: text("104.21.1.10\n")}))
	start := 1_000_100.0
	run(t, u, start, map[string][]fakeAnswer{blockedURL: {{body: text(""), etag: `"empty"`}}})
	if !equalStrings(stored(t, u).Blocked, []string{"104.21.1.10/32"}) {
		t.Fatal("lista vacía aceptada de inmediato")
	}
	fetcher, _, _ := run(t, u, start+60, map[string][]fakeAnswer{blockedURL: {{body: text(""), etag: `"empty"`}}})
	if fetcher.calls[0][1] != "" {
		t.Fatal("petición condicional tras una lista vacía")
	}
	run(t, u, start+emptyListGraceSeconds+1, map[string][]fakeAnswer{blockedURL: {{body: text(""), etag: `"empty"`}}})
	if len(stored(t, u).Blocked) != 0 {
		t.Fatal("lista vacía no aceptada tras la espera")
	}
}

func TestCloudflareFallbackAndRefresh(t *testing.T) {
	u := testUpdater(t)
	run(t, u, 1_000_000, map[string][]fakeAnswer{
		blockedURL:      {{body: text("104.21.1.10\n")}},
		cloudflareV4URL: {{err: errors.New("sin red")}},
	})
	if !equalStrings(stored(t, u).CloudflareV4, fallbackCloudflareV4) {
		t.Fatal("no se usó la lista integrada")
	}
	run(t, u, 1_000_000+cloudflareRetrySeconds+1, with(cloudflareAnswers(), blockedURL, fakeAnswer{body: text("104.21.1.10\n")}))
	if !equalStrings(stored(t, u).CloudflareV4, []string{"104.16.0.0/13"}) {
		t.Fatal("prefijos no actualizados tras reintentar")
	}
}

func TestDataFileIsCompatibleWithPythonVersion(t *testing.T) {
	u := testUpdater(t)
	run(t, u, 1_000_000, with(cloudflareAnswers(), blockedURL, fakeAnswer{body: text("104.21.1.10\n")}))
	raw, _ := os.ReadFile(u.DataFile)
	var generic map[string]any
	if err := json.Unmarshal(raw, &generic); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"updated_at", "source", "blocked", "cloudflare_v4", "cloudflare_v6"} {
		if _, ok := generic[key]; !ok {
			t.Fatalf("falta %s", key)
		}
	}
	data := newPolicyData(u.DataFile, "")
	if !data.Get().IsListed(blockedV4) {
		t.Fatal("el proxy no lee los datos del actualizador")
	}
}
