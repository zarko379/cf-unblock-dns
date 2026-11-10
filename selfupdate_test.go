package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCompareVersionsIsNumeric(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"3.10.0", "3.9.0", 1},
		{"v4.0.0", "4.0.0", 0},
		{"3.99.0", "4.0.0", -1},
		{"4.0.1", "4.0.0", 1},
	}
	for _, c := range cases {
		got, err := compareVersions(c.a, c.b)
		if err != nil || got != c.want {
			t.Errorf("compareVersions(%q, %q) = %d, %v; want %d", c.a, c.b, got, err, c.want)
		}
	}
	for _, bad := range []string{"", "4.0", "4.0.0-rc1", "a.b.c"} {
		if _, err := compareVersions(bad, "1.0.0"); err == nil {
			t.Errorf("compareVersions aceptó %q", bad)
		}
	}
	if _, err := parseVersion(version); err != nil {
		t.Errorf("la versión del programa no es X.Y.Z: %v", err)
	}
}

func TestChecksumFor(t *testing.T) {
	hash := strings.Repeat("ab", 32)
	sums := []byte(strings.Repeat("cd", 32) + "  other.tar.gz\n" + hash + " *" + packageName("amd64") + "\n")
	got, err := checksumFor(sums, packageName("amd64"))
	if err != nil || got != hash {
		t.Fatalf("checksumFor = %q, %v", got, err)
	}
	if _, err := checksumFor(sums, packageName("arm64")); err == nil {
		t.Fatal("checksumFor encontró un paquete que no está")
	}
	if _, err := checksumFor([]byte("xyz  "+packageName("amd64")), packageName("amd64")); err == nil {
		t.Fatal("checksumFor aceptó una suma mal formada")
	}
}

type tarEntry struct {
	name string
	kind byte
	body string
}

func makePackage(t *testing.T, entries []tarEntry) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		header := &tar.Header{Name: e.name, Typeflag: e.kind, Mode: 0o644, Size: int64(len(e.body))}
		if e.kind == tar.TypeSymlink {
			header.Linkname, header.Size = "/etc/passwd", 0
		}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if e.kind == tar.TypeReg {
			if _, err := tw.Write([]byte(e.body)); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func completePackage() []tarEntry {
	var entries []tarEntry
	for _, name := range requiredPackageFiles {
		entries = append(entries, tarEntry{"./" + name, tar.TypeReg, "contenido de " + name})
	}
	return entries
}

func TestExtractPackageWritesKnownFiles(t *testing.T) {
	dir := t.TempDir()
	if err := extractPackage(makePackage(t, completePackage()), dir); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "install.sh"))
	if err != nil || string(data) != "contenido de install.sh" {
		t.Fatalf("install.sh = %q, %v", data, err)
	}
}

func TestExtractPackageRejectsUnexpectedEntries(t *testing.T) {
	bad := map[string]tarEntry{
		"ruta fuera":  {"../cfu", tar.TypeReg, "x"},
		"subcarpeta":  {"bin/cfu", tar.TypeReg, "x"},
		"desconocido": {"evil.sh", tar.TypeReg, "x"},
		"enlace":      {"LICENSE", tar.TypeSymlink, ""},
		"duplicado":   {"cfu", tar.TypeReg, "x"},
	}
	for label, entry := range bad {
		entries := append(completePackage(), entry)
		if err := extractPackage(makePackage(t, entries), t.TempDir()); err == nil {
			t.Errorf("%s: se aceptó %q", label, entry.name)
		}
	}
	incomplete := completePackage()[1:]
	if err := extractPackage(makePackage(t, incomplete), t.TempDir()); err == nil {
		t.Error("se aceptó un paquete sin cfu")
	}
}

func TestReadDefaultsParsesWithoutExecuting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cf-unblock-dns")
	content := "# comentario\nCFU_DNS_ARGS=\"--port 5336 --cloudflare-max-ttl 30\"\nCFU_BLOCKED_URL=https://example.org/l.txt\n\nCFU_UPDATE_INTERVAL='15'\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	values := readDefaults(path)
	if values["CFU_DNS_ARGS"] != "--port 5336 --cloudflare-max-ttl 30" ||
		values["CFU_BLOCKED_URL"] != "https://example.org/l.txt" || values["CFU_UPDATE_INTERVAL"] != "15" {
		t.Fatalf("readDefaults = %#v", values)
	}
	if len(readDefaults(filepath.Join(t.TempDir(), "no-existe"))) != 0 {
		t.Fatal("un fichero inexistente debería dar un mapa vacío")
	}
}

func TestRunWithoutArgumentsPrintsHelpInsteadOfServing(t *testing.T) {
	if code := dispatch(nil); code != 0 {
		t.Fatalf("dispatch(nil) = %d", code)
	}
	if code := dispatch([]string{"no-existe"}); code != 2 {
		t.Fatalf("una orden desconocida devolvió %d", code)
	}
	if code := dispatch([]string{"list"}); code != 2 {
		t.Fatalf("'cfu list' sin 'update' devolvió %d", code)
	}
}
