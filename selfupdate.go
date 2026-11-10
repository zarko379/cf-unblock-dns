package main

// cfu update: downloads the latest GitHub release for this architecture,
// checks it against SHA256SUMS and runs its installer with -y, which keeps
// the current configuration. If that installer fails, the previous files are
// reinstalled the same way.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	repoSlug         = "zarko379/cf-unblock-dns"
	latestReleaseAPI = "https://api.github.com/repos/" + repoSlug + "/releases/latest"
	checksumsAsset   = "SHA256SUMS"
	signatureAsset   = checksumsAsset + ".sig"
	maxPackageSize   = 64 << 20
	// releasePublicKey verifies SHA256SUMS.sig (Ed25519). The private key
	// stays on the maintainer's machine; see release.py.
	releasePublicKey = "RSAaUfPsxSV/cZAEJpeB9q+dqDJzG7dK7sGt7vMkhd8="
)

// verifySignature checks SHA256SUMS against its detached Ed25519 signature.
func verifySignature(publicKey string, sums, signature []byte) error {
	key, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return fmt.Errorf("clave pública de firma no válida")
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(key), sums, signature) {
		return fmt.Errorf("la firma de %s no es válida: no se instala nada", checksumsAsset)
	}
	return nil
}

// packageName is the release asset for an architecture.
func packageName(goarch string) string {
	return "cf-unblock-dns-linux-" + goarch + ".tar.gz"
}

// packageFiles are the only files a release package may contain.
var packageFiles = map[string]os.FileMode{
	"cfu":                           0o755,
	"install.sh":                    0o755,
	"check.sh":                      0o755,
	"uninstall.sh":                  0o755,
	"cf-unblock-dns.service":        0o644,
	"cf-unblock-dns-update.service": 0o644,
	"README.md":                     0o644,
	"LICENSE":                       0o644,
}

var requiredPackageFiles = []string{
	"cfu", "install.sh", "check.sh", "uninstall.sh", "cf-unblock-dns.service", "cf-unblock-dns-update.service",
}

type releaseInfo struct {
	TagName string `json:"tag_name"`
	HTMLURL string `json:"html_url"`
	Assets  []struct {
		Name string `json:"name"`
		URL  string `json:"browser_download_url"`
	} `json:"assets"`
}

func (r *releaseInfo) assetURL(name string) string {
	for _, asset := range r.Assets {
		if asset.Name == name {
			return asset.URL
		}
	}
	return ""
}

var downloadClient = &http.Client{Timeout: 2 * time.Minute}

func download(url, accept string, limit int64) ([]byte, error) {
	request, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("User-Agent", userAgent)
	if accept != "" {
		request.Header.Set("Accept", accept)
	}
	response, err := downloadClient.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusNotFound && url == latestReleaseAPI {
		return nil, fmt.Errorf("no hay versiones publicadas en %s/releases", projectURL)
	}
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%s: respuesta demasiado grande", url)
	}
	return body, nil
}

func latestRelease() (*releaseInfo, error) {
	body, err := download(latestReleaseAPI, "application/vnd.github+json", 1<<20)
	if err != nil {
		return nil, fmt.Errorf("no se pudo consultar la última versión: %w", err)
	}
	var release releaseInfo
	if err := json.Unmarshal(body, &release); err != nil {
		return nil, fmt.Errorf("respuesta de GitHub no válida: %w", err)
	}
	return &release, nil
}

// parseVersion accepts "1.2.3" or "v1.2.3".
func parseVersion(text string) ([3]int, error) {
	var parts [3]int
	fields := strings.Split(strings.TrimPrefix(strings.TrimSpace(text), "v"), ".")
	if len(fields) != 3 {
		return parts, fmt.Errorf("versión no válida: %q", text)
	}
	for i, field := range fields {
		number, err := strconv.Atoi(field)
		if err != nil || number < 0 {
			return parts, fmt.Errorf("versión no válida: %q", text)
		}
		parts[i] = number
	}
	return parts, nil
}

// compareVersions returns -1, 0 or 1 comparing numerically (3.10.0 > 3.9.0).
func compareVersions(a, b string) (int, error) {
	left, err := parseVersion(a)
	if err != nil {
		return 0, err
	}
	right, err := parseVersion(b)
	if err != nil {
		return 0, err
	}
	for i := range left {
		if left[i] != right[i] {
			if left[i] < right[i] {
				return -1, nil
			}
			return 1, nil
		}
	}
	return 0, nil
}

// checksumFor finds a file's SHA-256 in a sha256sum-style listing.
func checksumFor(sums []byte, name string) (string, error) {
	for _, line := range strings.Split(string(sums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == name {
			if len(fields[0]) != 64 {
				break
			}
			if _, err := hex.DecodeString(fields[0]); err != nil {
				break
			}
			return strings.ToLower(fields[0]), nil
		}
	}
	return "", fmt.Errorf("%s no aparece en %s", name, checksumsAsset)
}

// extractPackage writes the known files of a .tar.gz into dir. Anything
// else (directories, links, unexpected names) is rejected.
func extractPackage(data []byte, dir string) error {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return err
	}
	defer gz.Close()
	reader := tar.NewReader(gz)
	seen := map[string]bool{}
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		name := strings.TrimPrefix(header.Name, "./")
		mode, known := packageFiles[name]
		if header.Typeflag == tar.TypeDir && (name == "" || name == ".") {
			continue
		}
		if !known || header.Typeflag != tar.TypeReg || seen[name] {
			return fmt.Errorf("el paquete contiene una entrada inesperada: %q", header.Name)
		}
		seen[name] = true
		file, err := os.OpenFile(filepath.Join(dir, name), os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return err
		}
		_, err = io.Copy(file, io.LimitReader(reader, maxPackageSize))
		if closeErr := file.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
	}
	for _, name := range requiredPackageFiles {
		if !seen[name] {
			return fmt.Errorf("al paquete le falta %s", name)
		}
	}
	return nil
}

// copyInstalled keeps a copy of the installed files for the rollback.
func copyInstalled(from, to string) error {
	if err := os.MkdirAll(to, 0o700); err != nil {
		return err
	}
	for name, mode := range packageFiles {
		data, err := os.ReadFile(filepath.Join(from, name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if err := os.WriteFile(filepath.Join(to, name), data, mode); err != nil {
			return err
		}
	}
	return nil
}

func runSelfUpdate(args []string) int {
	flags := flag.NewFlagSet("cfu update", flag.ExitOnError)
	checkOnly := flags.Bool("check", false, "solo comprobar si hay una versión nueva")
	force := flags.Bool("force", false, "reinstalar aunque ya esté en la última versión")
	_ = flags.Parse(args)
	if !*checkOnly && os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "Ejecuta la actualización como root:  sudo cfu update")
		return 1
	}

	release, err := latestRelease()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	latest := strings.TrimPrefix(release.TagName, "v")
	order, err := compareVersions(latest, version)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("Versión instalada: %s\nÚltima publicada:  %s\n", version, latest)
	if order <= 0 && !*force {
		fmt.Println("Ya tienes la última versión.")
		return 0
	}
	if *checkOnly {
		if order > 0 {
			fmt.Printf("Hay una versión nueva (%s). Para instalarla:  sudo cfu update\n", release.HTMLURL)
		}
		return 0
	}

	asset := packageName(runtime.GOARCH)
	packageURL, sumsURL := release.assetURL(asset), release.assetURL(checksumsAsset)
	signatureURL := release.assetURL(signatureAsset)
	if packageURL == "" || sumsURL == "" || signatureURL == "" {
		fmt.Fprintf(os.Stderr, "La versión %s no incluye %s, %s o %s; no se instala.\n",
			latest, asset, checksumsAsset, signatureAsset)
		return 1
	}
	fmt.Printf("Descargando %s...\n", asset)
	sums, err := download(sumsURL, "", 1<<16)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	signature, err := download(signatureURL, "", 1024)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Before trusting any hash in the file.
	if err := verifySignature(releasePublicKey, sums, signature); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Println("Firma de la versión verificada.")
	expected, err := checksumFor(sums, asset)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	data, err := download(packageURL, "", maxPackageSize)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	digest := sha256.Sum256(data)
	if hex.EncodeToString(digest[:]) != expected {
		fmt.Fprintln(os.Stderr, "La suma SHA-256 del paquete no coincide; no se instala nada.")
		return 1
	}

	// Not /tmp: it may be mounted noexec and the installer runs the new binary.
	work, err := os.MkdirTemp("/var/tmp", "cfu-update-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(work)
	fresh, previous := filepath.Join(work, "new"), filepath.Join(work, "previous")
	if err := os.Mkdir(fresh, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := extractPackage(data, fresh); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// A package whose binary reports another version would be "new" forever.
	out, err := exec.Command(filepath.Join(fresh, "cfu"), "version").Output()
	if err != nil || strings.TrimSpace(string(out)) != "cf-unblock-dns "+latest {
		fmt.Fprintf(os.Stderr, "El binario de la versión %s no funciona aquí o no coincide (%q).\n",
			latest, strings.TrimSpace(string(out)))
		return 1
	}
	if err := copyInstalled(installDir, previous); err != nil {
		fmt.Fprintf(os.Stderr, "No se pudo guardar la versión actual: %v\n", err)
		return 1
	}

	fmt.Printf("Instalando %s (se conserva la configuración)...\n", latest)
	if code := runAttached("bash", filepath.Join(fresh, "install.sh"), "-y"); code != 0 {
		fmt.Fprintf(os.Stderr, "\nLa instalación de %s falló; se vuelve a instalar %s.\n", latest, version)
		if _, err := os.Stat(filepath.Join(previous, "install.sh")); err == nil {
			runAttached("bash", filepath.Join(previous, "install.sh"), "-y")
		}
		return 1
	}
	fmt.Printf("\ncf-unblock-dns actualizado a %s.\n", latest)
	return 0
}
