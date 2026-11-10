// Command signrelease creates the release signing key and signs SHA256SUMS.
// It is only used by release.py on the maintainer's machine.
//
//	go run ./tools/signrelease keygen KEYFILE   crea la clave (no sobrescribe) y muestra la pública
//	go run ./tools/signrelease public KEYFILE   muestra la clave pública (base64 y PEM)
//	go run ./tools/signrelease sign KEYFILE FICHERO   escribe FICHERO.sig (64 bytes) y lo verifica
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "signrelease:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) < 2 {
		return errors.New("uso: signrelease keygen|public KEYFILE  o  signrelease sign KEYFILE FICHERO")
	}
	switch args[0] {
	case "keygen":
		if _, err := os.Stat(args[1]); err == nil {
			return fmt.Errorf("%s ya existe; no se sobrescribe", args[1])
		}
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(args[1]), 0o700); err != nil {
			return err
		}
		seed := base64.StdEncoding.EncodeToString(private.Seed()) + "\n"
		if err := os.WriteFile(args[1], []byte(seed), 0o600); err != nil {
			return err
		}
		return printPublic(private.Public().(ed25519.PublicKey))
	case "public":
		private, err := loadKey(args[1])
		if err != nil {
			return err
		}
		return printPublic(private.Public().(ed25519.PublicKey))
	case "sign":
		if len(args) != 3 {
			return errors.New("uso: signrelease sign KEYFILE FICHERO")
		}
		private, err := loadKey(args[1])
		if err != nil {
			return err
		}
		data, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		signature := ed25519.Sign(private, data)
		if !ed25519.Verify(private.Public().(ed25519.PublicKey), data, signature) {
			return errors.New("la firma no se verifica")
		}
		return os.WriteFile(args[2]+".sig", signature, 0o644)
	}
	return fmt.Errorf("orden desconocida: %s", args[0])
}

func loadKey(path string) (ed25519.PrivateKey, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%s no contiene una clave Ed25519 válida", path)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

func printPublic(public ed25519.PublicKey) error {
	der, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		return err
	}
	fmt.Println("base64:", base64.StdEncoding.EncodeToString(public))
	fmt.Print(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})))
	return nil
}
