package ssh

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/crypto/ssh"
)

// EnsureHostKey returns a persistent Ed25519 host key under dir, generating
// and persisting it on first run (zero-config, like the TLS certificate).
func EnsureHostKey(dir string) (ssh.Signer, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("mkdir host key dir: %w", err)
	}
	path := filepath.Join(dir, "host_key")

	if data, err := os.ReadFile(path); err == nil {
		if len(data) != ed25519.PrivateKeySize {
			return nil, fmt.Errorf("parse host key: bad size %d", len(data))
		}
		return ssh.NewSignerFromKey(ed25519.PrivateKey(data))
	}

	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, priv, 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}
