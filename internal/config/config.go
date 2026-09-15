// Package config loads Honeysight runtime configuration.
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the full runtime configuration.
type Config struct {
	Listen struct {
		HTTP  string `yaml:"http"`
		HTTPS string `yaml:"https"` // empty = TLS listener disabled
	} `yaml:"listen"`
	// TLSCertDir holds the (auto-generated) self-signed certificate.
	TLSCertDir string `yaml:"tls_cert_dir"`
	Storage    struct {
		SQLitePath string `yaml:"sqlite_path"`
	} `yaml:"storage"`
	Rules struct {
		Path string `yaml:"path"`
	} `yaml:"rules"`
	BlockThreshold int           `yaml:"block_threshold"`
	Window         time.Duration `yaml:"window"`
	BlockTTL       time.Duration `yaml:"block_ttl"`
	Tarpit         time.Duration `yaml:"tarpit"`
	// TrustedProxies: peer addresses allowed to set X-Real-IP /
	// X-Forwarded-For. Empty means "every peer is the real source".
	TrustedProxies []string `yaml:"trusted_proxies"`
}

// Load reads the YAML config at path and applies defaults for unset keys.
// If path does not exist but config.example.yml does, the example is used
// with a warning so a fresh checkout runs with zero setup.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if alt, altErr := os.ReadFile("config.example.yml"); altErr == nil {
				fmt.Fprintf(os.Stderr, "honeysight: %s not found, falling back to config.example.yml\n", path)
				data = alt
			} else {
				return nil, fmt.Errorf("read config: %w", err)
			}
		} else {
			return nil, fmt.Errorf("read config: %w", err)
		}
	}

	c := &Config{}
	c.Listen.HTTP = ":8080"
	c.Listen.HTTPS = ":8443"
	c.TLSCertDir = "data/tls"
	c.Storage.SQLitePath = "data/honeysight.db"
	c.Rules.Path = "rules/default.yml"
	c.BlockThreshold = 100
	c.Window = 5 * time.Minute
	c.BlockTTL = 10 * time.Minute
	c.Tarpit = 1500 * time.Millisecond

	if err := yaml.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	return c, nil
}
