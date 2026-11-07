// Package config holds runtime configuration for rosman.
package config

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Config is loaded from environment with sane defaults. Everything lives under
// DataDir so the whole service is "one binary + one directory".
type Config struct {
	DataDir        string        // where DB, keys and TLS cert live
	Listen         string        // HTTPS listen address
	DBPath         string        // sqlite file
	SecretKeyPath  string        // AES key for credential encryption
	TLSCertPath    string        // self-signed cert (auto-generated)
	TLSKeyPath     string        // self-signed key
	SSHKeyPath     string        // private key used for /export over SSH (fleet key)
	PollInterval   time.Duration // health poll cadence
	BackupInterval time.Duration // config backup cadence
	SSHTimeout     time.Duration
	APITimeout     time.Duration

	// Alerting / notifications (all optional).
	CertWarnDays  int    // warn when api-ssl cert expires within N days
	WebhookURL    string // generic JSON webhook for alerts
	TelegramToken string // Telegram bot token
	TelegramChat  string // Telegram chat id
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envDur(k string, def time.Duration) time.Duration {
	if v := os.Getenv(k); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
		if n, err := strconv.Atoi(v); err == nil {
			return time.Duration(n) * time.Second
		}
	}
	return def
}

// Load builds a Config from ROSMAN_* environment variables.
func Load() Config {
	data := env("ROSMAN_DATA_DIR", "./data")
	c := Config{
		DataDir:        data,
		Listen:         env("ROSMAN_LISTEN", ":8443"),
		DBPath:         env("ROSMAN_DB", filepath.Join(data, "rosman.db")),
		SecretKeyPath:  env("ROSMAN_SECRET_KEY", filepath.Join(data, "secret.key")),
		TLSCertPath:    env("ROSMAN_TLS_CERT", filepath.Join(data, "tls.crt")),
		TLSKeyPath:     env("ROSMAN_TLS_KEY", filepath.Join(data, "tls.key")),
		SSHKeyPath:     env("ROSMAN_SSH_KEY", ""),
		PollInterval:   envDur("ROSMAN_POLL_INTERVAL", 2*time.Minute),
		BackupInterval: envDur("ROSMAN_BACKUP_INTERVAL", 12*time.Hour),
		SSHTimeout:     envDur("ROSMAN_SSH_TIMEOUT", 15*time.Second),
		APITimeout:     envDur("ROSMAN_API_TIMEOUT", 15*time.Second),
		CertWarnDays:   envInt("ROSMAN_CERT_WARN_DAYS", 30),
		WebhookURL:     env("ROSMAN_WEBHOOK_URL", ""),
		TelegramToken:  env("ROSMAN_TELEGRAM_TOKEN", ""),
		TelegramChat:   env("ROSMAN_TELEGRAM_CHAT", ""),
	}
	return c
}

func envInt(k string, def int) int {
	if v := os.Getenv(k); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}
