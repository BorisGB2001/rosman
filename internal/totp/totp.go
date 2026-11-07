// Package totp implements RFC 6238 time-based one-time passwords (HMAC-SHA1,
// 30-second period, 6 digits) — the scheme used by Google Authenticator, Aegis,
// 1Password and others. No external dependencies.
package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	period = 30
	digits = 6
)

var enc = base32.StdEncoding.WithPadding(base32.NoPadding)

// NewSecret returns a fresh base32-encoded 20-byte secret.
func NewSecret() string {
	b := make([]byte, 20)
	_, _ = rand.Read(b)
	return enc.EncodeToString(b)
}

// codeAt computes the TOTP for a given Unix time.
func codeAt(secret string, t time.Time) (string, error) {
	key, err := enc.DecodeString(strings.ToUpper(strings.TrimSpace(secret)))
	if err != nil {
		return "", err
	}
	counter := uint64(t.Unix()) / period
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(buf[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off]&0x7f) << 24) | (uint32(sum[off+1]) << 16) |
		(uint32(sum[off+2]) << 8) | uint32(sum[off+3])
	return fmt.Sprintf("%0*d", digits, bin%1_000_000), nil
}

// Now returns the current TOTP for the secret (used in tests / previews).
func Now(secret string) string {
	c, _ := codeAt(secret, time.Now())
	return c
}

// Validate reports whether code matches the secret within a ±1 step window,
// tolerating small clock drift. Comparison is constant-time.
func Validate(secret, code string) bool {
	code = strings.TrimSpace(code)
	if len(code) != digits {
		return false
	}
	now := time.Now()
	for _, d := range []time.Duration{-period * time.Second, 0, period * time.Second} {
		if want, err := codeAt(secret, now.Add(d)); err == nil {
			if hmac.Equal([]byte(want), []byte(code)) {
				return true
			}
		}
	}
	return false
}

// URI builds the otpauth:// enrollment URI for an authenticator app.
func URI(issuer, account, secret string) string {
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", digits))
	q.Set("period", fmt.Sprintf("%d", period))
	return "otpauth://totp/" + label + "?" + q.Encode()
}
