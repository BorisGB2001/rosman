// Package ros talks to RouterOS devices: health/identity over the binary API
// (TLS, with trust-on-first-use certificate pinning) and config /export over SSH
// (host-key pinned). Credential choice for SSH here is key-based (the fleet key).
package ros

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"rosman/internal/model"

	"github.com/go-routeros/routeros/v3"
	"golang.org/x/crypto/ssh"
)

// Health is the subset of /system/resource + identity we collect.
type Health struct {
	Identity string
	Model    string
	Serial   string
	Version  string
	CPU      int
	FreeMem  int64
	TotalMem int64
	Uptime   string
	APISSLCert    string     // cert bound to the api-ssl service
	APICertExpiry *time.Time // its invalid-after
}

// parseROSTime parses RouterOS date strings in both the modern ISO form and the
// legacy "jan/02/2006 15:04:05" form.
func parseROSTime(s string) *time.Time {
	s = strings.TrimSpace(s)
	for _, layout := range []string{"2006-01-02 15:04:05", "Jan/02/2006 15:04:05", "2006-01-02"} {
		if t, err := time.Parse(layout, s); err == nil {
			return &t
		}
	}
	return nil
}

// certFingerprint is the hex SHA-256 of the DER leaf certificate.
func certFingerprint(der []byte) string {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:])
}

// dialAPI opens an API-SSL connection. If expectPin != "" the device's leaf
// certificate must match it; the actually-seen fingerprint is returned so the
// caller can pin it on first contact (TOFU).
func dialAPI(d model.Device, pass, expectPin string, timeout time.Duration) (*routeros.Client, string, error) {
	var seen string
	tlsConf := &tls.Config{
		InsecureSkipVerify: true, // we pin ourselves instead of using a CA
		VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
			if len(rawCerts) == 0 {
				return fmt.Errorf("device presented no certificate")
			}
			seen = certFingerprint(rawCerts[0])
			if expectPin != "" && !strings.EqualFold(seen, expectPin) {
				return fmt.Errorf("API certificate fingerprint changed (pinned %s, got %s)", expectPin, seen)
			}
			return nil
		},
	}
	addr := d.IP + ":" + strconv.Itoa(d.APIPort)
	type res struct {
		c   *routeros.Client
		err error
	}
	ch := make(chan res, 1)
	go func() {
		c, err := routeros.DialTLS(addr, d.APIUser, pass, tlsConf)
		ch <- res{c, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			return nil, seen, r.err
		}
		return r.c, seen, nil
	case <-time.After(timeout):
		return nil, seen, fmt.Errorf("API dial to %s timed out", addr)
	}
}

// Poll collects health + identity over the API. Returns the seen cert pin too.
func Poll(d model.Device, pass string, timeout time.Duration) (Health, string, error) {
	c, pin, err := dialAPI(d, pass, d.APICertPin, timeout)
	if err != nil {
		return Health{}, pin, err
	}
	defer c.Close()

	var h Health
	if r, err := c.Run("/system/identity/print"); err == nil && len(r.Re) > 0 {
		h.Identity = r.Re[0].Map["name"]
	}
	r, err := c.Run("/system/resource/print")
	if err != nil {
		return h, pin, err
	}
	if len(r.Re) > 0 {
		m := r.Re[0].Map
		h.Version = m["version"]
		h.Model = m["board-name"]
		h.Uptime = m["uptime"]
		h.CPU = atoi(m["cpu-load"])
		h.FreeMem = atoi64(m["free-memory"])
		h.TotalMem = atoi64(m["total-memory"])
	}
	if r, err := c.Run("/system/routerboard/print"); err == nil && len(r.Re) > 0 {
		h.Serial = r.Re[0].Map["serial-number"]
	}
	// api-ssl certificate name + expiry (for cert-expiry alerting).
	if r, err := c.Run("/ip/service/print", "?name=api-ssl"); err == nil && len(r.Re) > 0 {
		h.APISSLCert = r.Re[0].Map["certificate"]
	}
	if h.APISSLCert != "" {
		if r, err := c.Run("/certificate/print", "?name="+h.APISSLCert); err == nil && len(r.Re) > 0 {
			h.APICertExpiry = parseROSTime(r.Re[0].Map["invalid-after"])
		}
	}
	return h, pin, nil
}

// LoadSigner reads an SSH private key (no passphrase) for /export.
func LoadSigner(path string) (ssh.Signer, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(raw)
}

func hostKeyFingerprint(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return "SHA256:" + base64.StdEncoding.EncodeToString(sum[:])
}

// Export runs /export over SSH. The host key is pinned TOFU-style: the seen
// fingerprint is returned so the caller can store it on first contact.
func Export(d model.Device, signer ssh.Signer, timeout time.Duration) (text, hostPin string, err error) {
	var seen string
	cb := func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		seen = hostKeyFingerprint(key)
		if d.SSHHostPin != "" && seen != d.SSHHostPin {
			return fmt.Errorf("SSH host key changed (pinned %s, got %s)", d.SSHHostPin, seen)
		}
		return nil
	}
	conf := &ssh.ClientConfig{
		User:            d.SSHUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.HostKeyCallback(cb),
		// RouterOS still ships an ssh-rsa host key on many boxes; accept it.
		HostKeyAlgorithms: []string{ssh.KeyAlgoED25519, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSA},
		Timeout:           timeout,
	}
	client, err := ssh.Dial("tcp", d.IP+":22", conf)
	if err != nil {
		return "", seen, err
	}
	defer client.Close()
	sess, err := client.NewSession()
	if err != nil {
		return "", seen, err
	}
	defer sess.Close()
	out, err := sess.Output("/export")
	if err != nil {
		return "", seen, err
	}
	return string(out), seen, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}
