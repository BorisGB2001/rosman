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
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"rosman/internal/model"

	"github.com/go-routeros/routeros/v3"
	"github.com/pkg/sftp"
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
	FwLatest      string     // latest RouterOS version the device knows about
	FwChannel     string     // update channel
	FwStatus      string     // device update status string
	Neighbors     []model.Neighbor
	Ifaces        []model.IfaceSample
	Ports         []model.Port
	Temp          float64
	Clients       []model.Client
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
	// Firmware: the device's last-known update info (no network check forced here).
	if r, err := c.Run("/system/package/update/print"); err == nil && len(r.Re) > 0 {
		m := r.Re[0].Map
		h.FwChannel = m["channel"]
		h.FwLatest = m["latest-version"]
		h.FwStatus = m["status"]
	}
	// Interfaces: port list for the faceplate + byte counters for traffic graphs.
	if r, err := c.Run("/interface/print", "=stats="); err == nil {
		for _, re := range r.Re {
			m := re.Map
			disabled := m["disabled"] == "true"
			h.Ports = append(h.Ports, model.Port{
				Name: m["name"], Type: m["type"], Running: m["running"] == "true", Disabled: disabled})
			if disabled {
				continue
			}
			rx, tx := atoi64(m["rx-byte"]), atoi64(m["tx-byte"])
			if rx == 0 && tx == 0 {
				continue
			}
			h.Ifaces = append(h.Ifaces, model.IfaceSample{
				Iface: m["name"], RxBytes: rx, TxBytes: tx, Running: m["running"] == "true"})
		}
	}
	// Temperature from /system/health (optional; absent on many boards).
	if r, err := c.Run("/system/health/print"); err == nil {
		for _, re := range r.Re {
			m := re.Map
			if v := m["temperature"]; v != "" {
				h.Temp = atof(v)
			}
			if n := m["name"]; (n == "temperature" || n == "cpu-temperature" || n == "board-temperature1") && m["value"] != "" {
				h.Temp = atof(m["value"])
			}
		}
	}
	// Connected clients: DHCP leases (hostname) merged with ARP (interface).
	byMac := map[string]*model.Client{}
	if r, err := c.Run("/ip/dhcp-server/lease/print"); err == nil {
		for _, re := range r.Re {
			mm := re.Map
			mac := strings.ToUpper(mm["mac-address"])
			if mac == "" {
				continue
			}
			byMac[mac] = &model.Client{MAC: mac, IP: mm["address"], Hostname: mm["host-name"], Iface: mm["server"], Source: "dhcp"}
		}
	}
	if r, err := c.Run("/ip/arp/print"); err == nil {
		for _, re := range r.Re {
			mm := re.Map
			mac := strings.ToUpper(mm["mac-address"])
			if mac == "" {
				continue
			}
			if cl, ok := byMac[mac]; ok {
				if cl.Iface == "" {
					cl.Iface = mm["interface"]
				}
				if cl.IP == "" {
					cl.IP = mm["address"]
				}
			} else {
				byMac[mac] = &model.Client{MAC: mac, IP: mm["address"], Iface: mm["interface"], Source: "arp"}
			}
		}
	}
	for _, cl := range byMac {
		h.Clients = append(h.Clients, *cl)
	}

	// Discovered neighbours (MNDP/LLDP/CDP) for topology.
	if r, err := c.Run("/ip/neighbor/print"); err == nil {
		for _, re := range r.Re {
			m := re.Map
			h.Neighbors = append(h.Neighbors, model.Neighbor{
				Iface: m["interface"], Identity: m["identity"],
				IP: m["address"], MAC: m["mac-address"], Platform: m["platform"]})
		}
	}
	return h, pin, nil
}

// CheckUpdates forces the device to contact the upgrade server, then reads the
// result. This is the normal RouterOS update check (read-only; installs nothing).
func CheckUpdates(d model.Device, pass string, timeout time.Duration) (latest, channel, status string, err error) {
	c, _, err := dialAPI(d, pass, d.APICertPin, timeout)
	if err != nil {
		return "", "", "", err
	}
	defer c.Close()
	_, _ = c.Run("/system/package/update/check-for-updates")
	time.Sleep(2 * time.Second)
	if r, err := c.Run("/system/package/update/print"); err == nil && len(r.Re) > 0 {
		m := r.Re[0].Map
		latest, channel, status = m["latest-version"], m["channel"], m["status"]
	}
	return latest, channel, status, nil
}

// ServedFingerprint dials api-ssl without enforcing a pin and returns the
// fingerprint of the certificate the service actually presents.
func ServedFingerprint(d model.Device, pass string, timeout time.Duration) (string, error) {
	c, fp, err := dialAPI(d, pass, "", timeout)
	if err != nil {
		return fp, err
	}
	c.Close()
	return fp, nil
}

// FirmwareInstall checks for updates and, if a newer version exists, installs it
// (the device downloads and reboots). Returns rebooting=true when an install was
// kicked off; false when the device is already up to date.
func FirmwareInstall(d model.Device, pass string, timeout time.Duration) (rebooting bool, status string, err error) {
	c, _, err := dialAPI(d, pass, d.APICertPin, timeout)
	if err != nil {
		return false, "", err
	}
	_, _ = c.Run("/system/package/update/check-for-updates")
	time.Sleep(2 * time.Second)
	var installed, latest string
	if r, e := c.Run("/system/package/update/print"); e == nil && len(r.Re) > 0 {
		m := r.Re[0].Map
		status, installed, latest = m["status"], m["installed-version"], m["latest-version"]
	}
	if latest == "" || latest == installed {
		c.Close()
		return false, status, nil
	}
	_, _ = c.Run("/system/package/update/install") // device reboots; connection drops
	c.Close()
	return true, status, nil
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

// dialSSH opens an SSH client with TOFU host-key pinning. The seen host-key
// fingerprint is returned so the caller can store it on first contact.
func dialSSH(d model.Device, signer ssh.Signer, timeout time.Duration) (*ssh.Client, string, error) {
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
	return client, seen, err
}

func run(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// Export runs /export over SSH.
func Export(d model.Device, signer ssh.Signer, timeout time.Duration) (text, hostPin string, err error) {
	client, seen, err := dialSSH(d, signer, timeout)
	if err != nil {
		return "", seen, err
	}
	defer client.Close()
	out, err := run(client, "/export")
	if err != nil {
		return "", seen, err
	}
	return out, seen, nil
}

// ApplyWithGuard applies a RouterOS script with an automatic rollback safety net:
// it saves a binary backup, arms a scheduler that reloads that backup after
// guardSeconds (which reboots and fully reverts), then runs the script. If the
// change keeps the device reachable the caller disarms the guard; otherwise the
// scheduler fires and the device rolls itself back. base is a unique name used
// for the backup, scheduler and script file.
func ApplyWithGuard(d model.Device, signer ssh.Signer, base, scriptBody string, guardSeconds int, timeout time.Duration) error {
	client, _, err := dialSSH(d, signer, timeout)
	if err != nil {
		return err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return fmt.Errorf("sftp: %w", err)
	}
	f, err := sc.Create(base + ".rsc")
	if err != nil {
		sc.Close()
		return fmt.Errorf("upload script: %w", err)
	}
	if _, err := f.Write([]byte(scriptBody + "\n")); err != nil {
		f.Close()
		sc.Close()
		return fmt.Errorf("write script: %w", err)
	}
	f.Close()
	sc.Close()

	if out, err := run(client, fmt.Sprintf("/system backup save name=%s", base)); err != nil {
		return fmt.Errorf("backup save: %v (%s)", err, out)
	}
	if out, err := run(client, fmt.Sprintf(`/system scheduler add name=%s interval=%d on-event="/system backup load name=%s"`, base, guardSeconds, base)); err != nil {
		return fmt.Errorf("arm guard: %v (%s)", err, out)
	}
	// Apply the change.
	out, err := run(client, fmt.Sprintf("/import file-name=%s.rsc", base))
	_, _ = run(client, fmt.Sprintf(`/file remove [find where name="%s.rsc"]`, base))
	if err != nil || scriptFailed(out) {
		return fmt.Errorf("apply failed (guard will roll back in %ds): %v %s", guardSeconds, err, out)
	}
	return nil
}

// DisarmGuard cancels the rollback safety net after a successful, verified apply.
func DisarmGuard(d model.Device, signer ssh.Signer, base string, timeout time.Duration) error {
	client, _, err := dialSSH(d, signer, timeout)
	if err != nil {
		return err
	}
	defer client.Close()
	if _, err := run(client, fmt.Sprintf(`/system scheduler remove [find where name="%s"]`, base)); err != nil {
		return err
	}
	_, _ = run(client, fmt.Sprintf(`/file remove [find where name="%s.backup"]`, base))
	return nil
}

func scriptFailed(out string) bool {
	l := strings.ToLower(out)
	for _, s := range []string{"syntax error", "failure:", "expected command name", "bad command name", "no such item"} {
		if strings.Contains(l, s) {
			return true
		}
	}
	return false
}

// BinaryBackup runs /system backup save (password-protected) and downloads the
// resulting .backup file over SFTP, then removes it from the device.
func BinaryBackup(d model.Device, signer ssh.Signer, name, password string, timeout time.Duration) ([]byte, error) {
	client, _, err := dialSSH(d, signer, timeout)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	cmd := fmt.Sprintf(`/system backup save name=%s`, name)
	if password != "" {
		cmd += fmt.Sprintf(` password="%s"`, password)
	}
	if out, err := run(client, cmd); err != nil {
		return nil, fmt.Errorf("backup save: %v (%s)", err, out)
	}
	sc, err := sftp.NewClient(client)
	if err != nil {
		return nil, fmt.Errorf("sftp: %w", err)
	}
	defer sc.Close()
	f, err := sc.Open(name + ".backup")
	if err != nil {
		return nil, fmt.Errorf("open backup: %w", err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return nil, fmt.Errorf("read backup: %w", err)
	}
	_, _ = run(client, fmt.Sprintf(`/file remove [find where name="%s.backup"]`, name))
	return data, nil
}

// InstallServerCert uploads the CA + leaf certificate and key over SFTP, imports
// them, binds the api-ssl service to the leaf (matched by fingerprint, so re-issues
// are unambiguous) and cleans up the files. name is the cert name on the device.
func InstallServerCert(d model.Device, signer ssh.Signer, caPEM, certPEM, keyPEM []byte, fingerprint, name string, timeout time.Duration) (hostPin string, err error) {
	client, seen, err := dialSSH(d, signer, timeout)
	if err != nil {
		return seen, err
	}
	defer client.Close()

	sc, err := sftp.NewClient(client)
	if err != nil {
		return seen, fmt.Errorf("sftp: %w", err)
	}
	defer sc.Close()
	files := map[string][]byte{"rosman_ca.crt": caPEM, name + ".crt": certPEM, name + ".key": keyPEM}
	for fn, data := range files {
		f, err := sc.Create(fn)
		if err != nil {
			return seen, fmt.Errorf("upload %s: %w", fn, err)
		}
		if _, err := f.Write(data); err != nil {
			f.Close()
			return seen, fmt.Errorf("write %s: %w", fn, err)
		}
		f.Close()
	}

	steps := []string{
		`/certificate import file-name=rosman_ca.crt passphrase=""`,
		fmt.Sprintf(`/certificate import file-name=%s.crt passphrase=""`, name),
		fmt.Sprintf(`/certificate import file-name=%s.key passphrase=""`, name),
		fmt.Sprintf(`/certificate set [find where fingerprint="%s"] name="%s"`, fingerprint, name),
		fmt.Sprintf(`/ip service set api-ssl certificate="%s"`, name),
		`/ip service enable api-ssl`,
		`/file remove [find where name="rosman_ca.crt"]`,
		fmt.Sprintf(`/file remove [find where name="%s.crt"]`, name),
		fmt.Sprintf(`/file remove [find where name="%s.key"]`, name),
	}
	for _, cmd := range steps {
		if out, err := run(client, cmd); err != nil {
			return seen, fmt.Errorf("%q: %v (%s)", cmd, err, out)
		}
	}
	return seen, nil
}

func atoi(s string) int {
	n, _ := strconv.Atoi(strings.TrimSpace(s))
	return n
}

func atoi64(s string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
	return n
}

func atof(s string) float64 {
	n, _ := strconv.ParseFloat(strings.TrimSpace(s), 64)
	return n
}
