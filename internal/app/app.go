// Package app wires storage, secrets and device access into the operations the
// web layer and the scheduler both need.
package app

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"rosman/internal/config"
	"rosman/internal/model"
	"rosman/internal/notify"
	"rosman/internal/pki"
	"rosman/internal/ros"
	"rosman/internal/secret"
	"rosman/internal/store"

	"golang.org/x/crypto/ssh"
)

type App struct {
	Cfg    config.Config
	Store  *store.Store
	Box    *secret.Box
	Notify *notify.Notifier
	signer ssh.Signer // fleet SSH key for /export; may be nil
}

func New(cfg config.Config, st *store.Store, box *secret.Box) (*App, error) {
	a := &App{Cfg: cfg, Store: st, Box: box,
		Notify: notify.New(cfg.WebhookURL, cfg.TelegramToken, cfg.TelegramChat)}
	if cfg.SSHKeyPath != "" {
		s, err := ros.LoadSigner(cfg.SSHKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load SSH key %s: %w", cfg.SSHKeyPath, err)
		}
		a.signer = s
	}
	return a, nil
}

// HasSSHKey reports whether config backup over SSH is possible.
func (a *App) HasSSHKey() bool { return a.signer != nil }

// AddDevice probes the device once (API) to capture its cert pin and identity,
// then stores it. The API password is encrypted at rest.
func (a *App) AddDevice(name, ip string, apiPort int, apiUser, apiPass, sshUser string) (int64, error) {
	enc, err := a.Box.Encrypt(apiPass)
	if err != nil {
		return 0, err
	}
	d := model.Device{
		Name: name, IP: ip, APIPort: apiPort, APITLS: true,
		APIUser: apiUser, APIPassEnc: enc, SSHUser: sshUser,
	}
	// First contact: pin whatever certificate the device presents (TOFU).
	h, pin, err := ros.Poll(d, apiPass, a.Cfg.APITimeout)
	if err != nil {
		return 0, fmt.Errorf("probe failed: %w", err)
	}
	d.APICertPin = pin
	if h.Identity != "" && name == "" {
		d.Name = h.Identity
	}
	d.Model, d.Serial, d.ROSVersion = h.Model, h.Serial, h.Version
	id, err := a.Store.CreateDevice(d)
	if err != nil {
		return 0, err
	}
	now := time.Now()
	_ = a.Store.UpdateInventory(id, h.Model, h.Serial, h.Version, now)
	_ = a.Store.UpdateCertInfo(id, h.APISSLCert, h.APICertExpiry)
	_ = a.Store.AddHealth(model.Health{DeviceID: id, TS: now, CPU: h.CPU, FreeMem: h.FreeMem, TotalMem: h.TotalMem, Uptime: h.Uptime})
	return id, nil
}

// PollDevice refreshes health/inventory over the API and evaluates alerts.
func (a *App) PollDevice(d model.Device) error {
	pass, err := a.Box.Decrypt(d.APIPassEnc)
	if err != nil {
		return err
	}
	h, pin, err := ros.Poll(d, pass, a.Cfg.APITimeout)
	if err != nil {
		a.evalDown(d, true, err.Error())
		return err
	}
	a.evalDown(d, false, "")
	now := time.Now()
	if d.APICertPin == "" && pin != "" {
		_ = a.Store.UpdatePins(d.ID, pin, "")
	}
	_ = a.Store.AddHealth(model.Health{DeviceID: d.ID, TS: now, CPU: h.CPU, FreeMem: h.FreeMem, TotalMem: h.TotalMem, Uptime: h.Uptime})
	_ = a.Store.UpdateCertInfo(d.ID, h.APISSLCert, h.APICertExpiry)
	a.evalCert(d, h.APICertExpiry)
	_ = a.Store.UpdateFirmware(d.ID, h.FwLatest, h.FwChannel, h.FwStatus)
	a.evalFirmware(d, h.Version, h.FwLatest)
	_ = a.Store.ReplaceNeighbors(d.ID, h.Neighbors)
	_ = a.Store.AddIfaceSamples(d.ID, now, h.Ifaces)
	_ = a.Store.PruneIfaceBefore(now.Add(-24 * time.Hour))
	return a.Store.UpdateInventory(d.ID, h.Model, h.Serial, h.Version, now)
}

// RefreshFirmware forces an update check on the device and re-evaluates the alert.
func (a *App) RefreshFirmware(d model.Device) error {
	pass, err := a.Box.Decrypt(d.APIPassEnc)
	if err != nil {
		return err
	}
	latest, channel, status, err := ros.CheckUpdates(d, pass, a.Cfg.APITimeout+5*time.Second)
	if err != nil {
		return err
	}
	_ = a.Store.UpdateFirmware(d.ID, latest, channel, status)
	a.evalFirmware(d, d.ROSVersion, latest)
	return nil
}

// ---- change-guard ----

// ApplyResult is the outcome of applying a template to one device.
type ApplyResult struct {
	Device string
	OK     bool
	Detail string
}

// ApplyTemplate applies a script to one device under change-guard: it arms an
// auto-rollback, applies, verifies the device is still reachable over the API,
// and only then disarms. If verification fails the guard is left armed and the
// device rolls itself back.
func (a *App) ApplyTemplate(d model.Device, script string, guardSeconds int) error {
	if a.signer == nil {
		return fmt.Errorf("no SSH key configured (ROSMAN_SSH_KEY) — change-guard needs SSH")
	}
	if guardSeconds < 30 {
		guardSeconds = 30
	} else if guardSeconds > 3600 {
		guardSeconds = 3600
	}
	base := fmt.Sprintf("rosman-guard-%d", time.Now().UnixNano())
	if err := ros.ApplyWithGuard(d, a.signer, base, script, guardSeconds, a.Cfg.SSHTimeout+20*time.Second); err != nil {
		return err
	}
	// Verify the device is still reachable over the API before disarming.
	pass, derr := a.Box.Decrypt(d.APIPassEnc)
	if derr != nil {
		return derr
	}
	if _, err := ros.ServedFingerprint(d, pass, a.Cfg.APITimeout); err != nil {
		return fmt.Errorf("применено, но устройство недоступно по API — автооткат сработает через %d с", guardSeconds)
	}
	if err := ros.DisarmGuard(d, a.signer, base, a.Cfg.SSHTimeout); err != nil {
		return fmt.Errorf("применено и проверено, но не удалось снять страховку (%v) — откат через %d с; снимите планировщик %s вручную или примените снова", err, guardSeconds, base)
	}
	return nil
}

// ApplyTemplateAll applies a script to every device, sequentially, each guarded.
func (a *App) ApplyTemplateAll(script string, guardSeconds int) []ApplyResult {
	devs, _ := a.Store.Devices()
	results := make([]ApplyResult, 0, len(devs))
	for _, d := range devs {
		r := ApplyResult{Device: d.Name, OK: true, Detail: "ok"}
		if err := a.ApplyTemplate(d, script, guardSeconds); err != nil {
			r.OK, r.Detail = false, err.Error()
		}
		results = append(results, r)
	}
	return results
}

// ---- PKI / api-ssl ----

type CAInfo struct {
	CN      string
	Created time.Time
	Present bool
}

func (a *App) CAStatus() CAInfo {
	cn, _, _, created, ok := a.Store.GetCA()
	return CAInfo{CN: cn, Created: created, Present: ok}
}

// GenerateCA creates a new self-signed CA and stores it (key encrypted).
func (a *App) GenerateCA(cn string) error {
	if cn == "" {
		cn = "ROSMan CA"
	}
	certPEM, keyPEM, err := pki.GenerateCA(cn)
	if err != nil {
		return err
	}
	enc, err := a.Box.Encrypt(string(keyPEM))
	if err != nil {
		return err
	}
	return a.Store.SaveCA(cn, string(certPEM), enc)
}

// ImportCA validates and stores an existing CA (certificate + key PEM).
func (a *App) ImportCA(certPEM, keyPEM string) error {
	if _, _, err := pki.ParseCA([]byte(certPEM), []byte(keyPEM)); err != nil {
		return err
	}
	enc, err := a.Box.Encrypt(keyPEM)
	if err != nil {
		return err
	}
	cn := pki.CASubject([]byte(certPEM))
	if cn == "" {
		cn = "imported CA"
	}
	return a.Store.SaveCA(cn, certPEM, enc)
}

// IssueCert issues an api-ssl server certificate for the device signed by the
// CA, installs it over SSH, binds api-ssl, and re-pins ROSMan to the new cert.
func (a *App) IssueCert(d model.Device) error {
	if a.signer == nil {
		return fmt.Errorf("no SSH key configured (ROSMAN_SSH_KEY) — cert install needs SSH")
	}
	cn, caCertPEM, keyEnc, _, ok := a.Store.GetCA()
	_ = cn
	if !ok {
		return fmt.Errorf("no CA configured — generate or import one first")
	}
	caKeyPEM, err := a.Box.Decrypt(keyEnc)
	if err != nil {
		return err
	}
	name := d.Name
	if name == "" {
		name = "device"
	}
	var ips []net.IP
	if ip := net.ParseIP(d.IP); ip != nil {
		ips = append(ips, ip)
	}
	// Unique CN avoids RouterOS's unstable api-ssl cert selection when several
	// certificates share a common name; the device identity and IP go in SANs,
	// so hostname/IP validation still works.
	certName := fmt.Sprintf("rosman-%s-%d", name, time.Now().Unix())
	certPEM, keyPEM, fp, expiry, err := pki.IssueServerCert([]byte(caCertPEM), []byte(caKeyPEM), certName, ips, []string{name}, 3650)
	if err != nil {
		return err
	}
	if _, err := ros.InstallServerCert(d, a.signer, []byte(caCertPEM), certPEM, keyPEM, fp, certName, a.Cfg.SSHTimeout+10*time.Second); err != nil {
		return err
	}
	exp := expiry
	_ = a.Store.UpdateCertInfo(d.ID, certName, &exp)
	a.evalCert(d, &exp)

	// Verify what api-ssl actually serves and pin THAT, so polling keeps working
	// regardless. RouterOS selects the server cert by common name, so if another
	// certificate with the same CN is still present it may be served instead.
	pass, derr := a.Box.Decrypt(d.APIPassEnc)
	if derr == nil {
		if served, serr := ros.ServedFingerprint(d, pass, a.Cfg.APITimeout); serr == nil && served != "" {
			_ = a.Store.SetCertPin(d.ID, served)
			if served != fp {
				return fmt.Errorf("сертификат установлен, но api-ssl отдаёт другой (CN=%s уже есть у другого сертификата на устройстве — удалите лишние вручную, тогда будет отдаваться сертификат ROSMan)", name)
			}
			return nil
		}
	}
	// Could not verify the served cert; fall back to pinning the issued one.
	_ = a.Store.SetCertPin(d.ID, fp)
	return nil
}

// evalFirmware raises/resolves the firmware_outdated alert.
func (a *App) evalFirmware(d model.Device, installed, latest string) {
	const rule = "firmware_outdated"
	inst := strings.Fields(installed) // drop "(stable)" style suffixes
	cur := ""
	if len(inst) > 0 {
		cur = inst[0]
	}
	if latest != "" && cur != "" && latest != cur {
		prev, _ := a.Store.AlertState(d.ID, rule)
		_ = a.Store.RaiseAlert(d.ID, rule, "warn",
			fmt.Sprintf("доступна RouterOS %s (установлена %s)", latest, cur))
		if prev != "active" {
			a.alertNotify("🟡 "+d.Name+": доступна прошивка "+latest, "установлена "+cur)
		}
		return
	}
	_, _ = a.Store.ResolveAlert(d.ID, rule)
}

// evalDown raises/resolves the device_down alert and notifies on transitions.
func (a *App) evalDown(d model.Device, down bool, detail string) {
	const rule = "device_down"
	if down {
		prev, _ := a.Store.AlertState(d.ID, rule)
		_ = a.Store.RaiseAlert(d.ID, rule, "crit", "недоступно по API: "+detail)
		if prev != "active" {
			a.alertNotify("🔴 "+d.Name+" недоступно", d.IP+": "+detail)
		}
		return
	}
	if was, _ := a.Store.ResolveAlert(d.ID, rule); was {
		a.alertNotify("🟢 "+d.Name+" снова доступно", d.IP)
	}
}

// evalCert raises/resolves the cert_expiring alert.
func (a *App) evalCert(d model.Device, expiry *time.Time) {
	const rule = "cert_expiring"
	if expiry != nil && time.Until(*expiry) < time.Duration(a.Cfg.CertWarnDays)*24*time.Hour {
		days := int(time.Until(*expiry).Hours() / 24)
		prev, _ := a.Store.AlertState(d.ID, rule)
		_ = a.Store.RaiseAlert(d.ID, rule, "warn",
			fmt.Sprintf("api-ssl сертификат истекает %s (через %d дн.)", expiry.Format("2006-01-02"), days))
		if prev != "active" {
			a.alertNotify("🟡 "+d.Name+": истекает сертификат", expiry.Format("2006-01-02"))
		}
		return
	}
	_, _ = a.Store.ResolveAlert(d.ID, rule)
}

// BackupMode is the configured default backup mode.
func (a *App) BackupMode() string {
	if m, ok := a.Store.GetSetting("backup_mode"); ok && m != "" {
		return m
	}
	return "export"
}

func (a *App) setting(key string) string {
	v, _ := a.Store.GetSetting(key)
	return v
}

func (a *App) settingDecrypt(key string) string {
	v := a.setting(key)
	if v == "" {
		return ""
	}
	p, _ := a.Box.Decrypt(v)
	return p
}

// BackupDevice backs a device up in the requested mode (export | binary | both),
// stores a version, and delivers it to the configured destinations. mode=="" uses
// the configured default.
func (a *App) BackupDevice(d model.Device, mode string) (changed bool, err error) {
	if a.signer == nil {
		return false, fmt.Errorf("no SSH key configured (set ROSMAN_SSH_KEY) — backup needs SSH")
	}
	if mode == "" {
		mode = a.BackupMode()
	}
	ts := time.Now().Format("20060102-150405")
	base := sanitize(d.Name)

	switch mode {
	case "binary":
		data, err := ros.BinaryBackup(d, a.signer, base+"-"+ts, a.settingDecrypt("backup_password_enc"), a.Cfg.SSHTimeout+30*time.Second)
		if err != nil {
			return false, err
		}
		a.storeBlob(d.ID, "binary", data)
		a.deliverBackup(d.Name, base+"_"+ts+".backup", data)
		return true, nil
	case "both":
		text, hostPin, err := ros.Export(d, a.signer, a.Cfg.SSHTimeout)
		if err != nil {
			return false, err
		}
		if d.SSHHostPin == "" && hostPin != "" {
			_ = a.Store.UpdatePins(d.ID, "", hostPin)
		}
		bin, err := ros.BinaryBackup(d, a.signer, base+"-"+ts, a.settingDecrypt("backup_password_enc"), a.Cfg.SSHTimeout+30*time.Second)
		if err != nil {
			return false, err
		}
		zipData, err := makeZip(base+".rsc", []byte(text), base+".backup", bin)
		if err != nil {
			return false, err
		}
		a.storeBlob(d.ID, "archive", zipData)
		a.deliverBackup(d.Name, base+"_"+ts+".zip", zipData)
		return true, nil
	default: // export
		text, hostPin, err := ros.Export(d, a.signer, a.Cfg.SSHTimeout)
		if err != nil {
			return false, err
		}
		if d.SSHHostPin == "" && hostPin != "" {
			_ = a.Store.UpdatePins(d.ID, "", hostPin)
		}
		sum := sha256.Sum256([]byte(normalizeExport(text)))
		h := hex.EncodeToString(sum[:])
		last, _ := a.Store.LatestConfigHash(d.ID, "export")
		if last == h {
			return false, nil // unchanged
		}
		if _, err := a.Store.AddConfig(model.Config{DeviceID: d.ID, Kind: "export", SHA256: h, Content: text}); err != nil {
			return false, err
		}
		a.deliverBackup(d.Name, base+"_"+ts+".rsc", []byte(text))
		return true, nil
	}
}

func (a *App) storeBlob(deviceID int64, kind string, data []byte) {
	sum := sha256.Sum256(data)
	_, _ = a.Store.AddConfig(model.Config{DeviceID: deviceID, Kind: kind,
		SHA256: hex.EncodeToString(sum[:]), Content: base64.StdEncoding.EncodeToString(data)})
}

// deliverBackup sends a produced backup to the configured destinations.
func (a *App) deliverBackup(dev, filename string, data []byte) {
	for _, m := range strings.Split(a.setting("backup_deliver"), ",") {
		switch strings.TrimSpace(m) {
		case "folder":
			dir := a.setting("backup_folder")
			if dir == "" {
				continue
			}
			p := filepath.Join(dir, sanitize(dev))
			if err := os.MkdirAll(p, 0o700); err != nil {
				log.Printf("backup folder: %v", err)
				continue
			}
			if err := os.WriteFile(filepath.Join(p, filename), data, 0o600); err != nil {
				log.Printf("backup folder: %v", err)
			}
		case "telegram":
			tok, chat := a.setting("tg_token"), a.setting("tg_chat")
			if tok != "" && chat != "" {
				if err := notify.SendTelegramDoc(tok, chat, filename, data, dev); err != nil {
					log.Printf("backup telegram: %v", err)
				}
			}
		case "email":
			if err := notify.SendMail(a.smtp(), "ROSMan backup: "+dev, filename, filename, data); err != nil {
				log.Printf("backup email: %v", err)
			}
		}
	}
}

func (a *App) smtp() notify.SMTP {
	to := []string{}
	for _, t := range strings.Split(a.setting("smtp_to"), ",") {
		if s := strings.TrimSpace(t); s != "" {
			to = append(to, s)
		}
	}
	return notify.SMTP{
		Host: a.setting("smtp_host"), Port: a.setting("smtp_port"),
		User: a.setting("smtp_user"), Pass: a.settingDecrypt("smtp_pass_enc"),
		From: a.setting("smtp_from"), To: to,
	}
}

// alertNotify fans an alert out to env channels plus settings-configured Telegram and email.
func (a *App) alertNotify(subject, text string) {
	a.Notify.Send(subject, text)
	if tok, chat := a.setting("tg_token"), a.setting("tg_chat"); tok != "" && chat != "" {
		_ = notify.SendTelegramText(tok, chat, subject+"\n"+text)
	}
	if a.setting("smtp_host") != "" {
		_ = notify.SendMail(a.smtp(), subject, text, "", nil)
	}
}

func sanitize(s string) string {
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	if b.Len() == 0 {
		return "device"
	}
	return b.String()
}

func makeZip(n1 string, d1 []byte, n2 string, d2 []byte) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		n string
		d []byte
	}{{n1, d1}, {n2, d2}} {
		w, err := zw.Create(f.n)
		if err != nil {
			return nil, err
		}
		if _, err := w.Write(f.d); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// normalizeExport drops comment lines (which include the volatile export
// timestamp header) so identical configs hash identically.
func normalizeExport(s string) string {
	var b strings.Builder
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimRight(line, "\r")
		if strings.HasPrefix(strings.TrimSpace(t), "#") {
			continue
		}
		b.WriteString(t)
		b.WriteByte('\n')
	}
	return b.String()
}
