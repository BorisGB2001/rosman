// Package app wires storage, secrets and device access into the operations the
// web layer and the scheduler both need.
package app

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"rosman/internal/config"
	"rosman/internal/model"
	"rosman/internal/notify"
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
			a.Notify.Send("🟡 "+d.Name+": доступна прошивка "+latest, "установлена "+cur)
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
			a.Notify.Send("🔴 "+d.Name+" недоступно", d.IP+": "+detail)
		}
		return
	}
	if was, _ := a.Store.ResolveAlert(d.ID, rule); was {
		a.Notify.Send("🟢 "+d.Name+" снова доступно", d.IP)
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
			a.Notify.Send("🟡 "+d.Name+": истекает сертификат", expiry.Format("2006-01-02"))
		}
		return
	}
	_, _ = a.Store.ResolveAlert(d.ID, rule)
}

// BackupDevice fetches /export and stores a new version only if it changed.
func (a *App) BackupDevice(d model.Device) (changed bool, err error) {
	if a.signer == nil {
		return false, fmt.Errorf("no SSH key configured (set ROSMAN_SSH_KEY) — config backup needs SSH")
	}
	text, hostPin, err := ros.Export(d, a.signer, a.Cfg.SSHTimeout)
	if err != nil {
		return false, err
	}
	if d.SSHHostPin == "" && hostPin != "" {
		_ = a.Store.UpdatePins(d.ID, "", hostPin)
	}
	// Hash a normalized copy: RouterOS /export starts with a volatile
	// "# <date> by RouterOS <ver>" header, so hashing the raw text would make
	// every backup look changed. Strip comment lines for change detection; the
	// full text is still stored verbatim.
	sum := sha256.Sum256([]byte(normalizeExport(text)))
	h := hex.EncodeToString(sum[:])
	last, err := a.Store.LatestConfigHash(d.ID, "export")
	if err != nil {
		return false, err
	}
	if last == h {
		return false, nil // unchanged — no new version
	}
	_, err = a.Store.AddConfig(model.Config{DeviceID: d.ID, Kind: "export", SHA256: h, Content: text})
	return err == nil, err
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
