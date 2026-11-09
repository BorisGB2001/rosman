// Package store is the SQLite persistence layer (modernc, pure-Go, WAL).
package store

import (
	_ "embed"
	"database/sql"
	"errors"
	"strings"
	"time"

	"rosman/internal/model"

	_ "modernc.org/sqlite"
)

//go:embed migrations.sql
var migrations string

var ErrNotFound = errors.New("not found")

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(ON)")
	if err != nil {
		return nil, err
	}
	// SQLite with a single writer connection avoids "database is locked".
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(migrations); err != nil {
		db.Close()
		return nil, err
	}
	// Add columns for databases created before they existed. SQLite has no
	// "ADD COLUMN IF NOT EXISTS", so a duplicate-column error here is expected
	// and ignored.
	for _, alter := range []string{
		`ALTER TABLE devices ADD COLUMN api_ssl_cert TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN api_cert_expiry TIMESTAMP`,
		`ALTER TABLE devices ADD COLUMN fw_latest TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN fw_channel TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN fw_status TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN site_id INTEGER`,
		`ALTER TABLE metrics ADD COLUMN temp REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN snmp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN snmp_community_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN snmp_port INTEGER NOT NULL DEFAULT 161`,
		`ALTER TABLE users ADD COLUMN totp_secret_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE sites ADD COLUMN lat REAL`,
		`ALTER TABLE sites ADD COLUMN lon REAL`,
		`ALTER TABLE devices ADD COLUMN device_type TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN last_fail_at TIMESTAMP`,
		`ALTER TABLE devices ADD COLUMN poll_interval_sec INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE cron_jobs ADD COLUMN command TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN notes TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN rb_current_fw TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN rb_upgrade_fw TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE fw_jobs ADD COLUMN kind TEXT NOT NULL DEFAULT 'ros'`,
	} {
		_, _ = db.Exec(alter)
	}
	// Backfill a rough device type for rows added before the column existed.
	_, _ = db.Exec(`UPDATE devices SET device_type=CASE
		WHEN upper(model) LIKE 'CRS%' OR upper(model) LIKE 'CSS%' OR upper(model) LIKE '%SWITCH%' OR upper(model) LIKE 'NETPOWER%'
		THEN 'switch' ELSE 'router' END WHERE device_type='' AND model!=''`)
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

// ---- vendor / device-model catalog ----

func (s *Store) Vendors() ([]model.Vendor, error) {
	rows, err := s.db.Query(`SELECT v.id,v.name,v.website,v.notes,v.created_at,
		(SELECT count(*) FROM vendor_models m WHERE m.vendor_id=v.id)
		FROM vendors v ORDER BY v.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Vendor
	for rows.Next() {
		var v model.Vendor
		if err := rows.Scan(&v.ID, &v.Name, &v.Website, &v.Notes, &v.CreatedAt, &v.ModelCount); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *Store) Vendor(id int64) (model.Vendor, error) {
	var v model.Vendor
	err := s.db.QueryRow(`SELECT id,name,website,notes,created_at FROM vendors WHERE id=?`, id).
		Scan(&v.ID, &v.Name, &v.Website, &v.Notes, &v.CreatedAt)
	return v, err
}

func (s *Store) CreateVendor(name, website, notes string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO vendors(name,website,notes) VALUES(?,?,?)`, name, website, notes)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateVendor(id int64, name, website, notes string) error {
	_, err := s.db.Exec(`UPDATE vendors SET name=?, website=?, notes=? WHERE id=?`, name, website, notes, id)
	return err
}

func (s *Store) DeleteVendor(id int64) error {
	_, err := s.db.Exec(`DELETE FROM vendors WHERE id=?`, id)
	return err
}

func (s *Store) VendorModels(vendorID int64) ([]model.VendorModel, error) {
	rows, err := s.db.Query(`SELECT id,vendor_id,name,norm,notes,image_type,image IS NOT NULL,created_at
		FROM vendor_models WHERE vendor_id=? ORDER BY name`, vendorID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VendorModel
	for rows.Next() {
		var m model.VendorModel
		if err := rows.Scan(&m.ID, &m.VendorID, &m.Name, &m.Norm, &m.Notes, &m.ImageType, &m.HasImage, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// AllVendorModels lists every catalog model with its vendor name, for the
// add-device template picker.
func (s *Store) AllVendorModels() ([]model.VendorModel, error) {
	rows, err := s.db.Query(`SELECT m.id,m.vendor_id,m.name,m.norm,m.notes,m.image IS NOT NULL,v.name
		FROM vendor_models m JOIN vendors v ON v.id=m.vendor_id ORDER BY v.name,m.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.VendorModel
	for rows.Next() {
		var m model.VendorModel
		if err := rows.Scan(&m.ID, &m.VendorID, &m.Name, &m.Norm, &m.Notes, &m.HasImage, &m.VendorName); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) VendorModel(id int64) (model.VendorModel, error) {
	var m model.VendorModel
	err := s.db.QueryRow(`SELECT m.id,m.vendor_id,m.name,m.norm,m.notes,m.image_type,m.image IS NOT NULL,m.created_at,v.name,v.website
		FROM vendor_models m JOIN vendors v ON v.id=m.vendor_id WHERE m.id=?`, id).
		Scan(&m.ID, &m.VendorID, &m.Name, &m.Norm, &m.Notes, &m.ImageType, &m.HasImage, &m.CreatedAt, &m.VendorName, &m.VendorWebsite)
	return m, err
}

// VendorModelByNorm finds the catalog model matching a normalized model string
// (device.Model run through the same normalizer), for pulling template info onto
// the device card. Returns ok=false when nothing matches.
func (s *Store) VendorModelByNorm(norm string) (model.VendorModel, bool) {
	if norm == "" {
		return model.VendorModel{}, false
	}
	var m model.VendorModel
	err := s.db.QueryRow(`SELECT m.id,m.vendor_id,m.name,m.norm,m.notes,m.image_type,m.image IS NOT NULL,m.created_at,v.name,v.website
		FROM vendor_models m JOIN vendors v ON v.id=m.vendor_id WHERE m.norm=? LIMIT 1`, norm).
		Scan(&m.ID, &m.VendorID, &m.Name, &m.Norm, &m.Notes, &m.ImageType, &m.HasImage, &m.CreatedAt, &m.VendorName, &m.VendorWebsite)
	if err != nil {
		return model.VendorModel{}, false
	}
	return m, true
}

func (s *Store) CreateVendorModel(vendorID int64, name, norm, notes string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO vendor_models(vendor_id,name,norm,notes) VALUES(?,?,?,?)`, vendorID, name, norm, notes)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) UpdateVendorModel(id int64, name, norm, notes string) error {
	_, err := s.db.Exec(`UPDATE vendor_models SET name=?, norm=?, notes=? WHERE id=?`, name, norm, notes, id)
	return err
}

func (s *Store) DeleteVendorModel(id int64) error {
	_, err := s.db.Exec(`DELETE FROM vendor_models WHERE id=?`, id)
	return err
}

func (s *Store) SetVendorModelImage(id int64, contentType string, data []byte) error {
	_, err := s.db.Exec(`UPDATE vendor_models SET image=?, image_type=? WHERE id=?`, data, contentType, id)
	return err
}

func (s *Store) VendorModelImageData(id int64) (string, []byte, error) {
	var ct string
	var data []byte
	err := s.db.QueryRow(`SELECT image_type,image FROM vendor_models WHERE id=?`, id).Scan(&ct, &data)
	return ct, data, err
}

// Backup writes a consistent snapshot of the database to path using SQLite's
// VACUUM INTO, which is safe to run against the live DB (it takes a read lock
// and produces a compacted, self-contained copy).
func (s *Store) Backup(path string) error {
	_, err := s.db.Exec(`VACUUM INTO ?`, path)
	return err
}

// ---- users ----

func (s *Store) CountUsers() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n, err
}

func (s *Store) CreateUser(u model.User) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO users(username,password_hash,role) VALUES(?,?,?)`,
		u.Username, u.PasswordHash, string(u.Role))
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

const userCols = `id,username,password_hash,role,created_at,totp_secret_enc,totp_enabled`

func scanUser(row interface{ Scan(...any) error }) (model.User, error) {
	var u model.User
	var role string
	err := row.Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt, &u.TOTPSecretEnc, &u.TOTPEnabled)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Role = model.Role(role)
	return u, err
}

func (s *Store) UserByName(name string) (model.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE username=?`, name))
}

func (s *Store) UserByID(id int64) (model.User, error) {
	return scanUser(s.db.QueryRow(`SELECT `+userCols+` FROM users WHERE id=?`, id))
}

// Users lists all accounts, newest first.
func (s *Store) Users() ([]model.User, error) {
	rows, err := s.db.Query(`SELECT ` + userCols + ` FROM users ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, u)
	}
	return out, rows.Err()
}

// CountAdmins returns how many admin accounts exist (for the last-admin guard).
func (s *Store) CountAdmins() (int, error) {
	var n int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM users WHERE role='admin'`).Scan(&n)
	return n, err
}

func (s *Store) UpdateUserRole(id int64, role model.Role) error {
	_, err := s.db.Exec(`UPDATE users SET role=? WHERE id=?`, string(role), id)
	return err
}

func (s *Store) UpdateUserPassword(id int64, hash string) error {
	_, err := s.db.Exec(`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	return err
}

func (s *Store) DeleteUser(id int64) error {
	_, err := s.db.Exec(`DELETE FROM users WHERE id=?`, id)
	return err
}

// SetTOTP stores (or clears) a user's encrypted TOTP secret and enabled flag.
func (s *Store) SetTOTP(userID int64, secretEnc string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret_enc=?, totp_enabled=? WHERE id=?`, secretEnc, enabled, userID)
	return err
}

// ---- compliance rules ----

func (s *Store) CreateComplianceRule(r model.ComplianceRule) error {
	_, err := s.db.Exec(`INSERT INTO compliance_rules(name,severity,kind,pattern,enabled) VALUES(?,?,?,?,1)`,
		r.Name, r.Severity, r.Kind, r.Pattern)
	return err
}

func (s *Store) ComplianceRules() ([]model.ComplianceRule, error) {
	rows, err := s.db.Query(`SELECT id,name,severity,kind,pattern,enabled,created_at FROM compliance_rules ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.ComplianceRule
	for rows.Next() {
		var r model.ComplianceRule
		var en int
		if err := rows.Scan(&r.ID, &r.Name, &r.Severity, &r.Kind, &r.Pattern, &en, &r.CreatedAt); err != nil {
			return nil, err
		}
		r.Enabled = en != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteComplianceRule(id int64) error {
	_, err := s.db.Exec(`DELETE FROM compliance_rules WHERE id=?`, id)
	return err
}

func (s *Store) SetComplianceEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE compliance_rules SET enabled=? WHERE id=?`, b2i(enabled), id)
	return err
}

// ---- cron jobs ----

const cronCols = `id,name,action,target,template_id,guard,kind,interval_min,at_hour,at_min,weekday,enabled,last_run,last_status,next_run,created_at,command`

func scanCron(sc interface{ Scan(...any) error }) (model.CronJob, error) {
	var j model.CronJob
	var en int
	err := sc.Scan(&j.ID, &j.Name, &j.Action, &j.Target, &j.TemplateID, &j.Guard, &j.Kind,
		&j.IntervalMin, &j.AtHour, &j.AtMin, &j.Weekday, &en, &j.LastRun, &j.LastStatus, &j.NextRun, &j.CreatedAt, &j.Command)
	j.Enabled = en != 0
	return j, err
}

func (s *Store) CreateCronJob(j model.CronJob) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO cron_jobs(name,action,target,template_id,guard,kind,interval_min,at_hour,at_min,weekday,enabled,next_run,command)
		VALUES(?,?,?,?,?,?,?,?,?,?,1,?,?)`,
		j.Name, j.Action, j.Target, j.TemplateID, j.Guard, j.Kind, j.IntervalMin, j.AtHour, j.AtMin, j.Weekday, j.NextRun, j.Command)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) CronJobs() ([]model.CronJob, error) {
	rows, err := s.db.Query(`SELECT ` + cronCols + ` FROM cron_jobs ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.CronJob
	for rows.Next() {
		j, err := scanCron(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) CronJob(id int64) (model.CronJob, error) {
	return scanCron(s.db.QueryRow(`SELECT `+cronCols+` FROM cron_jobs WHERE id=?`, id))
}

func (s *Store) DeleteCronJob(id int64) error {
	_, err := s.db.Exec(`DELETE FROM cron_jobs WHERE id=?`, id)
	return err
}

func (s *Store) SetCronEnabled(id int64, enabled bool) error {
	_, err := s.db.Exec(`UPDATE cron_jobs SET enabled=? WHERE id=?`, b2i(enabled), id)
	return err
}

func (s *Store) UpdateCronRun(id int64, lastRun time.Time, status string, next time.Time) error {
	_, err := s.db.Exec(`UPDATE cron_jobs SET last_run=?, last_status=?, next_run=? WHERE id=?`, lastRun, status, next, id)
	return err
}

// ---- webhooks ----

func (s *Store) CreateWebhook(url, events, secretEnc string) error {
	_, err := s.db.Exec(`INSERT INTO webhooks(url,events,secret_enc,enabled) VALUES(?,?,?,1)`, url, events, secretEnc)
	return err
}

func scanWebhook(sc interface{ Scan(...any) error }) (model.Webhook, error) {
	var h model.Webhook
	err := sc.Scan(&h.ID, &h.URL, &h.Events, &h.SecretEnc, &h.Enabled, &h.LastStatus, &h.LastAt, &h.CreatedAt)
	return h, err
}

func (s *Store) Webhooks() ([]model.Webhook, error) {
	rows, err := s.db.Query(`SELECT id,url,events,secret_enc,enabled,last_status,last_at,created_at FROM webhooks ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Webhook
	for rows.Next() {
		h, err := scanWebhook(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWebhook(id int64) error {
	_, err := s.db.Exec(`DELETE FROM webhooks WHERE id=?`, id)
	return err
}

func (s *Store) SetWebhookStatus(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE webhooks SET last_status=?, last_at=CURRENT_TIMESTAMP WHERE id=?`, status, id)
	return err
}

// ---- maintenance windows ----

func (s *Store) CreateWindow(deviceID *int64, start, end time.Time, note, by string) error {
	_, err := s.db.Exec(`INSERT INTO maintenance_windows(device_id,starts_at,ends_at,note,created_by) VALUES(?,?,?,?,?)`,
		deviceID, start, end, note, by)
	return err
}

func (s *Store) Windows() ([]model.MaintenanceWindow, error) {
	rows, err := s.db.Query(`SELECT id,device_id,starts_at,ends_at,note,created_by,created_at FROM maintenance_windows ORDER BY starts_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.MaintenanceWindow
	for rows.Next() {
		var m model.MaintenanceWindow
		if err := rows.Scan(&m.ID, &m.DeviceID, &m.StartsAt, &m.EndsAt, &m.Note, &m.CreatedBy, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) DeleteWindow(id int64) error {
	_, err := s.db.Exec(`DELETE FROM maintenance_windows WHERE id=?`, id)
	return err
}

// InMaintenance reports whether a device is covered by an active window now
// (either a device-specific window or a fleet-wide one with device_id NULL).
func (s *Store) InMaintenance(deviceID int64, now time.Time) bool {
	var one int
	err := s.db.QueryRow(`SELECT 1 FROM maintenance_windows
		WHERE (device_id IS NULL OR device_id=?) AND starts_at<=? AND ends_at>=? LIMIT 1`,
		deviceID, now, now).Scan(&one)
	return err == nil
}

// ---- API tokens ----

func (s *Store) CreateToken(userID int64, name, hash string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO api_tokens(user_id,name,token_hash) VALUES(?,?,?)`, userID, name, hash)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) TokensByUser(userID int64) ([]model.APIToken, error) {
	rows, err := s.db.Query(`SELECT id,user_id,name,created_at,last_used FROM api_tokens WHERE user_id=? ORDER BY id DESC`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.APIToken
	for rows.Next() {
		var t model.APIToken
		if err := rows.Scan(&t.ID, &t.UserID, &t.Name, &t.CreatedAt, &t.LastUsed); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// UserByTokenHash returns the user owning the token with the given hash and
// updates its last_used timestamp.
func (s *Store) UserByTokenHash(hash string) (model.User, error) {
	var uid int64
	err := s.db.QueryRow(`SELECT user_id FROM api_tokens WHERE token_hash=?`, hash).Scan(&uid)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}
	_, _ = s.db.Exec(`UPDATE api_tokens SET last_used=CURRENT_TIMESTAMP WHERE token_hash=?`, hash)
	return s.UserByID(uid)
}

// DeleteToken revokes a token, but only if it belongs to userID.
func (s *Store) DeleteToken(id, userID int64) error {
	_, err := s.db.Exec(`DELETE FROM api_tokens WHERE id=? AND user_id=?`, id, userID)
	return err
}

// ---- sessions ----

func (s *Store) CreateSession(token string, userID int64, expires time.Time) error {
	_, err := s.db.Exec(`INSERT INTO sessions(token,user_id,expires_at) VALUES(?,?,?)`, token, userID, expires)
	return err
}

func (s *Store) SessionUser(token string) (model.User, error) {
	var uid int64
	var exp time.Time
	err := s.db.QueryRow(`SELECT user_id,expires_at FROM sessions WHERE token=?`, token).Scan(&uid, &exp)
	if errors.Is(err, sql.ErrNoRows) {
		return model.User{}, ErrNotFound
	}
	if err != nil {
		return model.User{}, err
	}
	if time.Now().After(exp) {
		s.DeleteSession(token)
		return model.User{}, ErrNotFound
	}
	return s.UserByID(uid)
}

func (s *Store) DeleteSession(token string) error {
	_, err := s.db.Exec(`DELETE FROM sessions WHERE token=?`, token)
	return err
}

// ---- devices ----

func (s *Store) CreateDevice(d model.Device) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO devices(name,ip,api_port,api_tls,api_user,api_pass_enc,ssh_user,api_cert_pin,ssh_host_pin,model,serial,ros_version)
		VALUES(?,?,?,?,?,?,?,?,?,?,?,?)`,
		d.Name, d.IP, d.APIPort, b2i(d.APITLS), d.APIUser, d.APIPassEnc, d.SSHUser,
		d.APICertPin, d.SSHHostPin, d.Model, d.Serial, d.ROSVersion)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeleteDevice removes a device and all of its dependent rows.
func (s *Store) DeleteDevice(id int64) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, t := range []string{"metrics", "configs", "alerts", "device_tags", "device_ports",
		"device_clients", "device_neighbors", "iface_traffic", "topo_pos", "topo_hidden", "device_images", "bridge_hosts", "device_vlans"} {
		if _, err := tx.Exec(`DELETE FROM `+t+` WHERE device_id=?`, id); err != nil {
			tx.Rollback()
			return err
		}
	}
	if _, err := tx.Exec(`DELETE FROM devices WHERE id=?`, id); err != nil {
		tx.Rollback()
		return err
	}
	return tx.Commit()
}

func scanDevice(row interface{ Scan(...any) error }) (model.Device, error) {
	var d model.Device
	var tls int
	var last, exp sql.NullTime
	var site sql.NullInt64
	var snmpEn int
	var fail sql.NullTime
	err := row.Scan(&d.ID, &d.Name, &d.IP, &d.APIPort, &tls, &d.APIUser, &d.APIPassEnc,
		&d.SSHUser, &d.APICertPin, &d.SSHHostPin, &d.Model, &d.Serial, &d.ROSVersion, &last, &d.CreatedAt,
		&d.APISSLCert, &exp, &d.FwLatest, &d.FwChannel, &d.FwStatus, &site,
		&snmpEn, &d.SNMPCommEnc, &d.SNMPPort, &d.DeviceType, &fail, &d.PollIntervalSec, &d.Notes,
		&d.RBCurrentFw, &d.RBUpgradeFw)
	d.APITLS = tls != 0
	d.SNMPEnabled = snmpEn != 0
	if fail.Valid {
		d.LastFail = &fail.Time
	}
	if last.Valid {
		d.LastSeen = &last.Time
	}
	if exp.Valid {
		d.APICertExpiry = &exp.Time
	}
	if site.Valid {
		d.SiteID = &site.Int64
	}
	return d, err
}

const deviceCols = `id,name,ip,api_port,api_tls,api_user,api_pass_enc,ssh_user,api_cert_pin,ssh_host_pin,model,serial,ros_version,last_seen,created_at,api_ssl_cert,api_cert_expiry,fw_latest,fw_channel,fw_status,site_id,snmp_enabled,snmp_community_enc,snmp_port,device_type,last_fail_at,poll_interval_sec,notes,rb_current_fw,rb_upgrade_fw`

// SetDeviceType sets a device's role (router/switch/mix, or "" for unknown).
func (s *Store) SetDeviceType(id int64, t string) error {
	_, err := s.db.Exec(`UPDATE devices SET device_type=? WHERE id=?`, t, id)
	return err
}

// SetDevicePollInterval sets a per-device poll interval in seconds (0 = global).
func (s *Store) SetDevicePollInterval(id int64, sec int) error {
	if sec < 0 {
		sec = 0
	}
	_, err := s.db.Exec(`UPDATE devices SET poll_interval_sec=? WHERE id=?`, sec, id)
	return err
}

// MarkDeviceFail records the time of the latest poll failure.
// MarkDeviceFail records a failed poll. The timestamp is set only on the first
// failure of a streak (last_fail_at IS NULL) and left untouched on subsequent
// consecutive failures, so it marks when the device first went bad; a
// successful poll clears it (see UpdateInventory).
func (s *Store) MarkDeviceFail(id int64) error {
	_, err := s.db.Exec(`UPDATE devices SET last_fail_at=CURRENT_TIMESTAMP WHERE id=? AND last_fail_at IS NULL`, id)
	return err
}

func (s *Store) SetDeviceSNMP(id int64, enabled bool, communityEnc string, port int) error {
	if port == 0 {
		port = 161
	}
	_, err := s.db.Exec(`UPDATE devices SET snmp_enabled=?, snmp_community_enc=COALESCE(NULLIF(?,''),snmp_community_enc), snmp_port=? WHERE id=?`,
		b2i(enabled), communityEnc, port, id)
	return err
}

func (s *Store) Device(id int64) (model.Device, error) {
	d, err := scanDevice(s.db.QueryRow(`SELECT `+deviceCols+` FROM devices WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return d, ErrNotFound
	}
	return d, err
}

func (s *Store) Devices() ([]model.Device, error) {
	rows, err := s.db.Query(`SELECT ` + deviceCols + ` FROM devices ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Device
	for rows.Next() {
		d, err := scanDevice(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// UpdateInventory writes identity/health-derived fields after a successful poll.
// It also clears last_fail_at, ending any failure streak (the device answered).
func (s *Store) UpdateInventory(id int64, model_, serial, ros string, seen time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET model=?,serial=?,ros_version=?,last_seen=?,last_fail_at=NULL WHERE id=?`,
		model_, serial, ros, seen, id)
	return err
}

// SetCertPin overwrites the API cert pin (used after ROSMan rebinds api-ssl to a
// cert it issued, so the new fingerprint becomes the pinned one).
func (s *Store) SetCertPin(id int64, pin string) error {
	_, err := s.db.Exec(`UPDATE devices SET api_cert_pin=? WHERE id=?`, pin, id)
	return err
}

// ---- CA ----

func (s *Store) HasCA() bool {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM ca WHERE id=1`).Scan(&n)
	return n > 0
}

func (s *Store) SaveCA(cn, certPEM, keyEnc string) error {
	_, err := s.db.Exec(`INSERT INTO ca(id,cn,cert_pem,key_enc) VALUES(1,?,?,?)
		ON CONFLICT(id) DO UPDATE SET cn=excluded.cn, cert_pem=excluded.cert_pem, key_enc=excluded.key_enc, created_at=CURRENT_TIMESTAMP`,
		cn, certPEM, keyEnc)
	return err
}

// GetCA returns the CN, certificate PEM and encrypted key, or ok=false.
func (s *Store) GetCA() (cn, certPEM, keyEnc string, created time.Time, ok bool) {
	err := s.db.QueryRow(`SELECT cn,cert_pem,key_enc,created_at FROM ca WHERE id=1`).Scan(&cn, &certPEM, &keyEnc, &created)
	if err != nil {
		return "", "", "", time.Time{}, false
	}
	return cn, certPEM, keyEnc, created, true
}

func (s *Store) UpdatePins(id int64, apiCertPin, sshHostPin string) error {
	_, err := s.db.Exec(`UPDATE devices SET api_cert_pin=COALESCE(NULLIF(?,''),api_cert_pin), ssh_host_pin=COALESCE(NULLIF(?,''),ssh_host_pin) WHERE id=?`,
		apiCertPin, sshHostPin, id)
	return err
}

// ---- metrics ----

func (s *Store) AddHealth(h model.Health) error {
	_, err := s.db.Exec(`INSERT INTO metrics(device_id,ts,cpu,free_mem,total_mem,uptime,temp) VALUES(?,?,?,?,?,?,?)`,
		h.DeviceID, h.TS, h.CPU, h.FreeMem, h.TotalMem, h.Uptime, h.Temp)
	return err
}

func (s *Store) LatestHealth(deviceID int64) (model.Health, error) {
	var h model.Health
	err := s.db.QueryRow(`SELECT device_id,ts,cpu,free_mem,total_mem,uptime,temp FROM metrics WHERE device_id=? ORDER BY ts DESC LIMIT 1`, deviceID).
		Scan(&h.DeviceID, &h.TS, &h.CPU, &h.FreeMem, &h.TotalMem, &h.Uptime, &h.Temp)
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

// MetricsSince returns health samples since t, oldest first, for graphs.
func (s *Store) MetricsSince(deviceID int64, t time.Time) ([]model.Health, error) {
	rows, err := s.db.Query(`SELECT ts,cpu,free_mem,total_mem,temp FROM metrics WHERE device_id=? AND ts>=? ORDER BY ts`, deviceID, t)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Health
	for rows.Next() {
		var h model.Health
		if err := rows.Scan(&h.TS, &h.CPU, &h.FreeMem, &h.TotalMem, &h.Temp); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// ---- clients ----

func (s *Store) ReplaceClients(deviceID int64, cs []model.Client) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_clients WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, c := range cs {
		if _, err := tx.Exec(`INSERT INTO device_clients(device_id,mac,ip,hostname,iface,source) VALUES(?,?,?,?,?,?)`,
			deviceID, c.MAC, c.IP, c.Hostname, c.Iface, c.Source); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) clientRows(where string, args ...any) ([]model.Client, error) {
	rows, err := s.db.Query(`SELECT c.device_id,COALESCE(d.name,''),c.mac,c.ip,c.hostname,c.iface,c.source
		FROM device_clients c LEFT JOIN devices d ON d.id=c.device_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Client
	for rows.Next() {
		var c model.Client
		if err := rows.Scan(&c.DeviceID, &c.DeviceName, &c.MAC, &c.IP, &c.Hostname, &c.Iface, &c.Source); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) Clients(deviceID int64) ([]model.Client, error) {
	return s.clientRows(`WHERE c.device_id=? ORDER BY c.ip`, deviceID)
}

func (s *Store) AllClients(limit int) ([]model.Client, error) {
	return s.clientRows(`ORDER BY d.name, c.ip LIMIT ?`, limit)
}

func (s *Store) CountClients() int {
	var n int
	_ = s.db.QueryRow(`SELECT COUNT(DISTINCT mac) FROM device_clients`).Scan(&n)
	return n
}

// ---- ports (faceplate) ----

// UpdateDeviceIP changes a device's primary IP (used for API connections).
func (s *Store) UpdateDeviceIP(id int64, ip string) error {
	_, err := s.db.Exec(`UPDATE devices SET ip=? WHERE id=?`, ip, id)
	return err
}

// AllManagedAddrs returns every IP address known on any managed device
// (primary IPs plus all configured addresses, masks stripped).
func (s *Store) AllManagedAddrs() (map[string]bool, error) {
	set := map[string]bool{}
	rows, err := s.db.Query(`SELECT ip FROM devices`)
	if err == nil {
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil && ip != "" {
				set[ip] = true
			}
		}
		rows.Close()
	}
	rows, err = s.db.Query(`SELECT address FROM device_addrs`)
	if err == nil {
		for rows.Next() {
			var a string
			if rows.Scan(&a) == nil {
				if i := strings.IndexByte(a, '/'); i >= 0 {
					a = a[:i]
				}
				if a != "" {
					set[a] = true
				}
			}
		}
		rows.Close()
	}
	return set, nil
}

// AllManagedMacs returns every interface MAC known on any managed device.
func (s *Store) AllManagedMacs() (map[string]bool, error) {
	set := map[string]bool{}
	rows, err := s.db.Query(`SELECT mac FROM device_macs`)
	if err != nil {
		return set, err
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		if rows.Scan(&m) == nil && !zeroMAC(m) {
			set[strings.ToUpper(m)] = true
		}
	}
	return set, rows.Err()
}

// AddrOwners maps every managed IP (interface addresses stripped of any /mask,
// plus each device's primary IP) to its owning device id.
func (s *Store) AddrOwners() (map[string]int64, error) {
	m := map[string]int64{}
	if rows, err := s.db.Query(`SELECT device_id,address FROM device_addrs`); err == nil {
		for rows.Next() {
			var id int64
			var a string
			if rows.Scan(&id, &a) == nil {
				if i := strings.IndexByte(a, '/'); i >= 0 {
					a = a[:i]
				}
				if a != "" {
					m[a] = id
				}
			}
		}
		rows.Close()
	}
	if rows, err := s.db.Query(`SELECT id,ip FROM devices`); err == nil {
		for rows.Next() {
			var id int64
			var ip string
			if rows.Scan(&id, &ip) == nil && ip != "" {
				if _, ok := m[ip]; !ok {
					m[ip] = id
				}
			}
		}
		rows.Close()
	}
	return m, nil
}

// zeroMAC reports whether a MAC is empty or the all-zero placeholder many
// virtual interfaces report, which must never be used as an identifier.
func zeroMAC(mac string) bool {
	return mac == "" || strings.ToUpper(mac) == "00:00:00:00:00:00"
}

// ReplaceVLANs replaces a device's stored bridge VLAN table.
func (s *Store) ReplaceVLANs(deviceID int64, vlans []model.BridgeVLAN) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_vlans WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, v := range vlans {
		if _, err := tx.Exec(`INSERT INTO device_vlans(device_id,vlan_ids,tagged,untagged,bridge) VALUES(?,?,?,?,?)`,
			deviceID, v.VlanIDs, v.Tagged, v.Untagged, v.Bridge); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// AllVLANs returns every device's VLAN rows with the device id attached.
func (s *Store) AllVLANs() ([]model.BridgeVLAN, error) {
	rows, err := s.db.Query(`SELECT device_id,vlan_ids,tagged,untagged,bridge FROM device_vlans`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.BridgeVLAN
	for rows.Next() {
		var v model.BridgeVLAN
		if err := rows.Scan(&v.DeviceID, &v.VlanIDs, &v.Tagged, &v.Untagged, &v.Bridge); err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ReplaceBridgeHosts replaces a device's stored bridge FDB.
func (s *Store) ReplaceBridgeHosts(deviceID int64, hosts []model.BridgeHost) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM bridge_hosts WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, h := range hosts {
		if zeroMAC(h.MAC) {
			continue
		}
		if _, err := tx.Exec(`INSERT INTO bridge_hosts(device_id,mac,iface,bridge) VALUES(?,?,?,?)`,
			deviceID, strings.ToUpper(h.MAC), h.Iface, h.Bridge); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

// BridgePortCounts returns, for one device, how many MACs are learned on each
// interface (its FDB grouped by port).
func (s *Store) BridgePortCounts(deviceID int64) (map[string]int, error) {
	rows, err := s.db.Query(`SELECT iface,COUNT(*) FROM bridge_hosts WHERE device_id=? GROUP BY iface`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[string]int{}
	for rows.Next() {
		var iface string
		var n int
		if rows.Scan(&iface, &n) == nil {
			m[iface] = n
		}
	}
	return m, rows.Err()
}

// BridgeHostsByMac returns every device+port that has learned the given MAC.
func (s *Store) BridgeHostsByMac(mac string) ([]model.BridgeHost, error) {
	rows, err := s.db.Query(`SELECT device_id,mac,iface,bridge FROM bridge_hosts WHERE mac=?`, strings.ToUpper(mac))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.BridgeHost
	for rows.Next() {
		var h model.BridgeHost
		if err := rows.Scan(&h.DeviceID, &h.MAC, &h.Iface, &h.Bridge); err != nil {
			return nil, err
		}
		out = append(out, h)
	}
	return out, rows.Err()
}

// BridgePortLoad returns, per device and interface, how many MACs are learned on
// it — so an access/edge port (few MACs) can be told from an uplink (many).
func (s *Store) BridgePortLoad() (map[int64]map[string]int, error) {
	rows, err := s.db.Query(`SELECT device_id,iface,COUNT(*) FROM bridge_hosts GROUP BY device_id,iface`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]map[string]int{}
	for rows.Next() {
		var dev int64
		var iface string
		var n int
		if rows.Scan(&dev, &iface, &n) == nil {
			if m[dev] == nil {
				m[dev] = map[string]int{}
			}
			m[dev][iface] = n
		}
	}
	return m, rows.Err()
}

// BridgePortOn returns the port on a specific device where a MAC is learned, "".
func (s *Store) BridgePortOn(deviceID int64, mac string) string {
	var iface string
	_ = s.db.QueryRow(`SELECT iface FROM bridge_hosts WHERE device_id=? AND mac=? LIMIT 1`,
		deviceID, strings.ToUpper(mac)).Scan(&iface)
	return iface
}

// DeviceMacMap maps each device id to one representative interface MAC.
func (s *Store) DeviceMacMap() (map[int64]string, error) {
	m := map[int64]string{}
	rows, err := s.db.Query(`SELECT device_id,mac FROM device_macs`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var mac string
		if rows.Scan(&id, &mac) == nil && !zeroMAC(mac) {
			if _, ok := m[id]; !ok {
				m[id] = strings.ToUpper(mac)
			}
		}
	}
	return m, rows.Err()
}

// MacOwners maps every managed interface MAC (upper-case) to its device id.
func (s *Store) MacOwners() (map[string]int64, error) {
	m := map[string]int64{}
	rows, err := s.db.Query(`SELECT device_id,mac FROM device_macs`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var mac string
		if rows.Scan(&id, &mac) == nil && !zeroMAC(mac) {
			m[strings.ToUpper(mac)] = id
		}
	}
	return m, rows.Err()
}

// SetDeviceNotes saves the free-text admin description for a device.
func (s *Store) SetDeviceNotes(id int64, notes string) error {
	_, err := s.db.Exec(`UPDATE devices SET notes=? WHERE id=?`, notes, id)
	return err
}

// AddDeviceImage stores one uploaded image and returns its id.
func (s *Store) AddDeviceImage(deviceID int64, caption, contentType string, data []byte) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO device_images(device_id,caption,content_type,data) VALUES(?,?,?,?)`,
		deviceID, caption, contentType, data)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

// DeviceImages lists a device's uploaded images (metadata only, no data).
func (s *Store) DeviceImages(deviceID int64) ([]model.DeviceImage, error) {
	rows, err := s.db.Query(`SELECT id,device_id,caption,content_type,created_at FROM device_images WHERE device_id=? ORDER BY id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.DeviceImage
	for rows.Next() {
		var im model.DeviceImage
		if err := rows.Scan(&im.ID, &im.DeviceID, &im.Caption, &im.Type, &im.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, im)
	}
	return out, rows.Err()
}

// DeviceImageData returns one image's content type and bytes.
func (s *Store) DeviceImageData(id int64) (string, []byte, error) {
	var ct string
	var data []byte
	err := s.db.QueryRow(`SELECT content_type,data FROM device_images WHERE id=?`, id).Scan(&ct, &data)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrNotFound
	}
	return ct, data, err
}

// DeleteDeviceImage removes one image, scoped to its device.
func (s *Store) DeleteDeviceImage(id, deviceID int64) error {
	_, err := s.db.Exec(`DELETE FROM device_images WHERE id=? AND device_id=?`, id, deviceID)
	return err
}

// TopoPositions returns saved manual topology node positions by device id.
func (s *Store) TopoPositions() (map[int64][2]float64, error) {
	m := map[int64][2]float64{}
	rows, err := s.db.Query(`SELECT device_id,x,y FROM topo_pos`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var x, y float64
		if rows.Scan(&id, &x, &y) == nil {
			m[id] = [2]float64{x, y}
		}
	}
	return m, rows.Err()
}

// SaveTopoPos upserts one node's manual position.
func (s *Store) SaveTopoPos(id int64, x, y float64) error {
	_, err := s.db.Exec(`INSERT INTO topo_pos(device_id,x,y) VALUES(?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET x=excluded.x, y=excluded.y`, id, x, y)
	return err
}

// HiddenTopoNodes returns the set of device ids hidden from the topology map.
func (s *Store) HiddenTopoNodes() (map[int64]bool, error) {
	m := map[int64]bool{}
	rows, err := s.db.Query(`SELECT device_id FROM topo_hidden`)
	if err != nil {
		return m, err
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		if rows.Scan(&id) == nil {
			m[id] = true
		}
	}
	return m, rows.Err()
}

// SetTopoHidden hides or unhides one device on the topology map.
func (s *Store) SetTopoHidden(id int64, hidden bool) error {
	if hidden {
		_, err := s.db.Exec(`INSERT INTO topo_hidden(device_id) VALUES(?) ON CONFLICT(device_id) DO NOTHING`, id)
		return err
	}
	_, err := s.db.Exec(`DELETE FROM topo_hidden WHERE device_id=?`, id)
	return err
}

// AllNeighborSightings returns every discovered neighbour across all managed
// devices, with the name of the device that saw it.
func (s *Store) AllNeighborSightings() ([]model.NeighborSighting, error) {
	rows, err := s.db.Query(`SELECT n.iface,n.identity,n.ip,n.mac,n.platform,d.name
		FROM device_neighbors n JOIN devices d ON d.id=n.device_id
		ORDER BY n.identity, n.ip`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.NeighborSighting
	for rows.Next() {
		var n model.NeighborSighting
		if err := rows.Scan(&n.Iface, &n.Identity, &n.IP, &n.MAC, &n.Platform, &n.SeenBy); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// SetDeviceVPN upserts the per-device active-tunnel summary.
func (s *Store) SetDeviceVPN(deviceID int64, count int, info string) error {
	_, err := s.db.Exec(`INSERT INTO device_vpn(device_id,count,info) VALUES(?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET count=excluded.count, info=excluded.info`, deviceID, count, info)
	return err
}

// DeviceVPNSummary returns the stored tunnel count and brief info.
func (s *Store) DeviceVPNSummary(deviceID int64) (int, string) {
	var n int
	var info string
	_ = s.db.QueryRow(`SELECT count,info FROM device_vpn WHERE device_id=?`, deviceID).Scan(&n, &info)
	return n, info
}

// SetDeviceLTE upserts the per-device LTE summary.
func (s *Store) SetDeviceLTE(deviceID int64, l model.LTEInfo) error {
	_, err := s.db.Exec(`INSERT INTO device_lte(device_id,present,info,rsrp,fw_upgrade) VALUES(?,?,?,?,?)
		ON CONFLICT(device_id) DO UPDATE SET present=excluded.present, info=excluded.info, rsrp=excluded.rsrp, fw_upgrade=excluded.fw_upgrade`,
		deviceID, b2i(l.Present), l.Info, l.RSRP, b2i(l.FwUpgrade))
	return err
}

func (s *Store) DeviceLTEInfo(deviceID int64) (model.LTEInfo, error) {
	var l model.LTEInfo
	var pr, fu int
	err := s.db.QueryRow(`SELECT present,info,rsrp,fw_upgrade FROM device_lte WHERE device_id=?`, deviceID).Scan(&pr, &l.Info, &l.RSRP, &fu)
	if errors.Is(err, sql.ErrNoRows) {
		return l, nil
	}
	l.Present = pr != 0
	l.FwUpgrade = fu != 0
	return l, err
}

func (s *Store) ReplaceAddrs(deviceID int64, addrs []model.NetAddr) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_addrs WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, a := range addrs {
		if _, err := tx.Exec(`INSERT INTO device_addrs(device_id,address,iface) VALUES(?,?,?)`, deviceID, a.Address, a.Iface); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ReplaceMacs(deviceID int64, macs []model.NetMac) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_macs WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, mc := range macs {
		if _, err := tx.Exec(`INSERT INTO device_macs(device_id,iface,mac) VALUES(?,?,?)`, deviceID, mc.Iface, mc.Mac); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DeviceAddrs(deviceID int64) ([]model.NetAddr, error) {
	rows, err := s.db.Query(`SELECT address,iface FROM device_addrs WHERE device_id=? ORDER BY rowid`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.NetAddr
	for rows.Next() {
		var a model.NetAddr
		if err := rows.Scan(&a.Address, &a.Iface); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) DeviceMacs(deviceID int64) ([]model.NetMac, error) {
	rows, err := s.db.Query(`SELECT iface,mac FROM device_macs WHERE device_id=? ORDER BY rowid`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.NetMac
	for rows.Next() {
		var m model.NetMac
		if err := rows.Scan(&m.Iface, &m.Mac); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (s *Store) ReplacePorts(deviceID int64, ports []model.Port) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_ports WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for i, p := range ports {
		if _, err := tx.Exec(`INSERT INTO device_ports(device_id,pos,name,type,running,disabled) VALUES(?,?,?,?,?,?)`,
			deviceID, i, p.Name, p.Type, b2i(p.Running), b2i(p.Disabled)); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) DevicePorts(deviceID int64) ([]model.Port, error) {
	rows, err := s.db.Query(`SELECT name,type,running,disabled FROM device_ports WHERE device_id=? ORDER BY pos`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Port
	for rows.Next() {
		var p model.Port
		var run, dis int
		if err := rows.Scan(&p.Name, &p.Type, &run, &dis); err != nil {
			return nil, err
		}
		p.Running, p.Disabled = run != 0, dis != 0
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---- configs ----

// LastConfigTimes returns, per device, the newest snapshot time of each kind
// (export / binary / archive) — for the backup-coverage view.
func (s *Store) LastConfigTimes() (map[int64]map[string]time.Time, error) {
	// Scan the non-aggregated taken_at column (so the driver preserves its
	// timestamp affinity) and keep the newest per device+kind in Go.
	rows, err := s.db.Query(`SELECT device_id,kind,taken_at FROM configs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	m := map[int64]map[string]time.Time{}
	for rows.Next() {
		var dev int64
		var kind string
		var t time.Time
		if err := rows.Scan(&dev, &kind, &t); err != nil {
			return nil, err
		}
		if m[dev] == nil {
			m[dev] = map[string]time.Time{}
		}
		if cur, ok := m[dev][kind]; !ok || t.After(cur) {
			m[dev][kind] = t
		}
	}
	return m, rows.Err()
}

// LatestConfigHash returns the sha256 of the most recent snapshot (or "").
func (s *Store) LatestConfigHash(deviceID int64, kind string) (string, error) {
	var h string
	err := s.db.QueryRow(`SELECT sha256 FROM configs WHERE device_id=? AND kind=? ORDER BY taken_at DESC LIMIT 1`, deviceID, kind).Scan(&h)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return h, err
}

func (s *Store) AddConfig(c model.Config) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO configs(device_id,taken_at,kind,sha256,content) VALUES(?,?,?,?,?)`,
		c.DeviceID, time.Now(), c.Kind, c.SHA256, c.Content)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) Configs(deviceID int64, limit int) ([]model.Config, error) {
	rows, err := s.db.Query(`SELECT id,device_id,taken_at,kind,sha256,'' FROM configs WHERE device_id=? ORDER BY taken_at DESC LIMIT ?`, deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Config
	for rows.Next() {
		var c model.Config
		if err := rows.Scan(&c.ID, &c.DeviceID, &c.TakenAt, &c.Kind, &c.SHA256, &c.Content); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// LatestConfig returns the newest snapshot of the given kind, with content.
func (s *Store) LatestConfig(deviceID int64, kind string) (model.Config, error) {
	var c model.Config
	err := s.db.QueryRow(`SELECT id,device_id,taken_at,kind,sha256,content FROM configs WHERE device_id=? AND kind=? ORDER BY taken_at DESC LIMIT 1`, deviceID, kind).
		Scan(&c.ID, &c.DeviceID, &c.TakenAt, &c.Kind, &c.SHA256, &c.Content)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func (s *Store) ConfigContent(id int64) (model.Config, error) {
	var c model.Config
	err := s.db.QueryRow(`SELECT id,device_id,taken_at,kind,sha256,content FROM configs WHERE id=?`, id).
		Scan(&c.ID, &c.DeviceID, &c.TakenAt, &c.Kind, &c.SHA256, &c.Content)
	if errors.Is(err, sql.ErrNoRows) {
		return c, ErrNotFound
	}
	return c, err
}

func (s *Store) UpdateCertInfo(id int64, certName string, expiry *time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET api_ssl_cert=?, api_cert_expiry=? WHERE id=?`, certName, expiry, id)
	return err
}

// ---- interface traffic ----

func (s *Store) AddIfaceSamples(deviceID int64, ts time.Time, samples []model.IfaceSample) error {
	if len(samples) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	for _, sm := range samples {
		if _, err := tx.Exec(`INSERT INTO iface_traffic(device_id,iface,ts,rx_bytes,tx_bytes) VALUES(?,?,?,?,?)`,
			deviceID, sm.Iface, ts, sm.RxBytes, sm.TxBytes); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) PruneIfaceBefore(t time.Time) error {
	_, err := s.db.Exec(`DELETE FROM iface_traffic WHERE ts < ?`, t)
	return err
}

// PruneMetricsBefore deletes health samples older than t and returns how many
// rows were removed.
func (s *Store) PruneMetricsBefore(t time.Time) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM metrics WHERE ts < ?`, t)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// CountMetrics returns the number of stored health samples.
func (s *Store) CountMetrics() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM metrics`).Scan(&n)
	return n, err
}

// IfaceNames lists interfaces with samples in the recent window (active ones).
func (s *Store) IfaceNames(deviceID int64, since time.Time) ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT iface FROM iface_traffic WHERE device_id=? AND ts>=? ORDER BY iface`, deviceID, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// IfaceSeries returns samples for one interface, oldest first.
func (s *Store) IfaceSeries(deviceID int64, iface string, since time.Time) ([]model.IfaceSample, error) {
	rows, err := s.db.Query(`SELECT ts,rx_bytes,tx_bytes FROM iface_traffic WHERE device_id=? AND iface=? AND ts>=? ORDER BY ts`, deviceID, iface, since)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.IfaceSample
	for rows.Next() {
		var sm model.IfaceSample
		sm.Iface = iface
		if err := rows.Scan(&sm.TS, &sm.RxBytes, &sm.TxBytes); err != nil {
			return nil, err
		}
		out = append(out, sm)
	}
	return out, rows.Err()
}

// ---- neighbours ----

func (s *Store) ReplaceNeighbors(deviceID int64, ns []model.Neighbor) error {
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	if _, err := tx.Exec(`DELETE FROM device_neighbors WHERE device_id=?`, deviceID); err != nil {
		tx.Rollback()
		return err
	}
	for _, n := range ns {
		if _, err := tx.Exec(`INSERT INTO device_neighbors(device_id,iface,identity,ip,mac,platform) VALUES(?,?,?,?,?,?)`,
			deviceID, n.Iface, n.Identity, n.IP, n.MAC, n.Platform); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) Neighbors(deviceID int64) ([]model.Neighbor, error) {
	return s.neighborRows(`WHERE device_id=?`, deviceID)
}

func (s *Store) AllNeighbors() ([]model.Neighbor, error) {
	return s.neighborRows(``)
}

func (s *Store) neighborRows(where string, args ...any) ([]model.Neighbor, error) {
	rows, err := s.db.Query(`SELECT device_id,iface,identity,ip,mac,platform FROM device_neighbors `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Neighbor
	for rows.Next() {
		var n model.Neighbor
		if err := rows.Scan(&n.DeviceID, &n.Iface, &n.Identity, &n.IP, &n.MAC, &n.Platform); err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, rows.Err()
}

// ---- config templates ----

func (s *Store) Templates() ([]model.Template, error) {
	rows, err := s.db.Query(`SELECT id,name,body,created_at FROM config_templates ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Template
	for rows.Next() {
		var t model.Template
		if err := rows.Scan(&t.ID, &t.Name, &t.Body, &t.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) Template(id int64) (model.Template, error) {
	var t model.Template
	err := s.db.QueryRow(`SELECT id,name,body,created_at FROM config_templates WHERE id=?`, id).
		Scan(&t.ID, &t.Name, &t.Body, &t.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return t, ErrNotFound
	}
	return t, err
}

func (s *Store) CreateTemplate(name, body string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO config_templates(name,body) VALUES(?,?)`, name, body)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteTemplate(id int64) error {
	_, err := s.db.Exec(`DELETE FROM config_templates WHERE id=?`, id)
	return err
}

func (s *Store) UpdateFirmware(id int64, latest, channel, status string) error {
	_, err := s.db.Exec(`UPDATE devices SET fw_latest=?, fw_channel=?, fw_status=? WHERE id=?`, latest, channel, status, id)
	return err
}

// SetRouterboardFw stores the RouterBOARD firmware state from a poll:
// current-firmware (running now) and upgrade-firmware (applied on next reboot
// after /system/routerboard upgrade). Both empty for devices without a
// RouterBOARD (CHR, x86), which simply show no FW column value.
func (s *Store) SetRouterboardFw(id int64, current, upgrade string) error {
	_, err := s.db.Exec(`UPDATE devices SET rb_current_fw=?, rb_upgrade_fw=? WHERE id=?`, current, upgrade, id)
	return err
}

// ---- alerts ----

func (s *Store) AlertState(deviceID int64, rule string) (string, error) {
	var st string
	err := s.db.QueryRow(`SELECT state FROM alerts WHERE device_id=? AND rule=?`, deviceID, rule).Scan(&st)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return st, err
}

// RaiseAlert makes an alert active (idempotent). `since` is preserved while the
// alert stays active and reset when it transitions resolved->active.
func (s *Store) RaiseAlert(deviceID int64, rule, severity, detail string) error {
	_, err := s.db.Exec(`
		INSERT INTO alerts(device_id,rule,state,severity,detail) VALUES(?,?,'active',?,?)
		ON CONFLICT(device_id,rule) DO UPDATE SET
			detail=excluded.detail, severity=excluded.severity, updated_at=CURRENT_TIMESTAMP,
			state='active',
			since=CASE WHEN alerts.state='active' THEN alerts.since ELSE CURRENT_TIMESTAMP END`,
		deviceID, rule, severity, detail)
	return err
}

// ResolveAlert clears an active alert; returns true if one was active.
func (s *Store) ResolveAlert(deviceID int64, rule string) (bool, error) {
	res, err := s.db.Exec(`UPDATE alerts SET state='resolved', updated_at=CURRENT_TIMESTAMP WHERE device_id=? AND rule=? AND state='active'`, deviceID, rule)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

func (s *Store) listAlerts(where string, args ...any) ([]model.Alert, error) {
	rows, err := s.db.Query(`SELECT a.id,a.device_id,COALESCE(d.name,''),a.rule,a.state,a.severity,a.detail,a.since,a.updated_at
		FROM alerts a LEFT JOIN devices d ON d.id=a.device_id `+where, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Alert
	for rows.Next() {
		var a model.Alert
		if err := rows.Scan(&a.ID, &a.DeviceID, &a.Device, &a.Rule, &a.State, &a.Severity, &a.Detail, &a.Since, &a.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func (s *Store) ActiveAlerts() ([]model.Alert, error) {
	return s.listAlerts(`WHERE a.state='active' ORDER BY a.severity DESC, a.since`)
}

func (s *Store) AllAlerts(limit int) ([]model.Alert, error) {
	return s.listAlerts(`ORDER BY a.updated_at DESC LIMIT ?`, limit)
}

// ---- firmware jobs ----

func (s *Store) CreateFwJob(actor, note, kind string) (int64, error) {
	if kind == "" {
		kind = "ros"
	}
	res, err := s.db.Exec(`INSERT INTO fw_jobs(actor,note,kind) VALUES(?,?,?)`, actor, note, kind)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) AddFwItem(jobID, deviceID int64, name, target string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO fw_job_items(job_id,device_id,device_name,target) VALUES(?,?,?,?)`,
		jobID, deviceID, name, target)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) SetFwItem(id int64, status, detail string) error {
	_, err := s.db.Exec(`UPDATE fw_job_items SET status=?, detail=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, status, detail, id)
	return err
}

func (s *Store) FinishFwJob(id int64, status string) error {
	_, err := s.db.Exec(`UPDATE fw_jobs SET status=? WHERE id=?`, status, id)
	return err
}

func (s *Store) FwJobs(limit int) ([]model.FwJob, error) {
	rows, err := s.db.Query(`SELECT id,created_at,actor,note,status,kind FROM fw_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FwJob
	for rows.Next() {
		var j model.FwJob
		if err := rows.Scan(&j.ID, &j.CreatedAt, &j.Actor, &j.Note, &j.Status, &j.Kind); err != nil {
			return nil, err
		}
		out = append(out, j)
	}
	return out, rows.Err()
}

func (s *Store) LatestFwJob() (model.FwJob, bool) {
	js, err := s.FwJobs(1)
	if err != nil || len(js) == 0 {
		return model.FwJob{}, false
	}
	return js[0], true
}

func (s *Store) FwItems(jobID int64) ([]model.FwItem, error) {
	rows, err := s.db.Query(`SELECT id,job_id,device_id,device_name,target,status,detail,updated_at FROM fw_job_items WHERE job_id=? ORDER BY id`, jobID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FwItem
	for rows.Next() {
		var it model.FwItem
		if err := rows.Scan(&it.ID, &it.JobID, &it.DeviceID, &it.DeviceName, &it.Target, &it.Status, &it.Detail, &it.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, it)
	}
	return out, rows.Err()
}

// ---- settings ----

func (s *Store) GetSetting(key string) (string, bool) {
	var v string
	err := s.db.QueryRow(`SELECT value FROM app_settings WHERE key=?`, key).Scan(&v)
	if err != nil {
		return "", false
	}
	return v, true
}

func (s *Store) SetSetting(key, value string) error {
	_, err := s.db.Exec(`INSERT INTO app_settings(key,value) VALUES(?,?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value`, key, value)
	return err
}

// ---- audit ----

func (s *Store) AddAudit(actor, action, detail string) error {
	_, err := s.db.Exec(`INSERT INTO audit_log(actor,action,detail) VALUES(?,?,?)`, actor, action, detail)
	return err
}

func (s *Store) RecentAudit(limit int) ([]model.Audit, error) {
	rows, err := s.db.Query(`SELECT id,ts,actor,action,detail FROM audit_log ORDER BY ts DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Audit
	for rows.Next() {
		var a model.Audit
		if err := rows.Scan(&a.ID, &a.TS, &a.Actor, &a.Action, &a.Detail); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// ---- sites ----

func (s *Store) Sites() ([]model.Site, error) {
	rows, err := s.db.Query(`SELECT s.id,s.name,s.lat,s.lon,(SELECT COUNT(*) FROM devices d WHERE d.site_id=s.id) FROM sites s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Site
	for rows.Next() {
		var st model.Site
		if err := rows.Scan(&st.ID, &st.Name, &st.Lat, &st.Lon, &st.Count); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
}

// UpdateSiteGeo sets or clears a location's coordinates (nil clears).
func (s *Store) UpdateSiteGeo(id int64, lat, lon *float64) error {
	_, err := s.db.Exec(`UPDATE sites SET lat=?, lon=? WHERE id=?`, lat, lon, id)
	return err
}

func (s *Store) CreateSite(name string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO sites(name) VALUES(?)`, name)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) DeleteSite(id int64) error {
	if _, err := s.db.Exec(`UPDATE devices SET site_id=NULL WHERE site_id=?`, id); err != nil {
		return err
	}
	_, err := s.db.Exec(`DELETE FROM sites WHERE id=?`, id)
	return err
}

func (s *Store) SetDeviceSite(deviceID int64, siteID *int64) error {
	_, err := s.db.Exec(`UPDATE devices SET site_id=? WHERE id=?`, siteID, deviceID)
	return err
}

// ---- tags ----

func (s *Store) AddDeviceTag(deviceID int64, tag string) error {
	_, err := s.db.Exec(`INSERT OR IGNORE INTO device_tags(device_id,tag) VALUES(?,?)`, deviceID, tag)
	return err
}

func (s *Store) RemoveDeviceTag(deviceID int64, tag string) error {
	_, err := s.db.Exec(`DELETE FROM device_tags WHERE device_id=? AND tag=?`, deviceID, tag)
	return err
}

func (s *Store) DeviceTags(deviceID int64) ([]string, error) {
	rows, err := s.db.Query(`SELECT tag FROM device_tags WHERE device_id=? ORDER BY tag`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) AllTags() ([]string, error) {
	rows, err := s.db.Query(`SELECT DISTINCT tag FROM device_tags ORDER BY tag`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var t string
		if err := rows.Scan(&t); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// DeviceIDsByTag returns device ids carrying the tag.
func (s *Store) DeviceIDsByTag(tag string) (map[int64]bool, error) {
	rows, err := s.db.Query(`SELECT device_id FROM device_tags WHERE tag=?`, tag)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out[id] = true
	}
	return out, rows.Err()
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
