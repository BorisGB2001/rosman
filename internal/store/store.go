// Package store is the SQLite persistence layer (modernc, pure-Go, WAL).
package store

import (
	_ "embed"
	"database/sql"
	"errors"
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
	} {
		_, _ = db.Exec(alter)
	}
	return &Store{db: db}, nil
}

func (s *Store) Close() error { return s.db.Close() }

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

func (s *Store) UserByName(name string) (model.User, error) {
	var u model.User
	var role string
	err := s.db.QueryRow(`SELECT id,username,password_hash,role,created_at FROM users WHERE username=?`, name).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Role = model.Role(role)
	return u, err
}

func (s *Store) UserByID(id int64) (model.User, error) {
	var u model.User
	var role string
	err := s.db.QueryRow(`SELECT id,username,password_hash,role,created_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Username, &u.PasswordHash, &role, &u.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return u, ErrNotFound
	}
	u.Role = model.Role(role)
	return u, err
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

func scanDevice(row interface{ Scan(...any) error }) (model.Device, error) {
	var d model.Device
	var tls int
	var last, exp sql.NullTime
	err := row.Scan(&d.ID, &d.Name, &d.IP, &d.APIPort, &tls, &d.APIUser, &d.APIPassEnc,
		&d.SSHUser, &d.APICertPin, &d.SSHHostPin, &d.Model, &d.Serial, &d.ROSVersion, &last, &d.CreatedAt,
		&d.APISSLCert, &exp, &d.FwLatest, &d.FwChannel, &d.FwStatus)
	d.APITLS = tls != 0
	if last.Valid {
		d.LastSeen = &last.Time
	}
	if exp.Valid {
		d.APICertExpiry = &exp.Time
	}
	return d, err
}

const deviceCols = `id,name,ip,api_port,api_tls,api_user,api_pass_enc,ssh_user,api_cert_pin,ssh_host_pin,model,serial,ros_version,last_seen,created_at,api_ssl_cert,api_cert_expiry,fw_latest,fw_channel,fw_status`

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

// UpdateInventory writes identity/health-derived fields after a poll.
func (s *Store) UpdateInventory(id int64, model_, serial, ros string, seen time.Time) error {
	_, err := s.db.Exec(`UPDATE devices SET model=?,serial=?,ros_version=?,last_seen=? WHERE id=?`,
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
	_, err := s.db.Exec(`INSERT INTO metrics(device_id,ts,cpu,free_mem,total_mem,uptime) VALUES(?,?,?,?,?,?)`,
		h.DeviceID, h.TS, h.CPU, h.FreeMem, h.TotalMem, h.Uptime)
	return err
}

func (s *Store) LatestHealth(deviceID int64) (model.Health, error) {
	var h model.Health
	err := s.db.QueryRow(`SELECT device_id,ts,cpu,free_mem,total_mem,uptime FROM metrics WHERE device_id=? ORDER BY ts DESC LIMIT 1`, deviceID).
		Scan(&h.DeviceID, &h.TS, &h.CPU, &h.FreeMem, &h.TotalMem, &h.Uptime)
	if errors.Is(err, sql.ErrNoRows) {
		return h, ErrNotFound
	}
	return h, err
}

// ---- configs ----

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

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}
