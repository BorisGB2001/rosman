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
		`ALTER TABLE devices ADD COLUMN site_id INTEGER`,
		`ALTER TABLE metrics ADD COLUMN temp REAL NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN snmp_enabled INTEGER NOT NULL DEFAULT 0`,
		`ALTER TABLE devices ADD COLUMN snmp_community_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE devices ADD COLUMN snmp_port INTEGER NOT NULL DEFAULT 161`,
		`ALTER TABLE users ADD COLUMN totp_secret_enc TEXT NOT NULL DEFAULT ''`,
		`ALTER TABLE users ADD COLUMN totp_enabled INTEGER NOT NULL DEFAULT 0`,
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

// SetTOTP stores (or clears) a user's encrypted TOTP secret and enabled flag.
func (s *Store) SetTOTP(userID int64, secretEnc string, enabled bool) error {
	_, err := s.db.Exec(`UPDATE users SET totp_secret_enc=?, totp_enabled=? WHERE id=?`, secretEnc, enabled, userID)
	return err
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

func scanDevice(row interface{ Scan(...any) error }) (model.Device, error) {
	var d model.Device
	var tls int
	var last, exp sql.NullTime
	var site sql.NullInt64
	var snmpEn int
	err := row.Scan(&d.ID, &d.Name, &d.IP, &d.APIPort, &tls, &d.APIUser, &d.APIPassEnc,
		&d.SSHUser, &d.APICertPin, &d.SSHHostPin, &d.Model, &d.Serial, &d.ROSVersion, &last, &d.CreatedAt,
		&d.APISSLCert, &exp, &d.FwLatest, &d.FwChannel, &d.FwStatus, &site,
		&snmpEn, &d.SNMPCommEnc, &d.SNMPPort)
	d.APITLS = tls != 0
	d.SNMPEnabled = snmpEn != 0
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

const deviceCols = `id,name,ip,api_port,api_tls,api_user,api_pass_enc,ssh_user,api_cert_pin,ssh_host_pin,model,serial,ros_version,last_seen,created_at,api_ssl_cert,api_cert_expiry,fw_latest,fw_channel,fw_status,site_id,snmp_enabled,snmp_community_enc,snmp_port`

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

func (s *Store) CreateFwJob(actor, note string) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO fw_jobs(actor,note) VALUES(?,?)`, actor, note)
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
	rows, err := s.db.Query(`SELECT id,created_at,actor,note,status FROM fw_jobs ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.FwJob
	for rows.Next() {
		var j model.FwJob
		if err := rows.Scan(&j.ID, &j.CreatedAt, &j.Actor, &j.Note, &j.Status); err != nil {
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
	rows, err := s.db.Query(`SELECT s.id,s.name,(SELECT COUNT(*) FROM devices d WHERE d.site_id=s.id) FROM sites s ORDER BY s.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Site
	for rows.Next() {
		var st model.Site
		if err := rows.Scan(&st.ID, &st.Name, &st.Count); err != nil {
			return nil, err
		}
		out = append(out, st)
	}
	return out, rows.Err()
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
