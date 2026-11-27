package store

import (
	"strings"
	"time"

	"rosman/internal/model"
)

// ---- syslog collector ----

// AddSyslog stores a batch of received messages in one transaction.
func (s *Store) AddSyslog(batch []model.SyslogMsg) error {
	if len(batch) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	st, err := tx.Prepare(`INSERT INTO syslog(ts,device_id,src,sev,topics,msg) VALUES(?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, m := range batch {
		if _, err := st.Exec(m.TS.UTC(), m.DeviceID, m.Src, m.Sev, m.Topics, m.Msg); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func syslogWhere(f model.SyslogFilter) (string, []any) {
	var w []string
	var args []any
	if f.DeviceID > 0 {
		w = append(w, "l.device_id=?")
		args = append(args, f.DeviceID)
	}
	if f.SiteID > 0 {
		w = append(w, "l.device_id IN (SELECT id FROM devices WHERE site_id=?)")
		args = append(args, f.SiteID)
	}
	if f.MaxSev > 0 {
		w = append(w, "l.sev<=?")
		args = append(args, f.MaxSev)
	}
	if !f.Since.IsZero() {
		w = append(w, "l.ts>=?")
		args = append(args, f.Since.UTC())
	}
	if f.BeforeID > 0 {
		w = append(w, "l.id<?")
		args = append(args, f.BeforeID)
	}
	if t := strings.TrimSpace(f.Text); t != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(t)
		w = append(w, `(l.msg LIKE ? ESCAPE '\' OR l.topics LIKE ? ESCAPE '\')`)
		args = append(args, "%"+esc+"%", "%"+esc+"%")
	}
	if len(w) == 0 {
		return "", args
	}
	return " WHERE " + strings.Join(w, " AND "), args
}

// Syslog returns messages newest first.
func (s *Store) Syslog(f model.SyslogFilter) ([]model.SyslogMsg, error) {
	where, args := syslogWhere(f)
	if f.Limit <= 0 {
		f.Limit = 300
	}
	args = append(args, f.Limit)
	rows, err := s.db.Query(`SELECT l.id,l.ts,l.device_id,COALESCE(d.name,''),l.src,l.sev,l.topics,l.msg
		FROM syslog l LEFT JOIN devices d ON d.id=l.device_id`+where+` ORDER BY l.id DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SyslogMsg
	for rows.Next() {
		var m model.SyslogMsg
		if err := rows.Scan(&m.ID, &m.TS, &m.DeviceID, &m.DeviceName, &m.Src, &m.Sev, &m.Topics, &m.Msg); err != nil {
			return nil, err
		}
		m.TS = m.TS.Local()
		out = append(out, m)
	}
	return out, rows.Err()
}

// SyslogCounts returns total / errors-and-worse / warnings for the filter.
func (s *Store) SyslogCounts(f model.SyslogFilter) (total, errs, warns int, err error) {
	f.BeforeID = 0
	where, args := syslogWhere(f)
	err = s.db.QueryRow(`SELECT COUNT(*),COALESCE(SUM(l.sev<=3),0),COALESCE(SUM(l.sev=4),0) FROM syslog l`+where, args...).
		Scan(&total, &errs, &warns)
	return
}

// SyslogByDevice summarises messages per device since the given time.
func (s *Store) SyslogByDevice(since time.Time) ([]model.SyslogDevStat, error) {
	rows, err := s.db.Query(`SELECT l.device_id,COALESCE(d.name,''),COUNT(*),SUM(l.sev<=3),SUM(l.sev=4),MAX(l.ts)
		FROM syslog l LEFT JOIN devices d ON d.id=l.device_id WHERE l.ts>=?
		GROUP BY l.device_id ORDER BY SUM(l.sev<=3) DESC, COUNT(*) DESC`, since.UTC())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SyslogDevStat
	for rows.Next() {
		var st model.SyslogDevStat
		var last string
		if err := rows.Scan(&st.DeviceID, &st.DeviceName, &st.Total, &st.Errors, &st.Warnings, &last); err != nil {
			return nil, err
		}
		st.Last = parseDBTime(last)
		out = append(out, st)
	}
	return out, rows.Err()
}

// parseDBTime reads a timestamp that came back as text (aggregates lose the
// column type, so the driver does not convert them).
func parseDBTime(v string) time.Time {
	for _, l := range []string{"2006-01-02 15:04:05.999999999 -0700 MST", "2006-01-02 15:04:05.999999999-07:00", time.RFC3339Nano, "2006-01-02 15:04:05"} {
		if t, err := time.Parse(l, v); err == nil {
			return t.Local()
		}
	}
	return time.Time{}
}

// SyslogTop returns the most repeated messages for the filter.
func (s *Store) SyslogTop(f model.SyslogFilter, n int) ([]model.SyslogTop, error) {
	f.BeforeID = 0
	where, args := syslogWhere(f)
	args = append(args, n)
	rows, err := s.db.Query(`SELECT l.msg,COUNT(*),COUNT(DISTINCT l.device_id),MIN(l.sev) FROM syslog l`+where+`
		GROUP BY l.msg HAVING COUNT(*)>1 ORDER BY COUNT(*) DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.SyslogTop
	for rows.Next() {
		var t model.SyslogTop
		if err := rows.Scan(&t.Msg, &t.Count, &t.Devices, &t.Sev); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

// PruneSyslog drops messages older than the cutoff and, if the table is still
// above maxRows, the oldest rows beyond it.
func (s *Store) PruneSyslog(before time.Time, maxRows int64) (int64, error) {
	res, err := s.db.Exec(`DELETE FROM syslog WHERE ts<?`, before.UTC())
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	if maxRows > 0 {
		res, err = s.db.Exec(`DELETE FROM syslog WHERE id <= (SELECT COALESCE(MAX(id),0) FROM syslog) - ?`, maxRows)
		if err != nil {
			return n, err
		}
		m, _ := res.RowsAffected()
		n += m
	}
	return n, nil
}

func (s *Store) CountSyslog() (int64, error) {
	var n int64
	err := s.db.QueryRow(`SELECT COUNT(*) FROM syslog`).Scan(&n)
	return n, err
}

// SetDeviceSyslog records that the device was configured to log to target
// (target=="" forgets it).
func (s *Store) SetDeviceSyslog(id int64, target string) error {
	if target == "" {
		_, err := s.db.Exec(`DELETE FROM device_syslog WHERE device_id=?`, id)
		return err
	}
	_, err := s.db.Exec(`INSERT INTO device_syslog(device_id,target,configured_at) VALUES(?,?,CURRENT_TIMESTAMP)
		ON CONFLICT(device_id) DO UPDATE SET target=excluded.target, configured_at=CURRENT_TIMESTAMP`, id, target)
	return err
}

// DeviceSyslogTargets maps device id → the target it was configured with.
func (s *Store) DeviceSyslogTargets() (map[int64]string, error) {
	rows, err := s.db.Query(`SELECT device_id,target FROM device_syslog`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var id int64
		var t string
		if err := rows.Scan(&id, &t); err != nil {
			return nil, err
		}
		out[id] = t
	}
	return out, rows.Err()
}

// AllDeviceAddrs returns every polled address (without the mask) → device ids.
func (s *Store) AllDeviceAddrs() (map[string][]int64, error) {
	rows, err := s.db.Query(`SELECT device_id,address FROM device_addrs`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string][]int64{}
	for rows.Next() {
		var id int64
		var a string
		if err := rows.Scan(&id, &a); err != nil {
			return nil, err
		}
		if i := strings.IndexByte(a, '/'); i > 0 {
			a = a[:i]
		}
		out[a] = append(out[a], id)
	}
	return out, rows.Err()
}

// ---- AI reports ----

func (s *Store) CreateAIReport(r model.AIReport) (int64, error) {
	res, err := s.db.Exec(`INSERT INTO ai_reports(actor,device_id,title,status,model,lines,matched) VALUES(?,?,?,'running',?,?,?)`,
		r.Actor, r.DeviceID, r.Title, r.Model, r.Lines, r.Matched)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *Store) FinishAIReport(id int64, result, errText string, in, out int64) error {
	status := "done"
	if errText != "" {
		status = "error"
	}
	_, err := s.db.Exec(`UPDATE ai_reports SET status=?,result=?,error=?,tokens_in=?,tokens_out=? WHERE id=?`, status, result, errText, in, out, id)
	return err
}

// FailStaleAIReports marks analyses left "running" by a restart as failed.
func (s *Store) FailStaleAIReports() error {
	_, err := s.db.Exec(`UPDATE ai_reports SET status='error', error='interrupted by a restart' WHERE status='running'`)
	return err
}

const aiCols = `r.id,r.created_at,r.actor,r.device_id,COALESCE(d.name,''),r.title,r.status,r.model,r.lines,r.matched,r.tokens_in,r.tokens_out,r.result,r.error`

func scanAI(sc interface{ Scan(...any) error }) (model.AIReport, error) {
	var r model.AIReport
	err := sc.Scan(&r.ID, &r.CreatedAt, &r.Actor, &r.DeviceID, &r.DeviceName, &r.Title, &r.Status, &r.Model, &r.Lines, &r.Matched, &r.TokensIn, &r.TokensOut, &r.Result, &r.Error)
	r.CreatedAt = r.CreatedAt.Local()
	return r, err
}

func (s *Store) AIReport(id int64) (model.AIReport, error) {
	return scanAI(s.db.QueryRow(`SELECT `+aiCols+` FROM ai_reports r LEFT JOIN devices d ON d.id=r.device_id WHERE r.id=?`, id))
}

func (s *Store) AIReports(limit int) ([]model.AIReport, error) {
	rows, err := s.db.Query(`SELECT `+aiCols+` FROM ai_reports r LEFT JOIN devices d ON d.id=r.device_id ORDER BY r.id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.AIReport
	for rows.Next() {
		r, err := scanAI(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// SyslogSize returns how many stored log lines there are and roughly how many
// bytes their text takes (message, topics and source), for the Server panel.
func (s *Store) SyslogSize() (count int64, bytes int64, err error) {
	err = s.db.QueryRow(`SELECT COUNT(*), COALESCE(SUM(length(msg)+length(topics)+length(src)),0) FROM syslog`).Scan(&count, &bytes)
	return
}
