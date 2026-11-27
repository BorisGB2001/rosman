package web

import (
	"encoding/csv"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"rosman/internal/model"
)

// ---- syslog collector: log page, export, per-device switch ----

// sevName is the short syslog severity label.
func sevName(sev int) string {
	switch {
	case sev <= 2:
		return "critical"
	case sev == 3:
		return "error"
	case sev == 4:
		return "warning"
	case sev == 7:
		return "debug"
	}
	return "info"
}

// sevClass is the badge colour for a severity.
func sevClass(sev int) string {
	switch {
	case sev <= 3:
		return "bad"
	case sev == 4:
		return "warn"
	}
	return ""
}

func syslogFilter(r *http.Request) (f model.SyslogFilter, rng string) {
	q := r.URL.Query()
	f.DeviceID, _ = strconv.ParseInt(q.Get("dev"), 10, 64)
	f.SiteID, _ = strconv.ParseInt(q.Get("site"), 10, 64)
	switch q.Get("sev") {
	case "err":
		f.MaxSev = 3
	case "warn":
		f.MaxSev = 4
	}
	f.Text = q.Get("q")
	rng = q.Get("range")
	switch rng {
	case "1h":
		f.Since = time.Now().Add(-time.Hour)
	case "7d":
		f.Since = time.Now().AddDate(0, 0, -7)
	case "all":
	default:
		rng = "24h"
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	f.BeforeID, _ = strconv.ParseInt(q.Get("before"), 10, 64)
	return f, rng
}

func (s *Server) syslogPage(w http.ResponseWriter, r *http.Request) {
	f, rng := syslogFilter(r)
	f.Limit = 300
	rows, _ := s.a.Store.Syslog(f)
	total, errN, warnN, _ := s.a.Store.SyslogCounts(f)
	byDev, _ := s.a.Store.SyslogByDevice(f.Since)
	top, _ := s.a.Store.SyslogTop(f, 15)
	devs, _ := s.a.Store.Devices()
	targets, _ := s.a.Store.DeviceSyslogTargets()
	// Devices told to log here that have sent nothing in the period.
	sent := map[int64]bool{}
	for _, b := range byDev {
		sent[b.DeviceID] = true
	}
	var silent []model.Device
	for _, d := range devs {
		if targets[d.ID] != "" && !sent[d.ID] {
			silent = append(silent, d)
		}
	}
	var older int64
	if len(rows) == f.Limit {
		older = rows[len(rows)-1].ID
	}
	q := r.URL.Query()
	q.Del("before")
	q.Del("live")
	s.render(w, r, "syslog", map[string]any{"Active": "syslog",
		"Rows": rows, "Total": total, "ErrN": errN, "WarnN": warnN, "ByDev": byDev, "Top": top,
		"Devices": devs, "Configured": len(targets), "Silent": silent, "Sending": len(byDev),
		"Dev": f.DeviceID, "Sev": r.URL.Query().Get("sev"), "Q": f.Text, "Range": rng,
		"Site": f.SiteID, "Sites": func() []model.Site { ss, _ := s.a.Store.Sites(); return ss }(),
		"Older": older, "Paged": f.BeforeID > 0, "Query": q.Encode(), "Live": r.URL.Query().Get("live") == "1",
		"Info": s.a.SyslogStatus(),
	})
}

func (s *Server) syslogCSV(w http.ResponseWriter, r *http.Request) {
	f, _ := syslogFilter(r)
	f.BeforeID, f.Limit = 0, 50000
	rows, err := s.a.Store.Syslog(f)
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="syslog.csv"`)
	_, _ = w.Write([]byte{0xEF, 0xBB, 0xBF})
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"time", "device", "source", "severity", "topics", "message"})
	for _, m := range rows {
		_ = cw.Write([]string{m.TS.Format("2006-01-02 15:04:05"), m.DeviceName, m.Src, sevName(m.Sev), m.Topics, m.Msg})
	}
	cw.Flush()
}

// deviceSyslog switches "send the log to ROSMan" on or off on one device.
func (s *Server) deviceSyslog(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	on := r.FormValue("on") == "1"
	kind := "syslog_on"
	if !on {
		kind = "syslog_off"
	}
	t := s.a.StartTask(kind, d.Name, 0)
	target, err := s.a.ConfigureSyslog(d, on)
	t.Finish(err)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s#syslog", id, urlq(s.explain(langOf(r), d, "api", err))), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, kind, d.Name+" "+target)
	msg := "syslog-on"
	if !on {
		msg = "syslog-off"
	}
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=%s#syslog", id, msg), http.StatusSeeOther)
}

// syslogBulk is the bulk-action body for syslog_on / syslog_off.
func (s *Server) syslogBulk(lang string, on bool) func(model.Device) (string, error) {
	return func(d model.Device) (string, error) {
		target, err := s.a.ConfigureSyslog(d, on)
		if err != nil {
			return "", errors.New(s.explain(lang, d, "api", err))
		}
		return target, nil
	}
}
