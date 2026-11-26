package web

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"rosman/internal/i18n"
	"rosman/internal/model"
)

// ---- AI analysis of logs: start, report page, list ----

// aiMaxLines is how many log lines one analysis sends to the model.
const aiMaxLines = 2000

// aiContext builds the text given to the model: device facts, alerts, log
// statistics and the log lines themselves (oldest first).
func (s *Server) aiContext(f model.SyslogFilter, d *model.Device, period string) (text string, sent, matched int, err error) {
	matched, _, _, _ = s.a.Store.SyslogCounts(f)
	f.Limit = aiMaxLines
	rows, err := s.a.Store.Syslog(f)
	if err != nil {
		return "", 0, 0, err
	}
	if len(rows) == 0 {
		return "", 0, matched, fmt.Errorf("no log messages match")
	}
	var b strings.Builder
	b.WriteString("Collected at: " + time.Now().Format("2006-01-02 15:04 MST") + "\nPeriod: " + period + "\n")
	if d != nil {
		info, _ := s.mcpCall("get_device", map[string]any{"device": strconv.FormatInt(d.ID, 10)}, model.User{})
		b.WriteString("\n<device>\n" + info + "</device>\n")
	} else {
		alerts, _ := s.mcpCall("get_alerts", map[string]any{}, model.User{})
		b.WriteString("\n<active_alerts>\n" + alerts + "\n</active_alerts>\n")
	}
	top, _ := s.a.Store.SyslogTop(f, 20)
	if len(top) > 0 {
		b.WriteString("\n<most_repeated>\n")
		for _, t := range top {
			fmt.Fprintf(&b, "%d × [%s] %s\n", t.Count, sevName(t.Sev), t.Msg)
		}
		b.WriteString("</most_repeated>\n")
	}
	if len(rows) < matched {
		fmt.Fprintf(&b, "\nNote: %d messages match the filter; only the newest %d are included below. Say so in the report.\n", matched, len(rows))
	}
	b.WriteString("\n<log oldest_first=\"true\">\n")
	for i := len(rows) - 1; i >= 0; i-- {
		b.WriteString(logLine(rows[i], d == nil) + "\n")
	}
	b.WriteString("</log>\n")
	return b.String(), len(rows), matched, nil
}

func (s *Server) aiAnalyze(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	lang := langOf(r)
	back := r.FormValue("back")
	if !strings.HasPrefix(back, "/") || strings.HasPrefix(back, "//") {
		back = "/syslog"
	}
	fail := func(msg string) {
		sep := "?"
		if strings.Contains(back, "?") {
			sep = "&"
		}
		http.Redirect(w, r, back+sep+"flash="+putFlash(nil, []string{msg}), http.StatusSeeOther)
	}
	if !s.a.AIConfigured() {
		fail(i18n.T(lang, "ai.err_nokey"))
		return
	}
	var f model.SyslogFilter
	f.DeviceID, _ = strconv.ParseInt(r.FormValue("dev"), 10, 64)
	switch r.FormValue("sev") {
	case "err":
		f.MaxSev = 3
	case "warn":
		f.MaxSev = 4
	case "crit":
		f.MaxSev = 2
	}
	f.Text = r.FormValue("q")
	period := "last 24 hours"
	switch r.FormValue("range") {
	case "1h":
		f.Since, period = time.Now().Add(-time.Hour), "last hour"
	case "7d":
		f.Since, period = time.Now().AddDate(0, 0, -7), "last 7 days"
	case "all":
		period = "everything stored"
	default:
		f.Since = time.Now().Add(-24 * time.Hour)
	}
	var dev *model.Device
	title := i18n.T(lang, "ai.all_devices")
	if f.DeviceID > 0 {
		d, err := s.a.Store.Device(f.DeviceID)
		if err != nil {
			fail("device not found")
			return
		}
		dev, title = &d, d.Name
	}
	rng := r.FormValue("range")
	if rng != "1h" && rng != "7d" && rng != "all" {
		rng = "24h"
	}
	title += " · " + rng
	if f.MaxSev > 0 {
		title += " · ≥ " + sevName(f.MaxSev)
	}
	if f.Text != "" {
		title += " · «" + f.Text + "»"
	}
	text, sent, matched, err := s.aiContext(f, dev, period)
	if err != nil {
		fail(i18n.T(lang, "ai.err_nologs"))
		return
	}
	u := userFrom(r)
	id, err := s.a.StartAIReport(model.AIReport{Actor: u.Username, DeviceID: f.DeviceID, Title: title, Lines: sent, Matched: matched}, text, lang)
	if err != nil {
		fail(err.Error())
		return
	}
	_ = s.a.Store.AddAudit(u.Username, "ai_analyze", fmt.Sprintf("%s (%d lines)", title, sent))
	http.Redirect(w, r, fmt.Sprintf("/ai/%d", id), http.StatusSeeOther)
}

func (s *Server) aiReportPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rep, err := s.a.Store.AIReport(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	s.render(w, r, "aireport", map[string]any{"Active": "ai", "R": rep, "HTML": renderMD(rep.Result)})
}

func (s *Server) aiListPage(w http.ResponseWriter, r *http.Request) {
	reps, _ := s.a.Store.AIReports(100)
	devs, _ := s.a.Store.Devices()
	s.render(w, r, "ai", map[string]any{"Active": "ai", "Reports": reps, "Devices": devs,
		"Configured": s.a.AIConfigured(), "Model": s.a.AIModel(), "MaxLines": aiMaxLines})
}

// alertResolve lets an operator dismiss a log_critical alert by hand.
func (s *Server) alertResolve(w http.ResponseWriter, r *http.Request) {
	dev, _ := strconv.ParseInt(r.FormValue("device_id"), 10, 64)
	if r.FormValue("rule") == "log_critical" && dev > 0 {
		_, _ = s.a.Store.ResolveAlert(dev, "log_critical")
		_ = s.a.Store.AddAudit(userFrom(r).Username, "alert_dismiss", fmt.Sprintf("log_critical device %d", dev))
	}
	http.Redirect(w, r, "/alerts", http.StatusSeeOther)
}
