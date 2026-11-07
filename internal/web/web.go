// Package web serves the ROSMan UI and API over HTTPS. Server-rendered HTML with
// a sidebar shell, cookie-based language and theme (no client state needed),
// session-cookie auth. The visual style follows the WAFISP-Panel design system.
package web

import (
	"context"
	"embed"
	"encoding/base64"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"rosman/internal/app"
	"rosman/internal/auth"
	"rosman/internal/i18n"
	"rosman/internal/model"
	"rosman/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// Version is the product version shown in the UI and used for releases.
const Version = "0.10.1"

const (
	cookieName  = "rosman_session"
	langCookie  = "rosman_lang"
	themeCookie = "rosman_theme"
)

type Server struct {
	a    *app.App
	tmpl *template.Template
}

type ctxKey int

const userKey ctxKey = 1

func New(a *app.App) (*Server, error) {
	funcs := template.FuncMap{
		"mb": func(b int64) string { return fmt.Sprintf("%.0f MB", float64(b)/1024/1024) },
		"ago": func(t *time.Time) string {
			if t == nil {
				return "—"
			}
			return time.Since(*t).Round(time.Second).String()
		},
		"ts":       func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"date":     func(t *time.Time) string { if t == nil { return "—" }; return t.Format("2006-01-02") },
		"canWrite": func(u model.User) bool { return roleRank(u.Role) >= roleRank(model.RoleOperator) },
		"isAdmin":  func(u model.User) bool { return u.Role == model.RoleAdmin },
		"alertCount": func() int {
			al, _ := a.Store.ActiveAlerts()
			return len(al)
		},
		"version": func() string { return Version },
		"langs":   func() []string { return i18n.Langs() },
		"qesc":    url.QueryEscape,
		"upper":   strings.ToUpper,
		"deref":    func(p *int64) int64 { if p == nil { return 0 }; return *p },
		"contains": strings.Contains,
		"fwfirst":  fwFirst,
		// Per-request overrides are bound in render(); these are parse-time defaults.
		"t":     func(key string) string { return i18n.T(i18n.Default, key) },
		"lang":  func() string { return i18n.Default },
		"theme": func() string { return "" },
		"path":  func() string { return "/" },
	}
	t, err := template.New("").Funcs(funcs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{a: a, tmpl: t}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	sub, _ := fs.Sub(staticFS, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(http.FS(sub))))
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.HandleFunc("GET /lang/{lang}", s.setLang)
	mux.HandleFunc("GET /theme/{theme}", s.setTheme)
	mux.Handle("GET /{$}", s.authed(s.devices))
	mux.Handle("GET /devices/new", s.authed(s.requireRole(model.RoleOperator, s.newDeviceForm)))
	mux.Handle("POST /devices/new", s.authed(s.requireRole(model.RoleOperator, s.newDeviceSubmit)))
	mux.Handle("GET /devices/{id}", s.authed(s.deviceDetail))
	mux.Handle("POST /devices/{id}/poll", s.authed(s.requireRole(model.RoleOperator, s.devicePoll)))
	mux.Handle("POST /devices/{id}/backup", s.authed(s.requireRole(model.RoleOperator, s.deviceBackup)))
	mux.Handle("POST /devices/{id}/fwcheck", s.authed(s.requireRole(model.RoleOperator, s.deviceFwCheck)))
	mux.Handle("GET /configs/{id}", s.authed(s.configView))
	mux.Handle("POST /devices/{id}/issuecert", s.authed(s.requireRole(model.RoleOperator, s.deviceIssueCert)))
	mux.Handle("GET /firmware", s.authed(s.firmwarePage))
	mux.Handle("POST /firmware/upgrade", s.authed(s.requireRole(model.RoleOperator, s.firmwareUpgrade)))
	mux.Handle("POST /devices/{id}/upgrade", s.authed(s.requireRole(model.RoleOperator, s.deviceUpgrade)))
	mux.Handle("GET /sites", s.authed(s.sitesPage))
	mux.Handle("POST /sites/new", s.authed(s.requireRole(model.RoleOperator, s.siteCreate)))
	mux.Handle("POST /sites/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.siteDelete)))
	mux.Handle("POST /devices/{id}/site", s.authed(s.requireRole(model.RoleOperator, s.deviceSetSite)))
	mux.Handle("POST /devices/{id}/tag", s.authed(s.requireRole(model.RoleOperator, s.deviceTag)))
	mux.Handle("GET /topology", s.authed(s.topologyPage))
	mux.Handle("GET /alerts", s.authed(s.alerts))
	mux.Handle("GET /audit", s.authed(s.auditPage))
	mux.Handle("GET /templates", s.authed(s.templatesPage))
	mux.Handle("POST /templates/new", s.authed(s.requireRole(model.RoleOperator, s.templateCreate)))
	mux.Handle("POST /templates/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.templateDelete)))
	mux.Handle("POST /templates/{id}/apply", s.authed(s.requireRole(model.RoleOperator, s.templateApply)))
	mux.Handle("GET /settings", s.authed(s.requireRole(model.RoleAdmin, s.settingsPage)))
	mux.Handle("POST /settings", s.authed(s.requireRole(model.RoleAdmin, s.settingsSave)))
	mux.Handle("GET /configs/{id}/download", s.authed(s.configDownload))
	mux.Handle("GET /ca", s.authed(s.requireRole(model.RoleAdmin, s.caPage)))
	mux.Handle("POST /ca/generate", s.authed(s.requireRole(model.RoleAdmin, s.caGenerate)))
	mux.Handle("POST /ca/import", s.authed(s.requireRole(model.RoleAdmin, s.caImport)))
	return mux
}

// ---- language / theme ----

func langOf(r *http.Request) string {
	if c, err := r.Cookie(langCookie); err == nil && i18n.Valid(c.Value) {
		return c.Value
	}
	return i18n.Default
}

func themeOf(r *http.Request) string {
	if c, err := r.Cookie(themeCookie); err == nil && (c.Value == "light" || c.Value == "dark") {
		return c.Value
	}
	return ""
}

func safeNext(next string) string {
	if len(next) > 0 && next[0] == '/' && (len(next) == 1 || next[1] != '/') {
		return next
	}
	return "/"
}

func (s *Server) setLang(w http.ResponseWriter, r *http.Request) {
	lang := r.PathValue("lang")
	if !i18n.Valid(lang) {
		http.NotFound(w, r)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: langCookie, Value: lang, Path: "/", MaxAge: 365 * 24 * 3600,
		HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

func (s *Server) setTheme(w http.ResponseWriter, r *http.Request) {
	switch theme := r.PathValue("theme"); theme {
	case "light", "dark":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Value: theme, Path: "/", MaxAge: 365 * 24 * 3600,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	case "system":
		http.SetCookie(w, &http.Cookie{Name: themeCookie, Path: "/", MaxAge: -1,
			HttpOnly: true, Secure: r.TLS != nil, SameSite: http.SameSiteLaxMode})
	default:
		http.NotFound(w, r)
		return
	}
	http.Redirect(w, r, safeNext(r.URL.Query().Get("next")), http.StatusSeeOther)
}

// render clones the template set, binds per-request language/theme/path, injects
// common data, and executes the named template.
func (s *Server) render(w http.ResponseWriter, r *http.Request, name string, data map[string]any) {
	lang := langOf(r)
	theme := themeOf(r)
	path := r.URL.Path
	if data == nil {
		data = map[string]any{}
	}
	if _, ok := data["User"]; !ok {
		data["User"] = userFrom(r)
	}
	data["Lang"], data["Theme"], data["Path"] = lang, theme, path

	t, err := s.tmpl.Clone()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	t = t.Funcs(template.FuncMap{
		"t":     func(key string) string { return i18n.T(lang, key) },
		"lang":  func() string { return lang },
		"theme": func() string { return theme },
		"path":  func() string { return path },
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := t.ExecuteTemplate(w, name, data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// ---- auth middleware ----

func userFrom(r *http.Request) model.User {
	u, _ := r.Context().Value(userKey).(model.User)
	return u
}

func (s *Server) authed(h http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		u, err := s.a.Store.SessionUser(c.Value)
		if err != nil {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), userKey, u))
		h(w, r)
	})
}

func roleRank(r model.Role) int {
	switch r {
	case model.RoleAdmin:
		return 3
	case model.RoleOperator:
		return 2
	default:
		return 1
	}
}

func (s *Server) requireRole(min model.Role, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if roleRank(userFrom(r).Role) < roleRank(min) {
			http.Error(w, "forbidden: needs "+string(min), http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// ---- handlers ----

func (s *Server) loginForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "login", map[string]any{"Err": r.URL.Query().Get("err")})
}

func (s *Server) loginSubmit(w http.ResponseWriter, r *http.Request) {
	u, err := s.a.Store.UserByName(r.FormValue("username"))
	if err != nil || !auth.CheckPassword(u.PasswordHash, r.FormValue("password")) {
		http.Redirect(w, r, "/login?err=invalid+credentials", http.StatusSeeOther)
		return
	}
	tok := auth.NewToken()
	if err := s.a.Store.CreateSession(tok, u.ID, time.Now().Add(12*time.Hour)); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	_ = s.a.Store.AddAudit(u.Username, "login", r.RemoteAddr)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		_ = s.a.Store.DeleteSession(c.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1})
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.a.Store.Devices()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sites, _ := s.a.Store.Sites()
	siteName := map[int64]string{}
	for _, st := range sites {
		siteName[st.ID] = st.Name
	}
	allTags, _ := s.a.Store.AllTags()
	fSite := r.URL.Query().Get("site")
	fTag := r.URL.Query().Get("tag")
	var tagged map[int64]bool
	if fTag != "" {
		tagged, _ = s.a.Store.DeviceIDsByTag(fTag)
	}
	type row struct {
		model.Device
		CPU      int
		Uptime   string
		SiteName string
		DevTags  []string
	}
	rows := make([]row, 0, len(devs))
	for _, d := range devs {
		if fSite != "" {
			if d.SiteID == nil || strconv.FormatInt(*d.SiteID, 10) != fSite {
				continue
			}
		}
		if fTag != "" && !tagged[d.ID] {
			continue
		}
		rr := row{Device: d}
		if d.SiteID != nil {
			rr.SiteName = siteName[*d.SiteID]
		}
		rr.DevTags, _ = s.a.Store.DeviceTags(d.ID)
		if h, err := s.a.Store.LatestHealth(d.ID); err == nil {
			rr.CPU, rr.Uptime = h.CPU, h.Uptime
		}
		rows = append(rows, rr)
	}
	s.render(w, r, "devices", map[string]any{"Active": "devices", "Devices": rows,
		"Sites": sites, "AllTags": allTags, "FSite": fSite, "FTag": fTag})
}

func fwFirst(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func (s *Server) firmwarePage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	type Row struct {
		ID                            int64
		Name, Installed, Latest, Chan string
		Outdated                      bool
	}
	rows := make([]Row, 0, len(devs))
	for _, d := range devs {
		inst, lat := fwFirst(d.ROSVersion), fwFirst(d.FwLatest)
		rows = append(rows, Row{ID: d.ID, Name: d.Name, Installed: inst, Latest: lat, Chan: d.FwChannel,
			Outdated: lat != "" && lat != inst})
	}
	data := map[string]any{"Active": "firmware", "Rows": rows}
	if job, ok := s.a.Store.LatestFwJob(); ok {
		items, _ := s.a.Store.FwItems(job.ID)
		data["Job"] = job
		data["Items"] = items
	}
	s.render(w, r, "firmware", data)
}

func (s *Server) firmwareUpgrade(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	var ids []int64
	if r.FormValue("all_outdated") == "on" {
		devs, _ := s.a.Store.Devices()
		for _, d := range devs {
			if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
				ids = append(ids, d.ID)
			}
		}
	} else {
		for _, v := range r.Form["device_ids"] {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				ids = append(ids, n)
			}
		}
	}
	if len(ids) == 0 {
		http.Redirect(w, r, "/firmware?err=none", http.StatusSeeOther)
		return
	}
	canary, _ := strconv.Atoi(r.FormValue("canary"))
	conc, _ := strconv.Atoi(r.FormValue("concurrency"))
	halt := r.FormValue("halt") == "on"
	if _, err := s.a.StartUpgrade(ids, canary, conc, halt, userFrom(r).Username); err != nil {
		http.Redirect(w, r, "/firmware?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "fw_upgrade", fmt.Sprintf("%d devices", len(ids)))
	http.Redirect(w, r, "/firmware", http.StatusSeeOther)
}

func (s *Server) deviceUpgrade(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.a.StartUpgrade([]int64{id}, 1, 1, true, userFrom(r).Username); err != nil {
		http.Redirect(w, r, "/devices/"+r.PathValue("id")+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "fw_upgrade", r.PathValue("id"))
	http.Redirect(w, r, "/firmware", http.StatusSeeOther)
}

func (s *Server) sitesPage(w http.ResponseWriter, r *http.Request) {
	sites, _ := s.a.Store.Sites()
	s.render(w, r, "sites", map[string]any{"Active": "sites", "Sites": sites,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) siteCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		http.Redirect(w, r, "/sites?err=name+required", http.StatusSeeOther)
		return
	}
	if _, err := s.a.Store.CreateSite(name); err != nil {
		http.Redirect(w, r, "/sites?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/sites?msg=site-created", http.StatusSeeOther)
}

func (s *Server) siteDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteSite(id)
	http.Redirect(w, r, "/sites?msg=site-deleted", http.StatusSeeOther)
}

func (s *Server) deviceSetSite(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var sid *int64
	if v := r.FormValue("site_id"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			sid = &n
		}
	}
	_ = s.a.Store.SetDeviceSite(id, sid)
	http.Redirect(w, r, "/devices/"+r.PathValue("id"), http.StatusSeeOther)
}

func (s *Server) deviceTag(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	tag := strings.TrimSpace(r.FormValue("tag"))
	if tag != "" {
		if r.FormValue("action") == "remove" {
			_ = s.a.Store.RemoveDeviceTag(id, tag)
		} else {
			_ = s.a.Store.AddDeviceTag(id, tag)
		}
	}
	http.Redirect(w, r, "/devices/"+r.PathValue("id"), http.StatusSeeOther)
}

func (s *Server) newDeviceForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "new_device", map[string]any{"Active": "devices"})
}

func (s *Server) newDeviceSubmit(w http.ResponseWriter, r *http.Request) {
	port, _ := strconv.Atoi(r.FormValue("api_port"))
	if port == 0 {
		port = 8729
	}
	sshUser := r.FormValue("ssh_user")
	if sshUser == "" {
		sshUser = r.FormValue("api_user")
	}
	id, err := s.a.AddDevice(r.FormValue("name"), r.FormValue("ip"), port,
		r.FormValue("api_user"), r.FormValue("api_pass"), sshUser)
	if err != nil {
		s.render(w, r, "new_device", map[string]any{"Active": "devices", "Err": err.Error(),
			"Name": r.FormValue("name"), "IP": r.FormValue("ip"), "APIUser": r.FormValue("api_user")})
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "add_device", r.FormValue("ip"))
	http.Redirect(w, r, "/devices/"+strconv.FormatInt(id, 10), http.StatusSeeOther)
}

func (s *Server) deviceDetail(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "device not found", 404)
		return
	}
	health, _ := s.a.Store.LatestHealth(id)
	cfgs, _ := s.a.Store.Configs(id, 20)
	neighbors, _ := s.a.Store.Neighbors(id)
	traffic := s.trafficRows(id)
	sites, _ := s.a.Store.Sites()
	devTags, _ := s.a.Store.DeviceTags(id)
	ports, _ := s.a.Store.DevicePorts(id)
	metrics, _ := s.a.Store.MetricsSince(id, time.Now().Add(-2*time.Hour))
	var cpu, ram, temp []float64
	for _, m := range metrics {
		cpu = append(cpu, float64(m.CPU))
		if m.TotalMem > 0 {
			ram = append(ram, float64(m.TotalMem-m.FreeMem)/float64(m.TotalMem)*100)
		}
		if m.Temp > 0 {
			temp = append(temp, m.Temp)
		}
	}
	s.render(w, r, "device", map[string]any{"Active": "devices",
		"D": d, "H": health, "Configs": cfgs, "Neighbors": neighbors, "Traffic": traffic,
		"Sites": sites, "DevTags": devTags, "BackupMode": s.a.BackupMode(),
		"Faceplate": facePlateSVG(ports),
		"CPUGraph":  graphSVG(cpu, 100, "var(--accent)"), "RAMGraph": graphSVG(ram, 100, "var(--warn)"),
		"TempGraph": graphSVG(temp, 0, "var(--bad)"), "HasTemp": len(temp) > 0,
		"HasSSH": s.a.HasSSHKey(), "Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err"),
	})
}

func (s *Server) devicePoll(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id")
	if err := s.a.PollDevice(d); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, dst+"?msg=polled", http.StatusSeeOther)
}

func (s *Server) deviceBackup(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id")
	changed, err := s.a.BackupDevice(d, r.FormValue("mode"))
	if err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	msg := "backup-unchanged"
	if changed {
		msg = "backup-stored"
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "backup", d.Name+" ("+msg+")")
	http.Redirect(w, r, dst+"?msg="+msg, http.StatusSeeOther)
}

func (s *Server) deviceFwCheck(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id")
	if err := s.a.RefreshFirmware(d); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, dst+"?msg=fwchecked", http.StatusSeeOther)
}

func (s *Server) configView(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	c, err := s.a.Store.ConfigContent(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	s.render(w, r, "config", map[string]any{"Active": "devices", "C": c})
}

func (s *Server) topologyPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	neigh, _ := s.a.Store.AllNeighbors()
	byIP := map[string]int64{}
	byIdent := map[string]int64{}
	for _, d := range devs {
		byIP[d.IP] = d.ID
		if d.Name != "" {
			byIdent[d.Name] = d.ID
		}
	}
	// Edges between known devices (deduped, undirected).
	edgeset := map[[2]int64]bool{}
	for _, n := range neigh {
		to := byIP[n.IP]
		if to == 0 {
			to = byIdent[n.Identity]
		}
		if to == 0 || to == n.DeviceID {
			continue
		}
		a, b := n.DeviceID, to
		if a > b {
			a, b = b, a
		}
		edgeset[[2]int64{a, b}] = true
	}
	type Node struct {
		ID         int64
		Name       string
		X, Y       int
		Status     string // up|down|unknown
	}
	const cx, cy, rad = 330, 300, 250
	pos := map[int64][2]int{}
	nodes := make([]Node, 0, len(devs))
	n := len(devs)
	if n == 0 {
		n = 1
	}
	for i, d := range devs {
		ang := 2 * math.Pi * float64(i) / float64(n)
		x := cx + int(float64(rad)*math.Cos(ang))
		y := cy + int(float64(rad)*math.Sin(ang))
		pos[d.ID] = [2]int{x, y}
		st := "unknown"
		if d.LastSeen != nil {
			if time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval {
				st = "up"
			} else {
				st = "down"
			}
		}
		nodes = append(nodes, Node{ID: d.ID, Name: d.Name, X: x, Y: y, Status: st})
	}
	type Edge struct{ X1, Y1, X2, Y2 int }
	edges := make([]Edge, 0, len(edgeset))
	for e := range edgeset {
		a, b := pos[e[0]], pos[e[1]]
		edges = append(edges, Edge{a[0], a[1], b[0], b[1]})
	}
	s.render(w, r, "topology", map[string]any{"Active": "topology",
		"Nodes": nodes, "Edges": edges, "Count": len(devs)})
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	active, _ := s.a.Store.ActiveAlerts()
	all, _ := s.a.Store.AllAlerts(100)
	s.render(w, r, "alerts", map[string]any{"Active": "alerts", "ActiveAlerts": active, "All": all})
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.a.Store.RecentAudit(200)
	s.render(w, r, "audit", map[string]any{"Active": "audit", "Rows": rows})
}

func (s *Server) templatesPage(w http.ResponseWriter, r *http.Request) {
	s.renderTemplates(w, r, nil, r.URL.Query().Get("msg"), r.URL.Query().Get("err"))
}

func (s *Server) renderTemplates(w http.ResponseWriter, r *http.Request, results []app.ApplyResult, msg, errMsg string) {
	tpls, _ := s.a.Store.Templates()
	devs, _ := s.a.Store.Devices()
	s.render(w, r, "templates", map[string]any{"Active": "templates",
		"Templates": tpls, "Devices": devs, "Results": results, "Msg": msg, "Err": errMsg})
}

func (s *Server) templateCreate(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	if name == "" || r.FormValue("body") == "" {
		http.Redirect(w, r, "/templates?err=name+and+body+required", http.StatusSeeOther)
		return
	}
	if _, err := s.a.Store.CreateTemplate(name, r.FormValue("body")); err != nil {
		http.Redirect(w, r, "/templates?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "template_create", name)
	http.Redirect(w, r, "/templates?msg=template-saved", http.StatusSeeOther)
}

func (s *Server) templateDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteTemplate(id)
	http.Redirect(w, r, "/templates?msg=template-deleted", http.StatusSeeOther)
}

func (s *Server) templateApply(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t, err := s.a.Store.Template(id)
	if err != nil {
		http.Error(w, "template not found", 404)
		return
	}
	guard, _ := strconv.Atoi(r.FormValue("guard"))
	if guard == 0 {
		guard = 120
	}
	target := r.FormValue("target")
	if target == "all" {
		res := s.a.ApplyTemplateAll(t.Body, guard)
		_ = s.a.Store.AddAudit(userFrom(r).Username, "template_apply_all", t.Name)
		s.renderTemplates(w, r, res, "", "")
		return
	}
	did, _ := strconv.ParseInt(target, 10, 64)
	d, err := s.a.Store.Device(did)
	if err != nil {
		http.Redirect(w, r, "/templates?err=device+not+found", http.StatusSeeOther)
		return
	}
	dst := "/devices/" + strconv.FormatInt(did, 10)
	if err := s.a.ApplyTemplate(d, t.Body, guard); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "template_apply", t.Name+" -> "+d.Name)
	http.Redirect(w, r, dst+"?msg=template-applied", http.StatusSeeOther)
}

func (s *Server) settingsPage(w http.ResponseWriter, r *http.Request) {
	get := func(k string) string { v, _ := s.a.Store.GetSetting(k); return v }
	s.render(w, r, "settings", map[string]any{"Active": "settings",
		"V": map[string]string{
			"backup_mode": get("backup_mode"), "backup_deliver": get("backup_deliver"),
			"backup_folder": get("backup_folder"), "tg_token": get("tg_token"), "tg_chat": get("tg_chat"),
			"smtp_host": get("smtp_host"), "smtp_port": get("smtp_port"), "smtp_user": get("smtp_user"),
			"smtp_from": get("smtp_from"), "smtp_to": get("smtp_to"),
		},
		"BpwSet": get("backup_password_enc") != "", "SmtpPwSet": get("smtp_pass_enc") != "",
		"Msg": r.URL.Query().Get("msg"),
	})
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	set := func(k, v string) { _ = s.a.Store.SetSetting(k, v) }
	set("backup_mode", r.FormValue("backup_mode"))
	set("backup_deliver", strings.Join(r.Form["deliver"], ","))
	for _, k := range []string{"backup_folder", "tg_token", "tg_chat", "smtp_host", "smtp_port", "smtp_user", "smtp_from", "smtp_to"} {
		set(k, strings.TrimSpace(r.FormValue(k)))
	}
	if v := r.FormValue("backup_password"); v != "" {
		if enc, err := s.a.Box.Encrypt(v); err == nil {
			set("backup_password_enc", enc)
		}
	}
	if v := r.FormValue("smtp_pass"); v != "" {
		if enc, err := s.a.Box.Encrypt(v); err == nil {
			set("smtp_pass_enc", enc)
		}
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "settings_save", "")
	http.Redirect(w, r, "/settings?msg=saved", http.StatusSeeOther)
}

func (s *Server) configDownload(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	c, err := s.a.Store.ConfigContent(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	var data []byte
	var ext, ct string
	switch c.Kind {
	case "binary":
		data, _ = base64.StdEncoding.DecodeString(c.Content)
		ext, ct = "backup", "application/octet-stream"
	case "archive":
		data, _ = base64.StdEncoding.DecodeString(c.Content)
		ext, ct = "zip", "application/zip"
	default:
		data, ext, ct = []byte(c.Content), "rsc", "text/plain; charset=utf-8"
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="config-%d.%s"`, c.ID, ext))
	_, _ = w.Write(data)
}

func (s *Server) caPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "ca", map[string]any{"Active": "ca", "CA": s.a.CAStatus(),
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) caGenerate(w http.ResponseWriter, r *http.Request) {
	if err := s.a.GenerateCA(r.FormValue("cn")); err != nil {
		http.Redirect(w, r, "/ca?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "ca_generate", r.FormValue("cn"))
	http.Redirect(w, r, "/ca?msg=generated", http.StatusSeeOther)
}

func (s *Server) caImport(w http.ResponseWriter, r *http.Request) {
	if err := s.a.ImportCA(r.FormValue("cert"), r.FormValue("key")); err != nil {
		s.render(w, r, "ca", map[string]any{"Active": "ca", "CA": s.a.CAStatus(), "Err": err.Error()})
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "ca_import", "")
	http.Redirect(w, r, "/ca?msg=imported", http.StatusSeeOther)
}

func (s *Server) deviceIssueCert(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id")
	if err := s.a.IssueCert(d); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "issue_cert", d.Name)
	http.Redirect(w, r, dst+"?msg=cert-issued", http.StatusSeeOther)
}

// TrafficRow is one interface's current rates and sparklines for the device page.
type TrafficRow struct {
	Name           string
	RxRate, TxRate string
	RxSpark        template.HTML
	TxSpark        template.HTML
	cur            float64
}

func (s *Server) trafficRows(deviceID int64) []TrafficRow {
	since := time.Now().Add(-2 * time.Hour)
	names, _ := s.a.Store.IfaceNames(deviceID, since)
	var rows []TrafficRow
	for _, ifn := range names {
		samples, _ := s.a.Store.IfaceSeries(deviceID, ifn, since)
		if len(samples) < 2 {
			continue
		}
		var rx, tx []float64
		for i := 1; i < len(samples); i++ {
			dt := samples[i].TS.Sub(samples[i-1].TS).Seconds()
			if dt <= 0 {
				continue
			}
			drx := float64(samples[i].RxBytes - samples[i-1].RxBytes)
			dtx := float64(samples[i].TxBytes - samples[i-1].TxBytes)
			if drx < 0 {
				drx = 0
			}
			if dtx < 0 {
				dtx = 0
			}
			rx = append(rx, drx*8/dt)
			tx = append(tx, dtx*8/dt)
		}
		if len(rx) == 0 {
			continue
		}
		cur := rx[len(rx)-1] + tx[len(tx)-1]
		rows = append(rows, TrafficRow{
			Name:    ifn,
			RxRate:  fmtbps(rx[len(rx)-1]),
			TxRate:  fmtbps(tx[len(tx)-1]),
			RxSpark: sparkline(rx, "var(--good)"),
			TxSpark: sparkline(tx, "var(--accent)"),
			cur:     cur,
		})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].cur > rows[j].cur })
	if len(rows) > 20 {
		rows = rows[:20]
	}
	return rows
}

func portLabel(name string) string {
	i := len(name)
	for i > 0 && name[i-1] >= '0' && name[i-1] <= '9' {
		i--
	}
	d := name[i:]
	if d == "" {
		return name
	}
	switch {
	case strings.Contains(name, "sfp"), strings.Contains(name, "qsfp"):
		return "S" + d
	case strings.HasPrefix(name, "wlan"), strings.HasPrefix(name, "wifi"):
		return "W" + d
	default:
		return d
	}
}

// facePlateSVG draws a schematic front panel of the device's physical ports,
// coloured by link state (green up, grey down, dim disabled).
func facePlateSVG(ports []model.Port) template.HTML {
	var ph []model.Port
	for _, p := range ports {
		t := p.Type
		if strings.HasPrefix(t, "ether") || strings.Contains(t, "sfp") || strings.Contains(t, "qsfp") || t == "wlan" || strings.HasPrefix(t, "wifi") {
			ph = append(ph, p)
		}
	}
	if len(ph) == 0 {
		return ""
	}
	const cw, ch, gap, perRow = 30, 30, 6, 16
	cols := perRow
	if len(ph) < cols {
		cols = len(ph)
	}
	rows := (len(ph) + perRow - 1) / perRow
	W := cols*(cw+gap) + gap
	H := rows*(ch+gap+12) + gap
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" style="max-width:%dpx;height:auto">`, W, H, W)
	fmt.Fprintf(&b, `<rect x="0" y="0" width="%d" height="%d" rx="8" fill="var(--bg)" stroke="var(--line)"/>`, W, H)
	for i, p := range ph {
		c, r := i%perRow, i/perRow
		x := gap + c*(cw+gap)
		y := gap + r*(ch+gap+12)
		color := "var(--muted)"
		if p.Disabled {
			color = "var(--line)"
		} else if p.Running {
			color = "var(--good)"
		}
		title := template.HTMLEscapeString(p.Name + " (" + p.Type + ")")
		if strings.Contains(p.Type, "sfp") || strings.Contains(p.Type, "qsfp") {
			fmt.Fprintf(&b, `<g><title>%s</title><rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="0.85"/><line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--surface)" stroke-width="2"/></g>`,
				title, x, y, cw, ch, color, x+6, y+ch-6, x+cw-6, y+6)
		} else {
			fmt.Fprintf(&b, `<g><title>%s</title><rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="%s" opacity="0.9"/><rect x="%d" y="%d" width="8" height="4" fill="var(--surface)"/></g>`,
				title, x, y, cw, ch, color, x+cw/2-4, y)
		}
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="8" fill="var(--muted)">%s</text>`,
			x+cw/2, y+ch+10, template.HTMLEscapeString(portLabel(p.Name)))
	}
	b.WriteString("</svg>")
	return template.HTML(b.String())
}

// graphSVG draws a line graph of series; maxFixed>0 pins the Y scale (e.g. 100 for %).
func graphSVG(series []float64, maxFixed float64, color string) template.HTML {
	const w, h = 240, 46
	if len(series) == 0 {
		return ""
	}
	max := maxFixed
	if max <= 0 {
		max = 1
		for _, v := range series {
			if v > max {
				max = v
			}
		}
	}
	n := len(series)
	var pts strings.Builder
	for i, v := range series {
		x := 0.0
		if n > 1 {
			x = float64(i) / float64(n-1) * w
		}
		y := h - v/max*h
		if i > 0 {
			pts.WriteByte(' ')
		}
		fmt.Fprintf(&pts, "%.1f,%.1f", x, y)
	}
	return template.HTML(fmt.Sprintf(
		`<svg viewBox="0 0 %d %d" width="100%%" style="max-width:%dpx;height:auto" preserveAspectRatio="none"><polyline fill="none" stroke="%s" stroke-width="1.8" points="%s"/></svg>`,
		w, h, w, color, pts.String()))
}

func fmtbps(v float64) string {
	switch {
	case v >= 1e9:
		return fmt.Sprintf("%.2f Gbit/s", v/1e9)
	case v >= 1e6:
		return fmt.Sprintf("%.1f Mbit/s", v/1e6)
	case v >= 1e3:
		return fmt.Sprintf("%.0f Kbit/s", v/1e3)
	default:
		return fmt.Sprintf("%.0f bit/s", v)
	}
}

func sparkline(series []float64, color string) template.HTML {
	const wpx, hpx = 120, 28
	if len(series) == 0 {
		return ""
	}
	max := 1.0
	for _, v := range series {
		if v > max {
			max = v
		}
	}
	n := len(series)
	var b strings.Builder
	for i, v := range series {
		x := 0.0
		if n > 1 {
			x = float64(i) / float64(n-1) * wpx
		}
		y := hpx - v/max*hpx
		if i > 0 {
			b.WriteByte(' ')
		}
		fmt.Fprintf(&b, "%.1f,%.1f", x, y)
	}
	return template.HTML(fmt.Sprintf(
		`<svg viewBox="0 0 %d %d" width="%d" height="%d" preserveAspectRatio="none"><polyline fill="none" stroke="%s" stroke-width="1.5" points="%s"/></svg>`,
		wpx, hpx, wpx, hpx, color, b.String()))
}

func urlq(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case ' ':
			out = append(out, '+')
		case '&', '?', '#', '%', '"', '\'', '<', '>':
		default:
			out = append(out, r)
		}
	}
	return string(out)
}

// SeedAdmin ensures at least one admin exists; returns the generated password if created.
func SeedAdmin(st *store.Store) (string, error) {
	n, err := st.CountUsers()
	if err != nil || n > 0 {
		return "", err
	}
	pw := auth.NewToken()[:16]
	hash, err := auth.HashPassword(pw)
	if err != nil {
		return "", err
	}
	_, err = st.CreateUser(model.User{Username: "admin", PasswordHash: hash, Role: model.RoleAdmin})
	return pw, err
}
