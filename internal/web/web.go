// Package web serves the ROSMan UI and API over HTTPS. Server-rendered HTML with
// a sidebar shell, cookie-based language and theme (no client state needed),
// session-cookie auth. The visual style follows the WAFISP-Panel design system.
package web

import (
	"context"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"rosman/internal/app"
	"rosman/internal/auth"
	"rosman/internal/cve"
	"rosman/internal/diff"
	"rosman/internal/i18n"
	"rosman/internal/model"
	"rosman/internal/ros"
	"rosman/internal/totp"

	qrcode "github.com/skip2/go-qrcode"
	"rosman/internal/oui"
	"rosman/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

//go:embed static
var staticFS embed.FS

// Version is the product version shown in the UI and used for releases.
const Version = "0.80.1"

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
		"tsp":      func(t *time.Time) string { if t == nil { return "—" }; return t.Format("2006-01-02 15:04:05") },
		"dateT":    func(t time.Time) string { if t.IsZero() { return "—" }; return t.Format("2006-01-02") },
		"sub":      func(a, b int) int { return a - b },
		"pct":      func(a, b int) int { if b <= 0 { return 0 }; return a * 100 / b },
		"ipbase":   func(a string) string { if i := strings.IndexByte(a, '/'); i >= 0 { return a[:i] }; return a },
		"modelImg":  func(m string) string { return modelImgPath(a.Cfg.DataDir, m) },
		"date":     func(t *time.Time) string { if t == nil { return "—" }; return t.Format("2006-01-02") },
		"canWrite": func(u model.User) bool { return roleRank(u.Role) >= roleRank(model.RoleOperator) },
		"isAdmin":  func(u model.User) bool { return u.Role == model.RoleAdmin },
		"alertCount": func() int {
			al, _ := a.Store.ActiveAlerts()
			return len(al)
		},
		"cveCount": func() int {
			devs, _ := a.Store.Devices()
			n := 0
			for _, d := range devs {
				if len(cve.Scan(d.ROSVersion)) > 0 {
					n++
				}
			}
			return n
		},
		"version": func() string { return Version },
		"update":  func() app.UpdateStatus { return a.UpdateInfo(Version) },
		"langs":   func() []string { return i18n.Langs() },
		"qesc":    url.QueryEscape,
		"upper":   strings.ToUpper,
		"deref":    func(p *int64) int64 { if p == nil { return 0 }; return *p },
		"contains": strings.Contains,
		"fwfirst":  fwFirst,
		"vendor":   oui.Vendor,
		"rsrpClass": func(s string) string {
			// RSRP (dBm): ≥ -90 good, -90..-105 fair, < -105 poor.
			s = strings.TrimSpace(strings.TrimSuffix(strings.Fields(s+" ")[0], "dBm"))
			v, err := strconv.ParseFloat(s, 64)
			if err != nil {
				return ""
			}
			switch {
			case v >= -90:
				return "good"
			case v >= -105:
				return "warn"
			default:
				return "bad"
			}
		},
		// Per-request overrides are bound in render(); these are parse-time defaults.
		"t":     func(key string) string { return i18n.T(i18n.Default, key) },
		"lang":  func() string { return i18n.Default },
		"theme": func() string { return "" },
		"path":  func() string { return "/" },
		"dmsg": func(code string) string {
			if v := i18n.T(i18n.Default, "dmsg."+code); code != "" && v != "dmsg."+code {
				return v
			}
			return code
		},
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
	mux.Handle("POST /devices/{id}/delete", s.authed(s.requireRole(model.RoleAdmin, s.deviceDelete)))
	mux.Handle("POST /devices/{id}/type", s.authed(s.requireRole(model.RoleOperator, s.deviceSetType)))
	mux.Handle("POST /devices/{id}/pollinterval", s.authed(s.requireRole(model.RoleOperator, s.deviceSetPollInterval)))
	mux.Handle("POST /devices/{id}/setip", s.authed(s.requireRole(model.RoleOperator, s.deviceSetIP)))
	mux.Handle("GET /devices/import", s.authed(s.requireRole(model.RoleOperator, s.importForm)))
	mux.Handle("POST /devices/import", s.authed(s.requireRole(model.RoleOperator, s.importRun)))
	mux.Handle("GET /devices/{id}", s.authed(s.deviceDetail))
	mux.Handle("POST /devices/{id}/poll", s.authed(s.requireRole(model.RoleOperator, s.devicePoll)))
	mux.Handle("POST /devices/{id}/backup", s.authed(s.requireRole(model.RoleOperator, s.deviceBackup)))
	mux.Handle("POST /devices/{id}/fwcheck", s.authed(s.requireRole(model.RoleOperator, s.deviceFwCheck)))
	mux.Handle("GET /configs/{id}", s.authed(s.configView))
	mux.Handle("GET /devices/{id}/services", s.authed(s.servicesPage))
	mux.Handle("GET /devices/{id}/capsman", s.authed(s.capsmanPage))
	mux.Handle("GET /devices/{id}/firewall", s.authed(s.firewallPage))
	mux.Handle("GET /devices/{id}/tools", s.authed(s.toolsPage))
	mux.Handle("GET /devices/{id}/lte", s.authed(s.ltePage))
	mux.Handle("GET /devices/{id}/vpn", s.authed(s.vpnPage))
	mux.Handle("GET /models/{name}", s.authed(s.serveModelImage))
	mux.Handle("GET /devices/{id}/net", s.authed(s.netPage))
	mux.Handle("GET /devices/{id}/image/{imgid}", s.authed(s.deviceImageServe))
	mux.Handle("POST /devices/{id}/image", s.authed(s.requireRole(model.RoleOperator, s.deviceImageUpload)))
	mux.Handle("POST /devices/{id}/image/{imgid}/delete", s.authed(s.requireRole(model.RoleOperator, s.deviceImageDelete)))
	mux.Handle("POST /devices/{id}/notes", s.authed(s.requireRole(model.RoleOperator, s.deviceNotesSave)))
	mux.Handle("GET /devices/{id}/history", s.authed(s.historyPage))
	mux.Handle("POST /devices/{id}/firewall", s.authed(s.requireRole(model.RoleOperator, s.firewallApply)))
	mux.Handle("GET /devices/{id}/diff", s.authed(s.diffPage))
	mux.Handle("POST /configs/{id}/restore", s.authed(s.requireRole(model.RoleOperator, s.configRestore)))
	mux.Handle("POST /devices/{id}/issuecert", s.authed(s.requireRole(model.RoleOperator, s.deviceIssueCert)))
	mux.Handle("POST /devices/{id}/snmp", s.authed(s.requireRole(model.RoleOperator, s.deviceSNMPSave)))
	mux.Handle("POST /devices/{id}/snmppoll", s.authed(s.requireRole(model.RoleOperator, s.deviceSNMPPoll)))
	mux.Handle("GET /dashboard", s.authed(s.dashboardPage))
	mux.Handle("GET /firmware", s.authed(s.firmwarePage))
	mux.Handle("GET /firmware/progress", s.authed(s.firmwareProgress))
	mux.Handle("POST /firmware/upgrade", s.authed(s.requireRole(model.RoleOperator, s.firmwareUpgrade)))
	mux.Handle("POST /devices/{id}/upgrade", s.authed(s.requireRole(model.RoleOperator, s.deviceUpgrade)))
	mux.Handle("POST /devices/{id}/rbupgrade", s.authed(s.requireRole(model.RoleOperator, s.deviceRBUpgrade)))
	mux.Handle("POST /devices/{id}/reboot", s.authed(s.requireRole(model.RoleOperator, s.deviceReboot)))
	mux.Handle("GET /sites", s.authed(s.sitesPage))
	mux.Handle("POST /sites/new", s.authed(s.requireRole(model.RoleOperator, s.siteCreate)))
	mux.Handle("POST /sites/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.siteDelete)))
	mux.Handle("POST /sites/{id}/geo", s.authed(s.requireRole(model.RoleOperator, s.siteGeo)))
	mux.Handle("GET /map", s.authed(s.mapPage))
	mux.Handle("POST /devices/{id}/site", s.authed(s.requireRole(model.RoleOperator, s.deviceSetSite)))
	mux.Handle("POST /devices/{id}/tag", s.authed(s.requireRole(model.RoleOperator, s.deviceTag)))
	mux.Handle("GET /clients", s.authed(s.clientsPage))
	mux.Handle("GET /find", s.authed(s.findPage))
	mux.Handle("GET /backups", s.authed(s.backupsPage))
	mux.Handle("GET /ports", s.authed(s.portsPage))
	mux.Handle("GET /ports.csv", s.authed(s.portsCSV))
	mux.Handle("GET /vlans", s.authed(s.vlansPage))
	mux.Handle("GET /vlans.csv", s.authed(s.vlansCSV))
	mux.Handle("GET /reports", s.authed(s.reportsPage))
	mux.Handle("GET /reports/fleet.csv", s.authed(s.fleetCSV))
	mux.Handle("GET /reports/fleet", s.authed(s.fleetReport))
	mux.Handle("GET /bulk", s.authed(s.bulkPage))
	mux.Handle("POST /bulk", s.authed(s.requireRole(model.RoleOperator, s.bulkRun)))
	mux.Handle("GET /run", s.authed(s.requireRole(model.RoleOperator, s.runPage)))
	mux.Handle("POST /run", s.authed(s.requireRole(model.RoleOperator, s.runExec)))
	mux.Handle("GET /configsearch", s.authed(s.requireRole(model.RoleOperator, s.configSearchPage)))
	mux.Handle("GET /compliance", s.authed(s.compliancePage))
	mux.Handle("POST /compliance", s.authed(s.requireRole(model.RoleOperator, s.complianceCreate)))
	mux.Handle("POST /compliance/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.complianceDelete)))
	mux.Handle("POST /compliance/{id}/toggle", s.authed(s.requireRole(model.RoleOperator, s.complianceToggle)))
	mux.Handle("GET /security", s.authed(s.securityPage))
	mux.Handle("GET /devices/{id}/cve", s.authed(s.cvePage))
	mux.Handle("GET /cron", s.authed(s.requireRole(model.RoleAdmin, s.cronPage)))
	mux.Handle("POST /cron", s.authed(s.requireRole(model.RoleAdmin, s.cronCreate)))
	mux.Handle("POST /cron/{id}/delete", s.authed(s.requireRole(model.RoleAdmin, s.cronDelete)))
	mux.Handle("POST /cron/{id}/toggle", s.authed(s.requireRole(model.RoleAdmin, s.cronToggle)))
	mux.Handle("POST /cron/{id}/run", s.authed(s.requireRole(model.RoleAdmin, s.cronRunNow)))
	mux.Handle("GET /webhooks", s.authed(s.requireRole(model.RoleAdmin, s.webhooksPage)))
	mux.Handle("POST /webhooks", s.authed(s.requireRole(model.RoleAdmin, s.webhookCreate)))
	mux.Handle("POST /webhooks/{id}/delete", s.authed(s.requireRole(model.RoleAdmin, s.webhookDelete)))
	mux.Handle("POST /webhooks/{id}/test", s.authed(s.requireRole(model.RoleAdmin, s.webhookTest)))
	mux.Handle("GET /users", s.authed(s.requireRole(model.RoleAdmin, s.usersPage)))
	mux.Handle("POST /users", s.authed(s.requireRole(model.RoleAdmin, s.userCreate)))
	mux.Handle("POST /users/{id}/role", s.authed(s.requireRole(model.RoleAdmin, s.userRole)))
	mux.Handle("POST /users/{id}/password", s.authed(s.requireRole(model.RoleAdmin, s.userPassword)))
	mux.Handle("POST /users/{id}/2fa-disable", s.authed(s.requireRole(model.RoleAdmin, s.userDisable2FA)))
	mux.Handle("POST /users/{id}/delete", s.authed(s.requireRole(model.RoleAdmin, s.userDelete)))
	mux.Handle("GET /maintenance", s.authed(s.maintenancePage))
	mux.Handle("POST /maintenance", s.authed(s.requireRole(model.RoleOperator, s.windowCreate)))
	mux.Handle("POST /maintenance/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.windowDelete)))
	mux.Handle("GET /account", s.authed(s.accountPage))
	mux.Handle("POST /account/2fa/begin", s.authed(s.totpBegin))
	mux.Handle("POST /account/2fa/enable", s.authed(s.totpEnable))
	mux.Handle("POST /account/2fa/disable", s.authed(s.totpDisable))
	mux.Handle("POST /account/tokens", s.authed(s.tokenCreate))
	mux.Handle("POST /account/tokens/{id}/delete", s.authed(s.tokenDelete))
	mux.HandleFunc("GET /api/v1/devices", s.apiAuth(s.apiDevices))
	mux.HandleFunc("GET /api/v1/devices/{id}", s.apiAuth(s.apiDevice))
	mux.HandleFunc("GET /api/v1/alerts", s.apiAuth(s.apiAlerts))
	mux.HandleFunc("GET /api/v1/security", s.apiAuth(s.apiSecurity))
	mux.HandleFunc("GET /metrics", s.apiAuth(s.metricsEndpoint))
	mux.Handle("GET /topology", s.authed(s.topologyPage))
	mux.Handle("POST /topology/pos", s.authed(s.requireRole(model.RoleOperator, s.topoSavePos)))
	mux.Handle("GET /topology/find", s.authed(s.topoFind))
	mux.Handle("GET /alerts", s.authed(s.alerts))
	mux.Handle("GET /audit", s.authed(s.auditPage))
	mux.Handle("GET /templates", s.authed(s.templatesPage))
	mux.Handle("POST /templates/new", s.authed(s.requireRole(model.RoleOperator, s.templateCreate)))
	mux.Handle("POST /templates/{id}/delete", s.authed(s.requireRole(model.RoleOperator, s.templateDelete)))
	mux.Handle("POST /templates/{id}/apply", s.authed(s.requireRole(model.RoleOperator, s.templateApply)))
	mux.Handle("GET /settings", s.authed(s.requireRole(model.RoleAdmin, s.settingsPage)))
	mux.Handle("POST /settings", s.authed(s.requireRole(model.RoleAdmin, s.settingsSave)))
	mux.Handle("POST /settings/gitexport", s.authed(s.requireRole(model.RoleAdmin, s.gitExportNow)))
	mux.Handle("POST /settings/prune", s.authed(s.requireRole(model.RoleAdmin, s.pruneNow)))
	mux.Handle("POST /settings/testnotify", s.authed(s.requireRole(model.RoleAdmin, s.settingsTestNotify)))
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
		// dmsg localizes a short redirect message code (dmsg.<code>), falling
		// back to the raw code when no translation exists so a new code never
		// renders as a blank or a bare "dmsg.foo".
		"dmsg": func(code string) string {
			if code == "" {
				return ""
			}
			if v := i18n.T(lang, "dmsg."+code); v != "dmsg."+code {
				return v
			}
			return code
		},
		"version": func() string { return Version },
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
	if u.TOTPEnabled {
		sec, derr := s.a.Box.Decrypt(u.TOTPSecretEnc)
		if derr != nil || !totp.Validate(sec, r.FormValue("otp")) {
			http.Redirect(w, r, "/login?err=invalid+2fa+code", http.StatusSeeOther)
			return
		}
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

// ---- account: 2FA and API tokens ----

func tokenHash(tok string) string {
	h := sha256.Sum256([]byte(tok))
	return hex.EncodeToString(h[:])
}

func (s *Server) accountData(r *http.Request, extra map[string]any) map[string]any {
	u := userFrom(r)
	// Re-read to get fresh TOTP state.
	if fresh, err := s.a.Store.UserByID(u.ID); err == nil {
		u = fresh
	}
	toks, _ := s.a.Store.TokensByUser(u.ID)
	data := map[string]any{"Active": "account", "U": u, "Tokens": toks,
		"TOTPEnabled": u.TOTPEnabled, "TOTPPending": !u.TOTPEnabled && u.TOTPSecretEnc != "",
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")}
	if data["TOTPPending"] == true {
		if sec, err := s.a.Box.Decrypt(u.TOTPSecretEnc); err == nil {
			uri := totp.URI("ROSMan", u.Username, sec)
			data["TOTPSecret"] = sec
			data["TOTPURI"] = uri
			if png, err := qrcode.Encode(uri, qrcode.Medium, 220); err == nil {
				// template.URL bypasses html/template's URL sanitizer, which
				// otherwise rewrites a data: URI to "#ZgotmplZ".
				data["TOTPQR"] = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(png))
			}
		}
	}
	for k, v := range extra {
		data[k] = v
	}
	return data
}

func (s *Server) accountPage(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "account", s.accountData(r, nil))
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	enc, err := s.a.Box.Encrypt(totp.NewSecret())
	if err != nil {
		http.Redirect(w, r, "/account?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	if err := s.a.Store.SetTOTP(u.ID, enc, false); err != nil {
		http.Redirect(w, r, "/account?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account", http.StatusSeeOther)
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	u, err := s.a.Store.UserByID(userFrom(r).ID)
	if err != nil || u.TOTPSecretEnc == "" {
		http.Redirect(w, r, "/account?err=no+pending+secret", http.StatusSeeOther)
		return
	}
	sec, derr := s.a.Box.Decrypt(u.TOTPSecretEnc)
	if derr != nil || !totp.Validate(sec, r.FormValue("code")) {
		http.Redirect(w, r, "/account?err=wrong+code", http.StatusSeeOther)
		return
	}
	_ = s.a.Store.SetTOTP(u.ID, u.TOTPSecretEnc, true)
	_ = s.a.Store.AddAudit(u.Username, "2fa_enable", "")
	http.Redirect(w, r, "/account?msg=2fa-enabled", http.StatusSeeOther)
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	if !auth.CheckPassword(u.PasswordHash, r.FormValue("password")) {
		http.Redirect(w, r, "/account?err=wrong+password", http.StatusSeeOther)
		return
	}
	_ = s.a.Store.SetTOTP(u.ID, "", false)
	_ = s.a.Store.AddAudit(u.Username, "2fa_disable", "")
	http.Redirect(w, r, "/account?msg=2fa-disabled", http.StatusSeeOther)
}

func (s *Server) tokenCreate(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = "token"
	}
	raw := "rosman_" + auth.NewToken()
	if _, err := s.a.Store.CreateToken(u.ID, name, tokenHash(raw)); err != nil {
		http.Redirect(w, r, "/account?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(u.Username, "token_create", name)
	// Show the raw token once by rendering the page directly (never in a URL).
	s.render(w, r, "account", s.accountData(r, map[string]any{"NewToken": raw, "NewTokenName": name}))
}

func (s *Server) tokenDelete(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteToken(id, u.ID)
	_ = s.a.Store.AddAudit(u.Username, "token_delete", r.PathValue("id"))
	http.Redirect(w, r, "/account?msg=token-revoked", http.StatusSeeOther)
}

// ---- JSON API (bearer token) ----

func (s *Server) apiAuth(h func(http.ResponseWriter, *http.Request, model.User)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h2 := r.Header.Get("Authorization")
		if !strings.HasPrefix(h2, "Bearer ") {
			writeJSON(w, 401, map[string]any{"error": "missing bearer token"})
			return
		}
		u, err := s.a.Store.UserByTokenHash(tokenHash(strings.TrimPrefix(h2, "Bearer ")))
		if err != nil {
			writeJSON(w, 401, map[string]any{"error": "invalid token"})
			return
		}
		h(w, r, u)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func deviceJSON(d model.Device) map[string]any {
	return map[string]any{
		"id": d.ID, "name": d.Name, "ip": d.IP, "model": d.Model, "serial": d.Serial,
		"routeros": d.ROSVersion, "fw_latest": d.FwLatest, "fw_status": d.FwStatus,
		"last_seen": d.LastSeen, "cve": cve.Scan(d.ROSVersion),
	}
}

func (s *Server) apiDevices(w http.ResponseWriter, r *http.Request, _ model.User) {
	devs, _ := s.a.Store.Devices()
	out := make([]map[string]any, 0, len(devs))
	for _, d := range devs {
		out = append(out, deviceJSON(d))
	}
	writeJSON(w, 200, map[string]any{"devices": out})
}

func (s *Server) apiDevice(w http.ResponseWriter, r *http.Request, _ model.User) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		writeJSON(w, 404, map[string]any{"error": "not found"})
		return
	}
	writeJSON(w, 200, deviceJSON(d))
}

func (s *Server) apiAlerts(w http.ResponseWriter, r *http.Request, _ model.User) {
	al, _ := s.a.Store.ActiveAlerts()
	writeJSON(w, 200, map[string]any{"alerts": al})
}

// promLabel escapes a Prometheus label value (backslash, quote, newline).
func promLabel(v string) string {
	v = strings.ReplaceAll(v, `\`, `\\`)
	v = strings.ReplaceAll(v, `"`, `\"`)
	v = strings.ReplaceAll(v, "\n", `\n`)
	return v
}

// metricsEndpoint exposes fleet metrics in the Prometheus text format. It is
// bearer-protected (reuse an API token): scrape with
//   authorization: { credentials: "<token>" }
func (s *Server) metricsEndpoint(w http.ResponseWriter, r *http.Request, _ model.User) {
	devs, _ := s.a.Store.Devices()
	alerts, _ := s.a.Store.ActiveAlerts()
	var b strings.Builder
	p := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	p("# HELP rosman_build_info Build information.\n# TYPE rosman_build_info gauge\n")
	p("rosman_build_info{version=%q} 1\n", Version)
	p("# HELP rosman_alerts_active Number of active alerts.\n# TYPE rosman_alerts_active gauge\n")
	p("rosman_alerts_active %d\n", len(alerts))
	p("# HELP rosman_devices_total Number of managed devices.\n# TYPE rosman_devices_total gauge\n")
	p("rosman_devices_total %d\n", len(devs))

	p("# HELP rosman_device_up Device reachability (1 up, 0 down/unknown).\n# TYPE rosman_device_up gauge\n")
	upLine := func(d model.Device) int {
		if d.LastSeen != nil && time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval {
			return 1
		}
		return 0
	}
	for _, d := range devs {
		p("rosman_device_up{device=%q,ip=%q,model=%q} %d\n", promLabel(d.Name), promLabel(d.IP), promLabel(d.Model), upLine(d))
	}

	p("# HELP rosman_device_cpu_percent Device CPU load percent (last poll).\n# TYPE rosman_device_cpu_percent gauge\n")
	cpu := map[int64]model.Health{}
	for _, d := range devs {
		if h, err := s.a.Store.LatestHealth(d.ID); err == nil {
			cpu[d.ID] = h
			p("rosman_device_cpu_percent{device=%q} %d\n", promLabel(d.Name), h.CPU)
		}
	}
	p("# HELP rosman_device_mem_free_bytes Free memory (last poll).\n# TYPE rosman_device_mem_free_bytes gauge\n")
	for _, d := range devs {
		if h, ok := cpu[d.ID]; ok {
			p("rosman_device_mem_free_bytes{device=%q} %d\n", promLabel(d.Name), h.FreeMem)
		}
	}
	p("# HELP rosman_device_mem_total_bytes Total memory (last poll).\n# TYPE rosman_device_mem_total_bytes gauge\n")
	for _, d := range devs {
		if h, ok := cpu[d.ID]; ok {
			p("rosman_device_mem_total_bytes{device=%q} %d\n", promLabel(d.Name), h.TotalMem)
		}
	}
	p("# HELP rosman_device_temp_celsius Device temperature (last poll).\n# TYPE rosman_device_temp_celsius gauge\n")
	for _, d := range devs {
		if h, ok := cpu[d.ID]; ok && h.Temp > 0 {
			p("rosman_device_temp_celsius{device=%q} %g\n", promLabel(d.Name), h.Temp)
		}
	}
	p("# HELP rosman_device_fw_outdated RouterOS update available (1 yes, 0 no).\n# TYPE rosman_device_fw_outdated gauge\n")
	for _, d := range devs {
		out := 0
		if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
			out = 1
		}
		p("rosman_device_fw_outdated{device=%q,routeros=%q} %d\n", promLabel(d.Name), promLabel(d.ROSVersion), out)
	}
	p("# HELP rosman_device_cve_count Known CVEs matching the device's RouterOS version.\n# TYPE rosman_device_cve_count gauge\n")
	for _, d := range devs {
		p("rosman_device_cve_count{device=%q} %d\n", promLabel(d.Name), len(cve.Scan(d.ROSVersion)))
	}
	p("# HELP rosman_device_last_seen_timestamp_seconds Unix time of the last successful poll.\n# TYPE rosman_device_last_seen_timestamp_seconds gauge\n")
	for _, d := range devs {
		if d.LastSeen != nil {
			p("rosman_device_last_seen_timestamp_seconds{device=%q} %d\n", promLabel(d.Name), d.LastSeen.Unix())
		}
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	_, _ = w.Write([]byte(b.String()))
}

func (s *Server) apiSecurity(w http.ResponseWriter, r *http.Request, _ model.User) {
	devs, _ := s.a.Store.Devices()
	out := make([]map[string]any, 0)
	for _, d := range devs {
		fs := cve.Scan(d.ROSVersion)
		if len(fs) > 0 {
			out = append(out, map[string]any{"id": d.ID, "name": d.Name,
				"routeros": d.ROSVersion, "worst": cve.Worst(fs), "findings": fs})
		}
	}
	writeJSON(w, 200, map[string]any{"affected": out})
}

func (s *Server) devices(w http.ResponseWriter, r *http.Request) {
	devs, err := s.a.Store.Devices()
	if err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	sites, _ := s.a.Store.Sites()
	tpls, _ := s.a.Store.Templates()
	siteName := map[int64]string{}
	for _, st := range sites {
		siteName[st.ID] = st.Name
	}
	allTags, _ := s.a.Store.AllTags()
	fSite := r.URL.Query().Get("site")
	fTag := r.URL.Query().Get("tag")
	fType := r.URL.Query().Get("type")
	var tagged map[int64]bool
	if fTag != "" {
		tagged, _ = s.a.Store.DeviceIDsByTag(fTag)
	}
	// Active-alert counts per device for the Alerts column.
	alertN := map[int64]int{}
	if al, e := s.a.Store.ActiveAlerts(); e == nil {
		for _, a := range al {
			alertN[a.DeviceID]++
		}
	}
	type row struct {
		model.Device
		CPU      int
		Uptime   string
		SiteName string
		DevTags  []string
		Outdated bool
		Alerts   int
		Addrs    []model.NetAddr
		Macs     []model.NetMac
		LTE      model.LTEInfo
		VPNCount int
		VPNInfo  string
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
		if fType != "" && d.DeviceType != fType {
			continue
		}
		rr := row{Device: d, Alerts: alertN[d.ID]}
		if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
			rr.Outdated = true
		}
		if d.SiteID != nil {
			rr.SiteName = siteName[*d.SiteID]
		}
		rr.DevTags, _ = s.a.Store.DeviceTags(d.ID)
		rr.Addrs, _ = s.a.Store.DeviceAddrs(d.ID)
		rr.Macs, _ = s.a.Store.DeviceMacs(d.ID)
		rr.LTE, _ = s.a.Store.DeviceLTEInfo(d.ID)
		rr.VPNCount, rr.VPNInfo = s.a.Store.DeviceVPNSummary(d.ID)
		if h, err := s.a.Store.LatestHealth(d.ID); err == nil {
			rr.CPU, rr.Uptime = h.CPU, h.Uptime
		}
		rows = append(rows, rr)
	}
	// Discovered neighbours (combined /ip/neighbor view). Neighbours that are
	// already one of our managed devices — matched by ANY of their interface
	// IPs or MACs — are hidden, since they are already added.
	managedIP, _ := s.a.Store.AllManagedAddrs()
	managedMAC, _ := s.a.Store.AllManagedMacs()
	showAllNeigh := r.URL.Query().Get("allneigh") == "1"
	type disc struct {
		Identity, IP, MAC, Platform, SeenBy string
		Managed                             bool
	}
	aggm := map[string]*disc{}
	var dorder []string
	if sight, e := s.a.Store.AllNeighborSightings(); e == nil {
		for _, n := range sight {
			isManaged := (n.IP != "" && managedIP[n.IP]) || (n.MAC != "" && managedMAC[strings.ToUpper(n.MAC)])
			if isManaged && !showAllNeigh {
				continue // already managed — hidden unless "show all"
			}
			key := n.MAC
			if key == "" {
				key = n.IP
			}
			if key == "" {
				key = n.Identity
			}
			if key == "" {
				continue
			}
			d := aggm[key]
			if d == nil {
				d = &disc{Identity: n.Identity, IP: n.IP, MAC: n.MAC, Platform: n.Platform, Managed: isManaged}
				aggm[key] = d
				dorder = append(dorder, key)
			}
			if d.IP == "" {
				d.IP = n.IP
			}
			if d.Identity == "" {
				d.Identity = n.Identity
			}
			if n.SeenBy != "" && !strings.Contains(d.SeenBy, n.SeenBy) {
				if d.SeenBy != "" {
					d.SeenBy += ", "
				}
				d.SeenBy += n.SeenBy
			}
		}
	}
	discovered := make([]disc, 0, len(dorder))
	for _, k := range dorder {
		discovered = append(discovered, *aggm[k])
	}
	s.render(w, r, "devices", map[string]any{"Active": "devices", "Devices": rows,
		"Sites": sites, "AllTags": allTags, "FSite": fSite, "FTag": fTag, "FType": fType,
		"Discovered": discovered, "ShowAllNeigh": showAllNeigh, "Templates": tpls,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func fwFirst(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return f[0]
}

func (s *Server) dashboardPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	var online, offline, unknown, outdated int
	verCount := map[string]int{}
	for _, d := range devs {
		switch {
		case d.LastSeen == nil:
			unknown++
		case time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval:
			online++
		default:
			offline++
		}
		if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
			outdated++
		}
		if v := fwFirst(d.ROSVersion); v != "" {
			verCount[v]++
		}
	}
	type vc struct {
		Ver string
		N   int
	}
	var vers []vc
	for v, n := range verCount {
		vers = append(vers, vc{v, n})
	}
	sort.Slice(vers, func(i, j int) bool { return vers[i].N > vers[j].N })
	alerts, _ := s.a.Store.ActiveAlerts()
	sites, _ := s.a.Store.Sites()

	alertByDev := map[int64]int{}
	for _, a := range alerts {
		alertByDev[a.DeviceID]++
	}
	type cpuRow struct {
		ID   int64
		Name string
		CPU  int
	}
	type attnRow struct {
		ID      int64
		Name    string
		Reasons string
	}
	var topCPU []cpuRow
	var attention []attnRow
	cveAffected := 0
	for _, d := range devs {
		cpu := 0
		if h, err := s.a.Store.LatestHealth(d.ID); err == nil {
			cpu = h.CPU
		}
		topCPU = append(topCPU, cpuRow{d.ID, d.Name, cpu})
		ncve := len(cve.Scan(d.ROSVersion))
		if ncve > 0 {
			cveAffected++
		}
		var reasons []string
		if d.LastSeen == nil {
			reasons = append(reasons, "no data")
		} else if time.Since(*d.LastSeen) >= 3*s.a.Cfg.PollInterval {
			reasons = append(reasons, "offline")
		}
		if alertByDev[d.ID] > 0 {
			reasons = append(reasons, fmt.Sprintf("%d alert(s)", alertByDev[d.ID]))
		}
		if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
			reasons = append(reasons, "update "+l)
		}
		if d.RBUpgradeFw != "" && d.RBUpgradeFw != d.RBCurrentFw {
			reasons = append(reasons, "board FW "+d.RBUpgradeFw)
		}
		if ncve > 0 {
			reasons = append(reasons, fmt.Sprintf("%d CVE", ncve))
		}
		if len(reasons) > 0 {
			attention = append(attention, attnRow{d.ID, d.Name, strings.Join(reasons, " · ")})
		}
	}
	sort.Slice(topCPU, func(i, j int) bool { return topCPU[i].CPU > topCPU[j].CPU })
	if len(topCPU) > 8 {
		topCPU = topCPU[:8]
	}
	onlinePct := 0
	if len(devs) > 0 {
		onlinePct = online * 100 / len(devs)
	}

	// Fleet port capacity (free physical ports) and distinct VLAN count.
	freePorts := 0
	for _, d := range devs {
		ports, _ := s.a.Store.DevicePorts(d.ID)
		for _, p := range ports {
			if physicalPort(p.Name) != "" && !p.Disabled && !p.Running {
				freePorts++
			}
		}
	}
	vlanSet := map[int]bool{}
	if vr, _ := s.a.Store.AllVLANs(); vr != nil {
		for _, v := range vr {
			for _, id := range expandVlanIDs(v.VlanIDs) {
				vlanSet[id] = true
			}
		}
	}

	s.render(w, r, "dashboard", map[string]any{"Active": "dashboard",
		"Total": len(devs), "Online": online, "Offline": offline, "Unknown": unknown,
		"Outdated": outdated, "SitesN": len(sites), "Alerts": alerts, "AlertCount": len(alerts),
		"Versions": vers, "CVEAffected": cveAffected, "TopCPU": topCPU,
		"Attention": attention, "OnlinePct": onlinePct, "FreePorts": freePorts, "VlanN": len(vlanSet)})
}

func (s *Server) firmwarePage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	type Row struct {
		ID                            int64
		Name, Installed, Latest, Chan string
		Outdated                      bool
		RBCurrent, RBUpgrade          string // RouterBOARD firmware now / pending
		RBOutdated                    bool   // a board firmware upgrade is pending
	}
	rows := make([]Row, 0, len(devs))
	rbPending := 0
	for _, d := range devs {
		inst, lat := fwFirst(d.ROSVersion), fwFirst(d.FwLatest)
		rbOut := d.RBUpgradeFw != "" && d.RBUpgradeFw != d.RBCurrentFw
		if rbOut {
			rbPending++
		}
		rows = append(rows, Row{ID: d.ID, Name: d.Name, Installed: inst, Latest: lat, Chan: d.FwChannel,
			Outdated: lat != "" && lat != inst, RBCurrent: d.RBCurrentFw, RBUpgrade: d.RBUpgradeFw, RBOutdated: rbOut})
	}
	data := map[string]any{"Active": "firmware", "Rows": rows, "RBPending": rbPending}
	if job, ok := s.a.Store.LatestFwJob(); ok {
		items, _ := s.a.Store.FwItems(job.ID)
		done := 0
		for _, it := range items {
			if it.Status == "done" || it.Status == "failed" || it.Status == "skipped" {
				done++
			}
		}
		pct := 0
		if len(items) > 0 {
			pct = done * 100 / len(items)
		}
		data["Job"] = job
		data["Items"] = items
		data["FwDone"] = done
		data["FwTotal"] = len(items)
		data["FwPct"] = pct
		// Auto-refresh only while a recent job is still in flight — a stale
		// "running" job left over from the past must not reload the page forever.
		data["FwActive"] = job.Status != "done" && done < len(items) && time.Since(job.CreatedAt) < 30*time.Minute
	}
	s.render(w, r, "firmware", data)
}

// firmwareProgress returns the live state of the latest firmware job as JSON so
// the page can update the progress bar and per-device rows in place, without a
// full reload that would flicker and lose the scroll position.
func (s *Server) firmwareProgress(w http.ResponseWriter, r *http.Request) {
	job, ok := s.a.Store.LatestFwJob()
	if !ok {
		writeJSON(w, 200, map[string]any{"job": false})
		return
	}
	items, _ := s.a.Store.FwItems(job.ID)
	done := 0
	type it struct {
		DeviceName, Target, Status, Detail string
	}
	out := make([]it, 0, len(items))
	for _, i := range items {
		if i.Status == "done" || i.Status == "failed" || i.Status == "skipped" {
			done++
		}
		out = append(out, it{i.DeviceName, i.Target, i.Status, i.Detail})
	}
	pct := 0
	if len(items) > 0 {
		pct = done * 100 / len(items)
	}
	active := job.Status != "done" && done < len(items) && time.Since(job.CreatedAt) < 30*time.Minute
	writeJSON(w, 200, map[string]any{
		"job":    true,
		"id":     job.ID,
		"status": job.Status,
		"done":   done,
		"total":  len(items),
		"pct":    pct,
		"active": active,
		"items":  out,
	})
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

// deviceRBUpgrade applies the pending RouterBOARD firmware and reboots the
// device. The operator confirms in the browser first (the device reboots).
func (s *Server) deviceRBUpgrade(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	dst := "/devices/" + r.PathValue("id")
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	rebooting, err := s.a.RouterboardUpgrade(d)
	if err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "rb_fw_upgrade", r.PathValue("id"))
	if rebooting {
		http.Redirect(w, r, dst+"?msg=rb_upgrading", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, dst+"?msg=rb_current", http.StatusSeeOther)
	}
}

// deviceReboot reboots a single device. The operator confirms in the browser
// first (the device drops off the network for the reboot).
func (s *Server) deviceReboot(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	dst := "/devices/" + r.PathValue("id")
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	if err := s.a.Reboot(d); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "reboot", r.PathValue("id"))
	http.Redirect(w, r, dst+"?msg=rebooting", http.StatusSeeOther)
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

func (s *Server) siteGeo(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	latS := strings.TrimSpace(r.FormValue("lat"))
	lonS := strings.TrimSpace(r.FormValue("lon"))
	if latS == "" || lonS == "" {
		_ = s.a.Store.UpdateSiteGeo(id, nil, nil) // clear
		http.Redirect(w, r, "/sites?msg=geo-cleared", http.StatusSeeOther)
		return
	}
	lat, e1 := strconv.ParseFloat(latS, 64)
	lon, e2 := strconv.ParseFloat(lonS, 64)
	if e1 != nil || e2 != nil || lat < -90 || lat > 90 || lon < -180 || lon > 180 {
		http.Redirect(w, r, "/sites?err=invalid+coordinates", http.StatusSeeOther)
		return
	}
	_ = s.a.Store.UpdateSiteGeo(id, &lat, &lon)
	http.Redirect(w, r, "/sites?msg=geo-saved", http.StatusSeeOther)
}

func (s *Server) mapPage(w http.ResponseWriter, r *http.Request) {
	sites, _ := s.a.Store.Sites()
	devs, _ := s.a.Store.Devices()
	type mdev struct {
		Name string `json:"name"`
		Up   int    `json:"up"`
	}
	type msite struct {
		Name    string `json:"name"`
		Lat     float64 `json:"lat"`
		Lon     float64 `json:"lon"`
		Devices []mdev `json:"devices"`
		Online  int    `json:"online"`
		Total   int    `json:"total"`
	}
	var out []msite
	for _, st := range sites {
		if st.Lat == nil || st.Lon == nil {
			continue
		}
		ms := msite{Name: st.Name, Lat: *st.Lat, Lon: *st.Lon}
		for _, d := range devs {
			if d.SiteID == nil || *d.SiteID != st.ID {
				continue
			}
			up := 0
			if d.LastSeen != nil && time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval {
				up = 1
			}
			ms.Devices = append(ms.Devices, mdev{Name: d.Name, Up: up})
			ms.Total++
			ms.Online += up
		}
		out = append(out, ms)
	}
	js, _ := json.Marshal(out)
	s.render(w, r, "map", map[string]any{"Active": "map", "MapData": template.JS(js), "SiteN": len(out)})
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
	s.render(w, r, "new_device", map[string]any{"Active": "devices",
		"IP": r.URL.Query().Get("ip"), "Name": r.URL.Query().Get("name")})
}

func (s *Server) deviceSetType(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	t := r.FormValue("device_type")
	if t != "router" && t != "switch" && t != "mix" {
		t = ""
	}
	_ = s.a.Store.SetDeviceType(id, t)
	http.Redirect(w, r, "/devices/"+r.PathValue("id")+"?msg=type-saved", http.StatusSeeOther)
}

func (s *Server) deviceSetIP(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	ip := strings.TrimSpace(r.FormValue("ip"))
	if i := strings.IndexByte(ip, '/'); i >= 0 {
		ip = ip[:i]
	}
	if !ros.ValidTarget(ip) {
		http.Redirect(w, r, "/?err=invalid+ip", http.StatusSeeOther)
		return
	}
	_ = s.a.Store.UpdateDeviceIP(id, ip)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_setip", ip)
	http.Redirect(w, r, "/?msg=default-ip-set", http.StatusSeeOther)
}

func (s *Server) deviceSetPollInterval(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	sec, _ := strconv.Atoi(r.FormValue("poll_interval_sec"))
	if sec < 0 {
		sec = 0
	}
	_ = s.a.Store.SetDevicePollInterval(id, sec)
	http.Redirect(w, r, "/devices/"+r.PathValue("id")+"?msg=poll-interval-saved", http.StatusSeeOther)
}

func (s *Server) deviceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	if err := s.a.Store.DeleteDevice(id); err != nil {
		http.Redirect(w, r, "/?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_delete", d.Name+" ("+d.IP+")")
	http.Redirect(w, r, "/?msg=device-deleted", http.StatusSeeOther)
}

func (s *Server) importForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, r, "import", map[string]any{"Active": "devices"})
}

func (s *Server) importRun(w http.ResponseWriter, r *http.Request) {
	raw := strings.TrimSpace(r.FormValue("csv"))
	if raw == "" {
		s.render(w, r, "import", map[string]any{"Active": "devices", "Err": "empty input"})
		return
	}
	rd := csv.NewReader(strings.NewReader(raw))
	rd.FieldsPerRecord = -1 // tolerate ragged rows
	rd.TrimLeadingSpace = true
	rows, err := rd.ReadAll()
	if err != nil {
		s.render(w, r, "import", map[string]any{"Active": "devices", "Err": "parse: " + err.Error(), "CSV": raw})
		return
	}
	var results []app.ApplyResult
	added := 0
	for i, row := range rows {
		if len(row) == 0 || (len(row) == 1 && strings.TrimSpace(row[0]) == "") {
			continue
		}
		// Skip an optional header line.
		if i == 0 && (strings.EqualFold(strings.TrimSpace(row[0]), "ip") || strings.EqualFold(strings.TrimSpace(row[0]), "name")) {
			continue
		}
		col := func(n int) string {
			if n < len(row) {
				return strings.TrimSpace(row[n])
			}
			return ""
		}
		ip, user, pass := col(0), col(1), col(2)
		name, portS, sshUser := col(3), col(4), col(5)
		label := ip
		if name != "" {
			label = name + " (" + ip + ")"
		}
		if ip == "" || user == "" || pass == "" {
			results = append(results, app.ApplyResult{Device: label, OK: false, Detail: "need ip,user,pass"})
			continue
		}
		port, _ := strconv.Atoi(portS)
		if port == 0 {
			port = 8729
		}
		if sshUser == "" {
			sshUser = user
		}
		if _, err := s.a.AddDevice(name, ip, port, user, pass, sshUser); err != nil {
			results = append(results, app.ApplyResult{Device: label, OK: false, Detail: err.Error()})
			continue
		}
		added++
		results = append(results, app.ApplyResult{Device: label, OK: true, Detail: "added"})
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "import_devices", fmt.Sprintf("%d added", added))
	s.render(w, r, "import", map[string]any{"Active": "devices", "Results": results, "Added": added})
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
	images, _ := s.a.Store.DeviceImages(id)
	ports, _ := s.a.Store.DevicePorts(id)
	clients, _ := s.a.Store.Clients(id)
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
		"Clients":  clients,
		"Images":   images, "ModelImg": modelImgPath(s.a.Cfg.DataDir, d.Model),
		"PortConns": s.portConnections(id),
		"Faceplate": facePlateSVG(ports),
		"CPUGraph":  graphSVG(cpu, 100, "var(--accent)"), "RAMGraph": graphSVG(ram, 100, "var(--warn)"),
		"TempGraph": graphSVG(temp, 0, "var(--bad)"), "HasTemp": len(temp) > 0,
		"HasSSH": s.a.HasSSHKey(), "Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err"),
		"InMaint":       s.a.Store.InMaintenance(d.ID, time.Now()),
		"GlobalPollSec": int(s.a.Cfg.PollInterval.Seconds()),
	})
}

var imageTypeOK = map[string]bool{
	"image/png": true, "image/jpeg": true, "image/webp": true,
	"image/gif": true, "image/svg+xml": true,
}

const maxImageBytes = 6 << 20 // 6 MiB

func (s *Server) deviceImageUpload(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.a.Store.Device(id); err != nil {
		http.Error(w, "not found", 404)
		return
	}
	if err := r.ParseMultipartForm(maxImageBytes + (1 << 20)); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq("upload too large")), http.StatusSeeOther)
		return
	}
	file, hdr, err := r.FormFile("image")
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq("no file")), http.StatusSeeOther)
		return
	}
	defer file.Close()
	data := make([]byte, 0, hdr.Size)
	buf := make([]byte, 32*1024)
	for {
		n, e := file.Read(buf)
		data = append(data, buf[:n]...)
		if len(data) > maxImageBytes {
			http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq("image over 6 MB")), http.StatusSeeOther)
			return
		}
		if e != nil {
			break
		}
	}
	ct := http.DetectContentType(data)
	// SVG is detected as text/plain or text/xml; trust the uploaded type for SVG.
	if hdr.Header.Get("Content-Type") == "image/svg+xml" && (strings.HasPrefix(ct, "text/") ) {
		ct = "image/svg+xml"
	}
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = ct[:i]
	}
	if !imageTypeOK[ct] {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq("unsupported image type")), http.StatusSeeOther)
		return
	}
	caption := strings.TrimSpace(r.FormValue("caption"))
	if _, err := s.a.Store.AddDeviceImage(id, caption, ct, data); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq(err.Error())), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_image_add", fmt.Sprintf("device %d (%s)", id, ct))
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=%s", id, urlq("image added")), http.StatusSeeOther)
}

func (s *Server) deviceImageServe(w http.ResponseWriter, r *http.Request) {
	imgID, _ := strconv.ParseInt(r.PathValue("imgid"), 10, 64)
	ct, data, err := s.a.Store.DeviceImageData(imgID)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(data)
}

func (s *Server) deviceImageDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	imgID, _ := strconv.ParseInt(r.PathValue("imgid"), 10, 64)
	_ = s.a.Store.DeleteDeviceImage(imgID, id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_image_delete", fmt.Sprintf("device %d image %d", id, imgID))
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=%s", id, urlq("image removed")), http.StatusSeeOther)
}

func (s *Server) deviceNotesSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.a.Store.Device(id); err != nil {
		http.Error(w, "not found", 404)
		return
	}
	notes := r.FormValue("notes")
	if len(notes) > 8000 {
		notes = notes[:8000]
	}
	_ = s.a.Store.SetDeviceNotes(id, notes)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_notes", fmt.Sprintf("device %d", id))
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=%s", id, urlq("notes saved")), http.StatusSeeOther)
}

// PortConn summarises what is reachable through one physical port of a device.
type PortConn struct {
	Port     string
	Neighbor string   // managed/discovered device identity seen on this port
	MACs     int      // learned MACs behind it (FDB)
	Hosts    []string // sample client IP/hostnames on this port
}

// portConnections builds a per-physical-port view from the FDB, MNDP neighbours
// and the client table.
func (s *Server) portConnections(deviceID int64) []PortConn {
	counts, _ := s.a.Store.BridgePortCounts(deviceID)
	neighbors, _ := s.a.Store.Neighbors(deviceID)
	clients, _ := s.a.Store.Clients(deviceID)
	ports := map[string]*PortConn{}
	get := func(p string) *PortConn {
		if ports[p] == nil {
			ports[p] = &PortConn{Port: p}
		}
		return ports[p]
	}
	for iface, n := range counts {
		if p := physicalPort(iface); p != "" {
			get(p).MACs += n
		}
	}
	for _, nb := range neighbors {
		if p := physicalPort(nb.Iface); p != "" {
			name := firstNonEmptyStr(nb.Identity, nb.IP, nb.MAC)
			if pc := get(p); pc.Neighbor == "" {
				pc.Neighbor = name
			} else if name != "" && !strings.Contains(pc.Neighbor, name) {
				pc.Neighbor += ", " + name
			}
		}
	}
	for _, c := range clients {
		if p := physicalPort(c.Iface); p != "" {
			pc := get(p)
			if len(pc.Hosts) < 4 {
				h := firstNonEmptyStr(c.Hostname, c.IP, c.MAC)
				if h != "" {
					pc.Hosts = append(pc.Hosts, h)
				}
			}
		}
	}
	out := make([]PortConn, 0, len(ports))
	for _, pc := range ports {
		out = append(out, *pc)
	}
	sort.Slice(out, func(i, j int) bool { return ethLess(out[i].Port, out[j].Port) })
	return out
}

// firstNonEmptyStr returns the first non-empty argument.
func firstNonEmptyStr(ss ...string) string {
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}

// ethLess orders interface names so ether2 sorts before ether10.
func ethLess(a, b string) bool {
	na, sa := splitTrailingNum(a)
	nb, sb := splitTrailingNum(b)
	if sa == sb {
		return na < nb
	}
	return a < b
}

func splitTrailingNum(s string) (int, string) {
	i := len(s)
	for i > 0 && s[i-1] >= '0' && s[i-1] <= '9' {
		i--
	}
	if i == len(s) {
		return -1, s
	}
	n, _ := strconv.Atoi(s[i:])
	return n, s[:i]
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

func (s *Server) servicesPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d}
	si, err := s.a.DeviceServices(d)
	if err != nil {
		data["Err"] = err.Error()
	} else {
		data["S"] = si
	}
	s.render(w, r, "services", data)
}

func (s *Server) capsmanPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d}
	ci, err := s.a.DeviceCAPsMAN(d)
	if err != nil {
		data["Err"] = err.Error()
	} else {
		data["C"] = ci
	}
	s.render(w, r, "capsman", data)
}

func (s *Server) vpnPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d}
	if v, e := s.a.DeviceVPN(d); e != nil {
		data["Err"] = e.Error()
	} else {
		data["V"] = v
	}
	s.render(w, r, "vpn", data)
}

func (s *Server) ltePage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d}
	if ifs, e := s.a.DeviceLTE(d); e != nil {
		data["Err"] = e.Error()
	} else {
		data["L"] = ifs
	}
	s.render(w, r, "lte", data)
}

func (s *Server) toolsPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	addr := strings.TrimSpace(r.URL.Query().Get("addr"))
	action := r.URL.Query().Get("action")
	count, _ := strconv.Atoi(r.URL.Query().Get("count"))
	if count == 0 {
		count = 4
	}
	data := map[string]any{"Active": "devices", "D": d, "Addr": addr, "Action": action, "Count": count}
	if addr != "" {
		if !ros.ValidTarget(addr) {
			data["Err"] = "invalid target"
		} else if action == "trace" {
			if hops, e := s.a.DeviceTraceroute(d, addr); e != nil {
				data["Err"] = e.Error()
			} else {
				data["Trace"] = hops
			}
		} else {
			if pr, e := s.a.DevicePing(d, addr, count); e != nil {
				data["Err"] = e.Error()
			} else {
				data["Ping"] = pr
			}
		}
	}
	s.render(w, r, "tools", data)
}

func validRole(r string) bool {
	return r == string(model.RoleAdmin) || r == string(model.RoleOperator) || r == string(model.RoleViewer)
}

var userNameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{2,32}$`)

func (s *Server) cronPage(w http.ResponseWriter, r *http.Request) {
	jobs, _ := s.a.Store.CronJobs()
	tpls, _ := s.a.Store.Templates()
	sites, _ := s.a.Store.Sites()
	tags, _ := s.a.Store.AllTags()
	devs, _ := s.a.Store.Devices()
	s.render(w, r, "cron", map[string]any{"Active": "cron", "Jobs": jobs, "Templates": tpls,
		"Sites": sites, "Tags": tags, "Devices": devs,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) cronCreate(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.FormValue("action")
	if action != "poll" && action != "backup" && action != "fwcheck" && action != "gitexport" && action != "template" && action != "command" {
		http.Redirect(w, r, "/cron?err=invalid+action", http.StatusSeeOther)
		return
	}
	if action == "command" && strings.TrimSpace(r.FormValue("command")) == "" {
		http.Redirect(w, r, "/cron?err="+urlq(i18n.T(langOf(r), "run.err_empty")), http.StatusSeeOther)
		return
	}
	j := model.CronJob{
		Name:    strings.TrimSpace(r.FormValue("name")),
		Action:  action,
		Target:  r.FormValue("target"),
		Kind:    r.FormValue("kind"),
		Command: strings.TrimRight(r.FormValue("command"), "\r\n "),
	}
	if j.Name == "" {
		j.Name = action
	}
	if j.Target == "" {
		j.Target = "all"
	}
	if j.Kind != "daily" {
		j.Kind = "interval"
	}
	j.IntervalMin, _ = strconv.Atoi(r.FormValue("interval_min"))
	if j.IntervalMin < 1 {
		j.IntervalMin = 60
	}
	j.AtHour, _ = strconv.Atoi(r.FormValue("at_hour"))
	j.AtMin, _ = strconv.Atoi(r.FormValue("at_min"))
	wd, err := strconv.Atoi(r.FormValue("weekday"))
	if err != nil {
		wd = -1
	}
	j.Weekday = wd
	j.Guard, _ = strconv.Atoi(r.FormValue("guard"))
	// A command job keeps guard=0 (no rollback) — the common case is a read-only
	// command. Other actions default to a 120s rollback guard when unset.
	if j.Guard == 0 && action != "command" {
		j.Guard = 120
	}
	if tid, e := strconv.ParseInt(r.FormValue("template_id"), 10, 64); e == nil && tid > 0 {
		j.TemplateID = &tid
	}
	next := app.CronNext(j, time.Now())
	j.NextRun = &next
	if _, err := s.a.Store.CreateCronJob(j); err != nil {
		http.Redirect(w, r, "/cron?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "cron_create", j.Name+" ("+action+")")
	http.Redirect(w, r, "/cron?msg=job-created", http.StatusSeeOther)
}

func (s *Server) cronDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteCronJob(id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "cron_delete", r.PathValue("id"))
	http.Redirect(w, r, "/cron?msg=job-removed", http.StatusSeeOther)
}

func (s *Server) cronToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	j, err := s.a.Store.CronJob(id)
	if err != nil {
		http.Redirect(w, r, "/cron?err=not+found", http.StatusSeeOther)
		return
	}
	_ = s.a.Store.SetCronEnabled(id, !j.Enabled)
	http.Redirect(w, r, "/cron?msg=toggled", http.StatusSeeOther)
}

func (s *Server) cronRunNow(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	j, err := s.a.Store.CronJob(id)
	if err != nil {
		http.Redirect(w, r, "/cron?err=not+found", http.StatusSeeOther)
		return
	}
	status, rerr := s.a.RunCronJob(j)
	if rerr != nil {
		status = "error: " + rerr.Error()
	}
	_ = s.a.Store.UpdateCronRun(id, time.Now(), status, app.CronNext(j, time.Now()))
	http.Redirect(w, r, "/cron?msg="+urlq("run: "+status), http.StatusSeeOther)
}

func (s *Server) webhooksPage(w http.ResponseWriter, r *http.Request) {
	hooks, _ := s.a.Store.Webhooks()
	s.render(w, r, "webhooks", map[string]any{"Active": "webhooks", "Hooks": hooks,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) webhookCreate(w http.ResponseWriter, r *http.Request) {
	url := strings.TrimSpace(r.FormValue("url"))
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		http.Redirect(w, r, "/webhooks?err=url+must+be+http(s)", http.StatusSeeOther)
		return
	}
	events := strings.TrimSpace(r.FormValue("events"))
	if events == "" {
		events = "all"
	}
	secEnc := ""
	if sec := r.FormValue("secret"); sec != "" {
		if enc, err := s.a.Box.Encrypt(sec); err == nil {
			secEnc = enc
		}
	}
	if err := s.a.Store.CreateWebhook(url, events, secEnc); err != nil {
		http.Redirect(w, r, "/webhooks?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "webhook_create", url)
	http.Redirect(w, r, "/webhooks?msg=webhook-added", http.StatusSeeOther)
}

func (s *Server) webhookDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteWebhook(id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "webhook_delete", r.PathValue("id"))
	http.Redirect(w, r, "/webhooks?msg=webhook-removed", http.StatusSeeOther)
}

func (s *Server) webhookTest(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	st, err := s.a.TestWebhook(id)
	if err != nil {
		http.Redirect(w, r, "/webhooks?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/webhooks?msg="+urlq("test: "+st), http.StatusSeeOther)
}

func (s *Server) usersPage(w http.ResponseWriter, r *http.Request) {
	users, _ := s.a.Store.Users()
	s.render(w, r, "users", map[string]any{"Active": "users", "Users": users,
		"Me": userFrom(r).ID, "Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) userCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.FormValue("username"))
	pass := r.FormValue("password")
	role := r.FormValue("role")
	if !userNameRe.MatchString(name) {
		http.Redirect(w, r, "/users?err=invalid+username", http.StatusSeeOther)
		return
	}
	if len(pass) < 8 {
		http.Redirect(w, r, "/users?err=password+min+8+chars", http.StatusSeeOther)
		return
	}
	if !validRole(role) {
		http.Redirect(w, r, "/users?err=invalid+role", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		http.Redirect(w, r, "/users?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	if _, err := s.a.Store.CreateUser(model.User{Username: name, PasswordHash: hash, Role: model.Role(role)}); err != nil {
		http.Redirect(w, r, "/users?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "user_create", name+" ("+role+")")
	http.Redirect(w, r, "/users?msg=user-created", http.StatusSeeOther)
}

func (s *Server) userRole(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	role := r.FormValue("role")
	if !validRole(role) {
		http.Redirect(w, r, "/users?err=invalid+role", http.StatusSeeOther)
		return
	}
	target, err := s.a.Store.UserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?err=not+found", http.StatusSeeOther)
		return
	}
	// Guard: don't demote the last admin.
	if target.Role == model.RoleAdmin && role != string(model.RoleAdmin) {
		if n, _ := s.a.Store.CountAdmins(); n <= 1 {
			http.Redirect(w, r, "/users?err=cannot+demote+last+admin", http.StatusSeeOther)
			return
		}
	}
	_ = s.a.Store.UpdateUserRole(id, model.Role(role))
	_ = s.a.Store.AddAudit(userFrom(r).Username, "user_role", target.Username+" -> "+role)
	http.Redirect(w, r, "/users?msg=role-updated", http.StatusSeeOther)
}

func (s *Server) userPassword(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	pass := r.FormValue("password")
	if len(pass) < 8 {
		http.Redirect(w, r, "/users?err=password+min+8+chars", http.StatusSeeOther)
		return
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		http.Redirect(w, r, "/users?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.UpdateUserPassword(id, hash)
	if t, e := s.a.Store.UserByID(id); e == nil {
		_ = s.a.Store.AddAudit(userFrom(r).Username, "user_password_reset", t.Username)
	}
	http.Redirect(w, r, "/users?msg=password-reset", http.StatusSeeOther)
}

func (s *Server) userDisable2FA(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.SetTOTP(id, "", false)
	if t, e := s.a.Store.UserByID(id); e == nil {
		_ = s.a.Store.AddAudit(userFrom(r).Username, "user_2fa_reset", t.Username)
	}
	http.Redirect(w, r, "/users?msg=2fa-reset", http.StatusSeeOther)
}

func (s *Server) userDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if id == userFrom(r).ID {
		http.Redirect(w, r, "/users?err=cannot+delete+yourself", http.StatusSeeOther)
		return
	}
	target, err := s.a.Store.UserByID(id)
	if err != nil {
		http.Redirect(w, r, "/users?err=not+found", http.StatusSeeOther)
		return
	}
	if target.Role == model.RoleAdmin {
		if n, _ := s.a.Store.CountAdmins(); n <= 1 {
			http.Redirect(w, r, "/users?err=cannot+delete+last+admin", http.StatusSeeOther)
			return
		}
	}
	_ = s.a.Store.DeleteUser(id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "user_delete", target.Username)
	http.Redirect(w, r, "/users?msg=user-deleted", http.StatusSeeOther)
}

func (s *Server) maintenancePage(w http.ResponseWriter, r *http.Request) {
	wins, _ := s.a.Store.Windows()
	devs, _ := s.a.Store.Devices()
	names := map[int64]string{}
	for _, d := range devs {
		names[d.ID] = d.Name
	}
	now := time.Now()
	rows := make([]map[string]any, 0, len(wins))
	for _, wn := range wins {
		scope, fleet := "", true
		if wn.DeviceID != nil {
			fleet = false
			if n, ok := names[*wn.DeviceID]; ok {
				scope = n
			} else {
				scope = "#" + strconv.FormatInt(*wn.DeviceID, 10)
			}
		}
		active := !now.Before(wn.StartsAt) && !now.After(wn.EndsAt)
		rows = append(rows, map[string]any{"W": wn, "Scope": scope, "Fleet": fleet,
			"Active": active, "Upcoming": now.Before(wn.StartsAt)})
	}
	s.render(w, r, "maintenance", map[string]any{"Active": "maintenance",
		"Rows": rows, "Devices": devs, "Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) windowCreate(w http.ResponseWriter, r *http.Request) {
	const layout = "2006-01-02T15:04"
	start, e1 := time.ParseInLocation(layout, r.FormValue("start"), time.Local)
	end, e2 := time.ParseInLocation(layout, r.FormValue("end"), time.Local)
	if e1 != nil || e2 != nil || !end.After(start) {
		http.Redirect(w, r, "/maintenance?err=invalid+time+range", http.StatusSeeOther)
		return
	}
	var dev *int64
	if v := r.FormValue("device_id"); v != "" {
		if id, err := strconv.ParseInt(v, 10, 64); err == nil {
			dev = &id
		}
	}
	if err := s.a.Store.CreateWindow(dev, start, end, strings.TrimSpace(r.FormValue("note")), userFrom(r).Username); err != nil {
		http.Redirect(w, r, "/maintenance?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "maintenance_add", r.FormValue("note"))
	http.Redirect(w, r, "/maintenance?msg=window-added", http.StatusSeeOther)
}

func (s *Server) windowDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteWindow(id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "maintenance_delete", r.PathValue("id"))
	http.Redirect(w, r, "/maintenance?msg=window-removed", http.StatusSeeOther)
}

func (s *Server) netPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")}
	ni, nerr := s.a.DeviceNet(d)
	if nerr != nil {
		data["Err"] = nerr.Error()
	} else {
		data["N"] = ni
	}
	s.render(w, r, "net", data)
}

func (s *Server) firewallPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	data := map[string]any{"Active": "devices", "D": d,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err"), "HasSSH": s.a.HasSSHKey()}
	fi, ferr := s.a.DeviceFirewall(d)
	if ferr != nil {
		if data["Err"] == "" {
			data["Err"] = ferr.Error()
		}
	} else {
		data["F"] = fi
	}
	s.render(w, r, "firewall", data)
}

// fwSafe permits only characters valid in RouterOS firewall value fields
// (addresses, ports, ranges, interface names), blocking anything that could
// break out of the generated command line.
var fwSafe = regexp.MustCompile(`^[A-Za-z0-9 ._:/,\-!]*$`)

// buildFilterAddCmd composes a validated "/ip firewall filter add" command
// from form fields. It returns an error on an unknown chain/action or on a
// value containing characters outside the safe set.
func buildFilterAddCmd(r *http.Request) (string, error) {
	chain := r.FormValue("chain")
	action := r.FormValue("action")
	allowed := map[string]bool{"input": true, "forward": true, "output": true}
	allowedAct := map[string]bool{"accept": true, "drop": true, "reject": true, "log": true, "tarpit": true}
	if !allowed[chain] {
		return "", fmt.Errorf("invalid chain")
	}
	if !allowedAct[action] {
		return "", fmt.Errorf("invalid action")
	}
	parts := []string{"/ip firewall filter add", "chain=" + chain, "action=" + action}
	add := func(key, val string) error {
		val = strings.TrimSpace(val)
		if val == "" {
			return nil
		}
		if !fwSafe.MatchString(val) {
			return fmt.Errorf("invalid value in %s", key)
		}
		parts = append(parts, key+"="+val)
		return nil
	}
	if p := r.FormValue("protocol"); p != "" {
		if p != "tcp" && p != "udp" && p != "icmp" {
			return "", fmt.Errorf("invalid protocol")
		}
		parts = append(parts, "protocol="+p)
	}
	for key, form := range map[string]string{
		"src-address": "src_address", "dst-address": "dst_address",
		"dst-port": "dst_port", "src-port": "src_port",
		"in-interface": "in_iface", "out-interface": "out_iface",
	} {
		if err := add(key, r.FormValue(form)); err != nil {
			return "", err
		}
	}
	if r.FormValue("disabled") == "on" {
		parts = append(parts, "disabled=yes")
	}
	// Comment: strip quotes/backslashes, always tag as rosman-made.
	cmt := strings.NewReplacer(`"`, "", `\`, "", "\n", " ", "\r", " ").Replace(r.FormValue("comment"))
	cmt = strings.TrimSpace("rosman: " + cmt)
	parts = append(parts, `comment="`+cmt+`"`)
	if pb := strings.TrimSpace(r.FormValue("place_before")); pb != "" {
		if !regexp.MustCompile(`^[0-9]+$`).MatchString(pb) {
			return "", fmt.Errorf("invalid place-before")
		}
		parts = append(parts, "place-before="+pb)
	}
	return strings.Join(parts, " "), nil
}

func (s *Server) firewallApply(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id") + "/firewall"
	cmd, berr := buildFilterAddCmd(r)
	if berr != nil {
		http.Redirect(w, r, dst+"?err="+urlq(berr.Error()), http.StatusSeeOther)
		return
	}
	guard, _ := strconv.Atoi(r.FormValue("guard"))
	if guard == 0 {
		guard = 120
	}
	if err := s.a.ApplyTemplate(d, cmd, guard); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "firewall_add", d.Name+": "+cmd)
	http.Redirect(w, r, dst+"?msg=rule-added", http.StatusSeeOther)
}

func (s *Server) cvePage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	fs := cve.Scan(d.ROSVersion)
	s.render(w, r, "cve", map[string]any{"Active": "devices", "D": d,
		"Findings": fs, "Worst": cve.Worst(fs), "DBCount": len(cve.Data)})
}

// fleetRow is one device line in a report.
type fleetRow struct {
	Name, IP, Model, Serial, ROS, FwLatest, Site, Status, LastSeen string
	Outdated                                                       bool
	CVE                                                            int
}

func (s *Server) fleetRows() ([]fleetRow, map[string]int) {
	devs, _ := s.a.Store.Devices()
	rows := make([]fleetRow, 0, len(devs))
	sum := map[string]int{"total": len(devs)}
	for _, d := range devs {
		status := "unknown"
		switch {
		case d.LastSeen == nil:
			status = "unknown"
			sum["unknown"]++
		case time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval:
			status = "online"
			sum["online"]++
		default:
			status = "offline"
			sum["offline"]++
		}
		outdated := false
		if l := fwFirst(d.FwLatest); l != "" && l != fwFirst(d.ROSVersion) {
			outdated = true
			sum["outdated"]++
		}
		n := len(cve.Scan(d.ROSVersion))
		sum["cve"] += n
		ls := "—"
		if d.LastSeen != nil {
			ls = d.LastSeen.Format("2006-01-02 15:04")
		}
		rows = append(rows, fleetRow{Name: d.Name, IP: d.IP, Model: d.Model, Serial: d.Serial,
			ROS: d.ROSVersion, FwLatest: d.FwLatest, Site: d.SiteName, Status: status,
			LastSeen: ls, Outdated: outdated, CVE: n})
	}
	return rows, sum
}

// expandVlanIDs parses a RouterOS vlan-ids field ("200", "10,20-30") into a
// sorted list of individual VLAN IDs.
func expandVlanIDs(s string) []int {
	seen := map[int]bool{}
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, e1 := strconv.Atoi(strings.TrimSpace(a))
			hi, e2 := strconv.Atoi(strings.TrimSpace(b))
			if e1 == nil && e2 == nil && hi >= lo && hi-lo < 4096 {
				for v := lo; v <= hi; v++ {
					seen[v] = true
				}
			}
		} else if v, e := strconv.Atoi(part); e == nil {
			seen[v] = true
		}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

// vlansPage shows a fleet-wide VLAN overview: each VLAN id and the devices (and
// their tagged/untagged ports) that carry it.
func (s *Server) vlansPage(w http.ResponseWriter, r *http.Request) {
	vrows, _ := s.a.Store.AllVLANs()
	devs, _ := s.a.Store.Devices()
	name := map[int64]string{}
	for _, d := range devs {
		name[d.ID] = d.Name
	}
	type DevVlan struct {
		DeviceID         int64
		Device           string
		Tagged, Untagged string
	}
	type VlanRow struct {
		ID      int
		Devices []DevVlan
	}
	agg := map[int][]DevVlan{}
	for _, vr := range vrows {
		dv := DevVlan{DeviceID: vr.DeviceID, Device: name[vr.DeviceID], Tagged: vr.Tagged, Untagged: vr.Untagged}
		for _, id := range expandVlanIDs(vr.VlanIDs) {
			agg[id] = append(agg[id], dv)
		}
	}
	rows := make([]VlanRow, 0, len(agg))
	for id, dvs := range agg {
		sort.Slice(dvs, func(i, j int) bool { return dvs[i].Device < dvs[j].Device })
		rows = append(rows, VlanRow{ID: id, Devices: dvs})
	}
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	s.render(w, r, "vlans", map[string]any{"Active": "vlans", "Rows": rows, "VlanCount": len(rows)})
}

// HostHit is one location where a searched host was found.
type HostHit struct {
	DeviceID            int64
	Device, Port        string
	MAC, Vendor         string
	IP, Hostname        string
	Source              string
	Managed             bool
}

// findPage is a fleet-wide host finder: given a MAC / IP / hostname it reports
// every device (and physical port) where the host is seen, with vendor/hostname.
func (s *Server) findPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	data := map[string]any{"Active": "find", "Q": q}
	if q == "" {
		s.render(w, r, "find", data)
		return
	}
	lq := strings.ToLower(q)
	uq := strings.ToUpper(q)
	frag := macFragment(q) // partial MAC: 4..11 hex digits from a sticker/label
	devName := map[int64]string{}
	devs, _ := s.a.Store.Devices()
	for _, d := range devs {
		devName[d.ID] = d.Name
	}
	var hits []HostHit
	seen := map[string]bool{}
	add := func(h HostHit) {
		key := fmt.Sprintf("%d|%s|%s", h.DeviceID, h.MAC, h.IP)
		if seen[key] {
			return
		}
		seen[key] = true
		hits = append(hits, h)
	}

	// Is the query itself a managed device? Exact MAC, or a partial-MAC fragment.
	if macOwner, _ := s.a.Store.MacOwners(); len(macOwner) > 0 {
		if id := macOwner[uq]; id != 0 {
			add(HostHit{DeviceID: id, Device: devName[id], MAC: uq, Vendor: oui.Vendor(uq), Managed: true})
		}
		if frag != "" {
			for mac, id := range macOwner {
				if strings.Contains(macHex(mac), frag) {
					add(HostHit{DeviceID: id, Device: devName[id], MAC: mac, Vendor: oui.Vendor(mac), Managed: true})
				}
			}
		}
	}
	if addrOwner, _ := s.a.Store.AddrOwners(); addrOwner[q] != 0 {
		id := addrOwner[q]
		add(HostHit{DeviceID: id, Device: devName[id], IP: q, Managed: true})
	}
	for _, d := range devs {
		if strings.EqualFold(d.Name, q) {
			add(HostHit{DeviceID: d.ID, Device: d.Name, IP: d.IP, Managed: true})
		}
	}

	// Client / endpoint matches (ARP/DHCP/wireless), with the exact FDB port.
	clients, _ := s.a.Store.AllClients(100000)
	for _, c := range clients {
		match := strings.EqualFold(c.MAC, q) || c.IP == q ||
			(len(lq) >= 2 && strings.Contains(strings.ToLower(c.Hostname), lq)) ||
			(len(lq) >= 3 && strings.Contains(strings.ToLower(c.IP), lq)) ||
			(frag != "" && strings.Contains(macHex(c.MAC), frag))
		if !match {
			continue
		}
		port := physicalPort(c.Iface)
		devID := c.DeviceID
		if c.MAC != "" {
			if fdbDev, fdbPort := s.bestFDBAttach(c.MAC); fdbDev != 0 {
				devID, port = fdbDev, fdbPort
			}
		}
		if port == "" {
			port = c.Iface
		}
		add(HostHit{DeviceID: devID, Device: devName[devID], Port: port,
			MAC: strings.ToUpper(c.MAC), Vendor: oui.Vendor(c.MAC),
			IP: c.IP, Hostname: c.Hostname, Source: c.Source})
	}

	// Pure L2 host present only in a bridge FDB (no ARP/DHCP entry). Skip when a
	// client hit already placed this MAC (that row is richer).
	if looksLikeMAC(q) {
		alreadyByMAC := false
		for _, h := range hits {
			if h.MAC == uq {
				alreadyByMAC = true
				break
			}
		}
		if !alreadyByMAC {
			if fdb, _ := s.a.Store.BridgeHostsByMac(q); len(fdb) > 0 {
				if dev, port := s.bestFDBAttach(q); dev != 0 {
					add(HostHit{DeviceID: dev, Device: devName[dev], Port: port,
						MAC: uq, Vendor: oui.Vendor(q), Source: "fdb"})
				}
			}
		}
	}

	data["Hits"] = hits
	data["Searched"] = true
	s.render(w, r, "find", data)
}

// macHex normalizes a MAC-ish string to a lowercase hex run, dropping ':' and
// '-' separators. Any character outside [0-9a-fA-F:-] (e.g. '.') yields "".
// It has no length limit: callers use it to normalize a full stored MAC into
// the haystack that a partial fragment is searched within.
func macHex(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9', r >= 'a' && r <= 'f':
			b.WriteRune(r)
		case r >= 'A' && r <= 'F':
			b.WriteRune(r + ('a' - 'A'))
		case r == ':' || r == '-':
			// separator, skip
		default:
			return "" // not a clean MAC-hex string
		}
	}
	return b.String()
}

// macFragment normalizes a query into a lowercase hex run when it looks like a
// partial MAC an operator typed from a device label — 4..11 hex digits. A full
// 12-digit MAC, an IP (contains '.'), or any non-hex character yields "", so the
// caller falls back to exact matching and IP/hostname handling. Returning ""
// disables the partial-MAC pass entirely.
func macFragment(q string) string {
	if strings.ContainsRune(q, '.') { // looks like an IP, not a MAC label
		return ""
	}
	h := macHex(q)
	if len(h) < 4 || len(h) >= 12 {
		return ""
	}
	return h
}

// looksLikeMAC reports whether a string is shaped like a MAC address.
func looksLikeMAC(s string) bool {
	n := 0
	for _, r := range s {
		switch {
		case (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F'):
			n++
		case r == ':' || r == '-':
		default:
			return false
		}
	}
	return n == 12
}

// backupsPage shows per-device backup coverage: the age of the latest config
// export and binary backup, flagging devices that are stale or never backed up.
func (s *Server) backupsPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	times, _ := s.a.Store.LastConfigTimes()
	const staleAfter = 7 * 24 * time.Hour
	type row struct {
		ID                 int64
		Name, Model        string
		Export, Binary     *time.Time
		Status             string // ok | stale | never
	}
	rows := make([]row, 0, len(devs))
	var okN, staleN, neverN int
	for _, d := range devs {
		rr := row{ID: d.ID, Name: d.Name, Model: d.Model}
		if t, ok := times[d.ID]["export"]; ok {
			rr.Export = &t
		}
		if t, ok := times[d.ID]["binary"]; ok {
			rr.Binary = &t
		} else if t, ok := times[d.ID]["archive"]; ok {
			rr.Binary = &t
		}
		var newest *time.Time
		for _, t := range []*time.Time{rr.Export, rr.Binary} {
			if t != nil && (newest == nil || t.After(*newest)) {
				newest = t
			}
		}
		switch {
		case newest == nil:
			rr.Status = "never"
			neverN++
		case time.Since(*newest) > staleAfter:
			rr.Status = "stale"
			staleN++
		default:
			rr.Status = "ok"
			okN++
		}
		rows = append(rows, rr)
	}
	// Worst first: never, then stale, then ok; within, oldest first.
	rank := map[string]int{"never": 0, "stale": 1, "ok": 2}
	sort.Slice(rows, func(i, j int) bool {
		if rank[rows[i].Status] != rank[rows[j].Status] {
			return rank[rows[i].Status] < rank[rows[j].Status]
		}
		return rows[i].Name < rows[j].Name
	})
	s.render(w, r, "backups", map[string]any{"Active": "backups", "Rows": rows,
		"OkN": okN, "StaleN": staleN, "NeverN": neverN, "Total": len(devs),
		"SSHPubKey": s.a.SSHPublicKey()})
}

// portsCSV exports per-device port capacity.
func (s *Server) portsCSV(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rosman-ports-%s.csv"`, time.Now().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"device", "model", "total", "used", "free", "disabled", "free_ports"})
	for _, d := range devs {
		ports, _ := s.a.Store.DevicePorts(d.ID)
		var total, up, free, dis int
		var freeP []string
		for _, p := range ports {
			if physicalPort(p.Name) == "" {
				continue
			}
			total++
			switch {
			case p.Disabled:
				dis++
			case p.Running:
				up++
			default:
				free++
				freeP = append(freeP, p.Name)
			}
		}
		if total == 0 {
			continue
		}
		_ = cw.Write([]string{d.Name, d.Model, strconv.Itoa(total), strconv.Itoa(up), strconv.Itoa(free), strconv.Itoa(dis), strings.Join(freeP, " ")})
	}
	cw.Flush()
}

// vlansCSV exports one row per VLAN id per device with its tagged/untagged ports.
func (s *Server) vlansCSV(w http.ResponseWriter, r *http.Request) {
	vrows, _ := s.a.Store.AllVLANs()
	devs, _ := s.a.Store.Devices()
	name := map[int64]string{}
	for _, d := range devs {
		name[d.ID] = d.Name
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rosman-vlans-%s.csv"`, time.Now().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"vlan", "device", "untagged", "tagged", "bridge"})
	type kv struct {
		id  int
		dev string
		vr  model.BridgeVLAN
	}
	var all []kv
	for _, vr := range vrows {
		for _, id := range expandVlanIDs(vr.VlanIDs) {
			all = append(all, kv{id, name[vr.DeviceID], vr})
		}
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].id != all[j].id {
			return all[i].id < all[j].id
		}
		return all[i].dev < all[j].dev
	})
	for _, e := range all {
		_ = cw.Write([]string{strconv.Itoa(e.id), e.dev, e.vr.Untagged, e.vr.Tagged, e.vr.Bridge})
	}
	cw.Flush()
}

// portsPage shows per-device physical-port capacity (used / free / disabled)
// across the fleet, with the names of the free ports.
func (s *Server) portsPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	type row struct {
		ID                          int64
		Name, Model                 string
		Total, Up, Free, Disabled   int
		FreePorts                   []string
	}
	rows := make([]row, 0, len(devs))
	var tTotal, tUp, tFree, tDis int
	for _, d := range devs {
		ports, _ := s.a.Store.DevicePorts(d.ID)
		rr := row{ID: d.ID, Name: d.Name, Model: d.Model}
		for _, p := range ports {
			if physicalPort(p.Name) == "" { // only physical ethernet-like ports
				continue
			}
			rr.Total++
			switch {
			case p.Disabled:
				rr.Disabled++
			case p.Running:
				rr.Up++
			default:
				rr.Free++
				if len(rr.FreePorts) < 24 {
					rr.FreePorts = append(rr.FreePorts, p.Name)
				}
			}
		}
		if rr.Total == 0 {
			continue
		}
		tTotal += rr.Total
		tUp += rr.Up
		tFree += rr.Free
		tDis += rr.Disabled
		rows = append(rows, rr)
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Free != rows[j].Free {
			return rows[i].Free > rows[j].Free
		}
		return rows[i].Name < rows[j].Name
	})
	s.render(w, r, "ports", map[string]any{"Active": "ports", "Rows": rows,
		"TTotal": tTotal, "TUp": tUp, "TFree": tFree, "TDis": tDis})
}

func (s *Server) reportsPage(w http.ResponseWriter, r *http.Request) {
	rows, sum := s.fleetRows()
	s.render(w, r, "reports", map[string]any{"Active": "reports", "Sum": sum, "N": len(rows)})
}

func (s *Server) fleetCSV(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.fleetRows()
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="rosman-fleet-%s.csv"`, time.Now().Format("2006-01-02")))
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"name", "ip", "model", "serial", "routeros", "fw_latest", "outdated", "site", "status", "last_seen", "cve_count"})
	for _, d := range rows {
		od := "no"
		if d.Outdated {
			od = "yes"
		}
		_ = cw.Write([]string{d.Name, d.IP, d.Model, d.Serial, d.ROS, d.FwLatest, od, d.Site, d.Status, d.LastSeen, strconv.Itoa(d.CVE)})
	}
	cw.Flush()
}

func (s *Server) fleetReport(w http.ResponseWriter, r *http.Request) {
	rows, sum := s.fleetRows()
	s.render(w, r, "report", map[string]any{"Rows": rows, "Sum": sum,
		"Now": time.Now().Format("2006-01-02 15:04"), "Version": Version})
}

func (s *Server) bulkPage(w http.ResponseWriter, r *http.Request) {
	s.renderBulk(w, r, nil, "", "")
}

func (s *Server) renderBulk(w http.ResponseWriter, r *http.Request, results []app.ApplyResult, action, errMsg string) {
	devs, _ := s.a.Store.Devices()
	tpls, _ := s.a.Store.Templates()
	s.render(w, r, "bulk", map[string]any{"Active": "bulk", "Devices": devs,
		"Templates": tpls, "Results": results, "RanAction": action, "Err": errMsg})
}

func (s *Server) bulkRun(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	action := r.FormValue("action")
	ids := r.Form["ids"]
	if len(ids) == 0 {
		s.renderBulk(w, r, nil, "", "no devices selected")
		return
	}
	guard, _ := strconv.Atoi(r.FormValue("guard"))
	if guard == 0 {
		guard = 120
	}
	var tpl model.Template
	if action == "template" {
		tid, _ := strconv.ParseInt(r.FormValue("template_id"), 10, 64)
		var err error
		if tpl, err = s.a.Store.Template(tid); err != nil {
			s.renderBulk(w, r, nil, "", "template not found")
			return
		}
	}
	results := make([]app.ApplyResult, 0, len(ids))
	for _, sid := range ids {
		id, _ := strconv.ParseInt(sid, 10, 64)
		d, err := s.a.Store.Device(id)
		if err != nil {
			continue
		}
		res := app.ApplyResult{Device: d.Name, OK: true, Detail: "ok"}
		switch action {
		case "poll":
			if err := s.a.PollDevice(d); err != nil {
				res.OK, res.Detail = false, err.Error()
			}
		case "backup":
			if changed, err := s.a.BackupDevice(d, ""); err != nil {
				res.OK, res.Detail = false, err.Error()
			} else if changed {
				res.Detail = "new version"
			} else {
				res.Detail = "no change"
			}
		case "fwcheck":
			if err := s.a.RefreshFirmware(d); err != nil {
				res.OK, res.Detail = false, err.Error()
			} else {
				res.Detail = d.FwStatus
			}
		case "template":
			if err := s.a.ApplyTemplate(d, tpl.Body, guard); err != nil {
				res.OK, res.Detail = false, err.Error()
			}
		default:
			s.renderBulk(w, r, nil, "", "unknown action")
			return
		}
		results = append(results, res)
	}
	detail := action
	if action == "template" {
		detail = "template:" + tpl.Name
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "bulk_"+action, fmt.Sprintf("%d devices (%s)", len(results), detail))
	s.renderBulk(w, r, results, action, "")
}

func (s *Server) runPage(w http.ResponseWriter, r *http.Request) {
	s.renderRun(w, r, nil, "", "", "", 0)
}

func (s *Server) renderRun(w http.ResponseWriter, r *http.Request, results []app.CmdResult, command, errMsg string, sel string, guard int) {
	devs, _ := s.a.Store.Devices()
	preset := map[string]bool{}
	for _, id := range r.URL.Query()["ids"] {
		preset[id] = true
	}
	for _, id := range strings.Fields(sel) {
		preset[id] = true
	}
	s.render(w, r, "run", map[string]any{"Active": "run", "Devices": devs,
		"Results": results, "Command": command, "Err": errMsg,
		"HasSSH": s.a.HasSSHKey(), "Preset": preset, "Guard": guard})
}

func (s *Server) runExec(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	command := strings.TrimRight(r.FormValue("command"), "\r\n ")
	ids := r.Form["ids"]
	sel := strings.Join(ids, " ")
	guard := 0
	if r.FormValue("guard_on") != "" {
		guard, _ = strconv.Atoi(r.FormValue("guard"))
		if guard == 0 {
			guard = 120
		}
	}
	if strings.TrimSpace(command) == "" {
		s.renderRun(w, r, nil, command, i18n.T(langOf(r), "run.err_empty"), sel, guard)
		return
	}
	if len(ids) == 0 {
		s.renderRun(w, r, nil, command, i18n.T(langOf(r), "run.err_nodev"), sel, guard)
		return
	}
	nids := make([]int64, 0, len(ids))
	for _, sid := range ids {
		if id, err := strconv.ParseInt(sid, 10, 64); err == nil {
			nids = append(nids, id)
		}
	}
	results := s.a.RunCommandOn(nids, command, guard)
	gnote := "no-guard"
	if guard > 0 {
		gnote = fmt.Sprintf("guard=%ds", guard)
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "run_command",
		fmt.Sprintf("%d devices, %s: %s", len(results), gnote, firstLine(command)))
	s.renderRun(w, r, results, command, "", sel, guard)
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i] + " …"
	}
	return s
}

func (s *Server) configSearchPage(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	useRegex := r.URL.Query().Get("re") == "1"
	caseSens := r.URL.Query().Get("cs") == "1"
	data := map[string]any{"Active": "configsearch", "Q": q, "Regex": useRegex, "Case": caseSens}
	if q != "" {
		results, err := s.a.ConfigSearch(q, useRegex, caseSens)
		if err != nil {
			data["Err"] = i18n.T(langOf(r), "cs.bad_regex") + ": " + err.Error()
		} else {
			matched := make([]app.ConfigSearchResult, 0, len(results))
			totalHits, noCfg := 0, 0
			for _, rr := range results {
				if rr.NoConfig {
					noCfg++
					continue
				}
				if len(rr.Hits) > 0 {
					matched = append(matched, rr)
					totalHits += len(rr.Hits)
				}
			}
			data["Results"] = matched
			data["TotalHits"] = totalHits
			data["NoCfg"] = noCfg
			data["Scanned"] = len(results) - noCfg
			data["Searched"] = true
		}
	}
	s.render(w, r, "configsearch", data)
}

func (s *Server) compliancePage(w http.ResponseWriter, r *http.Request) {
	rules, _ := s.a.Store.ComplianceRules()
	report, _ := s.a.ComplianceCheck()
	okN, failN := 0, 0
	for _, row := range report {
		if row.OK() {
			okN++
		} else if !row.NoConfig {
			failN++
		}
	}
	s.render(w, r, "compliance", map[string]any{"Active": "compliance", "Rules": rules,
		"Report": report, "OkN": okN, "FailN": failN,
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) complianceCreate(w http.ResponseWriter, r *http.Request) {
	kind := r.FormValue("kind")
	ok := map[string]bool{"require": true, "forbid": true, "require_re": true, "forbid_re": true}
	if !ok[kind] {
		http.Redirect(w, r, "/compliance?err=invalid+kind", http.StatusSeeOther)
		return
	}
	pat := r.FormValue("pattern")
	if strings.TrimSpace(pat) == "" {
		http.Redirect(w, r, "/compliance?err=empty+pattern", http.StatusSeeOther)
		return
	}
	sev := r.FormValue("severity")
	if sev != "crit" {
		sev = "warn"
	}
	name := strings.TrimSpace(r.FormValue("name"))
	if name == "" {
		name = kind + ": " + pat
	}
	if err := s.a.Store.CreateComplianceRule(model.ComplianceRule{Name: name, Severity: sev, Kind: kind, Pattern: pat}); err != nil {
		http.Redirect(w, r, "/compliance?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "compliance_add", name)
	http.Redirect(w, r, "/compliance?msg=rule-created", http.StatusSeeOther)
}

func (s *Server) complianceDelete(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	_ = s.a.Store.DeleteComplianceRule(id)
	http.Redirect(w, r, "/compliance?msg=rule-removed", http.StatusSeeOther)
}

func (s *Server) complianceToggle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	rules, _ := s.a.Store.ComplianceRules()
	for _, rl := range rules {
		if rl.ID == id {
			_ = s.a.Store.SetComplianceEnabled(id, !rl.Enabled)
			break
		}
	}
	http.Redirect(w, r, "/compliance?msg=toggled", http.StatusSeeOther)
}

func (s *Server) securityPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	rows := make([]map[string]any, 0, len(devs))
	affected := 0
	for _, d := range devs {
		fs := cve.Scan(d.ROSVersion)
		if len(fs) > 0 {
			affected++
		}
		rows = append(rows, map[string]any{"D": d, "Findings": fs, "Worst": cve.Worst(fs)})
	}
	s.render(w, r, "security", map[string]any{"Active": "security",
		"Rows": rows, "Affected": affected, "Total": len(devs), "DBCount": len(cve.Data)})
}

func (s *Server) diffPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	all, _ := s.a.Store.Configs(id, 50)
	var exports []model.Config
	for _, c := range all {
		if c.Kind == "export" {
			exports = append(exports, c)
		}
	}
	data := map[string]any{"Active": "devices", "D": d, "Configs": exports}
	aID, _ := strconv.ParseInt(r.URL.Query().Get("a"), 10, 64)
	bID, _ := strconv.ParseInt(r.URL.Query().Get("b"), 10, 64)
	if aID > 0 && bID > 0 {
		ca, e1 := s.a.Store.ConfigContent(aID)
		cb, e2 := s.a.Store.ConfigContent(bID)
		if e1 == nil && e2 == nil {
			lines := diff.Lines(ca.Content, cb.Content)
			added, removed := diff.Stat(lines)
			data["Lines"], data["Added"], data["Removed"] = lines, added, removed
			data["A"], data["B"] = aID, bID
		}
	}
	s.render(w, r, "diff", data)
}

func (s *Server) configRestore(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	c, err := s.a.Store.ConfigContent(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + strconv.FormatInt(c.DeviceID, 10)
	if err := s.a.RestoreConfig(id); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "config_restore", strconv.FormatInt(id, 10))
	http.Redirect(w, r, dst+"?msg=restore-started", http.StatusSeeOther)
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

func (s *Server) clientsPage(w http.ResponseWriter, r *http.Request) {
	clients, _ := s.a.Store.AllClients(2000)
	s.render(w, r, "clients", map[string]any{"Active": "clients", "Clients": clients})
}

// rosmanNodeID is the reserved topology-node id for the ROSMan host itself.
// Negative so it never collides with a (always-positive) device id, and
// non-zero so the position-save handler, which rejects id 0, accepts it.
const rosmanNodeID = -1

func (s *Server) topologyPage(w http.ResponseWriter, r *http.Request) {
	devs, _ := s.a.Store.Devices()
	neigh, _ := s.a.Store.AllNeighbors()
	addrOwner, _ := s.a.Store.AddrOwners()
	macOwner, _ := s.a.Store.MacOwners()
	saved, _ := s.a.Store.TopoPositions()
	byIdent := map[string]int64{}
	for _, d := range devs {
		if d.Name != "" {
			byIdent[d.Name] = d.ID
		}
	}
	ipbase := func(a string) string {
		if i := strings.IndexByte(a, '/'); i >= 0 {
			return a[:i]
		}
		return a
	}
	// Resolve each neighbour sighting to a managed device by MAC, then IP, then
	// identity, and record an undirected edge labelled with the physical port it
	// was seen on. On a flat L2 network /ip/neighbor floods every device onto the
	// management VLAN, so we keep only sightings seen on a real physical port
	// (etherX / sfp* / qsfp* / combo* / wlan*) and drop bridge/vlan/vxlan-only
	// ones — those are the hairball, not physical adjacency.
	type ekey [2]int64
	edgePort := map[ekey]string{}
	for _, n := range neigh {
		port := physicalPort(n.Iface)
		if port == "" {
			continue
		}
		to := macOwner[strings.ToUpper(n.MAC)]
		if to == 0 {
			to = addrOwner[ipbase(n.IP)]
		}
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
		k := ekey{a, b}
		if _, ok := edgePort[k]; !ok {
			edgePort[k] = port
		}
	}
	macByDev, _ := s.a.Store.DeviceMacMap()
	type Node struct {
		ID                     int64
		Name, IP, MAC, Model, ROS string
		X, Y                   float64
		Status                 string // up|down|unknown
		Server                 bool
	}
	const cx, cy, rad = 500.0, 360.0, 300.0
	nn := len(devs)
	if nn == 0 {
		nn = 1
	}
	nodes := make([]Node, 0, len(devs)+1)
	for i, d := range devs {
		ang := 2 * math.Pi * float64(i) / float64(nn)
		x := cx + rad*math.Cos(ang)
		y := cy + rad*math.Sin(ang)
		if p, ok := saved[d.ID]; ok {
			x, y = p[0], p[1]
		}
		st := "unknown"
		if d.LastSeen != nil {
			if time.Since(*d.LastSeen) < 3*s.a.Cfg.PollInterval {
				st = "up"
			} else {
				st = "down"
			}
		}
		nodes = append(nodes, Node{ID: d.ID, Name: d.Name, IP: d.IP, MAC: macByDev[d.ID],
			Model: d.Model, ROS: d.ROSVersion, X: x, Y: y, Status: st})
	}
	type Edge struct {
		A, B int64
		Port string
	}
	edges := make([]Edge, 0, len(edgePort)+1)
	for k, port := range edgePort {
		// Prefer the exact physical port from the bridge FDB: the port on A where
		// B's MAC is learned (or vice-versa) beats the MNDP interface guess.
		if p := s.a.Store.BridgePortOn(k[0], macByDev[k[1]]); physicalPort(p) != "" {
			port = p
		} else if p := s.a.Store.BridgePortOn(k[1], macByDev[k[0]]); physicalPort(p) != "" {
			port = p
		}
		edges = append(edges, Edge{A: k[0], B: k[1], Port: port})
	}
	// ROSMan monitoring host node: find which managed device sees this server's
	// own MAC/IP as a client, and attach a special node to it on that port. It
	// uses a reserved negative id (rosmanNodeID) so its dragged position can be
	// saved like any device's — a real device id is always positive, and id 0 is
	// rejected by the save handler as "no node".
	if attachID, port, srvIP, srvMAC := s.rosmanAttachment(); attachID != 0 {
		sx, sy := cx, cy
		if p, ok := saved[rosmanNodeID]; ok {
			sx, sy = p[0], p[1]
		}
		nodes = append(nodes, Node{ID: rosmanNodeID, Name: "ROSMan", IP: srvIP, MAC: srvMAC,
			Model: "monitoring", ROS: Version, X: sx, Y: sy, Status: "up", Server: true})
		edges = append(edges, Edge{A: rosmanNodeID, B: attachID, Port: port})
	}
	s.render(w, r, "topology", map[string]any{"Active": "topology", "CanWrite": roleRank(userFrom(r).Role) >= roleRank(model.RoleOperator),
		"Nodes": nodes, "Edges": edges, "Count": len(devs), "EdgeCount": len(edges)})
}

// bestFDBAttach picks the device and physical port where a MAC is most likely
// directly attached: among devices that learned it on a physical port, the one
// whose port carries the fewest MACs (an access/edge port, not an uplink).
func (s *Server) bestFDBAttach(mac string) (deviceID int64, port string) {
	hosts, _ := s.a.Store.BridgeHostsByMac(mac)
	if len(hosts) == 0 {
		return 0, ""
	}
	load, _ := s.a.Store.BridgePortLoad()
	best := -1
	for _, h := range hosts {
		p := physicalPort(h.Iface)
		if p == "" {
			continue
		}
		n := load[h.DeviceID][h.Iface]
		if best == -1 || n < best {
			best, deviceID, port = n, h.DeviceID, p
		}
	}
	return deviceID, port
}

// serverNICs returns this host's non-loopback interface MACs (upper-case) and
// IPv4 addresses.
func serverNICs() (macs, ips []string) {
	ifaces, _ := net.Interfaces()
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 || len(i.HardwareAddr) == 0 {
			continue
		}
		macs = append(macs, strings.ToUpper(i.HardwareAddr.String()))
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			if ipn, ok := a.(*net.IPNet); ok && ipn.IP.To4() != nil && !ipn.IP.IsLoopback() {
				ips = append(ips, ipn.IP.String())
			}
		}
	}
	return
}

// rosmanAttachment finds the managed device (and port) whose client table sees
// this server's own MAC or IP, i.e. where the monitoring host is plugged in.
func (s *Server) rosmanAttachment() (deviceID int64, port, ip, mac string) {
	macs, ips := serverNICs()
	macSet := map[string]bool{}
	for _, m := range macs {
		macSet[m] = true
	}
	ipSet := map[string]bool{}
	for _, p := range ips {
		ipSet[p] = true
	}
	// Exact physical port from the bridge FDB first.
	for _, m := range macs {
		if dev, port := s.bestFDBAttach(m); dev != 0 {
			return dev, port, srvAddr("", ips), m
		}
	}
	// Fall back to the clients table (ARP/DHCP) — may only give a logical iface.
	clients, _ := s.a.Store.AllClients(100000)
	var fb *model.Client
	for i := range clients {
		c := clients[i]
		if (c.MAC != "" && macSet[strings.ToUpper(c.MAC)]) || (c.IP != "" && ipSet[c.IP]) {
			if physicalPort(c.Iface) != "" {
				return c.DeviceID, physicalPort(c.Iface), srvAddr(c.IP, ips), srvAddr(strings.ToUpper(c.MAC), macs)
			}
			if fb == nil {
				fb = &clients[i]
			}
		}
	}
	if fb != nil {
		return fb.DeviceID, fb.Iface, srvAddr(fb.IP, ips), srvAddr(strings.ToUpper(fb.MAC), macs)
	}
	return 0, "", "", ""
}

// srvAddr returns v when non-empty, else the first of fallback, else "".
func srvAddr(v string, fallback []string) string {
	if v != "" {
		return v
	}
	if len(fallback) > 0 {
		return fallback[0]
	}
	return ""
}

// topoFind resolves a MAC/IP/name query to the managed device it belongs to or
// is connected through, for the topology search box.
func (s *Server) topoFind(w http.ResponseWriter, r *http.Request) {
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	w.Header().Set("Content-Type", "application/json")
	if q == "" {
		_, _ = w.Write([]byte(`{"found":false}`))
		return
	}
	uq := strings.ToUpper(q)
	write := func(id int64, label string) {
		_, _ = fmt.Fprintf(w, `{"found":true,"id":%d,"label":%q}`, id, label)
	}
	// Managed device by its own MAC / IP / name.
	if macOwner, _ := s.a.Store.MacOwners(); macOwner[uq] != 0 {
		id := macOwner[uq]
		d, _ := s.a.Store.Device(id)
		write(id, i18n.T(langOf(r), "topo.is_device")+": "+d.Name)
		return
	}
	if addrOwner, _ := s.a.Store.AddrOwners(); addrOwner[q] != 0 {
		id := addrOwner[q]
		d, _ := s.a.Store.Device(id)
		write(id, i18n.T(langOf(r), "topo.is_device")+": "+d.Name)
		return
	}
	devs, _ := s.a.Store.Devices()
	for _, d := range devs {
		if strings.EqualFold(d.Name, q) {
			write(d.ID, i18n.T(langOf(r), "topo.is_device")+": "+d.Name)
			return
		}
	}
	// Exact attachment from the bridge FDB when the query is a MAC.
	if dev, port := s.bestFDBAttach(q); dev != 0 {
		d, _ := s.a.Store.Device(dev)
		lbl := i18n.T(langOf(r), "topo.connected_to") + " " + d.Name
		if port != "" {
			lbl += " · " + port
		}
		write(dev, lbl)
		return
	}
	// Client / endpoint MAC or IP seen by a managed device (ARP/DHCP). Upgrade the
	// port to the FDB physical port when that MAC is in the forwarding database.
	clients, _ := s.a.Store.AllClients(100000)
	for _, c := range clients {
		if strings.EqualFold(c.MAC, q) || c.IP == q {
			targetID, port := c.DeviceID, physicalPort(c.Iface)
			if port == "" {
				port = c.Iface
			}
			if c.MAC != "" {
				if fdbDev, fdbPort := s.bestFDBAttach(c.MAC); fdbDev != 0 {
					targetID, port = fdbDev, fdbPort
				}
			}
			d, _ := s.a.Store.Device(targetID)
			lbl := i18n.T(langOf(r), "topo.connected_to") + " " + d.Name
			if port != "" {
				lbl += " · " + port
			}
			if c.Hostname != "" {
				lbl += " (" + c.Hostname + ")"
			}
			write(targetID, lbl)
			return
		}
	}
	_, _ = fmt.Fprintf(w, `{"found":false,"label":%q}`, i18n.T(langOf(r), "topo.not_found"))
}

// normModel reduces a RouterOS model string to a filename-safe key:
// lower-case, keeping only letters and digits (e.g. "RB4011iGS+" → "rb4011igs",
// "CRS328-24P-4S+" → "crs32824p4s", "hAP ac^2" → "hapac2").
func normModel(m string) string {
	var b strings.Builder
	for _, r := range strings.ToLower(m) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// modelImgPath returns the served URL of a product image for a model, or "" when
// none exists. Images live on disk in <DataDir>/models/<normModel>.svg so the
// set can be grown or replaced without rebuilding the binary.
func modelImgPath(dataDir, mdl string) string {
	n := normModel(mdl)
	if n == "" {
		return ""
	}
	if st, err := os.Stat(filepath.Join(dataDir, "models", n+".svg")); err == nil && !st.IsDir() {
		return "/models/" + n + ".svg"
	}
	return ""
}

// serveModelImage serves a product image from <DataDir>/models by base name.
func (s *Server) serveModelImage(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("name"))
	ext := strings.ToLower(filepath.Ext(name))
	ct := map[string]string{".svg": "image/svg+xml", ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg", ".webp": "image/webp"}[ext]
	if ct == "" || strings.Contains(name, "..") {
		http.Error(w, "not found", 404)
		return
	}
	p := filepath.Join(s.a.Cfg.DataDir, "models", name)
	data, err := os.ReadFile(p)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("Cache-Control", "public, max-age=604800")
	_, _ = w.Write(data)
}

// physicalPort returns the first physical interface in a RouterOS neighbour
// interface list (e.g. "ether1,bridgeLan" → "ether1"), or "" when the neighbour
// was seen only on a bridge/vlan/virtual interface (L2 flooding, not adjacency).
func physicalPort(ifaces string) string {
	for _, part := range strings.Split(ifaces, ",") {
		p := strings.TrimSpace(part)
		for _, pfx := range []string{"ether", "sfp", "qsfp", "combo", "wlan"} {
			if strings.HasPrefix(p, pfx) {
				return p
			}
		}
	}
	return ""
}

// topoSavePos persists one node's dragged position.
func (s *Server) topoSavePos(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	id, _ := strconv.ParseInt(r.FormValue("id"), 10, 64)
	x, _ := strconv.ParseFloat(r.FormValue("x"), 64)
	y, _ := strconv.ParseFloat(r.FormValue("y"), 64)
	if id == 0 {
		http.Error(w, "bad id", 400)
		return
	}
	if err := s.a.Store.SaveTopoPos(id, x, y); err != nil {
		http.Error(w, err.Error(), 500)
		return
	}
	w.WriteHeader(http.StatusNoContent)
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
			"git_dir": get("git_dir"), "git_remote": get("git_remote"), "git_branch": get("git_branch"),
			"git_last": get("git_last"),
			"alert_cpu": get("alert_cpu"), "alert_temp": get("alert_temp"), "alert_mem": get("alert_mem"),
		},
		"BpwSet": get("backup_password_enc") != "", "SmtpPwSet": get("smtp_pass_enc") != "",
		"GitEnabled": get("git_enabled") == "on",
		"Retention":  s.a.MetricsRetentionDays(), "MetricCount": func() int64 { n, _ := s.a.Store.CountMetrics(); return n }(),
		"Msg":        r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err"),
	})
}

func (s *Server) pruneNow(w http.ResponseWriter, r *http.Request) {
	n, err := s.a.PruneMetrics()
	if err != nil {
		http.Redirect(w, r, "/settings?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "metrics_prune", fmt.Sprintf("removed %d", n))
	http.Redirect(w, r, "/settings?msg="+urlq(fmt.Sprintf("pruned %d samples", n)), http.StatusSeeOther)
}

func (s *Server) gitExportNow(w http.ResponseWriter, r *http.Request) {
	res, err := s.a.GitExport()
	if err != nil {
		http.Redirect(w, r, "/settings?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "git_export", res)
	http.Redirect(w, r, "/settings?msg="+urlq("git: "+res), http.StatusSeeOther)
}

func (s *Server) settingsTestNotify(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	get := func(k string) string {
		v := strings.TrimSpace(r.FormValue(k))
		if v == "" {
			v = s.a.Setting(k)
		}
		return v
	}
	smtp := s.a.SmtpFromForm(get("smtp_host"), get("smtp_port"), get("smtp_user"),
		strings.TrimSpace(r.FormValue("smtp_pass")), get("smtp_from"), get("smtp_to"))
	msg, err := s.a.TestNotify(get("tg_token"), get("tg_chat"), smtp)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "settings_test_notify", msg)
	if err != nil {
		q := err.Error()
		if msg != "" {
			q = msg + " — " + q
		}
		http.Redirect(w, r, "/settings?err="+urlq(q), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/settings?msg="+urlq(i18n.T(langOf(r), "set.test_sent")+" ("+msg+")"), http.StatusSeeOther)
}

func (s *Server) settingsSave(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	set := func(k, v string) { _ = s.a.Store.SetSetting(k, v) }
	set("backup_mode", r.FormValue("backup_mode"))
	set("backup_deliver", strings.Join(r.Form["deliver"], ","))
	for _, k := range []string{"backup_folder", "tg_token", "tg_chat", "smtp_host", "smtp_port", "smtp_user", "smtp_from", "smtp_to", "git_dir", "git_remote", "git_branch", "metrics_retention_days", "alert_cpu", "alert_temp", "alert_mem"} {
		set(k, strings.TrimSpace(r.FormValue(k)))
	}
	if r.FormValue("git_enabled") == "on" {
		set("git_enabled", "on")
	} else {
		set("git_enabled", "")
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

func (s *Server) deviceSNMPSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	port, _ := strconv.Atoi(r.FormValue("snmp_port"))
	if err := s.a.SaveSNMP(id, r.FormValue("snmp_enabled") == "on", r.FormValue("snmp_community"), port); err != nil {
		http.Redirect(w, r, "/devices/"+r.PathValue("id")+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/devices/"+r.PathValue("id")+"?msg=snmp-saved", http.StatusSeeOther)
}

func (s *Server) deviceSNMPPoll(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	dst := "/devices/" + r.PathValue("id")
	if err := s.a.SNMPPollDevice(d); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, dst+"?msg=snmp-polled", http.StatusSeeOther)
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
	const cw, ch, gap, lbl, pad, perRow = 44, 38, 10, 16, 12, 16
	cols := perRow
	if len(ph) < cols {
		cols = len(ph)
	}
	rows := (len(ph) + perRow - 1) / perRow
	W := cols*(cw+gap) - gap + 2*pad
	H := rows*(ch+gap+lbl) - gap + 2*pad
	var b strings.Builder
	// A fixed display size keeps a 2-port panel from being tiny and a 24-port
	// panel from being huge; the SVG scales within these bounds.
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" width="100%%" preserveAspectRatio="xMinYMid meet" style="width:100%%;max-width:%dpx;height:%dpx;max-height:%dpx">`,
		W, H, int(float64(W)*1.2)+40, H, 150)
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="9" fill="var(--bg)" stroke="var(--line)"/>`, W-1, H-1)
	for i, p := range ph {
		c, r := i%perRow, i/perRow
		x := pad + c*(cw+gap)
		y := pad + r*(ch+gap+lbl)
		color, led := "var(--muted)", ""
		if p.Disabled {
			color = "var(--line)"
		} else if p.Running {
			color = "var(--good)"
			led = fmt.Sprintf(`<circle cx="%d" cy="%d" r="3" fill="#22c55e"/>`, x+cw-8, y+8)
		}
		title := template.HTMLEscapeString(p.Name + " (" + p.Type + ")")
		isFiber := strings.Contains(p.Type, "sfp") || strings.Contains(p.Type, "qsfp")
		b.WriteString(`<g><title>` + title + `</title>`)
		// Port body with a subtle bevel and a connector notch/slot on top.
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="5" fill="%s" opacity="0.92" stroke="#0004"/>`, x, y, cw, ch, color)
		fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="#0003"/>`, x+7, y+7, cw-14, ch-16)
		if isFiber {
			fmt.Fprintf(&b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--surface)" stroke-width="2"/>`, x+9, y+ch-10, x+cw-9, y+10)
		} else {
			fmt.Fprintf(&b, `<rect x="%d" y="%d" width="10" height="5" rx="1" fill="var(--surface)"/>`, x+cw/2-5, y+ch-8)
		}
		b.WriteString(led)
		b.WriteString(`</g>`)
		fmt.Fprintf(&b, `<text x="%d" y="%d" text-anchor="middle" font-size="10" fill="var(--muted)">%s</text>`,
			x+cw/2, y+ch+13, template.HTMLEscapeString(portLabel(p.Name)))
	}
	b.WriteString("</svg>")
	return template.HTML(b.String())
}

// graphSVG draws a line graph of series; maxFixed>0 pins the Y scale (e.g. 100 for %).
// downsample averages a series into at most n buckets (keeps it as-is when
// already short enough), so long windows render as small, legible graphs.
func downsample(series []float64, n int) []float64 {
	if n < 1 || len(series) <= n {
		return series
	}
	out := make([]float64, n)
	for i := 0; i < n; i++ {
		lo := i * len(series) / n
		hi := (i + 1) * len(series) / n
		if hi <= lo {
			hi = lo + 1
		}
		var sum float64
		for _, v := range series[lo:hi] {
			sum += v
		}
		out[i] = sum / float64(hi-lo)
	}
	return out
}

func seriesStat(series []float64) (min, avg, max float64) {
	if len(series) == 0 {
		return 0, 0, 0
	}
	min = series[0]
	max = series[0]
	var sum float64
	for _, v := range series {
		sum += v
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	return min, sum / float64(len(series)), max
}

var historyRanges = map[string]time.Duration{
	"6h": 6 * time.Hour, "24h": 24 * time.Hour, "7d": 7 * 24 * time.Hour, "30d": 30 * 24 * time.Hour,
}

func (s *Server) historyPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	rng := r.URL.Query().Get("range")
	dur, ok := historyRanges[rng]
	if !ok {
		rng, dur = "24h", 24*time.Hour
	}
	metrics, _ := s.a.Store.MetricsSince(id, time.Now().Add(-dur))
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
	const buckets = 200
	cpuMin, cpuAvg, cpuMax := seriesStat(cpu)
	ramMin, ramAvg, ramMax := seriesStat(ram)
	tMin, tAvg, tMax := seriesStat(temp)
	data := map[string]any{"Active": "devices", "D": d, "Range": rng,
		"Ranges":   []string{"6h", "24h", "7d", "30d"},
		"Samples":  len(metrics),
		"CPUGraph": graphSVG(downsample(cpu, buckets), 100, "var(--accent)"),
		"RAMGraph": graphSVG(downsample(ram, buckets), 100, "var(--warn)"),
		"TempGraph": graphSVG(downsample(temp, buckets), 0, "var(--bad)"), "HasTemp": len(temp) > 0,
		"CPUMin": cpuMin, "CPUAvg": cpuAvg, "CPUMax": cpuMax,
		"RAMMin": ramMin, "RAMAvg": ramAvg, "RAMMax": ramMax,
		"TMin": tMin, "TAvg": tAvg, "TMax": tMax,
	}
	if len(metrics) > 0 {
		data["From"] = metrics[0].TS
		data["To"] = metrics[len(metrics)-1].TS
	}
	s.render(w, r, "history", data)
}

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
		`<svg viewBox="0 0 %d %d" width="100%%" style="width:100%%;height:58px;display:block" preserveAspectRatio="none"><polyline fill="none" stroke="%s" stroke-width="1.8" points="%s"/></svg>`,
		w, h, color, pts.String()))
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
