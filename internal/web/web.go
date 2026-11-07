// Package web serves the rosman UI and API over HTTPS. Server-rendered HTML,
// session-cookie auth, minimal JS — deliberately light for weak hardware.
package web

import (
	"context"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strconv"
	"time"

	"rosman/internal/app"
	"rosman/internal/auth"
	"rosman/internal/model"
	"rosman/internal/store"
)

//go:embed templates/*.html
var tmplFS embed.FS

// Version is the product version shown in the UI and used for releases.
const Version = "0.1.0"

const cookieName = "rosman_session"

type Server struct {
	a    *app.App
	tmpl *template.Template
}

type ctxKey int

const userKey ctxKey = 1

func New(a *app.App) (*Server, error) {
	funcs := template.FuncMap{
		"mb":  func(b int64) string { return fmt.Sprintf("%.0f MB", float64(b)/1024/1024) },
		"ago": func(t *time.Time) string {
			if t == nil {
				return "never"
			}
			return time.Since(*t).Round(time.Second).String() + " ago"
		},
		"ts":       func(t time.Time) string { return t.Format("2006-01-02 15:04:05") },
		"canWrite": func(u model.User) bool { return roleRank(u.Role) >= roleRank(model.RoleOperator) },
		"date":     func(t *time.Time) string { if t == nil { return "—" }; return t.Format("2006-01-02") },
		"alertCount": func() int {
			al, _ := a.Store.ActiveAlerts()
			return len(al)
		},
		"version": func() string { return Version },
	}
	t, err := template.New("").Funcs(funcs).ParseFS(tmplFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{a: a, tmpl: t}, nil
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.loginForm)
	mux.HandleFunc("POST /login", s.loginSubmit)
	mux.HandleFunc("POST /logout", s.logout)
	mux.Handle("GET /{$}", s.authed(s.devices))
	mux.Handle("GET /devices/new", s.authed(s.requireRole(model.RoleOperator, s.newDeviceForm)))
	mux.Handle("POST /devices/new", s.authed(s.requireRole(model.RoleOperator, s.newDeviceSubmit)))
	mux.Handle("GET /devices/{id}", s.authed(s.deviceDetail))
	mux.Handle("POST /devices/{id}/poll", s.authed(s.requireRole(model.RoleOperator, s.devicePoll)))
	mux.Handle("POST /devices/{id}/backup", s.authed(s.requireRole(model.RoleOperator, s.deviceBackup)))
	mux.Handle("GET /configs/{id}", s.authed(s.configView))
	mux.Handle("GET /alerts", s.authed(s.alerts))
	mux.Handle("GET /audit", s.authed(s.auditPage))
	return mux
}

func (s *Server) render(w http.ResponseWriter, name string, data any) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := s.tmpl.ExecuteTemplate(w, name, data); err != nil {
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
	s.render(w, "login", map[string]any{"Err": r.URL.Query().Get("err")})
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
	type row struct {
		model.Device
		CPU    int
		Uptime string
	}
	rows := make([]row, 0, len(devs))
	for _, d := range devs {
		rr := row{Device: d}
		if h, err := s.a.Store.LatestHealth(d.ID); err == nil {
			rr.CPU, rr.Uptime = h.CPU, h.Uptime
		}
		rows = append(rows, rr)
	}
	s.render(w, "devices", map[string]any{"User": userFrom(r), "Devices": rows})
}

func (s *Server) newDeviceForm(w http.ResponseWriter, r *http.Request) {
	s.render(w, "new_device", map[string]any{"User": userFrom(r)})
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
		s.render(w, "new_device", map[string]any{"User": userFrom(r), "Err": err.Error(),
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
	s.render(w, "device", map[string]any{
		"User": userFrom(r), "D": d, "H": health, "Configs": cfgs,
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
	changed, err := s.a.BackupDevice(d)
	if err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	msg := "backup+unchanged"
	if changed {
		msg = "backup+stored+new+version"
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "backup", d.Name+" ("+msg+")")
	http.Redirect(w, r, dst+"?msg="+msg, http.StatusSeeOther)
}

func (s *Server) configView(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	c, err := s.a.Store.ConfigContent(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	s.render(w, "config", map[string]any{"User": userFrom(r), "C": c})
}

func (s *Server) alerts(w http.ResponseWriter, r *http.Request) {
	active, _ := s.a.Store.ActiveAlerts()
	all, _ := s.a.Store.AllAlerts(100)
	s.render(w, "alerts", map[string]any{"User": userFrom(r), "Active": active, "All": all})
}

func (s *Server) auditPage(w http.ResponseWriter, r *http.Request) {
	rows, _ := s.a.Store.RecentAudit(200)
	s.render(w, "audit", map[string]any{"User": userFrom(r), "Rows": rows})
}

func urlq(s string) string {
	// minimal query escaping for flash messages
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch r {
		case ' ':
			out = append(out, '+')
		case '&', '?', '#', '%', '"', '\'', '<', '>':
			// drop characters that would break the query string
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
