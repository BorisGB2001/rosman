package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"rosman/internal/notify"
)

// neighborIgnore hides (on=1) or shows again (on=0) a discovered neighbour on
// the devices page. The key is the neighbour's MAC, else its IP.
func (s *Server) neighborIgnore(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimSpace(r.FormValue("key"))
	on := r.FormValue("on") == "1"
	back := "/?allneigh=1"
	if key == "" {
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	if err := s.a.Store.SetNeighborIgnored(key, on); err != nil {
		http.Redirect(w, r, back+"&err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	msg := "neigh-shown"
	if on {
		msg = "neigh-ignored"
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "neighbor_ignore", fmt.Sprintf("%s on=%v", key, on))
	http.Redirect(w, r, "/?msg="+msg, http.StatusSeeOther)
}

// deviceExec runs one command on one device over SSH and returns the output as
// JSON. Used by the command box on the devices page; operators and admins only,
// every run is written to the audit log.
func (s *Server) deviceExec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	reply := func(code int, v map[string]any) {
		w.WriteHeader(code)
		_ = json.NewEncoder(w).Encode(v)
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		reply(http.StatusNotFound, map[string]any{"error": "device not found"})
		return
	}
	cmd := strings.TrimSpace(r.FormValue("command"))
	if cmd == "" {
		reply(http.StatusBadRequest, map[string]any{"error": "empty command"})
		return
	}
	if len(cmd) > 2000 {
		reply(http.StatusBadRequest, map[string]any{"error": "command too long"})
		return
	}
	actor := userFrom(r).Username
	_ = s.a.Store.AddAudit(actor, "device_exec", d.Name+": "+cmd)
	t := s.a.StartTask("exec", d.Name, 0)
	out, runErr := s.a.RunCommand(d, cmd, 0)
	t.Finish(runErr)
	if len(out) > 200<<10 {
		out = out[:200<<10] + "\n… (обрезано)"
	}
	res := map[string]any{"output": out}
	if runErr != nil {
		res["error"] = runErr.Error()
	}
	reply(http.StatusOK, res)
}

// deviceAlertPrefs saves a device's own temperature threshold (0 = use the
// global one) and the Telegram chats that receive its alerts.
func (s *Server) deviceAlertPrefs(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	dst := fmt.Sprintf("/devices/%d", id)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	tempStr := strings.TrimSpace(r.FormValue("temp_c"))
	temp := 0
	if tempStr != "" {
		temp, err = strconv.Atoi(tempStr)
		if err != nil || temp < 0 || temp > 150 {
			http.Redirect(w, r, dst+"?err="+urlq("temperature threshold must be 0…150 °C"), http.StatusSeeOther)
			return
		}
	}
	chats, bad := notify.ParseChats(r.FormValue("tg_chats"))
	if bad != "" {
		http.Redirect(w, r, dst+"?err="+urlq("invalid Telegram chat id: "+bad), http.StatusSeeOther)
		return
	}
	if err := s.a.Store.SetDeviceAlertPrefs(id, temp, strings.Join(chats, ",")); err != nil {
		http.Redirect(w, r, dst+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_alert_prefs", fmt.Sprintf("%s temp=%d chats=%d", d.Name, temp, len(chats)))
	http.Redirect(w, r, dst+"?msg=alerts-saved#alerts", http.StatusSeeOther)
}

// accountPrefs saves the signed-in user's own preferences (hint delay).
func (s *Server) accountPrefs(w http.ResponseWriter, r *http.Request) {
	u := userFrom(r)
	ms, err := strconv.Atoi(strings.TrimSpace(r.FormValue("tip_delay_ms")))
	if err != nil || ms < 0 || ms > 10000 {
		http.Redirect(w, r, "/account?err="+urlq("delay must be 0…10000 ms"), http.StatusSeeOther)
		return
	}
	if err := s.a.Store.SetUserTipDelay(u.ID, ms); err != nil {
		http.Redirect(w, r, "/account?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	http.Redirect(w, r, "/account?msg=prefs-saved", http.StatusSeeOther)
}
