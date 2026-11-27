package app

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"rosman/internal/config"
	"rosman/internal/model"
	"rosman/internal/notify"
	"rosman/internal/secret"
	"rosman/internal/store"
)

// fakeNB is a tiny in-memory NetBox: collections of objects with the filters
// ROSMan uses.
type fakeNB struct {
	mu     sync.Mutex
	next   int
	col    map[string][]map[string]any // "/dcim/devices/" → objects
	writes int
}

func (f *fakeNB) add(path string, o map[string]any) map[string]any {
	f.next++
	o["id"] = float64(f.next)
	o["url"] = "http://nb/api" + path + strconv.Itoa(f.next) + "/"
	o["display_url"] = "http://nb" + path + strconv.Itoa(f.next) + "/"
	f.col[path] = append(f.col[path], o)
	return o
}

func ref(v any) any {
	if f, ok := v.(float64); ok {
		return map[string]any{"id": f}
	}
	return v
}

func (f *fakeNB) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := strings.TrimPrefix(r.URL.Path, "/api")
	if p == "/status/" {
		_ = json.NewEncoder(w).Encode(map[string]any{"netbox-version": "4.7.6"})
		return
	}
	// /path/<id>/ ?
	parts := strings.Split(strings.Trim(p, "/"), "/")
	var id int
	if n, err := strconv.Atoi(parts[len(parts)-1]); err == nil {
		id = n
		p = "/" + strings.Join(parts[:len(parts)-1], "/") + "/"
	}
	find := func() map[string]any {
		for _, o := range f.col[p] {
			if int(o["id"].(float64)) == id {
				return o
			}
		}
		return nil
	}
	switch {
	case r.Method == "GET" && id > 0:
		o := find()
		if o == nil {
			http.Error(w, "nf", 404)
			return
		}
		_ = json.NewEncoder(w).Encode(o)
	case r.Method == "GET":
		q := r.URL.Query()
		var res []map[string]any
		for _, o := range f.col[p] {
			ok := true
			for k, vs := range q {
				v := vs[0]
				switch k {
				case "limit":
				case "name__ie":
					ok = ok && strings.EqualFold(o["name"].(string), v)
				case "q":
					s := strings.ToLower(v)
					ok = ok && (strings.Contains(strings.ToLower(str(o["model"])), s) || strings.Contains(strings.ToLower(str(o["slug"])), s))
				case "address":
					ok = ok && strings.SplitN(str(o["address"]), "/", 2)[0] == v
				case "device_id":
					ok = ok && str(o["device"].(map[string]any)["id"]) == v
				case "manufacturer_id":
					ok = ok && str(o["manufacturer"].(map[string]any)["id"]) == v
				default:
					ok = ok && str(o[k]) == v
				}
			}
			if ok {
				res = append(res, o)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"count": len(res), "results": res})
	case r.Method == "POST", r.Method == "PATCH":
		f.writes++
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		for _, k := range []string{"device", "manufacturer", "site", "role", "device_type", "platform", "primary_ip4"} {
			if v, ok := body[k]; ok {
				body[k] = ref(v)
			}
		}
		if t, ok := body["tags"].([]any); ok {
			var tl []any
			for _, x := range t {
				tl = append(tl, map[string]any{"id": x})
			}
			body["tags"] = tl
		}
		if aid, ok := body["assigned_object_id"].(float64); ok {
			for _, ifc := range f.col["/dcim/interfaces/"] {
				if ifc["id"].(float64) == aid {
					body["assigned_object"] = map[string]any{"id": aid, "device": ifc["device"]}
				}
			}
		}
		var o map[string]any
		if r.Method == "POST" {
			o = f.add(p, body)
		} else {
			o = find()
			for k, v := range body {
				o[k] = v
			}
		}
		_ = json.NewEncoder(w).Encode(o)
	}
}

func str(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatInt(int64(x), 10)
	}
	return ""
}

func TestNetBoxSync(t *testing.T) {
	nb := &fakeNB{col: map[string][]map[string]any{}}
	nb.add("/dcim/sites/", map[string]any{"name": "CRCP", "slug": "ru-crcp"})
	man := nb.add("/dcim/manufacturers/", map[string]any{"name": "MikroTik", "slug": "mikrotik"})
	dtExisting := nb.add("/dcim/device-types/", map[string]any{"model": "CRS354-48P-4S+2Q+", "slug": "crs354", "manufacturer": map[string]any{"id": man["id"]}})
	// a hand-made device already in NetBox
	hand := nb.add("/dcim/devices/", map[string]any{"name": "SW33 (manual)", "serial": "D5630F4F347E", "comments": "hand notes",
		"site": map[string]any{"id": float64(1)}, "device_type": map[string]any{"id": dtExisting["id"]}})
	srv := httptest.NewServer(nb)
	defer srv.Close()

	st, err := store.Open(t.TempDir() + "/t.db")
	if err != nil {
		t.Fatal(err)
	}
	box, err := secret.Open(t.TempDir() + "/secret.key")
	if err != nil {
		t.Fatal(err)
	}
	a := &App{Store: st, Box: box, Notify: notify.New("", "", ""), Cfg: config.Config{}}
	enc, _ := box.Encrypt("tok")
	_ = st.SetSetting("netbox_url", srv.URL)
	_ = st.SetSetting("netbox_token_enc", enc)
	_ = st.SetSetting("netbox_enabled", "on")
	_ = st.SetSetting("netbox_site", "ru-crcp")

	// 1) existing device matched by serial: only tag (and platform) added, name kept
	id1, _ := st.CreateDevice(model.Device{Name: "SW33-CRCP", IP: "172.20.6.33"})
	_ = st.UpdateInventory(id1, "CRS354-48P-4S+2Q+", "D5630F4F347E", "7.25.1 (stable)", time.Now())
	d1, _ := st.Device(id1)
	if err := a.NetBoxSync(d1, true); err != nil {
		t.Fatal(err)
	}
	if hand["name"] != "SW33 (manual)" || hand["comments"] != "hand notes" {
		t.Fatalf("hand-made device overwritten: %v", hand)
	}
	if l := a.NetBoxLink(id1); l.ID != int64(hand["id"].(float64)) || l.Owned || l.URL == "" {
		t.Fatalf("link: %+v", l)
	}
	if len(nb.col["/dcim/devices/"]) != 1 {
		t.Fatal("duplicate device created")
	}

	// 2) new device: created with role, site, platform, interface, primary IP
	id2, _ := st.CreateDevice(model.Device{Name: "cap-hall", IP: "10.6.0.50"})
	_ = st.UpdateInventory(id2, "cAPGi-5HaxD2HaxD", "HKB0AJM3EYP", "7.20", time.Now())
	_ = st.SetDeviceType(id2, "ap")
	d2, _ := st.Device(id2)
	if err := a.NetBoxSync(d2, true); err != nil {
		t.Fatal(err)
	}
	if len(nb.col["/dcim/devices/"]) != 2 {
		t.Fatal("device not created")
	}
	dev := nb.col["/dcim/devices/"][1]
	if dev["name"] != "cap-hall" || dev["primary_ip4"] == nil {
		t.Fatalf("created device: %v", dev)
	}
	var apRole any
	for _, r := range nb.col["/dcim/device-roles/"] {
		if r["slug"] == "access-point" {
			apRole = r["id"]
		}
	}
	if apRole == nil || dev["role"].(map[string]any)["id"] != apRole {
		t.Fatalf("role %v (ap role %v)", dev["role"], apRole)
	}
	found := false
	for _, ip := range nb.col["/ipam/ip-addresses/"] {
		if ip["address"] == "10.6.0.50/32" && dev["primary_ip4"].(map[string]any)["id"] == ip["id"] {
			found = true
		}
	}
	if !found {
		t.Fatalf("primary ip not set: %v", nb.col["/ipam/ip-addresses/"])
	}

	// 3) unchanged device, not forced: no writes at all
	w := nb.writes
	d2, _ = st.Device(id2)
	if err := a.NetBoxSync(d2, false); err != nil {
		t.Fatal(err)
	}
	if nb.writes != w {
		t.Fatalf("unchanged sync wrote %d times", nb.writes-w)
	}
	// 4) a type change in ROSMan reaches the device ROSMan owns (role → router)
	_ = st.SetDeviceType(id2, "router")
	d2, _ = st.Device(id2)
	if err := a.NetBoxSync(d2, false); err != nil {
		t.Fatal(err)
	}
	var routerRole float64
	for _, r := range nb.col["/dcim/device-roles/"] {
		if r["slug"] == "router" {
			routerRole = r["id"].(float64)
		}
	}
	if dev["role"].(map[string]any)["id"] != routerRole {
		t.Fatalf("role change not mirrored: %v", dev["role"])
	}
}
