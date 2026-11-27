package app

import (
	"crypto/sha256"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"rosman/internal/model"
	"rosman/internal/netbox"
)

// NetBox mirroring: ROSMan → NetBox, one way. A device is matched to an
// existing NetBox device (by the stored link, serial, any of its IPs, then
// name) or created. On a device ROSMan created itself ("owned") it keeps all
// mirrored fields current; on a device that already existed it only fills
// empty fields and adds the "rosman" tag, so hand-made NetBox data is never
// overwritten. Nothing is ever deleted in NetBox.

var nbMu sync.Mutex

// NetBoxConfigured reports whether URL and token are set and sync is on.
func (a *App) NetBoxConfigured() bool {
	return a.setting("netbox_enabled") == "on" && a.setting("netbox_url") != "" && a.setting("netbox_token_enc") != ""
}

func (a *App) netboxClient() *netbox.Client {
	return netbox.New(a.setting("netbox_url"), a.settingDecrypt("netbox_token_enc"), a.setting("netbox_insecure") == "on")
}

// NetBoxCheck tests a URL/token pair (empty token = the stored one).
func (a *App) NetBoxCheck(u, token string, insecure bool) (string, error) {
	if strings.TrimSpace(token) == "" {
		token = a.settingDecrypt("netbox_token_enc")
	}
	if strings.TrimSpace(u) == "" || token == "" {
		return "", fmt.Errorf("NetBox URL and API token are required")
	}
	return netbox.New(u, token, insecure).Status()
}

// NBLink is a device's last NetBox sync state, for the device card.
type NBLink struct {
	ID    int64
	URL   string
	At    string
	Err   string
	Owned bool
}

// NetBoxLink returns what is known about a device's NetBox mirror.
func (a *App) NetBoxLink(devID int64) NBLink {
	var l NBLink
	l.ID, _ = strconv.ParseInt(a.setting(nbKey("dev", devID)), 10, 64)
	l.Owned = a.setting(nbKey("own", devID)) == "1"
	st := strings.SplitN(a.setting(nbKey("stat", devID)), "|", 3)
	if len(st) == 3 {
		l.At = st[1]
		if st[0] == "ok" {
			l.URL = st[2]
		} else {
			l.Err = st[2]
		}
	}
	return l
}

func nbKey(kind string, id int64) string { return fmt.Sprintf("nb_%s_%d", kind, id) }

func (a *App) nbStatus(id int64, err error, webURL string) {
	now := time.Now().Format("2006-01-02 15:04")
	if err != nil {
		_ = a.Store.SetSetting(nbKey("stat", id), "err|"+now+"|"+strings.ReplaceAll(err.Error(), "|", "/"))
		return
	}
	_ = a.Store.SetSetting(nbKey("stat", id), "ok|"+now+"|"+webURL)
}

// NetBoxSyncAsync mirrors one device in the background when NetBox is
// configured and the device's mirrored facts changed since the last sync.
func (a *App) NetBoxSyncAsync(id int64) {
	if !a.NetBoxConfigured() {
		return
	}
	go func() {
		d, err := a.Store.Device(id)
		if err != nil {
			return
		}
		if err := a.NetBoxSync(d, false); err != nil {
			log.Printf("netbox sync %s: %v", d.Name, err)
		}
	}()
}

// NetBoxSyncAll mirrors every device now (force), reporting progress in the
// status bar. Returns how many succeeded and failed.
func (a *App) NetBoxSyncAll() (ok, failed int) {
	devs, _ := a.Store.Devices()
	t := a.StartTask("netbox", "", len(devs))
	for _, d := range devs {
		err := a.NetBoxSync(d, true)
		t.Step(d.Name, err == nil)
		if err != nil {
			failed++
		} else {
			ok++
		}
	}
	var ferr error
	if failed > 0 {
		ferr = fmt.Errorf("%d failed", failed)
	}
	t.Finish(ferr)
	return
}

func (a *App) siteName(d model.Device) string {
	if d.SiteID == nil {
		return ""
	}
	sites, _ := a.Store.Sites()
	for _, s := range sites {
		if s.ID == *d.SiteID {
			return s.Name
		}
	}
	return ""
}

// NetBoxSync mirrors one device. Without force it does nothing when the
// mirrored facts are unchanged since the last successful sync.
func (a *App) NetBoxSync(d model.Device, force bool) (err error) {
	nbMu.Lock()
	defer nbMu.Unlock()
	if a.setting("netbox_url") == "" || a.setting("netbox_token_enc") == "" {
		return fmt.Errorf("NetBox is not configured")
	}
	site := a.siteName(d)
	addrs, _ := a.Store.DeviceAddrs(d.ID)
	fp := fmt.Sprintf("%s|%s|%s|%s|%s|%s|%s|%d", d.Name, d.Serial, d.Model, d.DeviceType, site, d.IP, fwFirstWord(d.ROSVersion), len(addrs))
	hash := fmt.Sprintf("%x", sha256.Sum256([]byte(fp)))[:16]
	if !force && a.setting(nbKey("hash", d.ID)) == hash && strings.HasPrefix(a.setting(nbKey("stat", d.ID)), "ok|") {
		return nil
	}
	webURL := ""
	defer func() {
		a.nbStatus(d.ID, err, webURL)
		if err == nil {
			_ = a.Store.SetSetting(nbKey("hash", d.ID), hash)
		}
	}()
	c := a.netboxClient()

	man, err := nbEnsure(c, "/dcim/manufacturers/", url.Values{"slug": {"mikrotik"}}, map[string]any{"name": "MikroTik", "slug": "mikrotik"})
	if err != nil {
		return err
	}
	dt, err := nbDeviceType(c, man, d.Model)
	if err != nil {
		return err
	}
	roleSlug, roleName := "router", "Router"
	switch d.DeviceType {
	case "switch":
		roleSlug, roleName = "switch", "Switch"
	case "ap":
		roleSlug, roleName = "access-point", "Access point"
	}
	role, err := nbEnsure(c, "/dcim/device-roles/", url.Values{"slug": {roleSlug}}, map[string]any{"name": roleName, "slug": roleSlug, "color": "2196f3"})
	if err != nil {
		return err
	}
	plat, err := nbPlatform(c, man, d.ROSVersion)
	if err != nil {
		return err
	}
	siteID, err := nbSite(c, site, a.setting("netbox_site"))
	if err != nil {
		return err
	}
	tag, err := nbEnsure(c, "/extras/tags/", url.Values{"slug": {"rosman"}}, map[string]any{"name": "ROSMan", "slug": "rosman", "color": "3b82f6"})
	if err != nil {
		return err
	}

	// find the NetBox device
	var dev netbox.Obj
	if id, _ := strconv.ParseInt(a.setting(nbKey("dev", d.ID)), 10, 64); id > 0 {
		if dev, err = c.Get("/dcim/devices/", id); err != nil {
			return err
		}
		if dev == nil { // deleted in NetBox: forget the link and ownership
			_ = a.Store.SetSetting(nbKey("own", d.ID), "")
		}
	}
	if dev == nil && d.Serial != "" {
		if dev, err = c.First("/dcim/devices/", url.Values{"serial": {d.Serial}}); err != nil {
			return err
		}
	}
	if dev == nil {
		ips := []string{d.IP}
		for _, ad := range addrs {
			ips = append(ips, ipOnly(ad.Address))
		}
		for _, ip := range ips {
			if ip == "" {
				continue
			}
			o, e := c.First("/ipam/ip-addresses/", url.Values{"address": {ip}})
			if e != nil {
				return e
			}
			if devID := assignedDevice(o); devID > 0 {
				if dev, err = c.Get("/dcim/devices/", devID); err != nil {
					return err
				}
				if dev != nil {
					break
				}
			}
		}
	}
	if dev == nil {
		if dev, err = c.First("/dcim/devices/", url.Values{"name__ie": {d.Name}}); err != nil {
			return err
		}
	}

	owned := a.setting(nbKey("own", d.ID)) == "1"
	desc := fmt.Sprintf("ROSMan #%d", d.ID)
	if dev == nil {
		body := map[string]any{"name": d.Name, "device_type": dt, "role": role, "site": siteID,
			"platform": plat, "serial": d.Serial, "status": "active", "description": desc, "tags": []int64{tag}}
		if dev, err = c.Create("/dcim/devices/", body); err != nil {
			return err
		}
		owned = true
		_ = a.Store.SetSetting(nbKey("own", d.ID), "1")
	} else {
		patch := map[string]any{}
		if owned {
			if dev.Str("name") != d.Name {
				patch["name"] = d.Name
			}
			if dev.Ref("device_type") != dt {
				patch["device_type"] = dt
			}
			if dev.Ref("role") != role {
				patch["role"] = role
			}
			if dev.Ref("site") != siteID {
				patch["site"] = siteID
			}
			if dev.Ref("platform") != plat {
				patch["platform"] = plat
			}
			if dev.Str("serial") != d.Serial && d.Serial != "" {
				patch["serial"] = d.Serial
			}
		} else {
			if dev.Str("serial") == "" && d.Serial != "" {
				patch["serial"] = d.Serial
			}
			if dev.Ref("platform") == 0 {
				patch["platform"] = plat
			}
		}
		if tags, has := tagIDs(dev, tag); !has {
			patch["tags"] = append(tags, tag)
		}
		if len(patch) > 0 {
			if dev, err = c.Patch("/dcim/devices/", dev.ID(), patch); err != nil {
				return err
			}
		}
	}
	_ = a.Store.SetSetting(nbKey("dev", d.ID), strconv.FormatInt(dev.ID(), 10))
	webURL = dev.WebURL()

	// management address → interface + IP + primary IPv4 (never steals an IP
	// that NetBox has on another device)
	if owned || dev.Ref("primary_ip4") == 0 {
		if err = nbPrimaryIP(c, dev, d, addrs, desc); err != nil {
			return err
		}
	}
	return nil
}

func nbEnsure(c *netbox.Client, path string, q url.Values, create map[string]any) (int64, error) {
	o, err := c.First(path, q)
	if err != nil {
		return 0, err
	}
	if o == nil {
		if o, err = c.Create(path, create); err != nil {
			return 0, err
		}
	}
	return o.ID(), nil
}

// nbDeviceType finds the device type of a model ("hAP ac² (RBD52G-5HacD2HnD)"
// matches RBD52G-5HacD2HnD) or creates one.
func nbDeviceType(c *netbox.Client, man int64, mdl string) (int64, error) {
	mdl = strings.TrimSpace(mdl)
	if mdl == "" {
		mdl = "RouterOS device"
	}
	list, err := c.List("/dcim/device-types/", url.Values{"manufacturer_id": {strconv.FormatInt(man, 10)}, "q": {mdl}})
	if err != nil {
		return 0, err
	}
	low := strings.ToLower(mdl)
	for _, o := range list {
		m, pn := strings.ToLower(o.Str("model")), strings.ToLower(o.Str("part_number"))
		if m == low || pn == low || strings.Contains(m, "("+low+")") {
			return o.ID(), nil
		}
	}
	o, err := c.Create("/dcim/device-types/", map[string]any{"manufacturer": man, "model": mdl,
		"slug": netbox.Slug("mikrotik-" + mdl), "part_number": mdl})
	if err != nil {
		return 0, err
	}
	return o.ID(), nil
}

// nbPlatform picks "routeros-<major>" (or any RouterOS platform) or creates it.
func nbPlatform(c *netbox.Client, man int64, ver string) (int64, error) {
	major := "7"
	if v := fwFirstWord(ver); v != "" {
		major = strings.SplitN(v, ".", 2)[0]
	}
	list, err := c.List("/dcim/platforms/", url.Values{"q": {"routeros"}})
	if err != nil {
		return 0, err
	}
	var other int64
	for _, o := range list {
		if o.Str("slug") == "routeros-"+major {
			return o.ID(), nil
		}
		if strings.HasPrefix(o.Str("slug"), "routeros") && other == 0 {
			other = o.ID()
		}
	}
	if other != 0 && major != "6" {
		return other, nil
	}
	o, err := c.Create("/dcim/platforms/", map[string]any{"name": "MikroTik RouterOS " + major,
		"slug": "routeros-" + major, "manufacturer": man})
	if err != nil {
		return 0, err
	}
	return o.ID(), nil
}

// nbSite maps the ROSMan location to a NetBox site by name or slug, falling
// back to the default site from Settings.
func nbSite(c *netbox.Client, name, def string) (int64, error) {
	for _, n := range []string{name, def} {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		for _, q := range []url.Values{{"name__ie": {n}}, {"slug": {n}}, {"slug": {netbox.Slug(n)}}} {
			o, err := c.First("/dcim/sites/", q)
			if err != nil {
				return 0, err
			}
			if o != nil {
				return o.ID(), nil
			}
		}
	}
	if name != "" {
		return 0, fmt.Errorf("в NetBox нет площадки «%s» и не задана площадка по умолчанию", name)
	}
	return 0, fmt.Errorf("у устройства нет локации, а в настройках NetBox не задана площадка по умолчанию")
}

func nbPrimaryIP(c *netbox.Client, dev netbox.Obj, d model.Device, addrs []model.NetAddr, desc string) error {
	cidr, ifname := d.IP+"/32", "mgmt"
	for _, ad := range addrs {
		if ipOnly(ad.Address) == d.IP {
			cidr, ifname = ad.Address, ad.Iface
			if !strings.Contains(cidr, "/") {
				cidr += "/32"
			}
			break
		}
	}
	devID := strconv.FormatInt(dev.ID(), 10)
	ip, err := c.First("/ipam/ip-addresses/", url.Values{"address": {d.IP}})
	if err != nil {
		return err
	}
	if ip != nil {
		if other := assignedDevice(ip); other > 0 && other != dev.ID() {
			return nil // the address belongs to another NetBox device — leave it
		}
	}
	ifc, err := c.First("/dcim/interfaces/", url.Values{"device_id": {devID}, "name": {ifname}})
	if err != nil {
		return err
	}
	if ifc == nil {
		if ifc, err = c.Create("/dcim/interfaces/", map[string]any{"device": dev.ID(), "name": ifname, "type": "other", "description": desc}); err != nil {
			return err
		}
	}
	if ip == nil {
		if ip, err = c.Create("/ipam/ip-addresses/", map[string]any{"address": cidr, "status": "active",
			"assigned_object_type": "dcim.interface", "assigned_object_id": ifc.ID(), "description": d.Name + " — " + desc}); err != nil {
			return err
		}
	} else if assignedDevice(ip) == 0 {
		if ip, err = c.Patch("/ipam/ip-addresses/", ip.ID(), map[string]any{"assigned_object_type": "dcim.interface", "assigned_object_id": ifc.ID()}); err != nil {
			return err
		}
	}
	if dev.Ref("primary_ip4") != ip.ID() {
		if _, err = c.Patch("/dcim/devices/", dev.ID(), map[string]any{"primary_ip4": ip.ID()}); err != nil {
			return err
		}
	}
	return nil
}

// assignedDevice returns the device id an IP address object is assigned to.
func assignedDevice(o netbox.Obj) int64 {
	if o == nil {
		return 0
	}
	ao, ok := o["assigned_object"].(map[string]any)
	if !ok {
		return 0
	}
	if dv, ok := ao["device"].(map[string]any); ok {
		return netbox.Obj(dv).ID()
	}
	return 0
}

func tagIDs(o netbox.Obj, want int64) ([]int64, bool) {
	var ids []int64
	has := false
	if l, ok := o["tags"].([]any); ok {
		for _, t := range l {
			if m, ok := t.(map[string]any); ok {
				id := netbox.Obj(m).ID()
				ids = append(ids, id)
				if id == want {
					has = true
				}
			}
		}
	}
	return ids, has
}

func ipOnly(a string) string {
	if i := strings.IndexByte(a, '/'); i >= 0 {
		return a[:i]
	}
	return a
}

func fwFirstWord(s string) string {
	if f := strings.Fields(s); len(f) > 0 {
		return f[0]
	}
	return ""
}
