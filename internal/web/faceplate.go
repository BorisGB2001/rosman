package web

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"

	"rosman/internal/i18n"
	"rosman/internal/model"
)

// portKind classifies an interface for the front panel: which group it is
// drawn in and which glyph it gets. "" means "not shown" (bridges, VLANs,
// loopbacks and other purely logical interfaces).
func portKind(p model.Port) string {
	n, t := strings.ToLower(p.Name), strings.ToLower(p.Type)
	switch {
	case strings.Contains(n, "qsfp") || strings.Contains(t, "qsfp"):
		return "qsfp"
	case strings.Contains(n, "sfpplus") || strings.Contains(n, "sfp28") || strings.Contains(n, "sfp+"):
		return "sfpp"
	case strings.Contains(n, "sfp") || strings.Contains(t, "sfp"):
		return "sfp"
	case t == "wlan" || strings.HasPrefix(t, "wifi") || t == "cap" || strings.HasPrefix(n, "wlan") || strings.HasPrefix(n, "wifi"):
		return "wlan"
	case t == "lte" || strings.HasPrefix(n, "lte"):
		return "lte"
	case t == "ether":
		return "ether"
	}
	for _, k := range []string{"pppoe", "l2tp", "sstp", "ovpn", "pptp", "ppp-", "wg", "wireguard", "gre", "eoip", "ipip", "6to4", "vxlan", "zerotier", "ipsec"} {
		if strings.HasPrefix(t, k) || strings.Contains(t, k) {
			return "tun"
		}
	}
	return ""
}

// fpKinds is the order of the groups on the automatic panel.
var fpKinds = []string{"ether", "sfp", "sfpp", "qsfp", "wlan", "lte", "tun"}

func shortText(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// kindLabel is the short caption under a port tile on the automatic panel.
func kindLabel(kind, name string) string {
	switch kind {
	case "ether", "sfp", "sfpp", "qsfp":
		return portLabel(name)
	default:
		return shortText(name, 7)
	}
}

const (
	fpCW, fpCH, fpGap, fpLbl, fpPad = 44, 38, 10, 16, 12
)

// drawPort draws one port tile (body, connector glyph by kind, link LED) and
// its caption at the given top-left corner.
func drawPort(b *strings.Builder, x, y int, kind, color string, led bool, title, label string) {
	b.WriteString(`<g><title>` + template.HTMLEscapeString(title) + `</title>`)
	rx := 5
	if kind == "tun" {
		rx = 14
	}
	fmt.Fprintf(b, `<rect x="%d" y="%d" width="%d" height="%d" rx="%d" fill="%s" opacity="0.92" stroke="#0004"/>`, x, y, fpCW, fpCH, rx, color)
	cx, cy := x+fpCW/2, y+fpCH/2
	switch kind {
	case "sfp", "sfpp", "qsfp":
		fmt.Fprintf(b, `<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="#0003"/>`, x+7, y+7, fpCW-14, fpCH-16)
		fmt.Fprintf(b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--surface)" stroke-width="2"/>`, x+9, y+fpCH-10, x+fpCW-9, y+10)
	case "wlan":
		for i, r := range []int{5, 10, 15} {
			fmt.Fprintf(b, `<path d="M%d %d a%d %d 0 0 1 %d 0" fill="none" stroke="var(--surface)" stroke-width="2" stroke-linecap="round" opacity="%.1f"/>`,
				cx-r, cy+6-i, r, r, 2*r, 1.0-float64(i)*0.15)
		}
		fmt.Fprintf(b, `<circle cx="%d" cy="%d" r="2" fill="var(--surface)"/>`, cx, cy+8)
	case "lte":
		for i := 0; i < 4; i++ {
			h := 5 + i*4
			fmt.Fprintf(b, `<rect x="%d" y="%d" width="4" height="%d" rx="1" fill="var(--surface)"/>`, cx-11+i*6, cy+9-h, h)
		}
	case "tun":
		fmt.Fprintf(b, `<line x1="%d" y1="%d" x2="%d" y2="%d" stroke="var(--surface)" stroke-width="2" stroke-dasharray="3 3"/>`, cx-9, cy, cx+9, cy)
		fmt.Fprintf(b, `<circle cx="%d" cy="%d" r="4" fill="var(--surface)"/><circle cx="%d" cy="%d" r="4" fill="var(--surface)"/>`, cx-11, cy, cx+11, cy)
	default: // RJ45
		fmt.Fprintf(b, `<rect x="%d" y="%d" width="%d" height="%d" rx="3" fill="#0003"/>`, x+7, y+7, fpCW-14, fpCH-16)
		fmt.Fprintf(b, `<rect x="%d" y="%d" width="10" height="5" rx="1" fill="var(--surface)"/>`, cx-5, y+fpCH-8)
	}
	if led {
		fmt.Fprintf(b, `<circle cx="%d" cy="%d" r="3" fill="#22c55e"/>`, x+fpCW-8, y+8)
	}
	b.WriteString(`</g>`)
	fmt.Fprintf(b, `<text x="%d" y="%d" text-anchor="middle" font-size="10" fill="var(--muted)">%s</text>`,
		cx, y+fpCH+13, template.HTMLEscapeString(label))
}

func portColor(p model.Port) (color string, led bool) {
	switch {
	case p.Disabled:
		return "var(--line)", false
	case p.Running:
		return "var(--good)", true
	}
	return "var(--muted)", false
}

// facePlateSVG draws the automatic front panel: one framed block per interface
// type (Ethernet, SFP, SFP+, QSFP, wireless, LTE, VPN/tunnels), each port
// coloured by link state (green up, grey down, dim disabled).
func facePlateSVG(ports []model.Port, lang string) template.HTML {
	groups := map[string][]model.Port{}
	for _, p := range ports {
		if k := portKind(p); k != "" {
			groups[k] = append(groups[k], p)
		}
	}
	var b strings.Builder
	n := 0
	for _, k := range fpKinds {
		ps := groups[k]
		if len(ps) == 0 {
			continue
		}
		n++
		// Up to 16 ports in one row; bigger banks in two rows like a real
		// switch; tunnels wrap at 12.
		perRow := len(ps)
		switch {
		case k == "tun" && perRow > 12:
			perRow = 12
		case perRow > 64:
			perRow = 32
		case perRow > 16:
			perRow = (perRow + 1) / 2
		}
		rows := (len(ps) + perRow - 1) / perRow
		W := perRow*(fpCW+fpGap) - fpGap + 2*fpPad
		H := rows*(fpCH+fpGap+fpLbl) - fpGap + 2*fpPad
		up := 0
		for _, p := range ps {
			if p.Running && !p.Disabled {
				up++
			}
		}
		fmt.Fprintf(&b, `<div class="fpgroup"><div class="fptitle">%s <span>%d / %d</span></div>`,
			template.HTMLEscapeString(i18n.T(lang, "fp."+k)), up, len(ps))
		fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" style="width:%dpx;max-width:100%%;height:auto">`, W, H, W*85/100)
		fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="9" fill="var(--bg)" stroke="var(--line)"/>`, W-1, H-1)
		for i, p := range ps {
			color, led := portColor(p)
			drawPort(&b, fpPad+(i%perRow)*(fpCW+fpGap), fpPad+(i/perRow)*(fpCH+fpGap+fpLbl), k, color, led,
				p.Name+" ("+p.Type+")", kindLabel(k, p.Name))
		}
		b.WriteString(`</svg></div>`)
	}
	if n == 0 {
		return ""
	}
	return template.HTML(`<div class="fpgroups">` + b.String() + `</div>`)
}

// facePlateFromLayout renders the panel from a layout (a catalog model's
// template or a device's own), overlaying live link status. A slot's label
// matches a real port by its full interface name ("wifi1", "ether5") or by its
// short panel label ("5", "S1", "W1"); a slot may carry its own display name.
// Returns "" when the layout is empty.
func facePlateFromLayout(layoutJSON string, ports []model.Port) template.HTML {
	pl, ok := parsePortLayout(layoutJSON)
	if !ok {
		return ""
	}
	byLabel := map[string]model.Port{}
	for _, p := range ports {
		if portKind(p) != "" {
			byLabel[strings.ToLower(portLabel(p.Name))] = p
		}
	}
	for _, p := range ports { // full names win over short labels
		byLabel[strings.ToLower(p.Name)] = p
	}
	groupColor := map[string]string{}
	for _, g := range pl.Groups {
		if g.Color != "" {
			groupColor[g.ID] = g.Color
		}
	}
	maxCols := 0
	for _, row := range pl.Rows {
		if len(row) > maxCols {
			maxCols = len(row)
		}
	}
	if maxCols == 0 {
		return ""
	}
	W := maxCols*(fpCW+fpGap) - fpGap + 2*fpPad
	H := len(pl.Rows)*(fpCH+fpGap+fpLbl) - fpGap + 2*fpPad
	var b strings.Builder
	fmt.Fprintf(&b, `<svg viewBox="0 0 %d %d" style="width:%dpx;max-width:100%%;height:auto">`, W, H, W*85/100)
	fmt.Fprintf(&b, `<rect x="0.5" y="0.5" width="%d" height="%d" rx="9" fill="var(--bg)" stroke="var(--line)"/>`, W-1, H-1)
	for r, row := range pl.Rows {
		for c, slot := range row {
			if slot.Gap || slot.Label == "" {
				continue
			}
			x := fpPad + c*(fpCW+fpGap)
			y := fpPad + r*(fpCH+fpGap+fpLbl)
			low := strings.ToLower(slot.Label)
			p, present := byLabel[low]
			// Group colour is the base; live status dims a disabled/absent port
			// and lights the LED on a running one.
			color, led := "var(--muted)", false
			if gc := groupColor[slot.Group]; gc != "" {
				color = gc
			}
			kind := "ether"
			switch {
			case present:
				kind = portKind(p)
				if kind == "" {
					kind = "ether"
				}
				if p.Disabled {
					color = "var(--line)"
				} else if p.Running {
					if groupColor[slot.Group] == "" {
						color = "var(--good)"
					}
					led = true
				}
			default:
				color = "var(--line)"
				switch {
				case strings.HasPrefix(low, "w"):
					kind = "wlan"
				case strings.HasPrefix(low, "s") || strings.HasPrefix(low, "q"):
					kind = "sfp"
				}
			}
			title := slot.Label
			if present {
				title = p.Name + " (" + p.Type + ")"
			}
			text := slot.Label
			if slot.Name != "" {
				text = slot.Name
				title += " — " + slot.Name
			}
			drawPort(&b, x, y, kind, color, led, title, shortText(text, 8))
		}
	}
	b.WriteString("</svg>")
	return template.HTML(b.String())
}

// realPortsJS lists a device's panel-worthy interfaces for the layout editor.
func realPortsJS(ports []model.Port) template.JS {
	type rp struct {
		Name  string `json:"name"`
		Short string `json:"short"`
		Kind  string `json:"kind"`
	}
	out := []rp{}
	for _, k := range fpKinds {
		for _, p := range ports {
			if portKind(p) == k {
				out = append(out, rp{p.Name, portLabel(p.Name), k})
			}
		}
	}
	bs, _ := json.Marshal(out)
	return template.JS(bs)
}

func layoutJS(s string) template.JS {
	s = strings.TrimSpace(s)
	if _, ok := parsePortLayout(s); !ok {
		s = "{}"
	}
	return template.JS(s)
}

// ---- per-device panel ----

// deviceLayoutPage opens the panel editor for ONE device: its own layout if it
// has one, with the model template and the device's real ports on hand.
func (s *Server) deviceLayoutPage(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	ports, _ := s.a.Store.DevicePorts(id)
	tpl := ""
	if cm, ok := s.a.Store.VendorModelByNorm(normModel(d.Model)); ok {
		tpl = cm.PortLayout
	}
	s.render(w, r, "vmodellayout", map[string]any{"Active": "devices",
		"Title": d.Name, "Sub": d.Model, "Back": fmt.Sprintf("/devices/%d", id), "Action": fmt.Sprintf("/devices/%d/layout", id),
		"IsDevice": true, "Layout": layoutJS(d.PortLayout), "TplLayout": layoutJS(tpl), "HasTpl": strings.TrimSpace(tpl) != "",
		"RealPorts": realPortsJS(ports), "HasOwn": strings.TrimSpace(d.PortLayout) != "",
		"Msg": r.URL.Query().Get("msg"), "Err": r.URL.Query().Get("err")})
}

func (s *Server) deviceLayoutSave(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	raw := strings.TrimSpace(r.FormValue("layout"))
	if raw == "" || raw == "{}" || r.FormValue("reset") == "1" {
		_ = s.a.Store.SetDevicePortLayout(id, "")
		_ = s.a.Store.AddAudit(userFrom(r).Username, "device_layout_clear", d.Name)
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=layout-reset", id), http.StatusSeeOther)
		return
	}
	if _, ok := parsePortLayout(raw); !ok || len(raw) > 256<<10 {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d/layout?err=%s", id, urlq("invalid layout")), http.StatusSeeOther)
		return
	}
	if err := s.a.Store.SetDevicePortLayout(id, raw); err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d/layout?err=%s", id, urlq(err.Error())), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "device_layout_save", d.Name)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=layout-saved", id), http.StatusSeeOther)
}

// ---- SSH repair ----

// deviceInstallKey authorises ROSMan's SSH key on the device through the API.
func (s *Server) deviceInstallKey(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	t := s.a.StartTask("ssh_key", d.Name, 0)
	err = s.a.InstallSSHKey(d)
	t.Finish(err)
	if err != nil {
		http.Redirect(w, r, fmt.Sprintf("/devices/%d?err=%s", id, urlq(err.Error())), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "ssh_key_install", d.Name)
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=ssh-key-installed", id), http.StatusSeeOther)
}

// deviceResetHostPin forgets the pinned SSH host key (the device regenerated
// it, e.g. after a RouterOS upgrade); the next SSH connection pins the new one.
func (s *Server) deviceResetHostPin(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	d, err := s.a.Store.Device(id)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	_ = s.a.Store.ClearSSHHostPin(id)
	_ = s.a.Store.AddAudit(userFrom(r).Username, "ssh_hostpin_reset", d.Name+" (was "+d.SSHHostPin+")")
	http.Redirect(w, r, fmt.Sprintf("/devices/%d?msg=hostpin-reset", id), http.StatusSeeOther)
}

// ---- catalog model photos (cover + extras) ----

func (s *Server) vendorModelImageUpload(w http.ResponseWriter, r *http.Request) {
	mid, _ := strconv.ParseInt(r.PathValue("mid"), 10, 64)
	m, err := s.a.Store.VendorModel(mid)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	back := fmt.Sprintf("/vendors/%d", m.VendorID)
	if err := r.ParseMultipartForm(64 << 20); err != nil {
		http.Redirect(w, r, back+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	files := r.MultipartForm.File["image"]
	if len(files) == 0 {
		http.Redirect(w, r, back+"?err="+urlq(i18n.T(langOf(r), "bk.no_file")), http.StatusSeeOther)
		return
	}
	hasCover := m.HasImage
	added := 0
	for _, hdr := range files {
		ct := hdr.Header.Get("Content-Type")
		if !imageTypeOK[ct] {
			http.Redirect(w, r, back+"?err="+urlq(i18n.T(langOf(r), "img.bad_type")), http.StatusSeeOther)
			return
		}
		f, err := hdr.Open()
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 16<<20))
		f.Close()
		if err != nil || len(data) == 0 {
			continue
		}
		// The first photo of a model is its cover; the rest are extras.
		if !hasCover {
			_ = s.a.Store.SetVendorModelImage(mid, ct, data)
			hasCover = true
		} else {
			_ = s.a.Store.AddVendorModelImage(mid, ct, data)
		}
		added++
	}
	http.Redirect(w, r, fmt.Sprintf("%s?msg=saved#m%d", back, mid), http.StatusSeeOther)
}

func (s *Server) vendorModelExtraImageServe(w http.ResponseWriter, r *http.Request) {
	mid, _ := strconv.ParseInt(r.PathValue("mid"), 10, 64)
	iid, _ := strconv.ParseInt(r.PathValue("iid"), 10, 64)
	ct, data, err := s.a.Store.VendorModelExtraImage(mid, iid)
	if err != nil || len(data) == 0 {
		http.Error(w, "not found", 404)
		return
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, max-age=86400")
	_, _ = w.Write(data)
}

// vendorModelImageDelete removes one photo: iid "cover" is the main one (the
// next extra, if any, is promoted), otherwise an extra photo's id.
func (s *Server) vendorModelImageDelete(w http.ResponseWriter, r *http.Request) {
	mid, _ := strconv.ParseInt(r.PathValue("mid"), 10, 64)
	m, err := s.a.Store.VendorModel(mid)
	if err != nil {
		http.Error(w, "not found", 404)
		return
	}
	if r.PathValue("iid") == "cover" {
		err = s.a.Store.DeleteVendorModelCover(mid)
	} else {
		iid, _ := strconv.ParseInt(r.PathValue("iid"), 10, 64)
		err = s.a.Store.DeleteVendorModelExtraImage(mid, iid)
	}
	back := fmt.Sprintf("/vendors/%d", m.VendorID)
	if err != nil {
		http.Redirect(w, r, back+"?err="+urlq(err.Error()), http.StatusSeeOther)
		return
	}
	_ = s.a.Store.AddAudit(userFrom(r).Username, "model_image_delete", fmt.Sprintf("model %d (%s)", mid, m.Name))
	http.Redirect(w, r, fmt.Sprintf("%s?msg=image-deleted#m%d", back, mid), http.StatusSeeOther)
}
