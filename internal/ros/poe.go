package ros

import (
	"strings"

	"github.com/go-routeros/routeros/v3"
)

// pollPoE marks the ports that have PoE-out (/interface/ethernet/poe) with
// their mode and, when available, the live status and power drawn.
// Devices without PoE answer with an error or nothing — then nothing changes.
func pollPoE(c *routeros.Client, h *Health) {
	r, err := c.Run("/interface/ethernet/poe/print")
	if err != nil || len(r.Re) == 0 {
		return
	}
	mode := map[string]string{}
	var names []string
	for _, re := range r.Re {
		n := re.Map["name"]
		if n == "" {
			continue
		}
		m := re.Map["poe-out"]
		if m == "" {
			m = "auto-on"
		}
		mode[n] = m
		names = append(names, n)
	}
	status, power := map[string]string{}, map[string]string{}
	if mr, err := c.Run("/interface/ethernet/poe/monitor", "=numbers="+strings.Join(names, ","), "=once="); err == nil {
		for _, re := range mr.Re {
			n := re.Map["name"]
			status[n] = re.Map["poe-out-status"]
			power[n] = strings.TrimSuffix(re.Map["poe-out-power"], "W")
		}
	}
	for i := range h.Ports {
		if m, ok := mode[h.Ports[i].Name]; ok {
			h.Ports[i].PoE = m
			h.Ports[i].PoEStatus = status[h.Ports[i].Name]
			h.Ports[i].PoEPower = power[h.Ports[i].Name]
		}
	}
}
