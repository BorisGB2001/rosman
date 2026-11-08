package app

import (
	"regexp"
	"strings"
	"time"
)

// ConfigHit is one matching line within a device's stored config.
type ConfigHit struct {
	Line int
	Text string
}

// ConfigSearchResult holds the matches for one device.
type ConfigSearchResult struct {
	DeviceID int64
	Device   string
	IP       string
	TakenAt  time.Time
	Hits     []ConfigHit
	NoConfig bool
}

// ConfigSearch scans the latest stored export of every device for the query,
// either as a literal substring or a regular expression. It returns one result
// per device (NoConfig set when the device has no stored export); the caller
// decides how to present devices with zero hits.
func (a *App) ConfigSearch(query string, useRegex, caseSensitive bool) ([]ConfigSearchResult, error) {
	var re *regexp.Regexp
	if useRegex {
		pat := query
		if !caseSensitive {
			pat = "(?i)" + pat
		}
		r, err := regexp.Compile(pat)
		if err != nil {
			return nil, err
		}
		re = r
	}
	needle := query
	if !caseSensitive {
		needle = strings.ToLower(query)
	}
	devs, _ := a.Store.Devices()
	out := make([]ConfigSearchResult, 0, len(devs))
	for _, d := range devs {
		res := ConfigSearchResult{DeviceID: d.ID, Device: d.Name, IP: d.IP}
		cfg, err := a.Store.LatestConfig(d.ID, "export")
		if err != nil {
			res.NoConfig = true
			out = append(out, res)
			continue
		}
		res.TakenAt = cfg.TakenAt
		for i, line := range strings.Split(cfg.Content, "\n") {
			line = strings.TrimRight(line, "\r")
			var match bool
			switch {
			case re != nil:
				match = re.MatchString(line)
			case caseSensitive:
				match = strings.Contains(line, needle)
			default:
				match = strings.Contains(strings.ToLower(line), needle)
			}
			if match {
				res.Hits = append(res.Hits, ConfigHit{Line: i + 1, Text: line})
			}
		}
		out = append(out, res)
	}
	return out, nil
}
