package app

import (
	"regexp"
	"strings"
)

// ComplianceViolation is one rule a device fails.
type ComplianceViolation struct {
	Rule     string
	Severity string
}

// ComplianceRow is a device's compliance result.
type ComplianceRow struct {
	DeviceID   int64
	Device     string
	NoConfig   bool
	Violations []ComplianceViolation
}

// OK reports whether the device passed every rule.
func (r ComplianceRow) OK() bool { return !r.NoConfig && len(r.Violations) == 0 }

func ruleViolated(kind, pattern, content string) bool {
	switch kind {
	case "require":
		return !strings.Contains(content, pattern)
	case "forbid":
		return strings.Contains(content, pattern)
	case "require_re":
		re, err := regexp.Compile(pattern)
		return err == nil && !re.MatchString(content)
	case "forbid_re":
		re, err := regexp.Compile(pattern)
		return err == nil && re.MatchString(content)
	}
	return false
}

// ComplianceCheck evaluates every enabled rule against each device's latest
// stored /export. It reads no device — purely from the config history.
func (a *App) ComplianceCheck() ([]ComplianceRow, error) {
	rules, err := a.Store.ComplianceRules()
	if err != nil {
		return nil, err
	}
	devs, err := a.Store.Devices()
	if err != nil {
		return nil, err
	}
	var out []ComplianceRow
	for _, d := range devs {
		row := ComplianceRow{DeviceID: d.ID, Device: d.Name}
		cfg, cerr := a.Store.LatestConfig(d.ID, "export")
		if cerr != nil || strings.TrimSpace(cfg.Content) == "" {
			row.NoConfig = true
			out = append(out, row)
			continue
		}
		for _, rl := range rules {
			if !rl.Enabled {
				continue
			}
			if ruleViolated(rl.Kind, rl.Pattern, cfg.Content) {
				row.Violations = append(row.Violations, ComplianceViolation{Rule: rl.Name, Severity: rl.Severity})
			}
		}
		out = append(out, row)
	}
	return out, nil
}
