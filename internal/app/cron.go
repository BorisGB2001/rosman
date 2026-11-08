package app

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"rosman/internal/model"
)

// CronNext computes the next run time for a job after `from`.
func CronNext(j model.CronJob, from time.Time) time.Time {
	if j.Kind == "daily" {
		cand := time.Date(from.Year(), from.Month(), from.Day(), j.AtHour, j.AtMin, 0, 0, from.Location())
		if !cand.After(from) {
			cand = cand.Add(24 * time.Hour)
		}
		if j.Weekday >= 0 && j.Weekday <= 6 {
			for int(cand.Weekday()) != j.Weekday {
				cand = cand.Add(24 * time.Hour)
			}
		}
		return cand
	}
	// interval
	m := j.IntervalMin
	if m < 1 {
		m = 60
	}
	return from.Add(time.Duration(m) * time.Minute)
}

// cronTargets resolves a job's target spec to a device list.
func (a *App) cronTargets(target string) ([]model.Device, error) {
	devs, err := a.Store.Devices()
	if err != nil {
		return nil, err
	}
	switch {
	case target == "" || target == "all":
		return devs, nil
	case strings.HasPrefix(target, "site:"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(target, "site:"), 10, 64)
		var out []model.Device
		for _, d := range devs {
			if d.SiteID != nil && *d.SiteID == id {
				out = append(out, d)
			}
		}
		return out, nil
	case strings.HasPrefix(target, "tag:"):
		ids, _ := a.Store.DeviceIDsByTag(strings.TrimPrefix(target, "tag:"))
		var out []model.Device
		for _, d := range devs {
			if ids[d.ID] {
				out = append(out, d)
			}
		}
		return out, nil
	case strings.HasPrefix(target, "device:"):
		id, _ := strconv.ParseInt(strings.TrimPrefix(target, "device:"), 10, 64)
		if d, e := a.Store.Device(id); e == nil {
			return []model.Device{d}, nil
		}
		return nil, nil
	}
	return devs, nil
}

// RunCronJob executes a job now and returns a short status string.
func (a *App) RunCronJob(j model.CronJob) (string, error) {
	if j.Action == "gitexport" {
		return a.GitExport()
	}
	devs, err := a.cronTargets(j.Target)
	if err != nil {
		return "", err
	}
	var tpl model.Template
	if j.Action == "template" {
		if j.TemplateID == nil {
			return "", fmt.Errorf("no template set")
		}
		if tpl, err = a.Store.Template(*j.TemplateID); err != nil {
			return "", fmt.Errorf("template not found")
		}
	}
	if j.Action == "command" && strings.TrimSpace(j.Command) == "" {
		return "", fmt.Errorf("no command set")
	}
	ok, fail := 0, 0
	for _, d := range devs {
		var e error
		switch j.Action {
		case "poll":
			e = a.PollDevice(d)
		case "backup":
			_, e = a.BackupDevice(d, "")
		case "fwcheck":
			e = a.RefreshFirmware(d)
		case "template":
			e = a.ApplyTemplate(d, tpl.Body, j.Guard)
		case "command":
			_, e = a.RunCommand(d, j.Command, j.Guard)
		default:
			return "", fmt.Errorf("unknown action %q", j.Action)
		}
		if e != nil {
			fail++
		} else {
			ok++
		}
	}
	return fmt.Sprintf("%s: %d ok, %d failed", j.Action, ok, fail), nil
}

// RunDueCronJobs runs every enabled job whose next_run has passed, updating its
// schedule. Called periodically by the scheduler.
func (a *App) RunDueCronJobs() {
	jobs, err := a.Store.CronJobs()
	if err != nil {
		return
	}
	now := time.Now()
	for _, j := range jobs {
		if !j.Enabled {
			continue
		}
		if j.NextRun != nil && now.Before(*j.NextRun) {
			continue
		}
		status, err := a.RunCronJob(j)
		if err != nil {
			status = "error: " + err.Error()
		}
		_ = a.Store.UpdateCronRun(j.ID, now, status, CronNext(j, now))
		_ = a.Store.AddAudit("cron", "cron_run", j.Name+" — "+status)
	}
}
