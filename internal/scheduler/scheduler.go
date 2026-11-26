// Package scheduler runs periodic polls and backups with bounded concurrency.
package scheduler

import (
	"context"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"rosman/internal/app"
	"rosman/internal/model"
)

const maxConcurrent = 8 // keep memory/CPU predictable on weak hardware

func Run(ctx context.Context, a *app.App) {
	// A short base tick drives due-based polling so per-device intervals (which
	// can be shorter than the global default) are honoured; the global interval
	// still applies to devices without an override.
	base := 30 * time.Second
	if a.Cfg.PollInterval < base {
		base = a.Cfg.PollInterval
	}
	pollT := time.NewTicker(base)
	// Backups are due-based too (per-device period, else the fleet-wide one),
	// so a short tick only finds the devices whose period has elapsed.
	backupT := time.NewTicker(5 * time.Minute)
	pruneT := time.NewTicker(24 * time.Hour)
	cronT := time.NewTicker(60 * time.Second)
	defer pollT.Stop()
	defer backupT.Stop()
	defer pruneT.Stop()
	defer cronT.Stop()

	lastPoll := map[int64]time.Time{}
	var lpMu sync.Mutex

	// Polls and backups run off the loop goroutine so a slow device (or a long
	// backup round) never delays cron jobs or the next tick; the busy flags
	// keep rounds from overlapping.
	var pollBusy, backupBusy atomic.Bool
	poll := func() {
		if !pollBusy.CompareAndSwap(false, true) {
			return
		}
		go func() { defer pollBusy.Store(false); runDuePoll(a, lastPoll, &lpMu) }()
	}
	lastTry := map[int64]time.Time{}
	backup := func() {
		if !backupBusy.CompareAndSwap(false, true) {
			return
		}
		go func() { defer backupBusy.Store(false); runBackup(a, lastTry) }()
	}

	poll()
	go runPrune(a)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollT.C:
			poll()
		case <-backupT.C:
			backup()
		case <-pruneT.C:
			runPrune(a)
		case <-cronT.C:
			a.RunDueCronJobs()
		}
	}
}

// runDuePoll polls only the devices whose per-device interval (or the global
// default when unset) has elapsed since their last poll.
func runDuePoll(a *app.App, lastPoll map[int64]time.Time, mu *sync.Mutex) {
	devs, err := a.Store.Devices()
	if err != nil {
		log.Printf("scheduler: list devices: %v", err)
		return
	}
	now := time.Now()
	var due []model.Device
	mu.Lock()
	for _, d := range devs {
		iv := a.Cfg.PollInterval
		if d.PollIntervalSec > 0 {
			iv = time.Duration(d.PollIntervalSec) * time.Second
		}
		if lp, ok := lastPoll[d.ID]; !ok || now.Sub(lp) >= iv {
			due = append(due, d)
			lastPoll[d.ID] = now
		}
	}
	mu.Unlock()
	if len(due) == 0 {
		return
	}
	t := a.StartTask("poll", "", len(due))
	defer t.Finish(nil)

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, d := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(d model.Device) {
			defer wg.Done()
			defer func() { <-sem }()
			t.Detail(d.Name)
			err := a.PollDevice(d)
			if err != nil {
				log.Printf("poll %s (%s): %v", d.Name, d.IP, err)
			}
			t.Step(d.Name, err == nil)
			if d.SNMPEnabled {
				if err := a.SNMPPollDevice(d); err != nil {
					log.Printf("snmp %s (%s): %v", d.Name, d.IP, err)
				}
			}
		}(d)
	}
	wg.Wait()
}

func runPrune(a *app.App) {
	if n, err := a.PruneMetrics(); err != nil {
		log.Printf("prune metrics: %v", err)
	} else if n > 0 {
		log.Printf("prune metrics: removed %d old samples (retention %dd)", n, a.MetricsRetentionDays())
	}
}

// runBackup backs up the devices whose backup period (their own, else the
// fleet-wide one) has elapsed since their last successful backup. lastTry
// remembers attempts so an unreachable device is retried once per hour rather
// than on every tick. It is only touched from the single backup goroutine.
func runBackup(a *app.App, lastTry map[int64]time.Time) {
	if !a.HasSSHKey() {
		return
	}
	devs, err := a.Store.Devices()
	if err != nil {
		log.Printf("scheduler: list devices: %v", err)
		return
	}
	now := time.Now()
	var due []model.Device
	for _, d := range devs {
		iv := a.BackupIntervalFor(d)
		if d.LastBackup != nil && now.Sub(*d.LastBackup) < iv {
			continue
		}
		retry := time.Hour
		if iv < retry {
			retry = iv
		}
		if lt, ok := lastTry[d.ID]; ok && now.Sub(lt) < retry {
			continue
		}
		lastTry[d.ID] = now
		due = append(due, d)
	}
	if len(due) == 0 {
		return
	}
	t := a.StartTask("backup", "", len(due))
	defer t.Finish(nil)
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, d := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(d model.Device) {
			defer wg.Done()
			defer func() { <-sem }()
			t.Detail(d.Name)
			changed, err := a.BackupDevice(d, "")
			if err != nil {
				log.Printf("backup %s (%s): %v", d.Name, d.IP, err)
			} else if changed {
				log.Printf("backup %s: new config version stored", d.Name)
			}
			t.Step(d.Name, err == nil)
		}(d)
	}
	wg.Wait()
	// Mirror the latest exports into the git repo, if enabled.
	a.GitExportIfEnabled()
}
