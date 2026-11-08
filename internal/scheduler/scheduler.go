// Package scheduler runs periodic polls and backups with bounded concurrency.
package scheduler

import (
	"context"
	"log"
	"sync"
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
	backupT := time.NewTicker(a.Cfg.BackupInterval)
	pruneT := time.NewTicker(24 * time.Hour)
	cronT := time.NewTicker(60 * time.Second)
	defer pollT.Stop()
	defer backupT.Stop()
	defer pruneT.Stop()
	defer cronT.Stop()

	lastPoll := map[int64]time.Time{}
	var lpMu sync.Mutex

	go runDuePoll(a, lastPoll, &lpMu)
	go runPrune(a)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollT.C:
			runDuePoll(a, lastPoll, &lpMu)
		case <-backupT.C:
			runBackup(a)
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

	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, d := range due {
		wg.Add(1)
		sem <- struct{}{}
		go func(d model.Device) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := a.PollDevice(d); err != nil {
				log.Printf("poll %s (%s): %v", d.Name, d.IP, err)
			}
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

func eachDevice(a *app.App, fn func(id int64)) {
	devs, err := a.Store.Devices()
	if err != nil {
		log.Printf("scheduler: list devices: %v", err)
		return
	}
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup
	for _, d := range devs {
		wg.Add(1)
		sem <- struct{}{}
		go func(id int64) {
			defer wg.Done()
			defer func() { <-sem }()
			fn(id)
		}(d.ID)
	}
	wg.Wait()
}


func runBackup(a *app.App) {
	if !a.HasSSHKey() {
		return
	}
	eachDevice(a, func(id int64) {
		d, err := a.Store.Device(id)
		if err != nil {
			return
		}
		changed, err := a.BackupDevice(d, "")
		if err != nil {
			log.Printf("backup %s (%s): %v", d.Name, d.IP, err)
			return
		}
		if changed {
			log.Printf("backup %s: new config version stored", d.Name)
		}
	})
	// Mirror the latest exports into the git repo, if enabled.
	a.GitExportIfEnabled()
}
