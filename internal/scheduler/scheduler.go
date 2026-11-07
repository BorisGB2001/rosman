// Package scheduler runs periodic polls and backups with bounded concurrency.
package scheduler

import (
	"context"
	"log"
	"sync"
	"time"

	"rosman/internal/app"
)

const maxConcurrent = 8 // keep memory/CPU predictable on weak hardware

func Run(ctx context.Context, a *app.App) {
	pollT := time.NewTicker(a.Cfg.PollInterval)
	backupT := time.NewTicker(a.Cfg.BackupInterval)
	defer pollT.Stop()
	defer backupT.Stop()

	// An initial poll shortly after start so the UI is populated.
	go runPoll(a)

	for {
		select {
		case <-ctx.Done():
			return
		case <-pollT.C:
			runPoll(a)
		case <-backupT.C:
			runBackup(a)
		}
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

func runPoll(a *app.App) {
	eachDevice(a, func(id int64) {
		d, err := a.Store.Device(id)
		if err != nil {
			return
		}
		if err := a.PollDevice(d); err != nil {
			log.Printf("poll %s (%s): %v", d.Name, d.IP, err)
		}
		if d.SNMPEnabled {
			if err := a.SNMPPollDevice(d); err != nil {
				log.Printf("snmp %s (%s): %v", d.Name, d.IP, err)
			}
		}
	})
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
}
