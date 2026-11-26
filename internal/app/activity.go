package app

import (
	"sort"
	"sync"
	"time"
)

// Activity is one long-running operation shown in the UI status bar, so the
// operator can tell "working" from "hung". It is in-memory only: a restart
// drops it, which is right — the work it described died with the process.
type Activity struct {
	ID       int64
	Kind     string // i18n key suffix: act.<kind>
	Subject  string // free text appended to the title (device name, IP, count…)
	Stage    string // optional i18n key suffix: act.stage.<stage>
	Detail   string // free text (current device, error…)
	Done     int
	Total    int // 0 = indeterminate
	Failed   int
	Started  time.Time
	Finished time.Time // zero while running
	Err      string
}

// Running reports whether the activity is still in progress.
func (t Activity) Running() bool { return t.Finished.IsZero() }

var (
	actMu   sync.Mutex
	actSeq  int64
	actList = map[int64]*Activity{}
)

// keepFinished is how long a finished activity stays visible in the status bar.
const keepFinished = 12 * time.Second

// Task is a handle used by the worker to report progress. All methods are safe
// for concurrent use and are no-ops on a nil handle, so callers can pass nil to
// mean "don't report".
type Task struct{ id int64 }

// StartTask registers a new activity. total==0 means the amount of work is not
// known (the bar shows an indeterminate animation).
func (a *App) StartTask(kind, subject string, total int) *Task {
	actMu.Lock()
	defer actMu.Unlock()
	actSeq++
	actList[actSeq] = &Activity{ID: actSeq, Kind: kind, Subject: subject, Total: total, Started: time.Now()}
	return &Task{id: actSeq}
}

func (t *Task) with(fn func(*Activity)) {
	if t == nil {
		return
	}
	actMu.Lock()
	defer actMu.Unlock()
	if x := actList[t.id]; x != nil {
		fn(x)
	}
}

// Stage sets the current named stage (translated in the UI) and free detail.
func (t *Task) Stage(stage, detail string) {
	t.with(func(x *Activity) { x.Stage, x.Detail = stage, detail })
}

// Detail sets the free-text detail (e.g. the device being processed).
func (t *Task) Detail(detail string) { t.with(func(x *Activity) { x.Detail = detail }) }

// Step marks one unit of work finished; ok=false counts it as failed.
func (t *Task) Step(detail string, ok bool) {
	t.with(func(x *Activity) {
		x.Done++
		if !ok {
			x.Failed++
		}
		if detail != "" {
			x.Detail = detail
		}
	})
}

// Advance moves a staged (non-counted) task to step n of its total.
func (t *Task) Advance(n int) { t.with(func(x *Activity) { x.Done = n }) }

// Finish ends the activity. A non-nil err is shown in the bar.
func (t *Task) Finish(err error) {
	t.with(func(x *Activity) {
		if !x.Finished.IsZero() {
			return
		}
		x.Finished = time.Now()
		if x.Total > 0 && err == nil && x.Done < x.Total && x.Failed == 0 {
			x.Done = x.Total
		}
		if err != nil {
			x.Err = err.Error()
		}
	})
}

// Activities returns running activities plus the ones that finished a moment
// ago (so a short task is still seen), oldest first. Stale entries are pruned.
func (a *App) Activities() []Activity {
	actMu.Lock()
	defer actMu.Unlock()
	now := time.Now()
	out := make([]Activity, 0, len(actList))
	for id, x := range actList {
		if !x.Finished.IsZero() && now.Sub(x.Finished) > keepFinished {
			delete(actList, id)
			continue
		}
		// A task that has reported nothing for a very long time is a leak
		// (its worker died); drop it rather than show it forever.
		if x.Finished.IsZero() && now.Sub(x.Started) > 6*time.Hour {
			delete(actList, id)
			continue
		}
		out = append(out, *x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}
