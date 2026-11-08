package app

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// UpdateStatus is the cached result of comparing the running version with the
// latest GitHub release.
type UpdateStatus struct {
	Current  string
	Latest   string
	Outdated bool
	Checked  time.Time
}

var (
	updMu    sync.Mutex
	updCache UpdateStatus
)

// githubRepo is the repository whose releases are checked.
const githubRepo = "BorisGB2001/rosman"

// UpdateInfo returns the cached update status for the given running version,
// triggering a background refresh when the cache is stale. It never blocks on
// the network, so templates can call it safely.
func (a *App) UpdateInfo(current string) UpdateStatus {
	updMu.Lock()
	c := updCache
	updMu.Unlock()
	if c.Current != current || time.Since(c.Checked) > 6*time.Hour {
		go a.RefreshUpdate(current)
	}
	if c.Current == "" {
		c.Current = current
	}
	return c
}

// RefreshUpdate fetches the latest release tag and updates the cache.
func (a *App) RefreshUpdate(current string) {
	latest := fetchLatestTag()
	st := UpdateStatus{Current: current, Latest: latest, Checked: time.Now()}
	if latest != "" {
		st.Outdated = verGreater(strings.TrimPrefix(latest, "v"), strings.TrimPrefix(current, "v"))
	}
	updMu.Lock()
	updCache = st
	updMu.Unlock()
}

func fetchLatestTag() string {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		"https://api.github.com/repos/"+githubRepo+"/releases/latest", nil)
	if err != nil {
		return ""
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "ROSMan")
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return ""
	}
	var body struct {
		TagName string `json:"tag_name"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return ""
	}
	return body.TagName
}

// verGreater reports whether dotted-numeric version a is newer than b.
func verGreater(a, b string) bool {
	pa, pb := verParts(a), verParts(b)
	n := len(pa)
	if len(pb) > n {
		n = len(pb)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(pa) {
			x = pa[i]
		}
		if i < len(pb) {
			y = pb[i]
		}
		if x != y {
			return x > y
		}
	}
	return false
}

func verParts(s string) []int {
	fs := strings.Split(s, ".")
	out := make([]int, 0, len(fs))
	for _, f := range fs {
		num := ""
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			num += string(r)
		}
		n, _ := strconv.Atoi(num)
		out = append(out, n)
	}
	return out
}
