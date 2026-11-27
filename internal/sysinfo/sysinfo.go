// Package sysinfo reads the host and process numbers the dashboard shows in
// its "Server" panel: CPU, memory, disk, temperature, uptime, and how much of
// all that ROSMan itself uses. Linux is the target; every probe degrades to
// "unknown" (zero values) where /proc or /sys is missing, so it also builds
// and runs on macOS during development.
package sysinfo

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// started is when this process came up (for "ROSMan uptime").
var started = time.Now()

// Host is a snapshot of the machine ROSMan runs on.
type Host struct {
	Hostname  string
	OS        string // PRETTY_NAME from /etc/os-release
	Kernel    string
	Hardware  string // DMI product name, when exposed
	CPUModel  string
	Cores     int
	Load1     float64
	CPUPct    int    // 1-minute load relative to cores, capped at 100
	MemTotal  uint64 // bytes
	MemUsed   uint64 // bytes (total - MemAvailable)
	DiskTotal uint64 // bytes of the filesystem that holds the data dir
	DiskUsed  uint64
	TempC     float64 // hottest thermal zone, 0 when not exposed
	Uptime    time.Duration
}

// Self is the ROSMan process's own footprint.
type Self struct {
	RSS        uint64 // resident memory, bytes (0 when unknown)
	HeapInUse  uint64 // Go heap in use, bytes
	Goroutines int
	Uptime     time.Duration
	DataDir    uint64 // bytes of everything under the data dir
}

// ReadHost gathers the host numbers. dataDir is the directory whose
// filesystem is reported as "disk".
func ReadHost(dataDir string) Host {
	var h Host
	h.Hostname, _ = os.Hostname()
	h.OS = osRelease()
	h.Kernel = readTrim("/proc/sys/kernel/osrelease")
	h.Hardware = readTrim("/sys/class/dmi/id/product_name")
	h.Cores = runtime.NumCPU()
	h.CPUModel = cpuModel()
	if s := readTrim("/proc/loadavg"); s != "" {
		if f := strings.Fields(s); len(f) > 0 {
			h.Load1, _ = strconv.ParseFloat(f[0], 64)
		}
	}
	if h.Cores > 0 {
		h.CPUPct = int(h.Load1 / float64(h.Cores) * 100)
		if h.CPUPct > 100 {
			h.CPUPct = 100
		}
	}
	h.MemTotal, h.MemUsed = memory()
	if st, ok := fsStat(dataDir); ok {
		h.DiskTotal = st.total
		h.DiskUsed = st.total - st.free
	}
	h.TempC = hottestZone()
	if s := readTrim("/proc/uptime"); s != "" {
		if f := strings.Fields(s); len(f) > 0 {
			if sec, err := strconv.ParseFloat(f[0], 64); err == nil {
				h.Uptime = time.Duration(sec * float64(time.Second))
			}
		}
	}
	return h
}

// ReadSelf gathers ROSMan's own numbers.
func ReadSelf(dataDir string) Self {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	s := Self{HeapInUse: m.HeapInuse, Goroutines: runtime.NumGoroutine(), Uptime: time.Since(started)}
	s.RSS = rssBytes()
	s.DataDir = dirSize(dataDir)
	return s
}

type fsInfo struct{ total, free uint64 }

func fsStat(path string) (fsInfo, bool) {
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		return fsInfo{}, false
	}
	bs := uint64(st.Bsize)
	return fsInfo{total: st.Blocks * bs, free: st.Bavail * bs}, true
}

func osRelease() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "PRETTY_NAME="); ok {
			return strings.Trim(v, `"`)
		}
	}
	return ""
}

func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") || strings.HasPrefix(line, "Hardware") || strings.HasPrefix(line, "cpu model") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return ""
}

// memory returns total and used bytes from /proc/meminfo (used = total − MemAvailable).
func memory() (total, used uint64) {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	defer f.Close()
	var avail uint64
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		kb, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			total = kb * 1024
		case "MemAvailable:":
			avail = kb * 1024
		}
	}
	if total > avail {
		used = total - avail
	}
	return total, used
}

// rssBytes reads VmRSS from /proc/self/status.
func rssBytes() uint64 {
	f, err := os.Open("/proc/self/status")
	if err != nil {
		return 0
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if v, ok := strings.CutPrefix(sc.Text(), "VmRSS:"); ok {
			kb, _ := strconv.ParseUint(strings.Fields(v)[0], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// hottestZone returns the highest reading across /sys/class/thermal, in °C.
func hottestZone() float64 {
	zones, _ := filepath.Glob("/sys/class/thermal/thermal_zone*/temp")
	var max float64
	for _, z := range zones {
		v, err := strconv.ParseFloat(readTrim(z), 64)
		if err != nil {
			continue
		}
		if c := v / 1000; c > max {
			max = c
		}
	}
	return max
}

// dirSize sums regular files under dir (best effort; errors are skipped).
func dirSize(dir string) uint64 {
	var n uint64
	_ = filepath.Walk(dir, func(_ string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() {
			n += uint64(info.Size())
		}
		return nil
	})
	return n
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}
