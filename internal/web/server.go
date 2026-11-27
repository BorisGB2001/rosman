package web

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"

	"rosman/internal/model"
	"rosman/internal/sysinfo"
)

// fileSize returns a file's size in bytes, or 0 when it does not exist.
func fileSize(p string) int64 {
	st, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return st.Size()
}

// humanBytes formats a byte count for the UI ("812 KB", "1.4 GB").
func humanBytes(n uint64) string {
	const k = 1024
	switch {
	case n == 0:
		return "0 B"
	case n < k:
		return fmt.Sprintf("%d B", n)
	case n < k*k:
		return fmt.Sprintf("%.0f KB", float64(n)/k)
	case n < k*k*k:
		return fmt.Sprintf("%.1f MB", float64(n)/k/k)
	default:
		return fmt.Sprintf("%.2f GB", float64(n)/k/k/k)
	}
}

// serverPanel collects the numbers for the dashboard's "Server" row (the
// machine) and "ROSMan" row (what this program takes on that machine).
func (s *Server) serverPanel() map[string]any {
	dd := s.a.Cfg.DataDir
	host := sysinfo.ReadHost(dd)
	self := sysinfo.ReadSelf(dd)
	bkN, bkBytes, _ := s.a.Store.BackupTotals()
	logN, logBytes, _ := s.a.Store.SyslogSize()
	dbBytes := fileSize(s.a.Cfg.DBPath) + fileSize(s.a.Cfg.DBPath+"-wal") + fileSize(s.a.Cfg.DBPath+"-shm")
	return map[string]any{
		"Host": host, "Self": self,
		"BkN": bkN, "BkBytes": bkBytes,
		"LogN": logN, "LogBytes": logBytes,
		"DBBytes": dbBytes,
	}
}

// apModelPrefixes are MikroTik families that are wireless access points or
// CPEs rather than routers (hAP/hEX/RB stay routers).
var apModelPrefixes = []string{"CAP", "WAP", "MAP", "AUDIENCE", "GROOVE", "DISC", "LHG", "SXT", "QRT", "MANTBOX",
	"NETMETAL", "OMNITIK", "BASEBOX", "NETBOX", "METAL", "CUBE", "WIRELESS WIRE", "LDF", "DYNADISH", "CAPGI", "WAPGI"}

// nodeKind picks the topology symbol for a device: its type when set to
// switch or ap, otherwise a guess from the model name.
func nodeKind(d model.Device) string {
	switch d.DeviceType {
	case "switch", "ap":
		return d.DeviceType
	}
	m := strings.ToUpper(strings.TrimSpace(d.Model))
	for _, p := range apModelPrefixes {
		if strings.HasPrefix(m, p) {
			return "ap"
		}
	}
	if strings.HasPrefix(m, "CRS") || strings.HasPrefix(m, "CSS") || strings.Contains(m, "SWITCH") {
		return "switch"
	}
	return "router"
}

// hbytesAny is the template form of humanBytes: it takes any integer type
// (sizes come as int64 from SQL and uint64 from the OS).
func hbytesAny(v any) string {
	switch n := v.(type) {
	case int:
		return humanBytes(uint64(max(n, 0)))
	case int64:
		return humanBytes(uint64(max(n, 0)))
	case uint64:
		return humanBytes(n)
	case uint32:
		return humanBytes(uint64(n))
	}
	return "—"
}

// remoteIP is the client address without the port. ROSMan terminates TLS
// itself, so RemoteAddr is the real peer; proxy headers are not trusted.
func remoteIP(r *http.Request) string {
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return h
	}
	return r.RemoteAddr
}
