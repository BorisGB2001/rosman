package app

import (
	"context"
	"fmt"
	"log"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"rosman/internal/model"
	"rosman/internal/ros"
)

// ROSMan as a syslog collector: devices are pointed at it (see
// ConfigureSyslog), the UDP listener below accepts their messages — only from
// addresses that belong to known devices — and stores them for the log page.

const (
	syslogDefaultPort = 5514 // unprivileged, so it also works when not root
	syslogDefaultDays = 14
	syslogMaxRows     = 1_000_000
	syslogDefTopics   = "info,warning,error,critical"
)

type syslogState struct {
	mu       sync.Mutex
	conn     net.PacketConn
	addr     string // what we listen on ("" = not listening)
	err      string // last bind error
	reload   chan struct{}
	ipToDev  map[string]int64
	mapAt    time.Time
	unknown  map[string]*SyslogUnknown
	received int64
	dropped  int64
	queue    chan model.SyslogMsg
}

// SyslogUnknown is a sender that is not a known device address.
type SyslogUnknown struct {
	Addr  string
	Count int64
	Last  time.Time
	Host  string // hostname from the message, when present
}

// SyslogInfo is the collector status shown in the UI.
type SyslogInfo struct {
	Enabled  bool
	Port     int
	Listen   string
	Err      string
	Received int64
	Dropped  int64
	Stored   int64
	Days     int
	Topics   string
	Host     string
	Unknown  []SyslogUnknown
}

var slog = &syslogState{reload: make(chan struct{}, 1), unknown: map[string]*SyslogUnknown{}, queue: make(chan model.SyslogMsg, 8192)}

// SyslogEnabled reports whether the collector is switched on (default: on).
func (a *App) SyslogEnabled() bool { return a.setting("syslog_enabled") != "off" }

// SyslogPort is the UDP port the collector listens on.
func (a *App) SyslogPort() int {
	if n, _ := strconv.Atoi(a.setting("syslog_port")); n > 0 && n < 65536 {
		return n
	}
	return syslogDefaultPort
}

// SyslogDays is how long received messages are kept.
func (a *App) SyslogDays() int {
	if n, _ := strconv.Atoi(a.setting("syslog_days")); n > 0 {
		return n
	}
	return syslogDefaultDays
}

// SyslogTopics is the list of RouterOS log topics devices are told to send.
func (a *App) SyslogTopics() []string {
	raw := a.setting("syslog_topics")
	if strings.TrimSpace(raw) == "" {
		raw = syslogDefTopics
	}
	return NormalizeTopics(raw)
}

var topicRe = regexp.MustCompile(`^!?[a-z0-9-]+(,!?[a-z0-9-]+)*$`)

// NormalizeTopics splits a list of RouterOS logging topics. Entries are
// separated by spaces/semicolons/newlines; a comma inside an entry combines
// topics in one rule ("firewall,!debug"). A plain comma-separated list of
// single topics is accepted too.
func NormalizeTopics(raw string) []string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	sep := func(r rune) bool { return r == ' ' || r == ';' || r == '\n' || r == '\r' || r == '\t' }
	parts := strings.FieldsFunc(raw, sep)
	if len(parts) == 1 && !strings.Contains(raw, "!") {
		parts = strings.Split(raw, ",") // "info,warning,error" = three rules
	}
	seen := map[string]bool{}
	var out []string
	for _, p := range parts {
		p = strings.Trim(p, ",")
		if p == "" || seen[p] || !topicRe.MatchString(p) {
			continue
		}
		known := true // an unknown topic would make RouterOS reject the rule
		for _, t := range strings.Split(p, ",") {
			known = known && rosTopics[strings.TrimPrefix(t, "!")]
		}
		if !known {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// SyslogReload makes the listener re-read its settings (port / on-off).
func (a *App) SyslogReload() {
	select {
	case slog.reload <- struct{}{}:
	default:
	}
}

// SyslogStatus returns the collector status for the UI.
func (a *App) SyslogStatus() SyslogInfo {
	slog.mu.Lock()
	info := SyslogInfo{Listen: slog.addr, Err: slog.err, Received: slog.received, Dropped: slog.dropped}
	for _, u := range slog.unknown {
		info.Unknown = append(info.Unknown, *u)
	}
	slog.mu.Unlock()
	sort.Slice(info.Unknown, func(i, j int) bool { return info.Unknown[i].Last.After(info.Unknown[j].Last) })
	info.Enabled, info.Port, info.Days = a.SyslogEnabled(), a.SyslogPort(), a.SyslogDays()
	info.Topics = strings.Join(a.SyslogTopics(), " ")
	info.Host = a.setting("syslog_host")
	info.Stored, _ = a.Store.CountSyslog()
	return info
}

// RunSyslog runs the collector until ctx ends: the UDP listener (restarted on
// SyslogReload), the batching writer and the retention pruner.
func (a *App) RunSyslog(ctx context.Context) {
	go a.syslogWriter(ctx)
	for {
		var conn net.PacketConn
		if a.SyslogEnabled() {
			addr := fmt.Sprintf(":%d", a.SyslogPort())
			c, err := net.ListenPacket("udp", addr)
			slog.mu.Lock()
			if err != nil {
				slog.addr, slog.err = "", err.Error()
				log.Printf("syslog: listen %s: %v", addr, err)
			} else {
				slog.addr, slog.err, slog.conn = addr, "", c
				conn = c
				log.Printf("syslog: collecting on udp %s", addr)
			}
			slog.mu.Unlock()
		} else {
			slog.mu.Lock()
			slog.addr, slog.err = "", ""
			slog.mu.Unlock()
		}
		done := make(chan struct{})
		if conn != nil {
			go func() { defer close(done); a.syslogRead(conn) }()
		} else {
			close(done)
		}
		retry := time.NewTimer(time.Minute) // a failed bind is retried
		select {
		case <-ctx.Done():
		case <-slog.reload:
		case <-retry.C:
			if conn != nil {
				// Listening fine: nothing to retry, wait for a real event.
				select {
				case <-ctx.Done():
				case <-slog.reload:
				}
			}
		}
		retry.Stop()
		if conn != nil {
			conn.Close()
			<-done
		}
		if ctx.Err() != nil {
			return
		}
	}
}

func (a *App) syslogRead(conn net.PacketConn) {
	buf := make([]byte, 8192)
	for {
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return // closed
		}
		ip := ""
		if u, ok := from.(*net.UDPAddr); ok {
			ip = u.IP.String()
		}
		m, host := ParseSyslog(string(buf[:n]), time.Now())
		id := a.syslogDevice(ip)
		slog.mu.Lock()
		slog.received++
		if id == 0 {
			u := slog.unknown[ip]
			if u == nil {
				if len(slog.unknown) >= 50 { // bounded: forget the stalest
					var old string
					for k, v := range slog.unknown {
						if old == "" || v.Last.Before(slog.unknown[old].Last) {
							old = k
						}
					}
					delete(slog.unknown, old)
				}
				u = &SyslogUnknown{Addr: ip}
				slog.unknown[ip] = u
			}
			u.Count++
			u.Last = time.Now()
			if host != "" {
				u.Host = host
			}
			slog.mu.Unlock()
			continue
		}
		slog.mu.Unlock()
		m.DeviceID, m.Src = id, ip
		select {
		case slog.queue <- m:
		default: // writer cannot keep up: drop rather than block the socket
			slog.mu.Lock()
			slog.dropped++
			slog.mu.Unlock()
		}
	}
}

// syslogDevice maps a sender address to a device id (0 = unknown). The map is
// built from the management address of every device plus the addresses seen on
// its interfaces (skipping ones that several devices share) and refreshed
// every minute.
func (a *App) syslogDevice(ip string) int64 {
	slog.mu.Lock()
	fresh := slog.ipToDev != nil && time.Since(slog.mapAt) < time.Minute
	if fresh {
		id := slog.ipToDev[ip]
		slog.mu.Unlock()
		return id
	}
	slog.mu.Unlock()
	m := map[string]int64{}
	if all, err := a.Store.AllDeviceAddrs(); err == nil {
		for addr, ids := range all {
			uniq := map[int64]bool{}
			for _, id := range ids {
				uniq[id] = true
			}
			if len(uniq) == 1 {
				m[addr] = ids[0]
			}
		}
	}
	if devs, err := a.Store.Devices(); err == nil {
		for _, d := range devs {
			m[d.IP] = d.ID
			if p := net.ParseIP(d.IP); p == nil { // device added by name
				if addrs, err := net.LookupHost(d.IP); err == nil {
					for _, x := range addrs {
						m[x] = d.ID
					}
				}
			}
		}
	}
	slog.mu.Lock()
	slog.ipToDev, slog.mapAt = m, time.Now()
	id := m[ip]
	slog.mu.Unlock()
	return id
}

func (a *App) syslogWriter(ctx context.Context) {
	flush := time.NewTicker(time.Second)
	prune := time.NewTicker(30 * time.Minute)
	defer flush.Stop()
	defer prune.Stop()
	var batch []model.SyslogMsg
	write := func() {
		if len(batch) == 0 {
			return
		}
		if err := a.Store.AddSyslog(batch); err != nil {
			log.Printf("syslog: store %d messages: %v", len(batch), err)
		}
		batch = batch[:0]
	}
	doPrune := func() {
		if n, err := a.Store.PruneSyslog(time.Now().AddDate(0, 0, -a.SyslogDays()), syslogMaxRows); err != nil {
			log.Printf("syslog: prune: %v", err)
		} else if n > 0 {
			log.Printf("syslog: pruned %d old messages (retention %dd)", n, a.SyslogDays())
		}
	}
	doPrune()
	for {
		select {
		case <-ctx.Done():
			write()
			return
		case m := <-slog.queue:
			batch = append(batch, m)
			if len(batch) >= 500 {
				write()
			}
		case <-flush.C:
			write()
		case <-prune.C:
			doPrune()
		}
	}
}

var (
	priRe  = regexp.MustCompile(`^<(\d{1,3})>`)
	bsdRe  = regexp.MustCompile(`^[A-Z][a-z]{2} [ \d]\d \d\d:\d\d:\d\d `)
	isoRe  = regexp.MustCompile(`^(?:1 )?\d{4}-\d\d-\d\dT\S+ `)
	topTok = regexp.MustCompile(`^[a-z0-9!-]+(,[a-z0-9!-]+)*:?$`)
)

// rosTopics are RouterOS log topics; a leading token made only of these is the
// topic list of the message.
var rosTopics = func() map[string]bool {
	m := map[string]bool{}
	for _, t := range strings.Fields(`account amt async backup bfd bgp bridge calc caps capsman certificate critical
		ddns debug dhcp dns dot1x dude e-mail email error event evpn fetch firewall gps gsm health hotspot igmp-proxy
		info interface ipsec iscsi isdn isis kvm l2tp ldp lora lte manager mme mpls mqtt natpmp netwatch ntp ospf ovpn
		packet pim poe poe-out ppp pppoe pptp ptp queue radius radvd raw read rip route rpki rsvp script sertcp simulator
		smb snmp socksify ssh sstp state stp store system telephony tftp timer tr069-client update upnp ups vpls vrrp
		warning watchdog web-proxy wireguard wireless write zerotier container disk dhcpv6 ipv6 l3hw media netinstall
		port sfp switch tunnel user vxlan wifi`) {
		m[t] = true
	}
	return m
}()

// ParseSyslog decodes one syslog datagram. It understands RFC 3164 (what
// RouterOS sends with bsd-syslog=yes), RFC 5424 and RouterOS' default bare
// "<pri>topics message" form. now is used as the timestamp: device clocks are
// often wrong, and arrival order is what the operator wants to see.
func ParseSyslog(raw string, now time.Time) (m model.SyslogMsg, host string) {
	m.TS, m.Sev = now, 6
	s := strings.TrimRight(raw, "\r\n\x00 ")
	if g := priRe.FindStringSubmatch(s); g != nil {
		if p, err := strconv.Atoi(g[1]); err == nil {
			m.Sev = p & 7
		}
		s = s[len(g[0]):]
	}
	hasHost := false
	if loc := bsdRe.FindString(s); loc != "" {
		s, hasHost = s[len(loc):], true
	} else if loc := isoRe.FindString(s); loc != "" {
		s, hasHost = s[len(loc):], true
	}
	first := func() (tok, rest string) {
		tok, rest, _ = strings.Cut(s, " ")
		return
	}
	isTopics := func(tok string) bool {
		tok = strings.TrimSuffix(tok, ":")
		if tok == "" || !topTok.MatchString(tok) {
			return false
		}
		for _, t := range strings.Split(tok, ",") {
			if !rosTopics[strings.TrimPrefix(t, "!")] {
				return false
			}
		}
		return true
	}
	if hasHost {
		if tok, rest := first(); tok != "" && !isTopics(tok) {
			host, s = tok, rest
		}
	}
	if tok, rest := first(); isTopics(tok) {
		m.Topics, s = strings.TrimSuffix(tok, ":"), rest
	}
	// The topic list is more reliable than PRI for RouterOS (which sends one
	// fixed severity unless told otherwise).
	for _, t := range strings.Split(m.Topics, ",") {
		switch t {
		case "critical":
			m.Sev = min(m.Sev, 2)
		case "error":
			m.Sev = min(m.Sev, 3)
		case "warning":
			m.Sev = min(m.Sev, 4)
		}
	}
	if len(s) > 2000 {
		s = s[:2000]
	}
	m.Msg = strings.ToValidUTF8(strings.TrimSpace(s), "?")
	return m, host
}

// SyslogTarget is the address a device should send its log to: the one from
// settings, otherwise the local address ROSMan uses to reach that device.
func (a *App) SyslogTarget(d model.Device) (string, error) {
	if h := strings.TrimSpace(a.setting("syslog_host")); h != "" {
		if net.ParseIP(h) == nil {
			return "", fmt.Errorf("syslog address in settings is not an IP: %q", h)
		}
		return h, nil
	}
	c, err := net.Dial("udp", net.JoinHostPort(d.IP, "514"))
	if err != nil {
		return "", fmt.Errorf("cannot work out ROSMan's address for %s: %w", d.IP, err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).IP.String(), nil
}

// ConfigureSyslog points the device's log at ROSMan (on=true) or removes that
// again (on=false). Only the logging action named "rosman" and the rules that
// use it are touched; the device's other logging stays as it is.
func (a *App) ConfigureSyslog(d model.Device, on bool) (string, error) {
	pass, err := a.Box.Decrypt(d.APIPassEnc)
	if err != nil {
		return "", err
	}
	if !on {
		if err := ros.RemoveSyslog(d, pass, a.Cfg.APITimeout); err != nil {
			return "", err
		}
		return "", a.Store.SetDeviceSyslog(d.ID, "")
	}
	if !a.SyslogEnabled() {
		return "", fmt.Errorf("syslog collector is switched off (Settings → Syslog)")
	}
	if err := a.StorageCheck(d); err != nil {
		return "", err
	}
	host, err := a.SyslogTarget(d)
	if err != nil {
		return "", err
	}
	topics := a.SyslogTopics()
	if len(topics) == 0 {
		return "", fmt.Errorf("no log topics configured (Settings → Syslog)")
	}
	if err := ros.ConfigureSyslog(d, pass, host, a.SyslogPort(), topics, a.Cfg.APITimeout); err != nil {
		return "", err
	}
	target := fmt.Sprintf("%s:%d", host, a.SyslogPort())
	return target, a.Store.SetDeviceSyslog(d.ID, target)
}
