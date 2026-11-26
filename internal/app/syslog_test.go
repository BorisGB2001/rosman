package app

import (
	"testing"
	"time"
)

func TestParseSyslog(t *testing.T) {
	now := time.Now()
	cases := []struct {
		raw, host, topics, msg string
		sev                    int
	}{
		{"<30>Nov 26 12:00:01 SW33-CRCP system,info,account user admin logged in from 10.6.0.19 via ssh", "SW33-CRCP", "system,info,account", "user admin logged in from 10.6.0.19 via ssh", 6},
		{"<134>system,error,critical login failure for user root from 1.2.3.4 via ssh", "", "system,error,critical", "login failure for user root from 1.2.3.4 via ssh", 2},
		{"<27>Nov  6 02:03:04 gw1 interface,warning ether1 link down", "gw1", "interface,warning", "ether1 link down", 3},
		{"<14>1 2026-11-26T12:00:00+03:00 r1 dhcp,info dhcp1 assigned 10.0.0.5", "r1", "dhcp,info", "dhcp1 assigned 10.0.0.5", 6},
		{"<30>Nov 26 12:00:01 Adler could not save configuration changes, not enough storage space available", "Adler", "", "could not save configuration changes, not enough storage space available", 6},
		{"<30>Nov 26 13:28:29 SW33-CRCP user audit logged in from 10.6.0.19 via ssh", "SW33-CRCP", "", "user audit logged in from 10.6.0.19 via ssh", 6},
		{"plain text without anything", "", "", "plain text without anything", 6},
	}
	for _, c := range cases {
		m, host := ParseSyslog(c.raw, now)
		if host != c.host || m.Topics != c.topics || m.Msg != c.msg || m.Sev != c.sev {
			t.Errorf("%q →\n host=%q topics=%q sev=%d msg=%q", c.raw, host, m.Topics, m.Sev, m.Msg)
		}
	}
}

func TestNormalizeTopics(t *testing.T) {
	if g := NormalizeTopics("info,warning,error,critical"); len(g) != 4 {
		t.Errorf("comma list: %v", g)
	}
	if g := NormalizeTopics("info warning firewall,!debug"); len(g) != 3 || g[2] != "firewall,!debug" {
		t.Errorf("mixed: %v", g)
	}
	if g := NormalizeTopics("info; DROP TABLE x' \"q\""); len(g) != 1 || g[0] != "info" {
		t.Errorf("junk: %v", g)
	}
}
