package web

import (
	"reflect"
	"testing"
)

func TestPhysicalPort(t *testing.T) {
	cases := map[string]string{
		"ether1":              "ether1",
		"ether1,bridgeLan":    "ether1",
		"sfp-sfpplus1":        "sfp-sfpplus1",
		"bridgeLan,ether10":   "ether10",
		"vlan200":             "",
		"bridge-lan":          "",
		"vxlan100":            "",
		"":                    "",
		"wlan1":               "wlan1",
		"qsfpplus1":           "qsfpplus1",
		"combo1":              "combo1",
		"vlanMNG,bridge":      "",
	}
	for in, want := range cases {
		if got := physicalPort(in); got != want {
			t.Errorf("physicalPort(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestNormModel(t *testing.T) {
	cases := map[string]string{
		"RB4011iGS+":         "rb4011igs",
		"CRS328-24P-4S+":     "crs32824p4s",
		"CRS354-48P-4S+2Q+":  "crs35448p4s2q",
		"hAP ac^2":           "hapac2",
		"cAP ac":             "capac",
		"RBD53GR-5HacD2HnD":  "rbd53gr5hacd2hnd",
		"":                   "",
	}
	for in, want := range cases {
		if got := normModel(in); got != want {
			t.Errorf("normModel(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExpandVlanIDs(t *testing.T) {
	cases := []struct {
		in   string
		want []int
	}{
		{"200", []int{200}},
		{"10,20,30", []int{10, 20, 30}},
		{"10,20-23", []int{10, 20, 21, 22, 23}},
		{"5-5", []int{5}},
		{"  1 , 2 ", []int{1, 2}},
		{"", nil},
		{"abc", nil},
		{"30,10,20", []int{10, 20, 30}}, // sorted, deduped
		{"10,10", []int{10}},
	}
	for _, c := range cases {
		got := expandVlanIDs(c.in)
		if len(got) == 0 && len(c.want) == 0 {
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("expandVlanIDs(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestLooksLikeMAC(t *testing.T) {
	// RouterOS reports MACs colon-separated; dash and bare-hex also accepted.
	yes := []string{"00:11:32:B0:B3:ED", "00-11-32-b0-b3-ed", "001132b0b3ed"}
	no := []string{"10.6.0.1", "hostname", "00:11:32:B0:B3", "00:11:32:B0:B3:ED:FF", "0011.32b0.b3ed", ""}
	for _, s := range yes {
		if !looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = false, want true", s)
		}
	}
	for _, s := range no {
		if looksLikeMAC(s) {
			t.Errorf("looksLikeMAC(%q) = true, want false", s)
		}
	}
}

func TestMacFragment(t *testing.T) {
	cases := map[string]string{
		"b0b3":          "b0b3",          // bare hex run
		"00:11:32":      "001132",        // colon-separated partial
		"00-11-32-b0":   "001132b0",      // dash-separated partial
		"B0B3":          "b0b3",          // uppercase lowered
		"001132b0b3ed":  "",              // full 12-digit MAC — exact match handles it
		"10.77.9.1":     "",              // IP, not a MAC
		"host":          "",              // non-hex
		"ab":            "",              // too short (<4)
		"0011.32b0":     "",              // dotted — treated as IP-like, excluded
		"4c5e":          "4c5e",          // vendor-prefix fragment
		"":              "",              // empty
	}
	for in, want := range cases {
		if got := macFragment(in); got != want {
			t.Errorf("macFragment(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMacHex(t *testing.T) {
	cases := map[string]string{
		"C4:AD:34:74:E6:99": "c4ad3474e699", // full MAC → 12 hex, no length cap
		"74e6":              "74e6",
		"08-55-31":          "085531",
		"10.0.0.1":          "", // '.' is not a separator here → non-hex → ""
		"host":              "",
		"":                  "",
	}
	for in, want := range cases {
		if got := macHex(in); got != want {
			t.Errorf("macHex(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEthLess(t *testing.T) {
	// ether2 must sort before ether10 (numeric-aware).
	if !ethLess("ether2", "ether10") {
		t.Error("ether2 should sort before ether10")
	}
	if ethLess("ether10", "ether2") {
		t.Error("ether10 should not sort before ether2")
	}
	if !ethLess("ether1", "sfp-sfpplus1") {
		t.Error("ether1 should sort before sfp-sfpplus1")
	}
	if !ethLess("ether9", "ether10") {
		t.Error("ether9 should sort before ether10")
	}
}
