package cve

import "testing"

func ids(fs []Finding) string {
	s := ""
	for _, f := range fs { s += f.CVE.ID + " " }
	return s
}
func TestScan(t *testing.T) {
	cases := map[string]string{
		"6.40.1":           "CVE-2018-14847 CVE-2019-3977 CVE-2019-3978 CVE-2023-30799 ",
		"6.44.3":           "CVE-2019-3977 CVE-2019-3978 CVE-2023-30799 ", // 6.44 long-term, below 6.44.6
		"6.44.6":           "CVE-2023-30799 ",                            // dns fixed; 30799 stable-boundary 6.49.7 via "6"
		"6.48.5 (long-term)": "CVE-2023-30799 ",
		"6.48.6":           "",  // long-term 30799 fixed
		"6.49.7":           "",  // stable 30799 fixed
		"6.49.6":           "CVE-2023-30799 ",
		"7.11.2":           "",  // v7: no 6.x CVE applies
	}
	for v, want := range cases {
		if got := ids(Scan(v)); got != want {
			t.Errorf("Scan(%q) = %q, want %q", v, got, want)
		}
	}
}
