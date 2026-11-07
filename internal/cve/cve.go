// Package cve scans an installed RouterOS version against a curated, offline
// dataset of publicly disclosed MikroTik RouterOS vulnerabilities.
//
// The dataset is a best-effort compilation from public security advisories and
// CVE records (facts, not vendor assets). It is intentionally conservative: it
// lists only well-documented issues with confident fixed-version boundaries.
// It is NOT a substitute for MikroTik's own advisories — treat a clean result
// as "no match in this dataset", not a guarantee. Extend the list as needed.
package cve

import "strings"

// Branch ties a RouterOS release tree (identified by the most specific numeric
// version prefix, e.g. "6", "6.48", "7") to the version that first contained
// the fix. A device on that tree below Fixed is considered affected.
type Branch struct {
	Series string
	Fixed  string
}

type CVE struct {
	ID       string
	Title    string
	Severity string // Critical | High | Medium
	CVSS     float64
	Ref      string
	Branches []Branch
}

// Finding is a CVE that applies to the scanned version, with the version that
// resolves it on the device's release tree.
type Finding struct {
	CVE   CVE
	Fixed string
}

// Data is the curated vulnerability list. Boundaries follow MikroTik's
// stable/long-term fix announcements for each CVE.
var Data = []CVE{
	{
		ID: "CVE-2018-14847", Title: "Winbox arbitrary file read — unauthenticated credential disclosure",
		Severity: "Critical", CVSS: 9.1, Ref: "https://nvd.nist.gov/vuln/detail/CVE-2018-14847",
		Branches: []Branch{{"6", "6.42.1"}},
	},
	{
		ID: "CVE-2019-3977", Title: "RouterOS insufficient validation of upgrade package origin (downgrade)",
		Severity: "High", CVSS: 7.3, Ref: "https://nvd.nist.gov/vuln/detail/CVE-2019-3977",
		Branches: []Branch{{"6", "6.45.7"}, {"6.44", "6.44.6"}},
	},
	{
		ID: "CVE-2019-3978", Title: "RouterOS DNS cache poisoning via unauthenticated request",
		Severity: "High", CVSS: 7.5, Ref: "https://nvd.nist.gov/vuln/detail/CVE-2019-3978",
		Branches: []Branch{{"6", "6.45.7"}, {"6.44", "6.44.6"}},
	},
	{
		ID: "CVE-2023-30799", Title: "Privilege escalation to super-admin via Winbox/API (authenticated)",
		Severity: "Critical", CVSS: 9.1, Ref: "https://nvd.nist.gov/vuln/detail/CVE-2023-30799",
		Branches: []Branch{{"6", "6.49.7"}, {"6.48", "6.48.6"}},
	},
}

// Scan returns the CVEs from Data that apply to version. version may carry a
// suffix like "6.48.6 (long-term)"; only the leading dotted-numeric part is used.
func Scan(version string) []Finding {
	v := normalize(version)
	if v == "" {
		return nil
	}
	var out []Finding
	for _, c := range Data {
		b, ok := bestBranch(v, c.Branches)
		if ok && cmp(v, b.Fixed) < 0 {
			out = append(out, Finding{CVE: c, Fixed: b.Fixed})
		}
	}
	return out
}

// bestBranch picks the branch whose Series is the most specific numeric prefix
// of v. Returns ok=false when none of the branches cover v's release tree.
func bestBranch(v string, bs []Branch) (Branch, bool) {
	var best Branch
	bestLen := -1
	for _, b := range bs {
		if prefixMatch(v, b.Series) {
			if n := len(parts(b.Series)); n > bestLen {
				best, bestLen = b, n
			}
		}
	}
	return best, bestLen >= 0
}

// prefixMatch reports whether every numeric component of series equals the
// corresponding component of v (so "6.48" matches "6.48.6" but not "6.49.1").
func prefixMatch(v, series string) bool {
	sp, vp := parts(series), parts(v)
	if len(sp) > len(vp) {
		return false
	}
	for i := range sp {
		if sp[i] != vp[i] {
			return false
		}
	}
	return true
}

func normalize(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " ("); i >= 0 {
		s = s[:i]
	}
	return s
}

func parts(s string) []int {
	fs := strings.Split(s, ".")
	out := make([]int, 0, len(fs))
	for _, f := range fs {
		n := 0
		// take leading digits only (handles "7rc1"-style tails defensively)
		for _, r := range f {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		out = append(out, n)
	}
	return out
}

// cmp compares two dotted-numeric versions. Missing components count as 0.
func cmp(a, b string) int {
	ap, bp := parts(a), parts(b)
	n := len(ap)
	if len(bp) > n {
		n = len(bp)
	}
	for i := 0; i < n; i++ {
		var x, y int
		if i < len(ap) {
			x = ap[i]
		}
		if i < len(bp) {
			y = bp[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// Worst returns the highest severity label among findings, or "" for none.
func Worst(fs []Finding) string {
	rank := map[string]int{"Critical": 3, "High": 2, "Medium": 1}
	best, name := 0, ""
	for _, f := range fs {
		if rank[f.CVE.Severity] > best {
			best, name = rank[f.CVE.Severity], f.CVE.Severity
		}
	}
	return name
}
