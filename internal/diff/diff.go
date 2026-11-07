// Package diff computes a simple line-based diff (LCS) for config comparison.
package diff

import "strings"

// Op marks a line as context (" "), removed ("-") or added ("+").
type Line struct {
	Op   string
	Text string
}

// Lines diffs two texts by line and returns the merged line list.
func Lines(a, b string) []Line {
	as := splitLines(a)
	bs := splitLines(b)
	n, m := len(as), len(bs)
	// LCS length table.
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if as[i] == bs[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var out []Line
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case as[i] == bs[j]:
			out = append(out, Line{" ", as[i]})
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			out = append(out, Line{"-", as[i]})
			i++
		default:
			out = append(out, Line{"+", bs[j]})
			j++
		}
	}
	for ; i < n; i++ {
		out = append(out, Line{"-", as[i]})
	}
	for ; j < m; j++ {
		out = append(out, Line{"+", bs[j]})
	}
	return out
}

// Stat returns the number of added and removed lines.
func Stat(lines []Line) (added, removed int) {
	for _, l := range lines {
		switch l.Op {
		case "+":
			added++
		case "-":
			removed++
		}
	}
	return
}

func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	return strings.Split(s, "\n")
}
