package web

import (
	"html"
	"html/template"
	"regexp"
	"strings"
)

// renderMD turns the small Markdown subset the AI report uses (## headings,
// bullet/numbered lists, **bold**, `code`, fenced code blocks, paragraphs)
// into HTML. Everything is escaped first, so model output cannot inject markup.

var (
	mdBold = regexp.MustCompile(`\*\*([^*\n]+)\*\*`)
	mdCode = regexp.MustCompile("`([^`\n]+)`")
	mdNum  = regexp.MustCompile(`^\d+[.)]\s+`)
)

func mdInline(s string) string {
	s = html.EscapeString(s)
	s = mdCode.ReplaceAllString(s, "<code>$1</code>")
	return mdBold.ReplaceAllString(s, "<b>$1</b>")
}

func renderMD(src string) template.HTML {
	var b strings.Builder
	lines := strings.Split(strings.ReplaceAll(src, "\r\n", "\n"), "\n")
	list := "" // "", "ul" or "ol"
	closeList := func() {
		if list != "" {
			b.WriteString("</" + list + ">\n")
			list = ""
		}
	}
	var para []string
	flush := func() {
		if len(para) > 0 {
			b.WriteString("<p>" + strings.Join(para, "<br>") + "</p>\n")
			para = nil
		}
	}
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		t := strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(t, "```"):
			flush()
			closeList()
			var code []string
			for i++; i < len(lines) && !strings.HasPrefix(strings.TrimSpace(lines[i]), "```"); i++ {
				code = append(code, lines[i])
			}
			b.WriteString(`<pre class="aicode">` + html.EscapeString(strings.Join(code, "\n")) + "</pre>\n")
		case t == "":
			flush()
			closeList()
		case strings.HasPrefix(t, "#"):
			flush()
			closeList()
			n := len(t) - len(strings.TrimLeft(t, "#"))
			tag := "h3"
			if n >= 3 {
				tag = "h4"
			}
			b.WriteString("<" + tag + ">" + mdInline(strings.TrimSpace(strings.TrimLeft(t, "#"))) + "</" + tag + ">\n")
		case strings.HasPrefix(t, "- ") || strings.HasPrefix(t, "* ") || strings.HasPrefix(t, "• "):
			flush()
			if list != "ul" {
				closeList()
				b.WriteString("<ul>\n")
				list = "ul"
			}
			b.WriteString("<li>" + mdInline(strings.TrimSpace(t[strings.Index(t, " ")+1:])) + "</li>\n")
		case mdNum.MatchString(t):
			flush()
			if list != "ol" {
				closeList()
				b.WriteString("<ol>\n")
				list = "ol"
			}
			b.WriteString("<li>" + mdInline(mdNum.ReplaceAllString(t, "")) + "</li>\n")
		default:
			if list != "" && (strings.HasPrefix(line, "  ") || strings.HasPrefix(line, "\t")) {
				// continuation of the previous list item
				b.WriteString("<div class=\"aicont\">" + mdInline(t) + "</div>\n")
				continue
			}
			closeList()
			para = append(para, mdInline(t))
		}
	}
	flush()
	closeList()
	return template.HTML(b.String())
}
