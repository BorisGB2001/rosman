// Package i18n loads UI translations from JSON files in locales/ (embedded).
// Each file is <lang>.json: a flat map of key -> translated string.
// T(lang, key) returns the string for the language, falling back to the default
// language and then to the key itself.
package i18n

import (
	"embed"
	"encoding/json"
	"sort"
)

//go:embed locales/*.json
var localesFS embed.FS

const Default = "en"

var dict = map[string]map[string]string{}
var langs []string

func init() {
	entries, err := localesFS.ReadDir("locales")
	if err != nil {
		panic("i18n: " + err.Error())
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name() // "<lang>.json"
		lang := name[:len(name)-len(".json")]
		raw, err := localesFS.ReadFile("locales/" + name)
		if err != nil {
			panic("i18n: " + err.Error())
		}
		m := map[string]string{}
		if err := json.Unmarshal(raw, &m); err != nil {
			panic("i18n: " + name + ": " + err.Error())
		}
		dict[lang] = m
		langs = append(langs, lang)
	}
	sort.Strings(langs)
}

// Langs lists the available languages (sorted).
func Langs() []string { return langs }

// Valid reports whether lang is a loaded language.
func Valid(lang string) bool {
	_, ok := dict[lang]
	return ok
}

// T returns the translation for key in lang, falling back to Default then key.
func T(lang, key string) string {
	if m, ok := dict[lang]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	if m, ok := dict[Default]; ok {
		if v, ok := m[key]; ok {
			return v
		}
	}
	return key
}
