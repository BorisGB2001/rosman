// Package netbox is a minimal NetBox REST client: just what ROSMan needs to
// keep its devices mirrored there (find-or-create of manufacturers, device
// types, roles, platforms, tags, devices, interfaces and IP addresses).
package netbox

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client talks to one NetBox instance.
type Client struct {
	base  string // https://netbox.example/api
	token string
	hc    *http.Client
}

// New returns a client. insecure skips TLS verification (self-signed NetBox).
func New(baseURL, token string, insecure bool) *Client {
	b := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if !strings.HasSuffix(b, "/api") {
		b += "/api"
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // operator's explicit choice for a self-signed NetBox
	}
	return &Client{base: b, token: strings.TrimSpace(token), hc: &http.Client{Timeout: 20 * time.Second, Transport: tr}}
}

// Obj is a NetBox object as decoded JSON.
type Obj map[string]any

// ID returns the object's numeric id (0 if absent).
func (o Obj) ID() int64 {
	if o == nil {
		return 0
	}
	if f, ok := o["id"].(float64); ok {
		return int64(f)
	}
	return 0
}

// Str returns a top-level string field.
func (o Obj) Str(k string) string {
	if s, ok := o[k].(string); ok {
		return s
	}
	return ""
}

// Ref returns the id of a nested object field (e.g. "site", "primary_ip4").
func (o Obj) Ref(k string) int64 {
	if m, ok := o[k].(map[string]any); ok {
		return Obj(m).ID()
	}
	return 0
}

// WebURL is the object's browsable URL (display_url / url without /api).
func (o Obj) WebURL() string {
	if s := o.Str("display_url"); s != "" {
		return s
	}
	return strings.Replace(o.Str("url"), "/api/", "/", 1)
}

func (c *Client) do(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.base+path, rd)
	if err != nil {
		return err
	}
	// NetBox 4.5+ v2 tokens ("nbt_…") use Bearer; classic tokens use "Token".
	if strings.HasPrefix(c.token, "nbt_") {
		req.Header.Set("Authorization", "Bearer "+c.token)
	} else {
		req.Header.Set("Authorization", "Token "+c.token)
	}
	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if len(msg) > 300 {
			msg = msg[:300] + "…"
		}
		return fmt.Errorf("NetBox %s %s: HTTP %d %s", method, path, resp.StatusCode, msg)
	}
	if out != nil && len(data) > 0 {
		return json.Unmarshal(data, out)
	}
	return nil
}

// Status returns the NetBox version (also checks URL and token).
func (c *Client) Status() (string, error) {
	var st Obj
	if err := c.do("GET", "/status/", nil, &st); err != nil {
		return "", err
	}
	// /status/ answers without a valid token too; prove the token works.
	if err := c.do("GET", "/dcim/sites/?limit=1", nil, nil); err != nil {
		return "", err
	}
	return st.Str("netbox-version"), nil
}

// List returns objects at path matching the query (first page, up to 200).
func (c *Client) List(path string, q url.Values) ([]Obj, error) {
	if q == nil {
		q = url.Values{}
	}
	if q.Get("limit") == "" {
		q.Set("limit", "200")
	}
	var res struct {
		Results []Obj `json:"results"`
	}
	if err := c.do("GET", path+"?"+q.Encode(), nil, &res); err != nil {
		return nil, err
	}
	return res.Results, nil
}

// First returns the first object matching q, or nil.
func (c *Client) First(path string, q url.Values) (Obj, error) {
	l, err := c.List(path, q)
	if err != nil || len(l) == 0 {
		return nil, err
	}
	return l[0], nil
}

// Get fetches one object by id (nil, nil when it no longer exists).
func (c *Client) Get(path string, id int64) (Obj, error) {
	var o Obj
	err := c.do("GET", fmt.Sprintf("%s%d/", path, id), nil, &o)
	if err != nil && strings.Contains(err.Error(), "HTTP 404") {
		return nil, nil
	}
	return o, err
}

// Create posts a new object.
func (c *Client) Create(path string, body map[string]any) (Obj, error) {
	var o Obj
	err := c.do("POST", path, body, &o)
	return o, err
}

// Patch updates fields of an object.
func (c *Client) Patch(path string, id int64, body map[string]any) (Obj, error) {
	var o Obj
	err := c.do("PATCH", fmt.Sprintf("%s%d/", path, id), body, &o)
	return o, err
}

// Slug turns a name into a NetBox slug (latin letters, digits, dashes).
func Slug(s string) string {
	var b strings.Builder
	dash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			dash = false
		case r == '+':
			b.WriteString("plus")
			dash = false
		default:
			if !dash && b.Len() > 0 {
				b.WriteByte('-')
				dash = true
			}
		}
	}
	out := strings.Trim(b.String(), "-")
	if len(out) > 100 {
		out = out[:100]
	}
	if out == "" {
		out = "x"
	}
	return out
}
