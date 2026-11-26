package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// runMCPProxy is `rosman mcp <url>`: a stdio MCP server that forwards every
// JSON-RPC message to a ROSMan instance's /mcp endpoint. It exists because AI
// clients (Claude Code, Claude Desktop) reject ROSMan's self-signed HTTPS
// certificate and often only launch local stdio servers; the proxy pins the
// certificate by fingerprint instead.
//
//	ROSMAN_TOKEN     API token (Account → API tokens)                required
//	ROSMAN_CERT_PIN  sha256 of the server certificate (hex)          recommended
func runMCPProxy(args []string) int {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "usage: ROSMAN_TOKEN=… [ROSMAN_CERT_PIN=…] rosman mcp https://host:port")
		return 2
	}
	url := strings.TrimRight(args[0], "/")
	if !strings.HasSuffix(url, "/mcp") {
		url += "/mcp"
	}
	token := os.Getenv("ROSMAN_TOKEN")
	if token == "" {
		fmt.Fprintln(os.Stderr, "rosman mcp: ROSMAN_TOKEN is not set")
		return 2
	}
	pin := strings.ToLower(strings.ReplaceAll(os.Getenv("ROSMAN_CERT_PIN"), ":", ""))
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pin != "" {
		// Self-signed certificate: trust exactly the pinned one.
		tlsCfg.InsecureSkipVerify = true
		tlsCfg.VerifyPeerCertificate = func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return fmt.Errorf("no server certificate")
			}
			sum := sha256.Sum256(raw[0])
			if got := hex.EncodeToString(sum[:]); got != pin {
				return fmt.Errorf("server certificate %s does not match ROSMAN_CERT_PIN", got)
			}
			return nil
		}
	}
	client := &http.Client{Timeout: 120 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}}

	in := bufio.NewReaderSize(os.Stdin, 1<<20)
	out := bufio.NewWriter(os.Stdout)
	for {
		line, err := in.ReadBytes('\n')
		if msg := bytes.TrimSpace(line); len(msg) > 0 {
			if resp := forwardMCP(client, url, token, msg); len(resp) > 0 {
				out.Write(resp)
				out.WriteByte('\n')
				out.Flush()
			}
		}
		if err != nil {
			return 0 // stdin closed: the client is done
		}
	}
}

func forwardMCP(client *http.Client, url, token string, msg []byte) []byte {
	fail := func(err error) []byte {
		fmt.Fprintln(os.Stderr, "rosman mcp:", err)
		// Answer requests (those with an id) so the client does not hang.
		var id string
		if i := bytes.Index(msg, []byte(`"id"`)); i >= 0 {
			rest := bytes.TrimLeft(msg[i+4:], ": \t")
			end := bytes.IndexAny(rest, ",}")
			if end > 0 {
				id = string(bytes.TrimSpace(rest[:end]))
			}
		}
		if id == "" {
			return nil
		}
		return []byte(fmt.Sprintf(`{"jsonrpc":"2.0","id":%s,"error":{"code":-32000,"message":%q}}`, id, "ROSMan unreachable: "+err.Error()))
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(msg))
	if err != nil {
		return fail(err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return fail(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 32<<20))
	if resp.StatusCode == http.StatusAccepted {
		return nil
	}
	if resp.StatusCode != http.StatusOK {
		return fail(fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body))))
	}
	return bytes.TrimSpace(bytes.ReplaceAll(body, []byte("\n"), nil))
}
