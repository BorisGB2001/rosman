// Package notify delivers alert notifications to optional channels
// (a generic JSON webhook and/or Telegram). Everything is best-effort.
package notify

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func join(ss []string) string { return strings.Join(ss, ", ") }

// b64wrap base64-encodes data, wrapped at 76 columns for MIME.
func b64wrap(data []byte) string {
	s := base64.StdEncoding.EncodeToString(data)
	var b strings.Builder
	for len(s) > 76 {
		b.WriteString(s[:76])
		b.WriteString("\r\n")
		s = s[76:]
	}
	b.WriteString(s)
	return b.String()
}

type Notifier struct {
	webhook string
	tgToken string
	tgChat  string
	client  *http.Client
}

func New(webhook, tgToken, tgChat string) *Notifier {
	return &Notifier{
		webhook: webhook, tgToken: tgToken, tgChat: tgChat,
		client: &http.Client{Timeout: 8 * time.Second},
	}
}

func (n *Notifier) Enabled() bool {
	return n != nil && (n.webhook != "" || (n.tgToken != "" && n.tgChat != ""))
}

// Send fires the message to every configured channel. Non-blocking-safe to call
// from request handlers; failures are logged, not returned.
func (n *Notifier) Send(subject, text string) {
	if !n.Enabled() {
		return
	}
	if n.webhook != "" {
		n.sendWebhook(subject, text)
	}
	if n.tgToken != "" && n.tgChat != "" {
		n.sendTelegram(subject + "\n" + text)
	}
}

func (n *Notifier) sendWebhook(subject, text string) {
	body, _ := json.Marshal(map[string]string{"subject": subject, "text": text})
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.webhook, bytes.NewReader(body))
	if err != nil {
		log.Printf("notify webhook: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("notify webhook: %v", err)
		return
	}
	resp.Body.Close()
}

// SendTelegramText sends a plain message to a Telegram chat.
func SendTelegramText(token, chat, text string) error {
	form := url.Values{"chat_id": {chat}, "text": {text}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// TestTelegram posts a message and verifies Telegram accepted it, checking the
// HTTP status and the API "ok" flag so a bad token or chat id surfaces as an
// error (unlike SendTelegramText, which is best-effort fire-and-forget).
func TestTelegram(token, chat, text string) error {
	form := url.Values{"chat_id": {chat}, "text": {text}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendMessage", bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := (&http.Client{Timeout: 15 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var res struct {
		OK          bool   `json:"ok"`
		Description string `json:"description"`
	}
	_ = json.Unmarshal(body, &res)
	if resp.StatusCode != 200 || !res.OK {
		d := res.Description
		if d == "" {
			d = strings.TrimSpace(string(body))
		}
		return fmt.Errorf("telegram rejected (HTTP %d): %s", resp.StatusCode, d)
	}
	return nil
}

// SendTelegramDoc sends a file to a Telegram chat (sendDocument).
func SendTelegramDoc(token, chat, filename string, data []byte, caption string) error {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	_ = mw.WriteField("chat_id", chat)
	if caption != "" {
		_ = mw.WriteField("caption", caption)
	}
	fw, err := mw.CreateFormFile("document", filename)
	if err != nil {
		return err
	}
	if _, err := fw.Write(data); err != nil {
		return err
	}
	mw.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost,
		"https://api.telegram.org/bot"+token+"/sendDocument", &body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("telegram sendDocument: HTTP %d", resp.StatusCode)
	}
	return nil
}

// SMTP holds mail-server settings.
type SMTP struct {
	Host, Port, User, Pass, From string
	To                           []string
}

// SendMail sends a plain-text message with an optional attachment via SMTP.
func SendMail(c SMTP, subject, bodyText, attachName string, attachData []byte) error {
	if c.Host == "" || len(c.To) == 0 || c.From == "" {
		return fmt.Errorf("smtp not configured")
	}
	var msg bytes.Buffer
	boundary := "rosman-" + strconv.FormatInt(time.Now().UnixNano(), 36)
	fmt.Fprintf(&msg, "From: %s\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\n", c.From, join(c.To), subject)
	if attachData == nil {
		fmt.Fprintf(&msg, "Content-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", bodyText)
	} else {
		fmt.Fprintf(&msg, "Content-Type: multipart/mixed; boundary=%s\r\n\r\n", boundary)
		fmt.Fprintf(&msg, "--%s\r\nContent-Type: text/plain; charset=UTF-8\r\n\r\n%s\r\n", boundary, bodyText)
		fmt.Fprintf(&msg, "--%s\r\nContent-Type: application/octet-stream\r\nContent-Transfer-Encoding: base64\r\nContent-Disposition: attachment; filename=\"%s\"\r\n\r\n", boundary, attachName)
		msg.WriteString(b64wrap(attachData))
		fmt.Fprintf(&msg, "\r\n--%s--\r\n", boundary)
	}
	addr := c.Host + ":" + c.Port
	var auth smtp.Auth
	if c.User != "" {
		auth = smtp.PlainAuth("", c.User, c.Pass, c.Host)
	}
	return smtp.SendMail(addr, auth, c.From, c.To, msg.Bytes())
}

func (n *Notifier) sendTelegram(text string) {
	api := "https://api.telegram.org/bot" + n.tgToken + "/sendMessage"
	form := url.Values{"chat_id": {n.tgChat}, "text": {text}}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, api, bytes.NewBufferString(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := n.client.Do(req)
	if err != nil {
		log.Printf("notify telegram: %v", err)
		return
	}
	resp.Body.Close()
}
