// Package notify delivers alert notifications to optional channels
// (a generic JSON webhook and/or Telegram). Everything is best-effort.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"net/url"
	"time"
)

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
