package app

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"rosman/internal/model"
)

func eventMatch(spec, event string) bool {
	spec = strings.TrimSpace(spec)
	if spec == "" || spec == "all" {
		return true
	}
	for _, e := range strings.Split(spec, ",") {
		if strings.TrimSpace(e) == event {
			return true
		}
	}
	return false
}

// fireWebhooks POSTs a JSON payload to every enabled webhook subscribed to the
// event. Delivery is asynchronous and best-effort; the per-hook status is
// recorded for the UI.
func (a *App) fireWebhooks(event string, data map[string]any) {
	hooks, err := a.Store.Webhooks()
	if err != nil {
		return
	}
	payload := map[string]any{"event": event, "time": time.Now().Format(time.RFC3339)}
	for k, v := range data {
		payload[k] = v
	}
	body, _ := json.Marshal(payload)
	for _, h := range hooks {
		if h.Enabled && eventMatch(h.Events, event) {
			go a.deliverWebhook(h, event, body)
		}
	}
}

func (a *App) deliverWebhook(h model.Webhook, event string, body []byte) {
	req, err := http.NewRequest(http.MethodPost, h.URL, bytes.NewReader(body))
	if err != nil {
		_ = a.Store.SetWebhookStatus(h.ID, "bad url")
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "ROSMan-webhook")
	req.Header.Set("X-ROSMan-Event", event)
	if h.SecretEnc != "" {
		if sec, e := a.Box.Decrypt(h.SecretEnc); e == nil && sec != "" {
			mac := hmac.New(sha256.New, []byte(sec))
			mac.Write(body)
			req.Header.Set("X-ROSMan-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
		}
	}
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		_ = a.Store.SetWebhookStatus(h.ID, "error: "+err.Error())
		return
	}
	defer resp.Body.Close()
	_ = a.Store.SetWebhookStatus(h.ID, resp.Status)
}

// TestWebhook delivers a sample event to one webhook synchronously and returns
// the recorded status.
func (a *App) TestWebhook(id int64) (string, error) {
	hooks, err := a.Store.Webhooks()
	if err != nil {
		return "", err
	}
	for _, h := range hooks {
		if h.ID == id {
			body, _ := json.Marshal(map[string]any{"event": "test", "time": time.Now().Format(time.RFC3339),
				"message": "ROSMan webhook test"})
			a.deliverWebhook(h, "test", body)
			for _, h2 := range mustWebhooks(a) {
				if h2.ID == id {
					return h2.LastStatus, nil
				}
			}
			return "sent", nil
		}
	}
	return "", fmt.Errorf("webhook not found")
}

func mustWebhooks(a *App) []model.Webhook {
	hs, _ := a.Store.Webhooks()
	return hs
}
