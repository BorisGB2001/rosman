// Command rosman is a single-binary RouterOS fleet manager (P0).
package main

import (
	"context"
	"crypto/tls"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"rosman/internal/app"
	"rosman/internal/config"
	"rosman/internal/scheduler"
	"rosman/internal/secret"
	"rosman/internal/store"
	"rosman/internal/tlsgen"
	"rosman/internal/web"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("rosman ")

	cfg := config.Load()
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		log.Fatalf("data dir: %v", err)
	}

	// Apply a staged full-backup restore (if any) before the DB and key open —
	// it replaces rosman.db and secret.key, so it must happen first.
	if applied, err := app.ApplyPendingRestore(cfg.DataDir); err != nil {
		log.Fatalf("restore: %v", err)
	} else if applied {
		log.Printf("applied pending full-backup restore from staging")
	}

	box, err := secret.Open(cfg.SecretKeyPath)
	if err != nil {
		log.Fatalf("secret key: %v", err)
	}
	st, err := store.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("open db: %v", err)
	}
	defer st.Close()

	if pw, err := web.SeedAdmin(st); err != nil {
		log.Fatalf("seed admin: %v", err)
	} else if pw != "" {
		log.Printf("created initial admin user — username: admin  password: %s  (change it after first login)", pw)
	}

	a, err := app.New(cfg, st, box)
	if err != nil {
		log.Fatalf("app: %v", err)
	}
	if !a.HasSSHKey() {
		log.Printf("no SSH key set (ROSMAN_SSH_KEY) — config backup disabled until configured")
	}

	if err := tlsgen.Ensure(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil {
		log.Fatalf("tls cert: %v", err)
	}

	srv, err := web.New(a)
	if err != nil {
		log.Fatalf("web: %v", err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	go scheduler.Run(ctx, a)

	httpSrv := &http.Server{
		Addr:              cfg.Listen,
		Handler:           srv.Routes(),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{MinVersion: tls.VersionTLS12},
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpSrv.Shutdown(shutCtx)
	}()

	log.Printf("listening on https://%s", cfg.Listen)
	if err := httpSrv.ListenAndServeTLS(cfg.TLSCertPath, cfg.TLSKeyPath); err != nil && err != http.ErrServerClosed {
		log.Fatalf("server: %v", err)
	}
	log.Printf("stopped")
}
