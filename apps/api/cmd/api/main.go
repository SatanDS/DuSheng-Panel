package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"dusheng-panel/apps/api/internal/app"
	"dusheng-panel/apps/api/internal/config"
	"dusheng-panel/apps/api/internal/store"
)

func main() {
	cfg := config.FromEnv()
	if err := cfg.Validate(); err != nil {
		log.Fatalf("invalid configuration: %v", err)
	}

	db, err := store.Open(cfg)
	if err != nil {
		log.Fatalf("open database: %v", err)
	}

	router := app.NewServer(cfg, db)
	server := &http.Server{
		Addr: cfg.Listen, Handler: router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
		MaxHeaderBytes:    1 << 20,
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	log.Printf("DuSheng API listening on %s", cfg.Listen)
	go func() { errCh <- server.ListenAndServe() }()
	select {
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("run api: %v", err)
		}
		return
	case <-ctx.Done():
	}
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("API graceful shutdown failed: %v", err)
		_ = server.Close()
	}
}
