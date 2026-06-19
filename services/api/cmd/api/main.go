package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"pvn-v2/services/api/internal/config"
	"pvn-v2/services/api/internal/db"
	"pvn-v2/services/api/internal/httpapi"
	"pvn-v2/services/api/internal/wg"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatal(err)
	}
	store, err := db.Open(cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer store.Close()

	migrationPath := filepath.Join("migrations", "001_init.sql")
	if _, err := os.Stat(migrationPath); err != nil {
		migrationPath = filepath.Join("..", "..", "migrations", "001_init.sql")
	}
	if err := store.Migrate(migrationPath); err != nil {
		log.Fatal(err)
	}

	server := &http.Server{
		Addr:              cfg.Addr(),
		Handler:           httpapi.New(store, wg.Manager{Interface: cfg.WGInterface, DryRun: cfg.WGDryRun}),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		log.Printf("PVN v2 API listening on %s", cfg.Addr())
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	<-stop

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		log.Fatal(err)
	}
}
