package main

import (
	"crypto/rand"
	"encoding/hex"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cyber-shuttle/frp-server/internal/api"
	"github.com/cyber-shuttle/frp-server/internal/config"
	"github.com/cyber-shuttle/frp-server/internal/db"
	"github.com/cyber-shuttle/frp-server/internal/relay"
)

func main() {
	cfg := config.Config{}
	flag.StringVar(&cfg.RelayAddr, "relay-addr", "0.0.0.0:7000", "FRP relay listen address")
	flag.StringVar(&cfg.APIAddr, "api-addr", "0.0.0.0:7500", "REST API listen address")
	flag.StringVar(&cfg.MasterSecret, "master-secret", "", "master secret for API key creation (required)")
	flag.StringVar(&cfg.DBPath, "db-path", "./frp-server.db", "SQLite database path")
	flag.StringVar(&cfg.JWTSecret, "jwt-secret", "", "JWT signing secret (auto-generated if empty)")
	flag.Parse()

	if cfg.MasterSecret == "" {
		log.Fatal("--master-secret is required")
	}

	if cfg.JWTSecret == "" {
		cfg.JWTSecret = generateRandomSecret(32)
		log.Printf("auto-generated JWT secret (use --jwt-secret to persist across restarts)")
	}

	store, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	r, err := relay.New(cfg.RelayAddr, cfg.JWTSecret, store)
	if err != nil {
		log.Fatalf("failed to create relay: %v", err)
	}
	go func() {
		if err := r.Start(); err != nil {
			log.Fatalf("relay error: %v", err)
		}
	}()
	log.Printf("FRP relay listening on %s", cfg.RelayAddr)

	apiServer := api.New(cfg, store)
	go func() {
		if err := apiServer.Start(); err != nil {
			log.Fatalf("API server error: %v", err)
		}
	}()
	log.Printf("REST API listening on %s", cfg.APIAddr)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig

	log.Println("shutting down...")
	apiServer.Stop()
	r.Stop()
	log.Println("done")
}

func generateRandomSecret(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("failed to generate random secret: %v", err)
	}
	return hex.EncodeToString(b)
}
