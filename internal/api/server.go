package api

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/cyber-shuttle/frp-server/internal/auth"
	"github.com/cyber-shuttle/frp-server/internal/config"
	"github.com/cyber-shuttle/frp-server/internal/db"
	"github.com/gorilla/mux"
)

type Server struct {
	httpServer   *http.Server
	store        *db.Store
	tokens       *auth.TokenService
	masterSecret string
}

func New(cfg config.Config, store *db.Store) *Server {
	s := &Server{
		store:        store,
		tokens:       auth.NewTokenService(cfg.JWTSecret),
		masterSecret: cfg.MasterSecret,
	}

	r := mux.NewRouter()
	api := r.PathPrefix("/api/v1").Subrouter()

	// Auth endpoints (master secret required)
	authRouter := api.PathPrefix("/auth").Subrouter()
	authRouter.Use(s.masterAuthMiddleware)
	authRouter.HandleFunc("/keys", s.handleCreateAPIKey).Methods("POST")
	authRouter.HandleFunc("/keys/{id}", s.handleRevokeAPIKey).Methods("DELETE")

	// Tunnel endpoints (API key required)
	tunnelRouter := api.PathPrefix("/tunnels").Subrouter()
	tunnelRouter.Use(s.authMiddleware)
	tunnelRouter.HandleFunc("", s.handleCreateTunnel).Methods("POST")
	tunnelRouter.HandleFunc("", s.handleListTunnels).Methods("GET")
	tunnelRouter.HandleFunc("/{id}", s.handleGetTunnel).Methods("GET")
	tunnelRouter.HandleFunc("/{id}", s.handleDeleteTunnel).Methods("DELETE")
	tunnelRouter.HandleFunc("/{id}/ports", s.handleAddPort).Methods("POST")
	tunnelRouter.HandleFunc("/{id}/ports/{port}", s.handleRemovePort).Methods("DELETE")
	tunnelRouter.HandleFunc("/{id}/tokens", s.handleGenerateToken).Methods("POST")

	// Health
	api.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"ok"}`))
	}).Methods("GET")

	s.httpServer = &http.Server{
		Addr:    cfg.APIAddr,
		Handler: r,
	}

	return s
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Stop() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := s.httpServer.Shutdown(ctx); err != nil {
		log.Printf("API server shutdown error: %v", err)
	}
}
