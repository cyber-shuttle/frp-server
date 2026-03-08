package api

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

type contextKey string

const keyIDContextKey contextKey = "keyID"

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			respondError(w, http.StatusUnauthorized, "missing authorization")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		keyID, err := s.store.ValidateAPIKey(token)
		if err != nil {
			respondError(w, http.StatusUnauthorized, "invalid API key")
			return
		}
		ctx := context.WithValue(r.Context(), keyIDContextKey, keyID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (s *Server) masterAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if !strings.HasPrefix(auth, "Bearer ") {
			respondError(w, http.StatusUnauthorized, "missing authorization")
			return
		}
		token := strings.TrimPrefix(auth, "Bearer ")
		if subtle.ConstantTimeCompare([]byte(token), []byte(s.masterSecret)) != 1 {
			respondError(w, http.StatusUnauthorized, "invalid master secret")
			return
		}
		next.ServeHTTP(w, r)
	})
}
