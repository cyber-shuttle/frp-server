package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/cyber-shuttle/frp-server/internal/auth"
	"github.com/gorilla/mux"
)

func (s *Server) handleCreateAPIKey(w http.ResponseWriter, r *http.Request) {
	id, rawKey, err := s.store.CreateAPIKey()
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, map[string]string{"id": id, "apiKey": rawKey})
}

func (s *Server) handleRevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	if err := s.store.RevokeAPIKey(id); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleCreateTunnel(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}

	var req struct {
		Expiration string `json:"expiration"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	var expiresAt *time.Time
	if req.Expiration != "" {
		d, err := time.ParseDuration(req.Expiration)
		if err != nil {
			if strings.HasSuffix(req.Expiration, "d") {
				days, _ := strconv.Atoi(strings.TrimSuffix(req.Expiration, "d"))
				if days > 0 {
					t := time.Now().Add(time.Duration(days) * 24 * time.Hour)
					expiresAt = &t
				}
			}
		} else {
			t := time.Now().Add(d)
			expiresAt = &t
		}
	}

	tunnelID, err := s.store.CreateTunnel(keyID, expiresAt)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	hostToken, err := s.tokens.GenerateToken(tunnelID, auth.ScopeHost, 24*time.Hour)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate host token: "+err.Error())
		return
	}

	connectToken, err := s.tokens.GenerateToken(tunnelID, auth.ScopeConnect, 24*time.Hour)
	if err != nil {
		respondError(w, http.StatusInternalServerError, "failed to generate connect token: "+err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, map[string]string{
		"tunnelId":     tunnelID,
		"hostToken":    hostToken,
		"connectToken": connectToken,
	})
}

func (s *Server) handleListTunnels(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnels, err := s.store.ListTunnels(keyID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type tunnelResp struct {
		TunnelID  string `json:"tunnelId"`
		CreatedAt string `json:"createdAt"`
	}
	var out []tunnelResp
	for _, t := range tunnels {
		out = append(out, tunnelResp{TunnelID: t.TunnelID, CreatedAt: t.CreatedAt.Format(time.RFC3339)})
	}
	if out == nil {
		out = []tunnelResp{}
	}
	respondJSON(w, http.StatusOK, out)
}

func (s *Server) handleGetTunnel(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnelID := mux.Vars(r)["id"]
	t, err := s.store.GetTunnel(tunnelID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if t.OwnerKeyID != keyID {
		respondError(w, http.StatusForbidden, "tunnel not owned by this API key")
		return
	}
	ports, err := s.store.ListPorts(tunnelID)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	type portResp struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	var portList []portResp
	for _, p := range ports {
		portList = append(portList, portResp{Port: p.Port, Protocol: p.Protocol})
	}
	if portList == nil {
		portList = []portResp{}
	}

	respondJSON(w, http.StatusOK, map[string]any{
		"tunnelId":  t.TunnelID,
		"createdAt": t.CreatedAt.Format(time.RFC3339),
		"ports":     portList,
	})
}

func (s *Server) handleDeleteTunnel(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnelID := mux.Vars(r)["id"]
	t, err := s.store.GetTunnel(tunnelID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if t.OwnerKeyID != keyID {
		respondError(w, http.StatusForbidden, "tunnel not owned by this API key")
		return
	}
	if err := s.store.DeleteTunnel(tunnelID); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleAddPort(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnelID := mux.Vars(r)["id"]
	t, err := s.store.GetTunnel(tunnelID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if t.OwnerKeyID != keyID {
		respondError(w, http.StatusForbidden, "tunnel not owned by this API key")
		return
	}
	var req struct {
		Port     int    `json:"port"`
		Protocol string `json:"protocol"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Port == 0 {
		respondError(w, http.StatusBadRequest, "port is required")
		return
	}
	if req.Port < 1 || req.Port > 65535 {
		respondError(w, http.StatusBadRequest, "port must be between 1 and 65535")
		return
	}
	if req.Protocol == "" {
		req.Protocol = "tcp"
	}
	if err := s.store.AddPort(tunnelID, req.Port, req.Protocol); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleRemovePort(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnelID := mux.Vars(r)["id"]
	t, err := s.store.GetTunnel(tunnelID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if t.OwnerKeyID != keyID {
		respondError(w, http.StatusForbidden, "tunnel not owned by this API key")
		return
	}
	portStr := mux.Vars(r)["port"]
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		respondError(w, http.StatusBadRequest, "invalid port")
		return
	}
	if err := s.store.RemovePort(tunnelID, port); err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGenerateToken(w http.ResponseWriter, r *http.Request) {
	keyID, ok := r.Context().Value(keyIDContextKey).(string)
	if !ok {
		respondError(w, http.StatusUnauthorized, "missing authentication")
		return
	}
	tunnelID := mux.Vars(r)["id"]
	t, err := s.store.GetTunnel(tunnelID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	if t.OwnerKeyID != keyID {
		respondError(w, http.StatusForbidden, "tunnel not owned by this API key")
		return
	}
	var req struct {
		Scope string `json:"scope"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	var scope auth.TokenScope
	switch req.Scope {
	case "host":
		scope = auth.ScopeHost
	case "connect":
		scope = auth.ScopeConnect
	default:
		respondError(w, http.StatusBadRequest, `scope must be "host" or "connect"`)
		return
	}

	token, err := s.tokens.GenerateToken(tunnelID, scope, 24*time.Hour)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}
	respondJSON(w, http.StatusCreated, map[string]string{"token": token})
}

func respondJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func respondError(w http.ResponseWriter, status int, msg string) {
	respondJSON(w, status, map[string]string{"error": msg})
}
