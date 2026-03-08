package db

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	sqlDB, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_foreign_keys=ON")
	if err != nil {
		return nil, fmt.Errorf("open db: %w", err)
	}
	if err := migrate(sqlDB); err != nil {
		sqlDB.Close()
		return nil, fmt.Errorf("migrate db: %w", err)
	}
	return &Store{db: sqlDB}, nil
}

func migrate(db *sql.DB) error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS api_keys (
			id         TEXT PRIMARY KEY,
			key_hash   TEXT NOT NULL UNIQUE,
			created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			revoked_at DATETIME
		);
		CREATE TABLE IF NOT EXISTS tunnels (
			id           TEXT PRIMARY KEY,
			tunnel_id    TEXT NOT NULL UNIQUE,
			owner_key_id TEXT NOT NULL REFERENCES api_keys(id),
			created_at   DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at   DATETIME
		);
		CREATE TABLE IF NOT EXISTS tunnel_ports (
			id        TEXT PRIMARY KEY,
			tunnel_id TEXT NOT NULL REFERENCES tunnels(tunnel_id) ON DELETE CASCADE,
			port      INTEGER NOT NULL,
			protocol  TEXT NOT NULL DEFAULT 'tcp',
			UNIQUE(tunnel_id, port)
		);
	`)
	return err
}

func (s *Store) Close() error { return s.db.Close() }

// --- API Keys ---

func (s *Store) CreateAPIKey() (id string, rawKey string, err error) {
	id = generateID("ak")
	rawKey = generateToken(32)
	hash := hashKey(rawKey)
	_, err = s.db.Exec("INSERT INTO api_keys (id, key_hash) VALUES (?, ?)", id, hash)
	if err != nil {
		return "", "", fmt.Errorf("create api key: %w", err)
	}
	return id, rawKey, nil
}

func (s *Store) ValidateAPIKey(rawKey string) (string, error) {
	hash := hashKey(rawKey)
	var id string
	err := s.db.QueryRow("SELECT id FROM api_keys WHERE key_hash = ? AND revoked_at IS NULL", hash).Scan(&id)
	if err == sql.ErrNoRows {
		return "", fmt.Errorf("invalid or revoked API key")
	}
	if err != nil {
		return "", fmt.Errorf("validate api key: %w", err)
	}
	return id, nil
}

func (s *Store) RevokeAPIKey(id string) error {
	_, err := s.db.Exec("UPDATE api_keys SET revoked_at = ? WHERE id = ?", time.Now(), id)
	return err
}

// --- Tunnels ---

func (s *Store) CreateTunnel(ownerKeyID string, expiresAt *time.Time) (string, error) {
	id := generateID("row")
	tunnelID := generateID("tun")
	_, err := s.db.Exec(
		"INSERT INTO tunnels (id, tunnel_id, owner_key_id, expires_at) VALUES (?, ?, ?, ?)",
		id, tunnelID, ownerKeyID, expiresAt,
	)
	if err != nil {
		return "", fmt.Errorf("create tunnel: %w", err)
	}
	return tunnelID, nil
}

func (s *Store) GetTunnel(tunnelID string) (*Tunnel, error) {
	var t Tunnel
	err := s.db.QueryRow(
		"SELECT id, tunnel_id, owner_key_id, created_at, expires_at FROM tunnels WHERE tunnel_id = ?",
		tunnelID,
	).Scan(&t.ID, &t.TunnelID, &t.OwnerKeyID, &t.CreatedAt, &t.ExpiresAt)
	if err == sql.ErrNoRows {
		return nil, fmt.Errorf("tunnel %s not found", tunnelID)
	}
	if err != nil {
		return nil, fmt.Errorf("get tunnel: %w", err)
	}
	return &t, nil
}

func (s *Store) ListTunnels(ownerKeyID string) ([]Tunnel, error) {
	rows, err := s.db.Query(
		"SELECT id, tunnel_id, owner_key_id, created_at, expires_at FROM tunnels WHERE owner_key_id = ?",
		ownerKeyID,
	)
	if err != nil {
		return nil, fmt.Errorf("list tunnels: %w", err)
	}
	defer rows.Close()
	var out []Tunnel
	for rows.Next() {
		var t Tunnel
		if err := rows.Scan(&t.ID, &t.TunnelID, &t.OwnerKeyID, &t.CreatedAt, &t.ExpiresAt); err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTunnel(tunnelID string) error {
	_, err := s.db.Exec("DELETE FROM tunnels WHERE tunnel_id = ?", tunnelID)
	return err
}

// --- Tunnel Ports ---

func (s *Store) AddPort(tunnelID string, port int, protocol string) error {
	id := generateID("tp")
	if protocol == "" {
		protocol = "tcp"
	}
	_, err := s.db.Exec(
		"INSERT INTO tunnel_ports (id, tunnel_id, port, protocol) VALUES (?, ?, ?, ?)",
		id, tunnelID, port, protocol,
	)
	return err
}

func (s *Store) ListPorts(tunnelID string) ([]TunnelPort, error) {
	rows, err := s.db.Query(
		"SELECT id, tunnel_id, port, protocol FROM tunnel_ports WHERE tunnel_id = ?",
		tunnelID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TunnelPort
	for rows.Next() {
		var p TunnelPort
		if err := rows.Scan(&p.ID, &p.TunnelID, &p.Port, &p.Protocol); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

func (s *Store) RemovePort(tunnelID string, port int) error {
	_, err := s.db.Exec("DELETE FROM tunnel_ports WHERE tunnel_id = ? AND port = ?", tunnelID, port)
	return err
}

// --- Helpers ---

func generateID(prefix string) string {
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return prefix + "-" + hex.EncodeToString(b)
}

func generateToken(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand failed: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func hashKey(rawKey string) string {
	h := sha256.Sum256([]byte(rawKey))
	return hex.EncodeToString(h[:])
}
