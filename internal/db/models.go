package db

import "time"

type APIKey struct {
	ID        string
	KeyHash   string
	CreatedAt time.Time
	RevokedAt *time.Time
}

type Tunnel struct {
	ID         string
	TunnelID   string
	OwnerKeyID string
	CreatedAt  time.Time
	ExpiresAt  *time.Time
}

type TunnelPort struct {
	ID       string
	TunnelID string
	Port     int
	Protocol string
}
