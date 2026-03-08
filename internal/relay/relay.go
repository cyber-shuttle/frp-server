package relay

import (
	"context"
	"fmt"
	"log"
	"net"
	"strconv"

	"github.com/cyber-shuttle/frp-server/internal/auth"
	"github.com/cyber-shuttle/frp-server/internal/db"
	v1 "github.com/fatedier/frp/pkg/config/v1"
	"github.com/fatedier/frp/server"
)

type Relay struct {
	svr    *server.Service
	addr   string
	tokens *auth.TokenService
	store  *db.Store
	cancel context.CancelFunc
}

func New(addr string, jwtSecret string, store *db.Store) (*Relay, error) {
	host, port := parseAddr(addr)

	cfg := &v1.ServerConfig{}
	cfg.BindAddr = host
	cfg.BindPort = port

	// Enable XTCP for P2P connections
	cfg.NatHoleAnalysisDataReserveHours = 24

	// Use token auth — proxies must authenticate with this token
	cfg.Auth.Method = v1.AuthMethodToken
	cfg.Auth.Token = jwtSecret

	svr, err := server.NewService(cfg)
	if err != nil {
		return nil, fmt.Errorf("create frp server: %w", err)
	}

	return &Relay{
		svr:    svr,
		addr:   addr,
		tokens: auth.NewTokenService(jwtSecret),
		store:  store,
	}, nil
}

func (r *Relay) Start() error {
	log.Printf("FRP relay starting on %s", r.addr)
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.svr.Run(ctx)
	return nil
}

func (r *Relay) Stop() {
	if r.cancel != nil {
		r.cancel()
	}
}

func parseAddr(addr string) (string, int) {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return addr, 7000
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return host, 7000
	}
	return host, port
}
