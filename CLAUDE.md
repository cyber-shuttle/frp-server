# FRP-Server

Go-based relay control plane for FRP tunneling. Manages tunnel provisioning, API key auth, JWT tokens, and coordinates with the FRP relay engine for P2P connections.

## Prerequisites

- Go 1.25+

## Commands

```bash
go build -o frp-server .        # Build
go test ./...                   # Run tests
go vet ./...                    # Static analysis
```

## Running

```bash
./frp-server \
  --relay-addr "0.0.0.0:7000" \
  --api-addr "0.0.0.0:7500" \
  --master-secret "your-secret" \
  --db-path "./frp-server.db" \
  --jwt-secret "optional-persist-across-restarts"
```

`--master-secret` is required (fatal if missing). `--jwt-secret` auto-generates if omitted (logged warning).

## Architecture (~850 LoC)

```
main.go                     # CLI flags, startup, graceful shutdown (SIGTERM/SIGINT, 5s timeout)
internal/
  config/config.go          # Config struct (5 fields)
  auth/jwt.go               # JWT generation/validation, scopes (host/connect)
  db/
    db.go                   # SQLite store (WAL mode, FK constraints)
    models.go               # APIKey, Tunnel, TunnelPort
  api/
    server.go               # HTTP server, route registration
    handlers.go             # 8 REST handlers
    middleware.go            # Master secret + API key auth middleware
  relay/relay.go            # FRP server.Service wrapper
```

## Auth Model (3 tiers)

1. **Master Secret** — Admin-only, for `/api/v1/auth/*`. Constant-time comparison.
2. **API Keys** — Created via master secret. Stored as SHA256 hash. Prefix: `ak-`. Used for tunnel CRUD.
3. **JWT Tokens** — Per-tunnel, scoped (`host`/`connect`). 24h TTL. Also used as FRP relay auth token.

## API (`/api/v1/`)

| Endpoint | Auth | Description |
|----------|------|-------------|
| `POST /auth/keys` | Master | Create API key |
| `DELETE /auth/keys/{id}` | Master | Revoke API key |
| `POST /tunnels` | API key | Create tunnel (returns hostToken + connectToken) |
| `GET /tunnels` | API key | List owner's tunnels |
| `GET /tunnels/{id}` | API key | Get tunnel + ports |
| `DELETE /tunnels/{id}` | API key | Delete tunnel |
| `POST /tunnels/{id}/ports` | API key | Add port (1-65535) |
| `DELETE /tunnels/{id}/ports/{port}` | API key | Remove port |
| `POST /tunnels/{id}/tokens` | API key | Generate new JWT (scope required) |
| `GET /health` | None | Health check |

## Database (SQLite3, WAL mode)

- `api_keys`: id (`ak-*`), key_hash (SHA256), created_at, revoked_at
- `tunnels`: id (`row-*`), tunnel_id (`tun-*`), owner_key_id (FK), created_at, expires_at
- `tunnel_ports`: id (`tp-*`), tunnel_id (FK CASCADE), port, protocol

ID pattern: `prefix-` + 12 hex chars (6 random bytes).

## Gotchas

- Tunnel `expires_at` is stored but never enforced — no background cleanup job
- JWT secret is shared with FRP relay auth token (`cfg.Auth.Token = jwtSecret`)
- Port deletion is a silent no-op if port doesn't exist
- Lists return empty `[]` not `null` (explicit nil-slice handling)
- Master secret stored as plain string in memory (compared via `subtle.ConstantTimeCompare`)
- Ownership check: tunnel operations return 403 if `OwnerKeyID != keyID` from context
