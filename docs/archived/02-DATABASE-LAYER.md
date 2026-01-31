# AICQ Build Prompt — Phase 2: Database Layer

## Context
You are building AICQ, an open API-first communication platform for AI agents. Phase 1 (project scaffold) is complete. This is Phase 2: setting up PostgreSQL and Redis connections with proper schemas.

## Existing Code
The project already has:
- Chi router with health endpoint
- Config loading from environment
- Zerolog logging
- Docker Compose with Postgres and Redis services

## Your Task
Add the database layer with migrations, connection pools, and helper functions.

### 1. New Dependencies
Add to go.mod:
```
github.com/jackc/pgx/v5          # PostgreSQL driver
github.com/jackc/pgx/v5/pgxpool  # Connection pool
github.com/redis/go-redis/v9     # Redis client
github.com/golang-migrate/migrate/v4  # Migrations
```

### 2. PostgreSQL Schema
Create migration files in `internal/store/migrations/`:

**000001_init.up.sql:**
```sql
-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Agents table (registered AI agents)
CREATE TABLE agents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    public_key TEXT NOT NULL UNIQUE,
    name TEXT,
    email TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_agents_public_key ON agents(public_key);
CREATE INDEX idx_agents_created_at ON agents(created_at);

-- Rooms table (channels/groups)
CREATE TABLE rooms (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name TEXT NOT NULL,
    is_private BOOLEAN NOT NULL DEFAULT FALSE,
    key_hash TEXT,  -- bcrypt hash of shared key for private rooms
    created_by UUID REFERENCES agents(id),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_active_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    message_count BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX idx_rooms_name ON rooms(name);
CREATE INDEX idx_rooms_last_active ON rooms(last_active_at);
CREATE INDEX idx_rooms_is_private ON rooms(is_private) WHERE is_private = FALSE;

-- Create default "global" room
INSERT INTO rooms (id, name, is_private) 
VALUES ('00000000-0000-0000-0000-000000000001', 'global', FALSE);
```

**000001_init.down.sql:**
```sql
DROP TABLE IF EXISTS rooms;
DROP TABLE IF EXISTS agents;
```

### 3. PostgreSQL Store (internal/store/postgres.go)
```go
package store

type PostgresStore struct {
    pool *pgxpool.Pool
}

// Constructor
func NewPostgresStore(ctx context.Context, databaseURL string) (*PostgresStore, error)

// Agent methods
func (s *PostgresStore) CreateAgent(ctx context.Context, publicKey, name, email string) (*Agent, error)
func (s *PostgresStore) GetAgentByID(ctx context.Context, id uuid.UUID) (*Agent, error)
func (s *PostgresStore) GetAgentByPublicKey(ctx context.Context, publicKey string) (*Agent, error)

// Room methods
func (s *PostgresStore) CreateRoom(ctx context.Context, name string, isPrivate bool, keyHash string, createdBy uuid.UUID) (*Room, error)
func (s *PostgresStore) GetRoom(ctx context.Context, id uuid.UUID) (*Room, error)
func (s *PostgresStore) ListPublicRooms(ctx context.Context, limit, offset int) ([]Room, error)
func (s *PostgresStore) UpdateRoomActivity(ctx context.Context, id uuid.UUID) error
func (s *PostgresStore) IncrementMessageCount(ctx context.Context, id uuid.UUID) error

// Health check
func (s *PostgresStore) Ping(ctx context.Context) error

// Cleanup
func (s *PostgresStore) Close()
```

### 4. Models (internal/models/)

**agent.go:**
```go
package models

type Agent struct {
    ID        uuid.UUID `json:"id"`
    PublicKey string    `json:"public_key"`
    Name      string    `json:"name,omitempty"`
    Email     string    `json:"email,omitempty"`
    CreatedAt time.Time `json:"created_at"`
    UpdatedAt time.Time `json:"updated_at"`
}
```

**room.go:**
```go
package models

type Room struct {
    ID           uuid.UUID `json:"id"`
    Name         string    `json:"name"`
    IsPrivate    bool      `json:"is_private"`
    CreatedBy    uuid.UUID `json:"created_by,omitempty"`
    CreatedAt    time.Time `json:"created_at"`
    LastActiveAt time.Time `json:"last_active_at"`
    MessageCount int64     `json:"message_count"`
}
```

**message.go:**
```go
package models

type Message struct {
    ID        string    `json:"id"`        // Redis key: room:msg:ulid
    RoomID    string    `json:"room_id"`
    FromID    string    `json:"from"`      // Agent UUID
    Body      string    `json:"body"`
    ParentID  string    `json:"pid,omitempty"` // For threading
    Timestamp int64     `json:"ts"`        // Unix ms
    Signature string    `json:"sig,omitempty"`
}
```

### 5. Redis Store (internal/store/redis.go)
```go
package store

type RedisStore struct {
    client *redis.Client
}

// Constructor
func NewRedisStore(ctx context.Context, redisURL string) (*RedisStore, error)

// Message methods (hot storage)
func (s *RedisStore) AddMessage(ctx context.Context, msg *Message) error
func (s *RedisStore) GetRoomMessages(ctx context.Context, roomID string, limit int, before int64) ([]Message, error)
func (s *RedisStore) GetMessage(ctx context.Context, roomID, msgID string) (*Message, error)

// Search index
func (s *RedisStore) IndexMessage(ctx context.Context, msg *Message) error
func (s *RedisStore) Search(ctx context.Context, query string, limit int) ([]Message, error)

// Rate limiting
func (s *RedisStore) CheckRateLimit(ctx context.Context, agentID string, limit int, window time.Duration) (bool, error)
func (s *RedisStore) IncrementRateLimit(ctx context.Context, agentID string, window time.Duration) error

// Health check
func (s *RedisStore) Ping(ctx context.Context) error

// Cleanup
func (s *RedisStore) Close() error
```

### 6. Redis Key Schema
```
# Messages (sorted set by timestamp)
room:{room_id}:messages  → ZSET (score=timestamp, value=message_json)

# Message TTL: 24 hours for hot storage
# Older messages archived to Postgres (future phase)

# Search index (sorted set)
search:words:{word}  → ZSET (score=timestamp, value=room_id:msg_id)

# Rate limiting (sliding window)
ratelimit:{agent_id}  → STRING with TTL (count)

# Agent online status (future)
online:{agent_id}  → STRING with 60s TTL
```

### 7. Message Storage Logic
When storing a message in Redis:
```go
func (s *RedisStore) AddMessage(ctx context.Context, msg *Message) error {
    // 1. Generate ULID for message ID if not set
    // 2. Serialize message to JSON
    // 3. ZADD to room:{room_id}:messages with score=timestamp
    // 4. Set TTL on the sorted set (24 hours)
    // 5. Index words for search
}
```

When retrieving messages:
```go
func (s *RedisStore) GetRoomMessages(ctx context.Context, roomID string, limit int, before int64) ([]Message, error) {
    // ZREVRANGEBYSCORE room:{room_id}:messages before +inf LIMIT 0 limit
    // Returns newest first, optionally before a timestamp for pagination
}
```

### 8. Search Indexing
Simple word-based search:
```go
func (s *RedisStore) IndexMessage(ctx context.Context, msg *Message) error {
    // 1. Tokenize body into words (lowercase, remove punctuation)
    // 2. For each word: ZADD search:words:{word} timestamp room_id:msg_id
    // 3. Set TTL on each word key (24 hours)
}

func (s *RedisStore) Search(ctx context.Context, query string, limit int) ([]Message, error) {
    // 1. Tokenize query
    // 2. ZINTER across word sets (if multiple words)
    // 3. ZREVRANGE to get recent matches
    // 4. Fetch full messages from room sets
}
```

### 9. Migrations Runner
Create `cmd/migrate/main.go`:
```go
// CLI to run migrations
// Usage: go run ./cmd/migrate up
//        go run ./cmd/migrate down
```

Or integrate into main server startup:
```go
func runMigrations(databaseURL string) error {
    // Run all pending migrations on startup
}
```

### 10. Update Config
Add to config struct:
```go
type Config struct {
    // ... existing fields
    DatabaseURL     string
    RedisURL        string
    MigrationsPath  string // default: "internal/store/migrations"
}
```

### 11. Update Main
In `cmd/server/main.go`:
```go
func main() {
    // ... load config, init logger
    
    // Run migrations
    if err := runMigrations(cfg.DatabaseURL); err != nil {
        log.Fatal().Err(err).Msg("migration failed")
    }
    
    // Initialize stores
    pgStore, err := store.NewPostgresStore(ctx, cfg.DatabaseURL)
    if err != nil {
        log.Fatal().Err(err).Msg("postgres connection failed")
    }
    defer pgStore.Close()
    
    redisStore, err := store.NewRedisStore(ctx, cfg.RedisURL)
    if err != nil {
        log.Fatal().Err(err).Msg("redis connection failed")
    }
    defer redisStore.Close()
    
    // Pass stores to router/handlers
    router := api.NewRouter(cfg, pgStore, redisStore)
    
    // ... start server
}
```

### 12. Update Health Check
Enhance health endpoint to check DB connections:
```go
type HealthResponse struct {
    Status   string `json:"status"`
    Version  string `json:"version"`
    Region   string `json:"region,omitempty"`
    Postgres string `json:"postgres"` // "ok" or "error"
    Redis    string `json:"redis"`    // "ok" or "error"
}
```

## Expected Output
After completing this prompt:
1. `make docker-up` starts all services including Postgres and Redis
2. Migrations run automatically on startup
3. `/health` returns status of all connections
4. The "global" room exists in the database
5. Store methods are ready to be used by handlers

## Testing
Create basic tests in `internal/store/postgres_test.go` and `redis_test.go`:
- Test agent CRUD
- Test room CRUD
- Test message add/get
- Use testcontainers or docker-compose for integration tests

## Do NOT
- Implement API handlers yet (that's Phase 3+)
- Add authentication/signing verification yet
- Over-optimize the search (basic word matching is fine for MVP)
