# AICQ Build Prompt — Phase 1: Project Scaffold & Core Server

## Context
You are building AICQ, an open API-first communication platform for AI agents. This is Phase 1: setting up the Go project structure, core HTTP server, and deployment configuration.

## Your Task
Initialize a production-ready Go project with the following:

### 1. Project Structure
Create this directory layout:
```
aicq/
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── api/
│   │   ├── router.go
│   │   └── middleware/
│   │       └── logging.go
│   ├── config/
│   │   └── config.go
│   └── handlers/
│       └── health.go
├── Dockerfile
├── docker-compose.yml
├── fly.toml
├── Makefile
├── go.mod
└── README.md
```

### 2. Go Module
- Module name: `github.com/aicq-protocol/aicq`
- Go version: 1.23+
- Dependencies:
  - `github.com/go-chi/chi/v5` (router)
  - `github.com/go-chi/chi/v5/middleware` (logging, recoverer)
  - `github.com/joho/godotenv` (env loading for dev)
  - `github.com/rs/zerolog` (structured logging)

### 3. Configuration (internal/config/config.go)
Environment-based config struct:
```go
type Config struct {
    Port        string // default: "8080"
    Env         string // "development" or "production"
    DatabaseURL string // Postgres connection string
    RedisURL    string // Redis connection string
}
```
- Load from environment variables
- Panic on missing required vars in production
- Use sensible defaults for development

### 4. Router Setup (internal/api/router.go)
- Use chi router
- Apply middleware: RequestID, RealIP, Logger, Recoverer
- Add CORS middleware (allow all origins for now — agents call from anywhere)
- Mount routes:
  - `GET /health` → returns `{"status": "ok", "version": "0.1.0"}`
  - `GET /` → returns `{"name": "AICQ", "docs": "https://aicq.ai/docs"}`

### 5. Logging Middleware (internal/api/middleware/logging.go)
- Use zerolog
- Log: method, path, status, latency, request_id
- JSON format in production, pretty console in development

### 6. Health Handler (internal/handlers/health.go)
```go
type HealthResponse struct {
    Status  string `json:"status"`
    Version string `json:"version"`
    Region  string `json:"region,omitempty"` // from FLY_REGION env
}
```

### 7. Main Entry Point (cmd/server/main.go)
- Load config
- Initialize logger
- Create router
- Start HTTP server with graceful shutdown (listen for SIGINT/SIGTERM)
- Log startup message with port and environment

### 8. Dockerfile
Multi-stage build:
```dockerfile
# Build stage
FROM golang:1.23-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -o /aicq ./cmd/server

# Runtime stage
FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /aicq /aicq
EXPOSE 8080
CMD ["/aicq"]
```

### 9. docker-compose.yml (for local dev)
```yaml
version: '3.8'
services:
  api:
    build: .
    ports:
      - "8080:8080"
    environment:
      - ENV=development
      - DATABASE_URL=postgres://aicq:aicq@postgres:5432/aicq?sslmode=disable
      - REDIS_URL=redis://redis:6379
    depends_on:
      - postgres
      - redis
  
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_USER: aicq
      POSTGRES_PASSWORD: aicq
      POSTGRES_DB: aicq
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  pgdata:
```

### 10. fly.toml
```toml
app = "aicq"
primary_region = "iad"

[build]

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = true
  auto_start_machines = true
  min_machines_running = 1
  processes = ["app"]

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 256

[env]
  ENV = "production"
```

### 11. Makefile
```makefile
.PHONY: run build test docker-up docker-down

run:
	go run ./cmd/server

build:
	go build -o bin/aicq ./cmd/server

test:
	go test -v ./...

docker-up:
	docker-compose up --build

docker-down:
	docker-compose down

deploy:
	fly deploy
```

### 12. README.md
Include:
- Project description (1 paragraph)
- Quick start (make docker-up, curl localhost:8080/health)
- API overview (link to docs)
- License: MIT

## Expected Output
After completing this prompt, I should be able to:
1. Run `make docker-up` and see the server start
2. `curl http://localhost:8080/health` returns `{"status":"ok","version":"0.1.0"}`
3. See structured JSON logs in the console

## Code Style Guidelines
- Use standard Go formatting (gofmt)
- Keep functions small and focused
- Add comments for exported functions
- Use meaningful variable names
- Handle errors explicitly (no silent failures)
- Use contexts appropriately for cancellation

## Do NOT
- Add authentication yet (that's Phase 3)
- Add database connections yet (that's Phase 2)
- Over-engineer — keep it minimal and working
