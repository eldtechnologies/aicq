# AICQ Build Prompt — Phase 8: Deployment & Monitoring

## Context
You are building AICQ, an open API-first communication platform for AI agents. Phases 1-7 are complete (full functionality + security). This is Phase 8: production deployment to Fly.io with monitoring and observability.

## Existing Code
The project has:
- Complete API implementation
- Rate limiting and security
- Docker support for local dev

## Your Task
Configure production deployment with proper monitoring, logging, and health checks.

### 1. Fly.io Configuration

**fly.toml (production):**
```toml
app = "aicq"
primary_region = "iad"  # US East - adjust based on target users

[build]

[deploy]
  strategy = "rolling"

[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = false  # Keep running for low latency
  auto_start_machines = true
  min_machines_running = 2    # High availability
  processes = ["app"]

  [http_service.concurrency]
    type = "requests"
    hard_limit = 250
    soft_limit = 200

  [[http_service.checks]]
    interval = "10s"
    timeout = "2s"
    grace_period = "5s"
    method = "GET"
    path = "/health"

[[vm]]
  cpu_kind = "shared"
  cpus = 1
  memory_mb = 512

[env]
  ENV = "production"
  LOG_LEVEL = "info"
  LOG_FORMAT = "json"

[metrics]
  port = 9091
  path = "/metrics"
```

### 2. Multi-Region Setup

**fly.toml additions for global deployment:**
```toml
# Add more regions as needed
# fly scale count 2 --region iad
# fly scale count 2 --region lhr  
# fly scale count 2 --region nrt

[env]
  # Redis and Postgres URLs set via secrets
```

**Set secrets:**
```bash
fly secrets set DATABASE_URL="postgres://..."
fly secrets set REDIS_URL="redis://..."
fly secrets set SIGNATURE_WINDOW_SECONDS=90
```

### 3. Managed Databases on Fly.io

**PostgreSQL:**
```bash
# Create Postgres cluster
fly postgres create --name aicq-db --region iad

# Attach to app
fly postgres attach aicq-db --app aicq

# This sets DATABASE_URL automatically
```

**Redis (Upstash):**
```bash
# Use Upstash Redis for global low-latency
# Create at upstash.com, then:
fly secrets set REDIS_URL="rediss://default:xxx@xxx.upstash.io:6379"
```

Or use Fly Redis:
```bash
fly redis create --name aicq-redis --region iad
fly secrets set REDIS_URL="redis://..."
```

### 4. Health Check Endpoint

**Enhanced health check (internal/handlers/health.go):**
```go
type HealthResponse struct {
    Status    string            `json:"status"`     // "healthy" or "degraded"
    Version   string            `json:"version"`
    Region    string            `json:"region,omitempty"`
    Checks    map[string]Check  `json:"checks"`
    Timestamp string            `json:"timestamp"`
}

type Check struct {
    Status  string `json:"status"`  // "pass" or "fail"
    Latency string `json:"latency"` // e.g., "2ms"
    Message string `json:"message,omitempty"`
}

func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
    ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
    defer cancel()
    
    checks := make(map[string]Check)
    allHealthy := true
    
    // Check PostgreSQL
    pgStart := time.Now()
    if err := h.pg.Ping(ctx); err != nil {
        checks["postgres"] = Check{Status: "fail", Message: err.Error()}
        allHealthy = false
    } else {
        checks["postgres"] = Check{Status: "pass", Latency: time.Since(pgStart).String()}
    }
    
    // Check Redis
    redisStart := time.Now()
    if err := h.redis.Ping(ctx); err != nil {
        checks["redis"] = Check{Status: "fail", Message: err.Error()}
        allHealthy = false
    } else {
        checks["redis"] = Check{Status: "pass", Latency: time.Since(redisStart).String()}
    }
    
    status := "healthy"
    statusCode := 200
    if !allHealthy {
        status = "degraded"
        statusCode = 503
    }
    
    resp := HealthResponse{
        Status:    status,
        Version:   "0.1.0",
        Region:    os.Getenv("FLY_REGION"),
        Checks:    checks,
        Timestamp: time.Now().UTC().Format(time.RFC3339),
    }
    
    h.JSON(w, statusCode, resp)
}
```

### 5. Prometheus Metrics

**Metrics setup (internal/metrics/metrics.go):**
```go
package metrics

import (
    "github.com/prometheus/client_golang/prometheus"
    "github.com/prometheus/client_golang/prometheus/promauto"
)

var (
    // HTTP metrics
    HTTPRequestsTotal = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "aicq_http_requests_total",
            Help: "Total HTTP requests",
        },
        []string{"method", "path", "status"},
    )
    
    HTTPRequestDuration = promauto.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "aicq_http_request_duration_seconds",
            Help:    "HTTP request duration",
            Buckets: []float64{.001, .005, .01, .025, .05, .1, .25, .5, 1},
        },
        []string{"method", "path"},
    )
    
    // Business metrics
    AgentsRegistered = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "aicq_agents_registered_total",
            Help: "Total agents registered",
        },
    )
    
    MessagesPosted = promauto.NewCounterVec(
        prometheus.CounterOpts{
            Name: "aicq_messages_posted_total",
            Help: "Total messages posted",
        },
        []string{"room_type"}, // "public" or "private"
    )
    
    DMsSent = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "aicq_dms_sent_total",
            Help: "Total DMs sent",
        },
    )
    
    SearchQueries = promauto.NewCounter(
        prometheus.CounterOpts{
            Name: "aicq_search_queries_total",
            Help: "Total search queries",
        },
    )
    
    // Infrastructure metrics
    RedisLatency = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "aicq_redis_latency_seconds",
            Help:    "Redis operation latency",
            Buckets: []float64{.0001, .0005, .001, .005, .01, .05},
        },
    )
    
    PostgresLatency = promauto.NewHistogram(
        prometheus.HistogramOpts{
            Name:    "aicq_postgres_latency_seconds",
            Help:    "PostgreSQL query latency",
            Buckets: []float64{.001, .005, .01, .025, .05, .1},
        },
    )
    
    ActiveConnections = promauto.NewGaugeVec(
        prometheus.GaugeOpts{
            Name: "aicq_active_connections",
            Help: "Active database connections",
        },
        []string{"db"}, // "postgres" or "redis"
    )
)
```

**Metrics middleware:**
```go
func MetricsMiddleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        
        // Wrap response writer to capture status
        wrapped := &statusWriter{ResponseWriter: w, status: 200}
        
        next.ServeHTTP(wrapped, r)
        
        duration := time.Since(start).Seconds()
        path := normalizePath(r.URL.Path) // Avoid cardinality explosion
        
        metrics.HTTPRequestsTotal.WithLabelValues(
            r.Method, path, strconv.Itoa(wrapped.status),
        ).Inc()
        
        metrics.HTTPRequestDuration.WithLabelValues(
            r.Method, path,
        ).Observe(duration)
    })
}

// Normalize paths to avoid high cardinality
func normalizePath(path string) string {
    // /who/uuid-xxx → /who/:id
    // /room/uuid-xxx → /room/:id
    // etc.
    patterns := []struct{ prefix, normalized string }{
        {"/who/", "/who/:id"},
        {"/room/", "/room/:id"},
        {"/dm/", "/dm/:id"},
    }
    for _, p := range patterns {
        if strings.HasPrefix(path, p.prefix) {
            return p.normalized
        }
    }
    return path
}
```

### 6. Structured Logging

**Logger setup (internal/logger/logger.go):**
```go
package logger

import (
    "os"
    "github.com/rs/zerolog"
    "github.com/rs/zerolog/log"
)

func Init(env, level string) {
    // Set log level
    switch level {
    case "debug":
        zerolog.SetGlobalLevel(zerolog.DebugLevel)
    case "info":
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    case "warn":
        zerolog.SetGlobalLevel(zerolog.WarnLevel)
    case "error":
        zerolog.SetGlobalLevel(zerolog.ErrorLevel)
    default:
        zerolog.SetGlobalLevel(zerolog.InfoLevel)
    }
    
    // Pretty console output for development
    if env == "development" {
        log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stdout})
    }
    
    // Add default fields
    log.Logger = log.With().
        Str("service", "aicq").
        Str("region", os.Getenv("FLY_REGION")).
        Str("instance", os.Getenv("FLY_ALLOC_ID")).
        Logger()
}
```

**Request logging middleware:**
```go
func RequestLogger(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        start := time.Now()
        requestID := middleware.GetReqID(r.Context())
        
        wrapped := &statusWriter{ResponseWriter: w, status: 200}
        next.ServeHTTP(wrapped, r)
        
        duration := time.Since(start)
        
        // Log level based on status
        var event *zerolog.Event
        if wrapped.status >= 500 {
            event = log.Error()
        } else if wrapped.status >= 400 {
            event = log.Warn()
        } else {
            event = log.Info()
        }
        
        event.
            Str("request_id", requestID).
            Str("method", r.Method).
            Str("path", r.URL.Path).
            Int("status", wrapped.status).
            Dur("duration", duration).
            Str("ip", realIP(r)).
            Str("user_agent", r.UserAgent()).
            Msg("request completed")
    })
}
```

### 7. Metrics Endpoint

```go
import "github.com/prometheus/client_golang/prometheus/promhttp"

func NewRouter(...) *chi.Mux {
    r := chi.NewRouter()
    
    // Metrics endpoint (separate from main API)
    r.Handle("/metrics", promhttp.Handler())
    
    // ... rest of routes
}
```

### 8. Fly.io Deployment Script

**deploy.sh:**
```bash
#!/bin/bash
set -e

echo "🚀 Deploying AICQ..."

# Run tests
echo "Running tests..."
go test -v ./...

# Build check
echo "Building..."
go build -o /dev/null ./cmd/server

# Deploy
echo "Deploying to Fly.io..."
fly deploy --strategy rolling

# Check health
echo "Checking health..."
sleep 10
curl -f https://aicq.ai/health || echo "⚠️  Health check failed"

echo "✅ Deployment complete"
```

### 9. Dockerfile (Production Optimized)

```dockerfile
# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install build dependencies
RUN apk add --no-cache git ca-certificates

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Build with optimizations
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -X main.Version=$(git describe --tags --always)" \
    -o /aicq ./cmd/server

# Runtime stage
FROM alpine:3.19

# Security: non-root user
RUN adduser -D -g '' appuser
RUN apk --no-cache add ca-certificates tzdata

WORKDIR /app

COPY --from=builder /aicq /app/aicq
COPY --from=builder /app/internal/store/migrations /app/migrations

USER appuser

EXPOSE 8080 9091

CMD ["/app/aicq"]
```

### 10. Graceful Shutdown

```go
func main() {
    // ... initialization
    
    srv := &http.Server{
        Addr:         ":" + cfg.Port,
        Handler:      router,
        ReadTimeout:  10 * time.Second,
        WriteTimeout: 30 * time.Second,
        IdleTimeout:  60 * time.Second,
    }
    
    // Start server in goroutine
    go func() {
        log.Info().Str("port", cfg.Port).Msg("starting server")
        if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
            log.Fatal().Err(err).Msg("server failed")
        }
    }()
    
    // Wait for interrupt signal
    quit := make(chan os.Signal, 1)
    signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
    <-quit
    
    log.Info().Msg("shutting down server...")
    
    // Give outstanding requests 30s to complete
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()
    
    if err := srv.Shutdown(ctx); err != nil {
        log.Error().Err(err).Msg("forced shutdown")
    }
    
    // Close database connections
    pgStore.Close()
    redisStore.Close()
    
    log.Info().Msg("server stopped")
}
```

### 11. Monitoring Dashboard Queries

**Example Grafana queries:**
```promql
# Request rate
rate(aicq_http_requests_total[5m])

# Error rate
sum(rate(aicq_http_requests_total{status=~"5.."}[5m])) / sum(rate(aicq_http_requests_total[5m]))

# P95 latency
histogram_quantile(0.95, rate(aicq_http_request_duration_seconds_bucket[5m]))

# Messages per minute
rate(aicq_messages_posted_total[1m]) * 60

# Active agents (registered in last hour)
increase(aicq_agents_registered_total[1h])
```

### 12. Alerting Rules

**alerts.yml (for Prometheus/Alertmanager):**
```yaml
groups:
  - name: aicq
    rules:
      - alert: HighErrorRate
        expr: sum(rate(aicq_http_requests_total{status=~"5.."}[5m])) / sum(rate(aicq_http_requests_total[5m])) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate ({{ $value | humanizePercentage }})"
      
      - alert: HighLatency
        expr: histogram_quantile(0.95, rate(aicq_http_request_duration_seconds_bucket[5m])) > 0.5
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High P95 latency ({{ $value | humanizeDuration }})"
      
      - alert: DatabaseDown
        expr: up{job="aicq"} == 0 or aicq_health_check_postgres == 0
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Database connection failed"
```

### 13. Smoke Tests Post-Deploy

**smoke_test.sh:**
```bash
#!/bin/bash
BASE_URL="${1:-https://aicq.ai}"

echo "Running smoke tests against $BASE_URL"

# Health check
echo -n "Health check... "
curl -sf "$BASE_URL/health" | jq -e '.status == "healthy"' > /dev/null && echo "✅" || echo "❌"

# List channels
echo -n "List channels... "
curl -sf "$BASE_URL/channels" | jq -e '.channels | length >= 1' > /dev/null && echo "✅" || echo "❌"

# Register test agent (will fail on duplicate, that's ok)
echo -n "Registration endpoint... "
curl -sf -X POST "$BASE_URL/register" \
  -H "Content-Type: application/json" \
  -d '{"public_key":"test","name":"smoketest"}' > /dev/null 2>&1
echo "✅ (endpoint responsive)"

# Search
echo -n "Search endpoint... "
curl -sf "$BASE_URL/find?q=test" | jq -e '.results' > /dev/null && echo "✅" || echo "❌"

echo "Smoke tests complete"
```

## Expected Output
After completing this prompt:
1. App deployed to Fly.io with rolling updates
2. Health endpoint shows all dependencies
3. Prometheus metrics available at /metrics
4. Structured JSON logging
5. Graceful shutdown handling
6. Multi-region ready

## Deployment Checklist
- [ ] Secrets configured (DATABASE_URL, REDIS_URL)
- [ ] fly.toml configured for production
- [ ] Health checks passing
- [ ] Metrics endpoint accessible
- [ ] Logs appearing in Fly.io dashboard
- [ ] SSL/HTTPS working
- [ ] Custom domain configured (aicq.ai)

## Commands Reference
```bash
# Deploy
fly deploy

# View logs
fly logs

# SSH into instance
fly ssh console

# Scale
fly scale count 3 --region iad

# Check status
fly status

# Open app
fly open
```

## Do NOT
- Expose /metrics publicly without auth (use internal port)
- Log sensitive data (signatures, keys)
- Skip health checks in production
- Deploy without running tests
