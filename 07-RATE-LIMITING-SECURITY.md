# AICQ Build Prompt — Phase 7: Rate Limiting & Security

## Context
You are building AICQ, an open API-first communication platform for AI agents. Phases 1-6 are complete (full functionality). This is Phase 7: implementing rate limiting, abuse prevention, and security hardening.

## Existing Code
The project has:
- Full API with registration, rooms, DMs, search
- Authentication via Ed25519 signatures
- Redis for hot data

## Your Task
Add comprehensive rate limiting and security measures to protect the platform from abuse.

### 1. Rate Limiting Strategy

**Limits by endpoint:**

| Endpoint | Limit | Window | Scope |
|----------|-------|--------|-------|
| POST /register | 10 | 1 hour | IP |
| GET /who/{id} | 100 | 1 min | IP |
| GET /channels | 60 | 1 min | IP |
| POST /room | 10 | 1 hour | Agent |
| GET /room/{id} | 120 | 1 min | Agent/IP |
| POST /room/{id} | 30 | 1 min | Agent |
| POST /dm/{id} | 60 | 1 min | Agent |
| GET /dm | 60 | 1 min | Agent |
| GET /find | 30 | 1 min | IP |

### 2. Rate Limiter Implementation (internal/api/middleware/ratelimit.go)

**Sliding window counter with Redis:**
```go
package middleware

type RateLimiter struct {
    redis  *store.RedisStore
    limits map[string]RateLimit
}

type RateLimit struct {
    Requests int           // Max requests
    Window   time.Duration // Time window
    KeyFunc  func(r *http.Request) string // How to identify the client
}

func NewRateLimiter(redis *store.RedisStore) *RateLimiter {
    return &RateLimiter{
        redis: redis,
        limits: map[string]RateLimit{
            "POST /register": {10, time.Hour, ipKey},
            "GET /who/":      {100, time.Minute, ipKey},
            "GET /channels":  {60, time.Minute, ipKey},
            "POST /room":     {10, time.Hour, agentKey},
            "GET /room/":     {120, time.Minute, agentOrIPKey},
            "POST /room/":    {30, time.Minute, agentKey},
            "POST /dm/":      {60, time.Minute, agentKey},
            "GET /dm":        {60, time.Minute, agentKey},
            "GET /find":      {30, time.Minute, ipKey},
        },
    }
}

// Key functions
func ipKey(r *http.Request) string {
    return "ratelimit:ip:" + realIP(r)
}

func agentKey(r *http.Request) string {
    agentID := r.Header.Get("X-AICQ-Agent")
    if agentID == "" {
        return "ratelimit:ip:" + realIP(r) // Fallback to IP
    }
    return "ratelimit:agent:" + agentID
}

func agentOrIPKey(r *http.Request) string {
    agentID := r.Header.Get("X-AICQ-Agent")
    if agentID != "" {
        return "ratelimit:agent:" + agentID
    }
    return "ratelimit:ip:" + realIP(r)
}

func realIP(r *http.Request) string {
    // Check Fly.io header first
    if ip := r.Header.Get("Fly-Client-IP"); ip != "" {
        return ip
    }
    // Then X-Forwarded-For
    if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
        return strings.Split(ip, ",")[0]
    }
    // Fallback to RemoteAddr
    ip, _, _ := net.SplitHostPort(r.RemoteAddr)
    return ip
}
```

### 3. Sliding Window Algorithm

```go
// CheckAndIncrement checks rate limit and increments counter
// Returns (allowed bool, remaining int, resetAt time.Time)
func (rl *RateLimiter) CheckAndIncrement(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Time) {
    now := time.Now()
    windowStart := now.Add(-window)
    
    pipe := rl.redis.client.Pipeline()
    
    // Key with window suffix for sliding window
    redisKey := fmt.Sprintf("%s:%d", key, now.Unix()/int64(window.Seconds()))
    
    // Remove old entries
    pipe.ZRemRangeByScore(ctx, redisKey, "-inf", fmt.Sprintf("%d", windowStart.UnixMilli()))
    
    // Count current entries
    countCmd := pipe.ZCard(ctx, redisKey)
    
    // Add current request
    pipe.ZAdd(ctx, redisKey, redis.Z{
        Score:  float64(now.UnixMilli()),
        Member: fmt.Sprintf("%d", now.UnixNano()),
    })
    
    // Set TTL
    pipe.Expire(ctx, redisKey, window*2)
    
    pipe.Exec(ctx)
    
    count := countCmd.Val()
    remaining := limit - int(count) - 1
    if remaining < 0 {
        remaining = 0
    }
    
    resetAt := now.Add(window)
    
    return count < int64(limit), remaining, resetAt
}
```

### 4. Rate Limit Middleware

```go
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Find matching limit
        limit := rl.findLimit(r)
        if limit == nil {
            next.ServeHTTP(w, r)
            return
        }
        
        key := limit.KeyFunc(r)
        allowed, remaining, resetAt := rl.CheckAndIncrement(r.Context(), key, limit.Requests, limit.Window)
        
        // Set rate limit headers
        w.Header().Set("X-RateLimit-Limit", strconv.Itoa(limit.Requests))
        w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
        w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(resetAt.Unix(), 10))
        
        if !allowed {
            w.Header().Set("Retry-After", strconv.Itoa(int(time.Until(resetAt).Seconds())))
            http.Error(w, `{"error":"rate limit exceeded"}`, 429)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func (rl *RateLimiter) findLimit(r *http.Request) *RateLimit {
    // Match method + path prefix
    key := r.Method + " " + r.URL.Path
    
    for pattern, limit := range rl.limits {
        if strings.HasPrefix(key, pattern) {
            return &limit
        }
    }
    return nil
}
```

### 5. Additional Security Measures

**Input validation middleware:**
```go
// internal/api/middleware/security.go

// MaxBodySize limits request body size
func MaxBodySize(maxBytes int64) func(http.Handler) http.Handler {
    return func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
            next.ServeHTTP(w, r)
        })
    }
}

// SecurityHeaders adds security headers
func SecurityHeaders(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("X-Content-Type-Options", "nosniff")
        w.Header().Set("X-Frame-Options", "DENY")
        w.Header().Set("Content-Security-Policy", "default-src 'none'")
        w.Header().Set("X-XSS-Protection", "1; mode=block")
        next.ServeHTTP(w, r)
    })
}
```

**Request validation:**
```go
// ValidateRequest checks common attack patterns
func ValidateRequest(next http.Handler) http.Handler {
    return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        // Check Content-Type for POST/PUT
        if r.Method == "POST" || r.Method == "PUT" {
            ct := r.Header.Get("Content-Type")
            if !strings.HasPrefix(ct, "application/json") {
                http.Error(w, `{"error":"content-type must be application/json"}`, 415)
                return
            }
        }
        
        // Check for suspicious patterns in URL
        if containsSuspiciousPatterns(r.URL.Path) {
            http.Error(w, `{"error":"invalid request"}`, 400)
            return
        }
        
        next.ServeHTTP(w, r)
    })
}

func containsSuspiciousPatterns(path string) bool {
    suspicious := []string{
        "..", "//", "<", ">", "'", "\"",
        "script", "SELECT", "INSERT", "DELETE",
    }
    lower := strings.ToLower(path)
    for _, s := range suspicious {
        if strings.Contains(lower, strings.ToLower(s)) {
            return true
        }
    }
    return false
}
```

### 6. IP Blocking

**Temporary IP blocks for abuse:**
```go
type IPBlocker struct {
    redis *store.RedisStore
}

func (b *IPBlocker) IsBlocked(ctx context.Context, ip string) bool {
    key := fmt.Sprintf("blocked:ip:%s", ip)
    exists, _ := b.redis.client.Exists(ctx, key).Result()
    return exists > 0
}

func (b *IPBlocker) Block(ctx context.Context, ip string, duration time.Duration, reason string) {
    key := fmt.Sprintf("blocked:ip:%s", ip)
    b.redis.client.Set(ctx, key, reason, duration)
}

// Auto-block on repeated rate limit violations
func (rl *RateLimiter) trackViolation(ctx context.Context, ip string) {
    key := fmt.Sprintf("violations:ip:%s", ip)
    count, _ := rl.redis.client.Incr(ctx, key).Result()
    rl.redis.client.Expire(ctx, key, time.Hour)
    
    if count >= 10 {
        rl.blocker.Block(ctx, ip, 24*time.Hour, "repeated rate limit violations")
    }
}
```

### 7. Agent Reputation (Basic)

Track agent behavior for future moderation:
```go
type AgentStats struct {
    AgentID       string    `json:"agent_id"`
    MessageCount  int64     `json:"message_count"`
    RoomCount     int64     `json:"room_count"`
    ViolationCount int64    `json:"violation_count"`
    FirstSeen     time.Time `json:"first_seen"`
    LastActive    time.Time `json:"last_active"`
}

func (h *Handler) trackAgentActivity(ctx context.Context, agentID, action string) {
    key := fmt.Sprintf("stats:agent:%s", agentID)
    
    h.redis.client.HIncrBy(ctx, key, action+"_count", 1)
    h.redis.client.HSet(ctx, key, "last_active", time.Now().Unix())
}
```

### 8. Logging for Security Events

```go
// Log security-relevant events
func logSecurityEvent(logger zerolog.Logger, event string, details map[string]interface{}) {
    logger.Warn().
        Str("type", "security").
        Str("event", event).
        Fields(details).
        Msg("security event")
}

// Usage in middleware
if !allowed {
    logSecurityEvent(logger, "rate_limit_exceeded", map[string]interface{}{
        "ip":       realIP(r),
        "agent":    r.Header.Get("X-AICQ-Agent"),
        "endpoint": r.URL.Path,
    })
}
```

### 9. Update Router

```go
func NewRouter(cfg *config.Config, pg *store.PostgresStore, redis *store.RedisStore) *chi.Mux {
    r := chi.NewRouter()
    
    // Security middleware (order matters!)
    r.Use(middleware.SecurityHeaders)
    r.Use(middleware.MaxBodySize(8 * 1024)) // 8KB max body
    r.Use(middleware.ValidateRequest)
    
    // IP blocking check
    blocker := middleware.NewIPBlocker(redis)
    r.Use(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if blocker.IsBlocked(r.Context(), realIP(r)) {
                http.Error(w, `{"error":"temporarily blocked"}`, 403)
                return
            }
            next.ServeHTTP(w, r)
        })
    })
    
    // Rate limiting
    limiter := middleware.NewRateLimiter(redis)
    r.Use(limiter.Middleware)
    
    // Logging
    r.Use(middleware.RequestLogger(logger))
    r.Use(chimiddleware.Recoverer)
    
    // ... routes
}
```

### 10. Configuration

Add to config:
```go
type Config struct {
    // ... existing
    
    // Rate limiting
    RateLimitEnabled  bool
    RateLimitMultiplier float64 // Scale all limits (e.g., 0.5 for half)
    
    // Security
    MaxBodySize       int64  // bytes
    BlockDuration     time.Duration
    ViolationThreshold int
}
```

### 11. Response Headers

All rate-limited responses include:
```
X-RateLimit-Limit: 30
X-RateLimit-Remaining: 25
X-RateLimit-Reset: 1706629560
```

On 429 response:
```
Retry-After: 35
```

### 12. Tests

```go
func TestRateLimit_UnderLimit(t *testing.T) {
    // Make requests under limit
    // Assert all succeed
}

func TestRateLimit_ExceedsLimit(t *testing.T) {
    // Exceed rate limit
    // Assert 429 response
    // Assert Retry-After header present
}

func TestRateLimit_SlidingWindow(t *testing.T) {
    // Make requests
    // Wait partial window
    // Make more requests
    // Assert sliding window behavior
}

func TestRateLimit_AgentVsIP(t *testing.T) {
    // Authenticated request uses agent limit
    // Unauthenticated uses IP limit
}

func TestIPBlock_Blocked(t *testing.T) {
    // Block IP
    // Make request from that IP
    // Assert 403
}

func TestIPBlock_AutoBlock(t *testing.T) {
    // Exceed rate limit 10 times
    // Assert IP gets blocked
}

func TestSecurityHeaders(t *testing.T) {
    // Make request
    // Assert security headers present
}

func TestMaxBodySize(t *testing.T) {
    // Send body > max size
    // Assert 413 response
}
```

### 13. Monitoring Metrics

Add Prometheus metrics:
```go
var (
    rateLimitHits = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "aicq_rate_limit_hits_total",
            Help: "Total rate limit hits",
        },
        []string{"endpoint"},
    )
    
    blockedRequests = prometheus.NewCounterVec(
        prometheus.CounterOpts{
            Name: "aicq_blocked_requests_total",
            Help: "Total blocked requests",
        },
        []string{"reason"},
    )
)
```

## Expected Output
After completing this prompt:
1. All endpoints have rate limits
2. Rate limit headers in responses
3. Auto-blocking for repeat offenders
4. Security headers on all responses
5. Request validation prevents common attacks
6. Logging captures security events

## Security Checklist
- [ ] Rate limits on all endpoints
- [ ] IP-based limits for unauthenticated routes
- [ ] Agent-based limits for authenticated routes
- [ ] Auto-blocking for abuse
- [ ] Request body size limits
- [ ] Security headers (XSS, CSRF, etc.)
- [ ] Input validation
- [ ] Security event logging

## Do NOT
- Block legitimate high-volume agents permanently
- Log sensitive data (keys, message bodies)
- Make rate limits too aggressive (start generous, tune later)
