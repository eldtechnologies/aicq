package middleware

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"
)

// RateLimit defines limits for an endpoint pattern.
type RateLimit struct {
	Requests int
	Window   time.Duration
	KeyFunc  func(r *http.Request) string
}

// RateLimiterConfig holds configuration for the rate limiter.
type RateLimiterConfig struct {
	Whitelist        []string // IPs or CIDRs exempt from rate limiting
	AutoBlockEnabled bool     // Enable auto-blocking after repeated violations
}

// RateLimiter implements sliding window rate limiting.
type RateLimiter struct {
	client           *redis.Client
	limits           map[string]RateLimit
	blocker          *IPBlocker
	logger           zerolog.Logger
	whitelist        []*net.IPNet
	whitelistIPs     map[string]bool
	autoBlockEnabled bool
}

// NewRateLimiter creates a new rate limiter.
func NewRateLimiter(client *redis.Client, logger zerolog.Logger, cfg RateLimiterConfig) *RateLimiter {
	rl := &RateLimiter{
		client:           client,
		blocker:          NewIPBlocker(client),
		logger:           logger,
		whitelistIPs:     make(map[string]bool),
		autoBlockEnabled: cfg.AutoBlockEnabled,
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

	// Parse whitelist entries
	for _, entry := range cfg.Whitelist {
		if strings.Contains(entry, "/") {
			// CIDR notation
			_, ipNet, err := net.ParseCIDR(entry)
			if err != nil {
				logger.Warn().Str("entry", entry).Err(err).Msg("invalid CIDR in whitelist")
				continue
			}
			rl.whitelist = append(rl.whitelist, ipNet)
		} else {
			// Single IP
			rl.whitelistIPs[entry] = true
		}
	}

	if len(cfg.Whitelist) > 0 {
		logger.Info().
			Int("ips", len(rl.whitelistIPs)).
			Int("cidrs", len(rl.whitelist)).
			Msg("rate limit whitelist configured")
	}

	return rl
}

// isWhitelisted checks if an IP is in the whitelist.
func (rl *RateLimiter) isWhitelisted(ipStr string) bool {
	// Check exact IP match
	if rl.whitelistIPs[ipStr] {
		return true
	}

	// Check CIDR ranges
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, ipNet := range rl.whitelist {
		if ipNet.Contains(ip) {
			return true
		}
	}
	return false
}

// ipKey returns rate limit key based on client IP.
func ipKey(r *http.Request) string {
	return "ratelimit:ip:" + RealIP(r)
}

// agentKey returns rate limit key based on agent ID.
func agentKey(r *http.Request) string {
	agentID := r.Header.Get("X-AICQ-Agent")
	if agentID == "" {
		return "ratelimit:ip:" + RealIP(r)
	}
	return "ratelimit:agent:" + agentID
}

// agentOrIPKey returns agent key if authenticated, otherwise IP key.
func agentOrIPKey(r *http.Request) string {
	agentID := r.Header.Get("X-AICQ-Agent")
	if agentID != "" {
		return "ratelimit:agent:" + agentID
	}
	return "ratelimit:ip:" + RealIP(r)
}

// RealIP extracts the real client IP from headers or connection.
func RealIP(r *http.Request) string {
	// Check Fly.io header first
	if ip := r.Header.Get("Fly-Client-IP"); ip != "" {
		return ip
	}
	// Then X-Forwarded-For
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.TrimSpace(strings.Split(ip, ",")[0])
	}
	// Then X-Real-IP
	if ip := r.Header.Get("X-Real-IP"); ip != "" {
		return ip
	}
	// Fallback to RemoteAddr
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return ip
}

// CheckAndIncrement checks rate limit and increments counter.
// Returns (allowed, remaining, resetAt).
func (rl *RateLimiter) CheckAndIncrement(ctx context.Context, key string, limit int, window time.Duration) (bool, int, time.Time) {
	now := time.Now()
	windowStart := now.Add(-window)

	// Use a fixed window key based on current time bucket
	windowKey := fmt.Sprintf("%s:%d", key, now.Unix()/int64(window.Seconds()))

	pipe := rl.client.Pipeline()

	// Remove old entries outside window
	pipe.ZRemRangeByScore(ctx, windowKey, "-inf", fmt.Sprintf("%d", windowStart.UnixMilli()))

	// Count current entries
	countCmd := pipe.ZCard(ctx, windowKey)

	// Add current request with unique member
	pipe.ZAdd(ctx, windowKey, redis.Z{
		Score:  float64(now.UnixMilli()),
		Member: fmt.Sprintf("%d", now.UnixNano()),
	})

	// Set TTL on key
	pipe.Expire(ctx, windowKey, window*2)

	_, _ = pipe.Exec(ctx)

	count := countCmd.Val()
	remaining := limit - int(count) - 1
	if remaining < 0 {
		remaining = 0
	}

	resetAt := now.Add(window)
	allowed := count < int64(limit)

	return allowed, remaining, resetAt
}

// Middleware returns the rate limiting middleware.
func (rl *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := RealIP(r)

		// Skip rate limiting for whitelisted IPs
		if rl.isWhitelisted(ip) {
			next.ServeHTTP(w, r)
			return
		}

		// Check IP block first
		if rl.blocker.IsBlocked(r.Context(), ip) {
			rl.logger.Warn().
				Str("type", "security").
				Str("event", "blocked_request").
				Str("ip", ip).
				Str("endpoint", r.URL.Path).
				Msg("blocked IP attempted request")
			http.Error(w, `{"error":"temporarily blocked"}`, http.StatusForbidden)
			return
		}

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

			// Track violation
			rl.trackViolation(r.Context(), ip)

			rl.logger.Warn().
				Str("type", "security").
				Str("event", "rate_limit_exceeded").
				Str("ip", ip).
				Str("agent", r.Header.Get("X-AICQ-Agent")).
				Str("endpoint", r.URL.Path).
				Str("key", key).
				Msg("rate limit exceeded")

			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(`{"error":"rate limit exceeded"}`))
			return
		}

		next.ServeHTTP(w, r)
	})
}

// findLimit finds the matching rate limit for a request.
func (rl *RateLimiter) findLimit(r *http.Request) *RateLimit {
	key := r.Method + " " + r.URL.Path

	for pattern, limit := range rl.limits {
		if strings.HasPrefix(key, pattern) {
			l := limit // Copy to avoid pointer issues
			return &l
		}
	}
	return nil
}

// trackViolation tracks rate limit violations and auto-blocks repeat offenders.
func (rl *RateLimiter) trackViolation(ctx context.Context, ip string) {
	if !rl.autoBlockEnabled {
		return
	}

	key := fmt.Sprintf("violations:ip:%s", ip)
	count, _ := rl.client.Incr(ctx, key).Result()
	rl.client.Expire(ctx, key, time.Hour)

	if count >= 10 {
		rl.blocker.Block(ctx, ip, 24*time.Hour, "repeated rate limit violations")
		rl.logger.Warn().
			Str("type", "security").
			Str("event", "ip_auto_blocked").
			Str("ip", ip).
			Int64("violations", count).
			Msg("IP auto-blocked for repeated violations")
	}
}

// IPBlocker manages temporary IP blocks.
type IPBlocker struct {
	client *redis.Client
}

// NewIPBlocker creates a new IP blocker.
func NewIPBlocker(client *redis.Client) *IPBlocker {
	return &IPBlocker{client: client}
}

// IsBlocked checks if an IP is blocked.
func (b *IPBlocker) IsBlocked(ctx context.Context, ip string) bool {
	key := fmt.Sprintf("blocked:ip:%s", ip)
	exists, _ := b.client.Exists(ctx, key).Result()
	return exists > 0
}

// Block blocks an IP for the specified duration.
func (b *IPBlocker) Block(ctx context.Context, ip string, duration time.Duration, reason string) {
	key := fmt.Sprintf("blocked:ip:%s", ip)
	b.client.Set(ctx, key, reason, duration)
}

// Unblock removes an IP block.
func (b *IPBlocker) Unblock(ctx context.Context, ip string) {
	key := fmt.Sprintf("blocked:ip:%s", ip)
	b.client.Del(ctx, key)
}
