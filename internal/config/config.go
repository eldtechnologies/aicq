package config

import (
	"os"
	"strings"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application.
type Config struct {
	Port        string
	Env         string
	DatabaseURL string // PostgreSQL URL (if empty, uses SQLite)
	SQLitePath  string // SQLite database path (default: ./data/aicq.db)
	RedisURL    string

	// Rate limiting
	RateLimitWhitelist []string // IPs or CIDRs exempt from rate limiting
	AutoBlockEnabled   bool     // Enable auto-blocking after repeated violations

	// Admin
	AdminAgentID string // Agent ID with elevated permissions (can delete any message)
}

// Load reads configuration from environment variables.
// In development, it loads from .env file if present.
// In production, it panics on missing required variables.
func Load() *Config {
	// Load .env file if it exists (for development)
	_ = godotenv.Load()

	cfg := &Config{
		Port:             getEnv("PORT", "8080"),
		Env:              getEnv("ENV", "development"),
		DatabaseURL:      os.Getenv("DATABASE_URL"),
		SQLitePath:       getEnv("SQLITE_PATH", "./data/aicq.db"),
		RedisURL:         os.Getenv("REDIS_URL"),
		AutoBlockEnabled: getEnv("AUTO_BLOCK_ENABLED", "false") == "true",
		AdminAgentID:     os.Getenv("ADMIN_AGENT_ID"),
	}

	// Parse whitelist (comma-separated IPs or CIDRs)
	if whitelist := os.Getenv("RATE_LIMIT_WHITELIST"); whitelist != "" {
		for _, entry := range strings.Split(whitelist, ",") {
			entry = strings.TrimSpace(entry)
			if entry != "" {
				cfg.RateLimitWhitelist = append(cfg.RateLimitWhitelist, entry)
			}
		}
	}

	// In production, require redis URL (database can be SQLite or PostgreSQL)
	if cfg.Env == "production" {
		if cfg.RedisURL == "" {
			panic("REDIS_URL is required in production")
		}
	}

	return cfg
}

// IsDevelopment returns true if running in development mode.
func (c *Config) IsDevelopment() bool {
	return c.Env == "development"
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
