package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"

	"github.com/aicq-protocol/aicq/internal/api"
	"github.com/aicq-protocol/aicq/internal/config"
	"github.com/aicq-protocol/aicq/internal/store"
)

func main() {
	// Load configuration
	cfg := config.Load()

	// Initialize logger
	var logger zerolog.Logger
	if cfg.IsDevelopment() {
		logger = zerolog.New(zerolog.ConsoleWriter{Out: os.Stdout, TimeFormat: time.RFC3339}).
			With().
			Timestamp().
			Logger()
	} else {
		logger = zerolog.New(os.Stdout).
			With().
			Timestamp().
			Logger()
	}

	ctx := context.Background()

	// Run migrations
	if cfg.DatabaseURL != "" {
		logger.Info().Msg("running database migrations...")
		if err := store.RunMigrations(cfg.DatabaseURL); err != nil {
			logger.Fatal().Err(err).Msg("migration failed")
		}
		logger.Info().Msg("migrations completed")
	}

	// Initialize PostgreSQL store
	var pgStore *store.PostgresStore
	if cfg.DatabaseURL != "" {
		var err error
		pgStore, err = store.NewPostgresStore(ctx, cfg.DatabaseURL)
		if err != nil {
			logger.Fatal().Err(err).Msg("postgres connection failed")
		}
		defer pgStore.Close()
		logger.Info().Msg("connected to PostgreSQL")
	}

	// Initialize Redis store
	var redisStore *store.RedisStore
	if cfg.RedisURL != "" {
		var err error
		redisStore, err = store.NewRedisStore(ctx, cfg.RedisURL)
		if err != nil {
			logger.Fatal().Err(err).Msg("redis connection failed")
		}
		defer redisStore.Close()
		logger.Info().Msg("connected to Redis")
	}

	// Create router
	router := api.NewRouter(logger, pgStore, redisStore)

	// Create server
	srv := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Start server in goroutine
	go func() {
		logger.Info().
			Str("port", cfg.Port).
			Str("env", cfg.Env).
			Msg("starting AICQ server")

		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			logger.Fatal().Err(err).Msg("server failed to start")
		}
	}()

	// Wait for interrupt signal
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	logger.Info().Msg("shutting down server...")

	// Graceful shutdown with 30 second timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		logger.Fatal().Err(err).Msg("server forced to shutdown")
	}

	logger.Info().Msg("server stopped")
}
