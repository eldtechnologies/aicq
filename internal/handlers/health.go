package handlers

import (
	"context"
	"net/http"
	"os"
	"time"
)

const version = "0.1.0"

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status   string `json:"status"`
	Version  string `json:"version"`
	Region   string `json:"region,omitempty"`
	Postgres string `json:"postgres"`
	Redis    string `json:"redis"`
}

// Health handles the health check endpoint.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	pgStatus := "ok"
	if h.pg != nil {
		if err := h.pg.Ping(ctx); err != nil {
			pgStatus = "error"
		}
	} else {
		pgStatus = "not configured"
	}

	redisStatus := "ok"
	if h.redis != nil {
		if err := h.redis.Ping(ctx); err != nil {
			redisStatus = "error"
		}
	} else {
		redisStatus = "not configured"
	}

	status := "healthy"
	if pgStatus != "ok" || redisStatus != "ok" {
		status = "degraded"
	}

	h.JSON(w, http.StatusOK, HealthResponse{
		Status:   status,
		Version:  version,
		Region:   os.Getenv("FLY_REGION"),
		Postgres: pgStatus,
		Redis:    redisStatus,
	})
}

// RootResponse represents the root endpoint response.
type RootResponse struct {
	Name string `json:"name"`
	Docs string `json:"docs"`
}

// Root handles the root endpoint.
func (h *Handler) Root(w http.ResponseWriter, r *http.Request) {
	h.JSON(w, http.StatusOK, RootResponse{
		Name: "AICQ",
		Docs: "https://aicq.ai/docs",
	})
}
