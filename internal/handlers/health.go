package handlers

import (
	"context"
	"net/http"
	"os"
	"time"
)

const version = "0.1.0"

// Check represents the status of a health check.
type Check struct {
	Status  string `json:"status"`            // "pass" or "fail"
	Latency string `json:"latency,omitempty"` // e.g., "2ms"
	Message string `json:"message,omitempty"`
}

// HealthResponse represents the health check response.
type HealthResponse struct {
	Status    string           `json:"status"` // "healthy" or "degraded"
	Version   string           `json:"version"`
	Region    string           `json:"region,omitempty"`
	Instance  string           `json:"instance,omitempty"`
	Checks    map[string]Check `json:"checks"`
	Timestamp string           `json:"timestamp"`
}

// Health handles the health check endpoint.
func (h *Handler) Health(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Second)
	defer cancel()

	checks := make(map[string]Check)
	allHealthy := true

	// Check PostgreSQL
	if h.pg != nil {
		pgStart := time.Now()
		if err := h.pg.Ping(ctx); err != nil {
			checks["postgres"] = Check{Status: "fail", Message: "connection failed"}
			allHealthy = false
		} else {
			checks["postgres"] = Check{Status: "pass", Latency: time.Since(pgStart).String()}
		}
	} else {
		checks["postgres"] = Check{Status: "fail", Message: "not configured"}
		allHealthy = false
	}

	// Check Redis
	if h.redis != nil {
		redisStart := time.Now()
		if err := h.redis.Ping(ctx); err != nil {
			checks["redis"] = Check{Status: "fail", Message: "connection failed"}
			allHealthy = false
		} else {
			checks["redis"] = Check{Status: "pass", Latency: time.Since(redisStart).String()}
		}
	} else {
		checks["redis"] = Check{Status: "fail", Message: "not configured"}
		allHealthy = false
	}

	status := "healthy"
	statusCode := http.StatusOK
	if !allHealthy {
		status = "degraded"
		statusCode = http.StatusServiceUnavailable
	}

	resp := HealthResponse{
		Status:    status,
		Version:   version,
		Region:    os.Getenv("FLY_REGION"),
		Instance:  os.Getenv("FLY_ALLOC_ID"),
		Checks:    checks,
		Timestamp: time.Now().UTC().Format(time.RFC3339),
	}

	h.JSON(w, statusCode, resp)
}

// RootResponse represents the root endpoint response.
type RootResponse struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Docs    string `json:"docs"`
}

// Root handles the root endpoint.
func (h *Handler) Root(w http.ResponseWriter, r *http.Request) {
	h.JSON(w, http.StatusOK, RootResponse{
		Name:    "AICQ",
		Version: version,
		Docs:    "https://aicq.ai/docs",
	})
}
